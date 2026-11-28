"""Experimental Linux-only, single-process ingress primitives.

The host supplies authentication, authorization and its protected WSGI app.
Never use this without the proxy/Unix-socket trust and operational limitations
in the adjacent deployment guide. This module does not expose demo routes.
"""
import fcntl
import os
from pathlib import Path
import re
import socket
import stat
import struct
import threading

from . import ProtectedApplication

_SAFE_PATH = re.compile(r'/[A-Za-z0-9_./-]+\Z', re.ASCII)
_SAFE_NAME = re.compile(r'[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}\Z', re.ASCII)


def _path(value):
    if type(value) is not str or not _SAFE_PATH.fullmatch(value) or '//' in value:
        raise ValueError('Expected a safe absolute path')
    if any(part in ('.', '..') for part in value.split('/')):
        raise ValueError('Relative path components are not allowed')
    return value


def _integer(value, minimum, maximum):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError('Invalid ingress bound')
    return value


def nginx_config(*, socket_path, certificate, private_key, port, public=False,
                 rate=10, burst=20, max_active=16):
    """Render a standalone one-worker nginx configuration, not a full deployment.

    Inputs are deliberately restricted to avoid nginx config injection. Public
    network listening is an explicit opt-in, and requires independent review.
    """
    socket_path, certificate, private_key = map(_path, (socket_path, certificate, private_key))
    if len(os.fsencode(socket_path)) > 100:
        raise ValueError('Unix socket path is too long')
    port = _integer(port, 1024, 65535)
    rate = _integer(rate, 1, 1000)
    burst = _integer(burst, 1, 1000)
    max_active = _integer(max_active, 1, 64)
    if type(public) is not bool:
        raise ValueError('Public listen flag must be boolean')
    host = '0.0.0.0' if public else '127.0.0.1'
    return f'''worker_processes 1;
error_log stderr warn;
pid nginx.pid;
events {{ worker_connections 256; }}
http {{
    access_log off;
    client_max_body_size 8k;
    client_header_timeout 10s;
    client_body_timeout 10s;
    client_header_buffer_size 1k;
    large_client_header_buffers 2 8k;
    limit_req_zone $server_name zone=archx_global_rate:1m rate={rate}r/s;
    limit_conn_zone $server_name zone=archx_global_connections:1m;
    server {{
        listen {host}:{port} ssl default_server backlog=32;
        server_name _;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_certificate {certificate};
        ssl_certificate_key {private_key};
        location / {{
            limit_req zone=archx_global_rate burst={burst} nodelay;
            limit_req_status 429;
            limit_conn archx_global_connections {max_active};
            limit_conn_status 503;
            proxy_request_buffering on;
            proxy_buffering on;
            proxy_http_version 1.0;
            proxy_set_header Connection close;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header Forwarded "";
            proxy_set_header X-Real-IP "";
            proxy_set_header X-Forwarded-Host "";
            proxy_set_header X-Forwarded-Proto "";
            proxy_set_header X-Forwarded-Port "";
            proxy_connect_timeout 5s;
            proxy_send_timeout 15s;
            proxy_read_timeout 15s;
            proxy_next_upstream off;
            proxy_pass http://unix:{socket_path}:;
        }}
    }}
}}
'''


def _bounded_dispatcher():
    """Build a Waitress 3.0.2 dispatcher with a fixed pending-task limit.

    This depends on private Waitress internals and is not an independently
    supported server. Waitress calls add_task while holding the channel's
    request lock; do not reacquire it on the rejection path.
    """
    from waitress.task import ThreadedTaskDispatcher

    class BoundedDispatcher(ThreadedTaskDispatcher):
        max_pending = 16

        def add_task(self, task):
            with self.lock:
                running = len(self.threads) - self.stop_count
                if running > 0 and len(self.queue) < self.max_pending:
                    self.queue.append(task)
                    self.queue_cv.notify()
                    return
            # Reject, don't queue. In Waitress 3.0.2 the caller holds the
            # channel request lock. Close buffered parsers before cancel drops
            # references; disconnected channels may otherwise accumulate.
            for request in task.requests:
                try:
                    request.close()
                except Exception:
                    pass
            task.cancel()
            try:
                task.server.pull_trigger()
            except OSError:
                pass

    return BoundedDispatcher()


def serve_unix(application, socket_path, *, proxy_uid=None, socket_gid=None):
    """Run one Waitress process on an exclusively-owned Unix socket.

    With both proxy_uid and socket_gid, experimental Linux peer credentials
    restrict connections to that distinct non-root UID. The socket directory
    must be owned by the origin UID, group-owned by socket_gid and mode 0710;
    the origin process must be a member of that group. Without them the
    legacy mode trusts all same-UID peers. Both the proxy UID and origin UID,
    their code and the directory's ancestors remain trusted. Run in a fresh,
    non-root process; this is not a supported production profile.
    """
    if not isinstance(application, ProtectedApplication) or application.max_inflight > 4:
        raise ValueError('A ProtectedApplication with at most four in-flight slots is required')
    socket_path = _path(socket_path)
    if len(os.fsencode(socket_path)) > 100:
        raise ValueError('Unix socket path is too long')
    parent, name = os.path.split(socket_path)
    if not _SAFE_NAME.fullmatch(name) or str(Path(parent).resolve()) != parent:
        raise ValueError('Invalid or symlinked socket path')
    if os.geteuid() == 0 or threading.active_count() != 1:
        raise ValueError('Origin requires a fresh non-root process')
    separated = proxy_uid is not None or socket_gid is not None
    if separated:
        if (type(proxy_uid) is not int or not 0 < proxy_uid < 2**32 - 1 or proxy_uid == os.geteuid() or
                type(socket_gid) is not int or not 0 < socket_gid < 2**32 - 1 or
                socket_gid not in set(os.getgroups()) | {os.getegid()} or
                not hasattr(socket, 'SO_PEERCRED')):
            raise ValueError('Distinct proxy UID and an accessible socket group are required')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    dirfd = os.open(parent, flags)
    lockfd = None
    server = None
    dispatcher = None
    created = None
    try:
        info = os.fstat(dirfd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
                (separated and (stat.S_IMODE(info.st_mode) != 0o710 or info.st_gid != socket_gid)) or
                (not separated and info.st_mode & 0o077)):
            raise ValueError('Socket directory must be private and owned by the service UID')
        lockfd = os.open('.archx-origin.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=dirfd)
        lockstat = os.fstat(lockfd)
        if (not stat.S_ISREG(lockstat.st_mode) or lockstat.st_uid != os.geteuid() or
                lockstat.st_mode & 0o077 or lockstat.st_nlink != 1):
            raise ValueError('Unsafe origin lock file')
        try:
            fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Another origin owns the socket directory') from None
        try:
            os.stat(name, dir_fd=dirfd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError('Socket path already exists; inspect before removing it')
        from importlib.metadata import version
        if version('waitress') != '3.0.2':
            raise ValueError('This prototype requires Waitress 3.0.2')
        from waitress.server import create_server
        dispatcher = _bounded_dispatcher()
        dispatcher.set_thread_count(4)
        # Waitress binds before chmod; use a restrictive umask in this dedicated
        # process to avoid an initially world-accessible Unix socket. The pinned
        # private dispatcher hook allows cleanup even when binding fails.
        old_umask = os.umask(0o077)
        try:
            server = create_server(application, _dispatcher=dispatcher, unix_socket=socket_path, unix_socket_perms='600',
                threads=4, connection_limit=64, backlog=32, recv_bytes=8192,
                max_request_header_size=8192, max_request_body_size=8192,
                channel_request_lookahead=0, trusted_proxy='localhost',
                trusted_proxy_headers='x-forwarded-for', clear_untrusted_proxy_headers=True,
                channel_timeout=15, cleanup_interval=1, expose_tracebacks=False)
        finally:
            os.umask(old_umask)
        created = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
        if not stat.S_ISSOCK(created.st_mode) or created.st_uid != os.geteuid() or stat.S_IMODE(created.st_mode) != 0o600:
            raise ValueError('Unexpected socket ownership or permissions')
        if separated:
            os.chown(name, -1, socket_gid, dir_fd=dirfd, follow_symlinks=False)
            # Parent and origin UID are trusted. There is no protection from a
            # process with the origin UID racing this path-based chmod.
            os.chmod(socket_path, 0o660)
            checked = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            if (not stat.S_ISSOCK(checked.st_mode) or checked.st_uid != os.geteuid() or
                    checked.st_gid != socket_gid or stat.S_IMODE(checked.st_mode) != 0o660 or
                    (checked.st_dev, checked.st_ino) != (created.st_dev, created.st_ino)):
                raise ValueError('Unexpected group socket ownership or permissions')
            original_accept = server.accept
            def accept_proxy_only():
                # Waitress 3.0.2 calls accept() before constructing a channel.
                # Reject unexpected UIDs before it parses or trusts headers.
                pair = original_accept()
                if pair is None:
                    return None
                conn, _ = pair
                try:
                    credentials = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('iII'))
                    _, uid, _ = struct.unpack('iII', credentials)
                except (OSError, ValueError, struct.error):
                    conn.close()
                    return None
                if uid != proxy_uid:
                    conn.close()
                    return None
                return pair
            server.accept = accept_proxy_only
        server.run()
    finally:
        if dispatcher is not None:
            dispatcher.shutdown()
        if server is not None:
            server.close()
        if created is not None:
            try:
                current = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
                if stat.S_ISSOCK(current.st_mode) and (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                    os.unlink(name, dir_fd=dirfd)
            except FileNotFoundError:
                pass
        if lockfd is not None:
            os.close(lockfd)
        os.close(dirfd)
