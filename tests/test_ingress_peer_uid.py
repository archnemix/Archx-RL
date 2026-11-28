"""Linux-only real-UID TLS experiment: not a production support claim."""
import http.client
import json
import os
from pathlib import Path
import pwd
import grp
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'integrations/wsgi'))
sys.path.insert(0, str(ROOT / 'demo'))
from archx_wsgi.ingress import nginx_config
from signal_validation import synthetic_signal

NGINX = os.environ.get('ARCHX_TEST_NGINX')
PROXY = os.environ.get('ARCHX_TEST_PROXY_USER')
GROUP = os.environ.get('ARCHX_TEST_SOCKET_GROUP')
DENIED = os.environ.get('ARCHX_TEST_DENIED_USER')


@unittest.skipUnless(NGINX and PROXY and GROUP and DENIED and os.geteuid() != 0,
                     'requires nginx, sudo, a socket group and two distinct unprivileged users')
class DistinctPeerExperiment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proxy_uid = pwd.getpwnam(PROXY).pw_uid
        cls.origin_uid = os.geteuid()
        denied_uid = pwd.getpwnam(DENIED).pw_uid
        cls.group_gid = grp.getgrnam(GROUP).gr_gid
        if (len({cls.proxy_uid, denied_uid, cls.origin_uid, 0}) != 4 or cls.group_gid == 0):
            raise RuntimeError('Tests require three distinct non-root UIDs and a non-root group')
        cls.origin_user = pwd.getpwuid(cls.origin_uid).pw_name
        cls.temp = tempfile.TemporaryDirectory(prefix='archx-peer-')
        cls.root = Path(cls.temp.name)
        # Restore ownership of proxy files before temporary-directory cleanup.
        cls.addClassCleanup(cls.temp.cleanup)
        cls.addClassCleanup(subprocess.run,
                            ['sudo', '-n', 'chown', '-R', f'{cls.origin_uid}:{os.getegid()}', str(cls.root)],
                            check=True, stdout=subprocess.DEVNULL)
        cls.root.chmod(0o711)
        origin_dir = cls.root / 'origin'
        origin_dir.mkdir(mode=0o700)
        subprocess.run(['sudo', '-n', 'chown', f'{cls.origin_uid}:{cls.group_gid}', str(origin_dir)], check=True)
        origin_dir.chmod(0o710)
        cls.sockpath = origin_dir / 'origin.sock'
        proxy_dir = cls.root / 'proxy'
        proxy_dir.mkdir()
        cls.cert = proxy_dir / 'cert.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(proxy_dir / 'key.pem'), '-out', str(cls.cert), '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        proxy_dir.joinpath('key.pem').chmod(0o600)
        # The optional nginx-wheel binary can be under an inaccessible home
        # directory; a disposable copy allows the distinct UID to execute it.
        binary = cls.root / 'nginx'
        shutil.copyfile(NGINX, binary)
        binary.chmod(0o755)
        env = {**os.environ, 'ARCHX_TEST_SOCKET': str(cls.sockpath),
               'ARCHX_TEST_EXPERIMENTAL_INGRESS': '1',
               'ARCHX_TEST_PROXY_UID': str(cls.proxy_uid),
               'ARCHX_TEST_SOCKET_GID': str(cls.group_gid)}
        cls.log = open(cls.root / 'origin.log', 'wb')
        cls.addClassCleanup(cls.log.close)
        passed = [f'{key}={env[key]}' for key in ('ARCHX_TEST_SOCKET', 'ARCHX_TEST_EXPERIMENTAL_INGRESS',
                                                    'ARCHX_TEST_PROXY_UID', 'ARCHX_TEST_SOCKET_GID')]
        cls.origin_prefix = ([] if cls.group_gid in set(os.getgroups()) | {os.getegid()}
                             else cls.as_uid(cls.origin_uid, cls.group_gid))
        cls.origin = subprocess.Popen([*cls.origin_prefix, '/usr/bin/env', *passed, sys.executable,
                                      str(ROOT / 'tests/fixtures/wsgi_unix_origin.py')],
                                     stdout=cls.log, stderr=subprocess.STDOUT)
        cls.addClassCleanup(cls.stop, cls.origin)
        deadline = time.monotonic() + 8
        while True:
            if cls.origin.poll() is not None:
                raise RuntimeError('Origin failed: ' + (cls.root / 'origin.log').read_text())
            try:
                info = cls.sockpath.stat()
                if stat.S_ISSOCK(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o660:
                    if info.st_uid != cls.origin_uid or info.st_gid != cls.group_gid:
                        raise RuntimeError('Unexpected socket ownership')
                    break
            except FileNotFoundError:
                pass
            if time.monotonic() > deadline: raise RuntimeError('Origin startup timed out')
            time.sleep(.05)
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0)); cls.port = sock.getsockname()[1]
        config = proxy_dir / 'nginx.conf'
        config.write_text(nginx_config(socket_path=str(cls.sockpath), certificate=str(cls.cert),
                                       private_key=str(proxy_dir / 'key.pem'), port=cls.port,
                                       rate=100, burst=100, max_active=8))
        proxy_dir.chmod(0o700)
        subprocess.run(['sudo', '-n', 'chown', '-R', f'{cls.proxy_uid}:{cls.group_gid}', str(proxy_dir)], check=True)
        cls.log_proxy = open(cls.root / 'proxy.log', 'wb')
        cls.addClassCleanup(cls.log_proxy.close)
        cls.proxy = subprocess.Popen([*cls.as_uid(cls.proxy_uid, cls.group_gid), str(binary),
                     '-p', str(proxy_dir), '-c', str(config), '-g', 'daemon off;'],
                    stdout=cls.log_proxy, stderr=subprocess.STDOUT)
        cls.addClassCleanup(cls.stop, cls.proxy)
        # Tests run as the origin UID, not the proxy UID; grant read of the
        # public certificate only, leaving the directory/key private.
        subprocess.run(['sudo', '-n', 'cp', str(cls.cert), str(cls.root / 'trusted.pem')], check=True)
        subprocess.run(['sudo', '-n', 'chown', f'{cls.origin_uid}:{os.getegid()}',
                        str(cls.root / 'trusted.pem')], check=True)
        cls.ca = cls.root / 'trusted.pem'
        deadline = time.monotonic() + 8
        while True:
            if cls.proxy.poll() is not None:
                raise RuntimeError('Proxy failed: ' + (cls.root / 'proxy.log').read_text())
            try:
                with socket.create_connection(('127.0.0.1', cls.port), timeout=.2): break
            except OSError:
                if time.monotonic() > deadline: raise
                time.sleep(.05)

    @staticmethod
    def as_uid(uid, gid):
        # GitHub-hosted sudo policy permits root but not arbitrary run-as users.
        # setpriv drops all supplemental groups before executing the test peer.
        return ['sudo', '-n', '/usr/bin/setpriv', f'--reuid={uid}', f'--regid={gid}', '--clear-groups']

    @staticmethod
    def stop(proc):
        if proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait(timeout=5)

    def body(self, seed):
        return json.dumps({'signals': {'machine_id': synthetic_signal('machine_id', seed)}}).encode()

    def https(self, source, headers, seed):
        conn = http.client.HTTPSConnection('localhost', self.port, timeout=5,
                 context=ssl.create_default_context(cafile=str(self.ca)), source_address=(source, 0))
        body = self.body(seed)
        try:
            conn.putrequest('POST', '/protected')
            conn.putheader('Content-Length', str(len(body)))
            for name, value in headers: conn.putheader(name, value)
            conn.endheaders(body)
            res = conn.getresponse(); res.read(); return res.status
        finally: conn.close()

    def test_unsafe_separation_settings_fail_closed(self):
        with tempfile.TemporaryDirectory(prefix='invalid-', dir=self.root) as dirname:
            root = Path(dirname)
            subprocess.run(['sudo', '-n', 'chown', f'{self.origin_uid}:{self.group_gid}', dirname], check=True)
            path = root / 'sock'
            for mode, uid in ((0o710, self.origin_uid), (0o700, self.proxy_uid), (0o770, self.proxy_uid)):
                root.chmod(mode)
                values = [f'ARCHX_TEST_SOCKET={path}', 'ARCHX_TEST_EXPERIMENTAL_INGRESS=1',
                          f'ARCHX_TEST_PROXY_UID={uid}', f'ARCHX_TEST_SOCKET_GID={self.group_gid}']
                proc = subprocess.run([*self.origin_prefix, '/usr/bin/env', *values, sys.executable,
                                       str(ROOT / 'tests/fixtures/wsgi_unix_origin.py')],
                                      capture_output=True, timeout=8)
                self.assertNotEqual(proc.returncode, 0)
                self.assertFalse(path.exists())
            root.chmod(0o700)

    def test_https_spoofs_do_not_change_peer(self):
        cases = [[('X-Forwarded-For', '192.0.2.11')],
                 [('X-Forwarded-For', '192.0.2.12, 192.0.2.13')],
                 [('X-Forwarded-For', '192.0.2.14'), ('X-Forwarded-For', '192.0.2.15'),
                  ('Forwarded', 'for=192.0.2.16')]]
        for i, headers in enumerate(cases):
            source = f'127.0.0.{60+i}'
            self.assertEqual(self.https(source, [], f'peer-base-{i}'), 200)
            self.assertEqual(self.https(source, headers, f'peer-forged-{i}'), 429)
        self.assertEqual(self.https('127.0.0.69', [], 'peer-independent'), 200)

    def test_origin_uid_and_other_group_member_are_denied(self):
        script = '''import socket,sys
s=socket.socket(socket.AF_UNIX); s.settimeout(4); s.connect(sys.argv[1])
try:
    s.sendall(b"GET / HTTP/1.0\\r\\n\\r\\n")
    response=s.recv(100)
    if response: raise SystemExit("unexpected origin response")
except (ConnectionResetError, BrokenPipeError): pass
print("rejected-after-connect")
'''
        for user in (self.origin_user, DENIED):
            with self.subTest(user=user):
                prefix = (self.origin_prefix if user == self.origin_user else
                          self.as_uid(pwd.getpwnam(user).pw_uid, self.group_gid))
                proc = subprocess.run([*prefix, '/usr/bin/python3', '-c', script, str(self.sockpath)],
                                      capture_output=True, timeout=8)
                self.assertEqual(proc.returncode, 0, proc.stderr.decode())
                self.assertIn(b'rejected-after-connect', proc.stdout)

    def test_proxy_uid_remains_trusted_and_can_forge_directly(self):
        # SO_PEERCRED authenticates an OS UID, not the nginx executable.
        script = '''import socket,sys
s=socket.socket(socket.AF_UNIX);s.settimeout(4);s.connect(sys.argv[1]);body=sys.argv[2].encode()
s.sendall(b"POST /protected HTTP/1.0\\r\\nX-Forwarded-For: 192.0.2.201\\r\\nContent-Length: " + str(len(body)).encode() + b"\\r\\n\\r\\n" + body)
print(s.recv(100).decode('ascii',errors='replace'))
'''
        proc = subprocess.run([*self.as_uid(self.proxy_uid, self.group_gid), '/usr/bin/python3',
                               '-c', script, str(self.sockpath), self.body('proxy-direct').decode()],
                              capture_output=True, timeout=8)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertIn(b'200 OK', proc.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
