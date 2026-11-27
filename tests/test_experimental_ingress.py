"""Tests for the experimental ingress candidate, not deployment certification."""
import http.client
import os
from pathlib import Path
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
from archx_wsgi.ingress import nginx_config

NGINX = os.environ.get('ARCHX_TEST_NGINX')


class ConfigTests(unittest.TestCase):
    def test_rejects_config_injection_and_bad_limits(self):
        values = dict(socket_path='/tmp/a.sock', certificate='/tmp/cert.pem',
                      private_key='/tmp/key.pem', port=8443)
        for key, value in [('socket_path', '/tmp/x;include /evil'),
                           ('socket_path', '/tmp/../a'), ('socket_path', '/tmp/' + 'a'*101),
                           ('certificate', '/tmp/a\nserver {}'), ('port', True),
                           ('port', 80), ('public', 1), ('rate', 0),
                           ('burst', 1001), ('max_active', 65)]:
            with self.subTest(key=key, value=value):
                with self.assertRaises(ValueError):
                    nginx_config(**{**values, key: value})
        self.assertIn('listen 127.0.0.1:8443', nginx_config(**values))
        self.assertIn('listen 0.0.0.0:8443', nginx_config(**values, public=True))


@unittest.skipUnless(NGINX and os.geteuid() != 0, 'requires nginx and an unprivileged Unix user')
class IngressTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ax-ingress-')
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        cls.root = root
        cls.socket_path = root / 'origin.sock'
        cls.cert = root / 'cert.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(root / 'key.pem'), '-out', str(cls.cert), '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        env = {**os.environ, 'ARCHX_TEST_SOCKET': str(cls.socket_path),
               'ARCHX_TEST_EXPERIMENTAL_INGRESS': '1'}
        cls.env = env
        cls.log = open(root / 'origin.log', 'wb')
        cls.addClassCleanup(cls.log.close)
        cls.origin = subprocess.Popen([sys.executable, str(ROOT / 'tests/fixtures/wsgi_unix_origin.py')],
                                      env=env, stdout=cls.log, stderr=subprocess.STDOUT)
        cls.addClassCleanup(cls.stop, cls.origin)
        deadline = time.monotonic() + 8
        while not cls.socket_path.exists():
            if cls.origin.poll() is not None:
                raise RuntimeError('Origin exited during startup: ' + (root / 'origin.log').read_text())
            if time.monotonic() > deadline:
                raise RuntimeError('Origin startup timed out')
            time.sleep(0.05)
        cls.assert_socket()
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            cls.port = sock.getsockname()[1]
        config = root / 'nginx.conf'
        config.write_text(nginx_config(socket_path=str(cls.socket_path), certificate=str(cls.cert),
                          private_key=str(root / 'key.pem'), port=cls.port, rate=1, burst=2,
                          max_active=2))
        subprocess.run([NGINX, '-t', '-p', str(root), '-c', str(config)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.proxy_log = open(root / 'proxy.log', 'wb')
        cls.addClassCleanup(cls.proxy_log.close)
        cls.proxy = subprocess.Popen([NGINX, '-p', str(root), '-c', str(config), '-g', 'daemon off;'],
                                     stdout=cls.proxy_log, stderr=subprocess.STDOUT)
        cls.addClassCleanup(cls.stop, cls.proxy)
        deadline = time.monotonic() + 8
        while True:
            if cls.proxy.poll() is not None:
                raise RuntimeError('nginx exited: ' + (root / 'proxy.log').read_text())
            try:
                with socket.create_connection(('127.0.0.1', cls.port), timeout=.2):
                    break
            except OSError:
                if time.monotonic() > deadline: raise
                time.sleep(.05)

    @classmethod
    def assert_socket(cls):
        info = cls.socket_path.stat()
        if not stat.S_ISSOCK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise AssertionError('Socket permissions/type invalid')

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=5)

    def request(self, method, path, source, headers=None, body=None):
        context = ssl.create_default_context(cafile=str(self.cert))
        conn = http.client.HTTPSConnection('localhost', self.port, timeout=5, context=context,
                                           source_address=(source, 0))
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            response.read()
            return response.status
        finally:
            conn.close()

    def test_duplicate_origin_fails_without_replacing_socket(self):
        original = self.socket_path.stat()
        second = subprocess.run([sys.executable, str(ROOT / 'tests/fixtures/wsgi_unix_origin.py')],
                                env=self.env, capture_output=True, timeout=8)
        self.assertNotEqual(second.returncode, 0)
        self.assertIn(b'Another origin owns', second.stderr)
        self.assertEqual((original.st_dev, original.st_ino),
                         (self.socket_path.stat().st_dev, self.socket_path.stat().st_ino))
        self.assertIsNone(self.origin.poll())

    def test_existing_paths_and_unsafe_directory_are_rejected(self):
        for kind in ('regular', 'symlink', 'stale_socket', 'unsafe_parent'):
            with self.subTest(kind=kind):
                with tempfile.TemporaryDirectory(prefix='ax-safety-') as dirname:
                    root = Path(dirname)
                    path = root / 'origin.sock'
                    held = None
                    try:
                        if kind == 'regular': path.write_text('keep me')
                        elif kind == 'symlink': path.symlink_to(root / 'missing')
                        elif kind == 'stale_socket':
                            held = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                            held.bind(str(path))
                        else: root.chmod(0o755)
                        env = {**self.env, 'ARCHX_TEST_SOCKET': str(path)}
                        proc = subprocess.run([sys.executable, str(ROOT / 'tests/fixtures/wsgi_unix_origin.py')],
                                              env=env, capture_output=True, timeout=8)
                        self.assertNotEqual(proc.returncode, 0)
                        self.assertIn(b'private and owned' if kind == 'unsafe_parent' else b'already exists', proc.stderr)
                        if kind == 'regular': self.assertEqual(path.read_text(), 'keep me')
                        if kind == 'symlink': self.assertTrue(path.is_symlink())
                        if kind == 'stale_socket': self.assertTrue(stat.S_ISSOCK(path.stat().st_mode))
                    finally:
                        if held: held.close()
                        root.chmod(0o700)

    @unittest.skipUnless(os.environ.get('ARCHX_TEST_OTHER_USER'), 'requires another unprivileged account')
    def test_other_uid_cannot_connect_to_origin(self):
        import pwd
        user = os.environ['ARCHX_TEST_OTHER_USER']
        if pwd.getpwnam(user).pw_uid in (0, os.geteuid()):
            self.fail('Test account must be a distinct, unprivileged UID')
        script = ('import socket,sys; s=socket.socket(socket.AF_UNIX); '
                  's.connect(sys.argv[1])')
        proc = subprocess.run(['sudo', '-n', '-u', user, '/usr/bin/python3', '-c', script,
                               str(self.socket_path)], capture_output=True, timeout=8)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b'PermissionError', proc.stderr)

    def test_slow_bodies_are_limited_and_recover(self):
        time.sleep(3.5)
        context = ssl.create_default_context(cafile=str(self.cert))
        held = []
        try:
            for index in range(2):
                raw = socket.create_connection(('127.0.0.1', self.port), timeout=4,
                                               source_address=(f'127.0.0.{50+index}', 0))
                tls = context.wrap_socket(raw, server_hostname='localhost')
                held.append(tls)
                tls.sendall(b'POST /slow HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n{')
                time.sleep(1.1)
            self.assertEqual(self.request('GET', '/any-route', '127.0.0.52'), 503)
        finally:
            for client in held: client.close()
        time.sleep(3.5)
        self.assertEqual(self.request('GET', '/any-route', '127.0.0.53'), 400)

    def test_mixed_route_limit_and_recovery(self):
        # Different routes and client peers share one zone. Origin's invalid
        # response is 400; the proxy produces its own 429 on saturation.
        time.sleep(3.5)
        statuses = [self.request(method, path, f'127.0.0.{20+i}', body=body)
                    for i, (method, path, body) in enumerate([
                        ('GET', '/', None), ('GET', '/challenge', None),
                        ('POST', '/protected', b'{}'), ('GET', '/other', None),
                        ('GET', '/other2', None), ('GET', '/other3', None)])]
        self.assertIn(429, statuses)
        self.assertIn(400, statuses)
        time.sleep(3.5)
        self.assertEqual(self.request('GET', '/recovery', '127.0.0.40'), 400)

    def test_same_uid_can_forge_origin_peer(self):
        # Document the local trust boundary: access as the origin UID can
        # bypass nginx and its forwarding-header overwrite.
        import json
        sys.path.insert(0, str(ROOT / 'demo'))
        from signal_validation import synthetic_signal
        class UnixConnection(http.client.HTTPConnection):
            def connect(inner):
                inner.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                inner.sock.settimeout(5)
                inner.sock.connect(str(self.socket_path))
        for i in (1, 2):
            conn = UnixConnection('localhost', timeout=5)
            raw = json.dumps({'signals': {'machine_id': synthetic_signal('machine_id', f'direct-{i}')}}).encode()
            try:
                conn.request('POST', '/protected', raw, {'X-Forwarded-For': f'192.0.2.{200+i}'})
                response = conn.getresponse()
                self.assertEqual(response.status, 200)
                response.read()
            finally: conn.close()

    def test_size_and_client_header_spoof(self):
        time.sleep(3.5)
        self.assertEqual(self.request('POST', '/large', '127.0.0.41', body=b'x'*8193), 413)
        # Distinct requests from the same network peer must not be charged as
        # different clients merely because a user sends a forwarding header.
        import json
        sys.path.insert(0, str(ROOT / 'demo'))
        from signal_validation import synthetic_signal
        def body(seed):
            return json.dumps({'signals': {'machine_id': synthetic_signal('machine_id', seed)}}).encode()
        self.assertEqual(self.request('POST', '/protected', '127.0.0.42', body=body('one')), 200)
        # Drain the proxy bucket so a 429 here can only come from the origin.
        time.sleep(3.5)
        self.assertEqual(self.request('POST', '/protected', '127.0.0.42',
                         headers={'X-Forwarded-For': '192.0.2.41'}, body=body('single')), 429)
        time.sleep(3.5)
        self.assertEqual(self.request('POST', '/protected', '127.0.0.42',
                         headers={'X-Forwarded-For': '192.0.2.42, 192.0.2.43'}, body=body('two')), 429)
        time.sleep(3.5)
        conn = http.client.HTTPSConnection('localhost', self.port, timeout=5,
                    context=ssl.create_default_context(cafile=str(self.cert)),
                    source_address=('127.0.0.42', 0))
        try:
            raw = body('three')
            conn.putrequest('POST', '/protected')
            conn.putheader('Content-Length', str(len(raw)))
            conn.putheader('X-Forwarded-For', '192.0.2.44')
            conn.putheader('X-Forwarded-For', '192.0.2.45')
            conn.putheader('Forwarded', 'for=192.0.2.46')
            conn.endheaders(raw)
            response = conn.getresponse()
            self.assertEqual(response.status, 429)
            response.read()
        finally:
            conn.close()


if __name__ == '__main__':
    unittest.main()
