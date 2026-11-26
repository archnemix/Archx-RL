"""Real TLS/nginx to private Unix-socket WSGI experiment, not a deployment profile."""
import http.client
import json
import os
from pathlib import Path
import pwd
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
sys.path.insert(0, str(ROOT / 'demo'))
from signal_validation import synthetic_signal

NGINX = os.environ.get('ARCHX_TEST_NGINX')
OTHER_USER = os.environ.get('ARCHX_TEST_OTHER_USER')


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__('localhost', timeout=3)
        self.path = path
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


@unittest.skipUnless(NGINX, 'set ARCHX_TEST_NGINX for the Unix-origin experiment')
class UnixProxyExperiment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Path(NGINX).is_file() or not os.access(NGINX, os.X_OK):
            raise RuntimeError('ARCHX_TEST_NGINX must name an executable nginx binary')
        if not shutil.which('openssl'):
            raise RuntimeError('openssl is required')
        try: import waitress  # noqa: F401
        except ImportError: raise RuntimeError('waitress is required for this experiment') from None
        cls.temp = tempfile.TemporaryDirectory(prefix='archx-unix-')
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        # The unprivileged negative test can traverse this directory; socket and
        # TLS private key remain mode 0600 and are not readable by that user.
        os.chmod(root, 0o711)
        cls.sockpath = str(root / 'origin.sock')
        cls.cert = root / 'cert.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(root / 'key.pem'), '-out', str(cls.cert), '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.chmod(root / 'key.pem', 0o600)
        cls.origin_log = open(root / 'origin.log', 'wb')
        cls.addClassCleanup(cls.origin_log.close)
        cls.origin = subprocess.Popen([sys.executable, str(ROOT / 'tests/fixtures/wsgi_unix_origin.py')],
                 cwd=ROOT, env={**os.environ, 'ARCHX_TEST_SOCKET':cls.sockpath},
                 stdout=cls.origin_log, stderr=subprocess.STDOUT)
        cls.addClassCleanup(cls.stop_process, cls.origin)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if cls.origin.poll() is not None: raise RuntimeError('Unix origin exited during startup')
            if os.path.exists(cls.sockpath): break
            time.sleep(0.05)
        else: raise RuntimeError('Unix origin did not create socket')
        mode = os.stat(cls.sockpath).st_mode
        if not stat.S_ISSOCK(mode) or stat.S_IMODE(mode) != 0o600:
            raise RuntimeError('Unexpected Unix socket type or permissions')
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            cls.port = sock.getsockname()[1]
        config = root / 'nginx.conf'
        config.write_text(f'''
worker_processes 1;
pid {root}/nginx.pid;
error_log {root}/error.log notice;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_max_body_size 8k;
    client_body_timeout 3s;
    server {{
        listen 127.0.0.1:{cls.port} ssl;
        server_name localhost;
        ssl_certificate {root}/cert.pem;
        ssl_certificate_key {root}/key.pem;
        location / {{
            proxy_pass http://unix:{cls.sockpath}:;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header Forwarded "";
            proxy_set_header X-Real-IP "";
            proxy_set_header X-Forwarded-Host "";
            proxy_set_header X-Forwarded-Proto "";
            proxy_set_header X-Forwarded-Port "";
        }}
    }}
}}
''', encoding='ascii')
        subprocess.run([NGINX, '-t', '-p', str(root), '-c', str(config)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.proxy_log = open(root / 'proxy.log', 'wb')
        cls.addClassCleanup(cls.proxy_log.close)
        cls.proxy = subprocess.Popen([NGINX, '-p', str(root), '-c', str(config), '-g', 'daemon off;'],
                                    stdout=cls.proxy_log, stderr=subprocess.STDOUT)
        cls.addClassCleanup(cls.stop_process, cls.proxy)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if cls.proxy.poll() is not None: raise RuntimeError('nginx exited during startup')
            try:
                conn = http.client.HTTPSConnection('localhost', cls.port, timeout=0.5,
                        context=ssl.create_default_context(cafile=str(cls.cert)))
                conn.request('GET','/ready')
                response=conn.getresponse(); response.read(); conn.close()
                # Any WSGI response demonstrates proxy-to-origin connectivity.
                if response.status in (400, 429, 503): break
            except (OSError, http.client.HTTPException): time.sleep(0.05)
        else: raise RuntimeError('HTTPS Unix-socket topology did not start')

    @staticmethod
    def stop_process(proc):
        if proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill(); proc.wait(timeout=5)

    def post(self, source, headers, seed, direct=False):
        if direct: conn = UnixHTTPConnection(self.sockpath)
        else:
            conn = http.client.HTTPSConnection('localhost', self.port, timeout=3,
                     context=ssl.create_default_context(cafile=str(self.cert)), source_address=(source, 0))
        body=json.dumps({'signals':{'machine_id':synthetic_signal('machine_id',seed)}}).encode()
        try:
            conn.putrequest('POST','/protected')
            conn.putheader('Content-Type','application/json')
            conn.putheader('Content-Length',str(len(body)))
            for key, value in headers: conn.putheader(key,value)
            conn.endheaders(body)
            response=conn.getresponse(); status=response.status; response.read(); return status
        finally: conn.close()

    def test_https_forwarding_spoofs_cannot_change_client_quota(self):
        cases = [
            [('X-Forwarded-For','192.0.2.11')],
            [('X-Forwarded-For','192.0.2.12'),('X-Forwarded-For','192.0.2.13')],
            [('X-Forwarded-For','192.0.2.14, 192.0.2.15')],
            [('Forwarded','for=192.0.2.16'),('X-Real-IP','192.0.2.17')],
        ]
        for i, headers in enumerate(cases):
            with self.subTest(headers=headers):
                source=f'127.0.0.{i+10}'
                self.assertEqual(self.post(source,[],f'unix-baseline-{i}'),200)
                self.assertEqual(self.post(source,headers,f'unix-spoof-{i}'),429)
        self.assertEqual(self.post('127.0.0.30',[],'unix-independent'),200)

    def test_oversized_https_body_is_rejected_before_origin(self):
        conn = http.client.HTTPSConnection('localhost', self.port, timeout=3,
                context=ssl.create_default_context(cafile=str(self.cert)),
                source_address=('127.0.0.41', 0))
        try:
            conn.request('POST', '/protected', body=b'x' * 8193,
                         headers={'Content-Type': 'application/json'})
            response = conn.getresponse()
            self.assertEqual(response.status, 413)
            response.read()
        finally:
            conn.close()
        # The rejected oversized request never charged this client's gate quota.
        self.assertEqual(self.post('127.0.0.41', [], 'oversized-recovery'), 200)

    def test_body_idle_timeout_is_not_an_absolute_deadline(self):
        # Nginx buffers this body and resets its idle timeout on each read. The
        # deliberately slow synthetic request takes longer than the configured
        # timeout but succeeds, exposing a missing absolute-time bound.
        body = json.dumps({'signals': {'machine_id': synthetic_signal('machine_id', 'slow-body')}}).encode()
        context = ssl.create_default_context(cafile=str(self.cert))
        raw = socket.create_connection(('127.0.0.1', self.port), timeout=8,
                                       source_address=('127.0.0.42', 0))
        try:
            with context.wrap_socket(raw, server_hostname='localhost') as tls:
                tls.sendall(('POST /protected HTTP/1.1\r\nHost: localhost\r\n'
                             'Content-Type: application/json\r\nContent-Length: %d\r\n'
                             'Connection: close\r\n\r\n' % len(body)).encode('ascii'))
                start = time.monotonic()
                for i in range(9):
                    tls.sendall(body[len(body) * i // 9:len(body) * (i + 1) // 9])
                    if i < 8:
                        time.sleep(0.5)
                self.assertGreater(time.monotonic() - start, 3)
                response = http.client.HTTPResponse(tls)
                response.begin()
                self.assertEqual(response.status, 200)
                response.read()
        finally:
            raw.close()

    def test_same_service_user_can_bypass_proxy(self):
        # The trusted service UID can open its own socket and spoof headers;
        # Unix permissions are NOT a boundary against this UID or root.
        self.assertEqual(self.post(None,[('X-Forwarded-For','198.51.100.61')],'direct-one',True),200)
        self.assertEqual(self.post(None,[('X-Forwarded-For','198.51.100.62')],'direct-two',True),200)

    @unittest.skipUnless(OTHER_USER, 'set ARCHX_TEST_OTHER_USER for a real other-UID check')
    def test_other_unprivileged_uid_cannot_connect_to_socket(self):
        entry = pwd.getpwnam(OTHER_USER)
        if entry.pw_uid == os.geteuid() or entry.pw_uid == 0:
            self.fail('ARCHX_TEST_OTHER_USER must be a distinct unprivileged UID')
        script = ('import errno,socket,sys\n'
                  's=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n'
                  'try: s.connect(sys.argv[1])\n'
                  'except OSError as e: sys.exit(0 if e.errno in (errno.EACCES,errno.EPERM) else 2)\n'
                  'else: sys.exit(1)\n')
        result = subprocess.run(['sudo','-n','-u',OTHER_USER,'/usr/bin/python3','-c',script,self.sockpath],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.assertEqual(result.returncode, 0, 'other UID unexpectedly connected or permission test failed')


if __name__ == '__main__': unittest.main(verbosity=2)
