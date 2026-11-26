"""Real nginx/TLS experiment against the private demo, NOT a deployment profile.

Run on Linux with ARCHX_TEST_NGINX=/absolute/path/to/nginx and openssl on PATH.
The test deliberately demonstrates why loopback alone is not origin isolation.
Only synthetic signals, addresses and an ephemeral test certificate are used.
"""
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'demo'))
from bounded_server import BoundedDemoServer
from engine import Engine, policy
from proxy import trusted_networks
from server import Handler
from signal_validation import synthetic_signal

NGINX = os.environ.get('ARCHX_TEST_NGINX')


@unittest.skipUnless(NGINX, 'set ARCHX_TEST_NGINX to run the real nginx experiment')
class HTTPSProxyExperiment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Path(NGINX).is_file() or not os.access(NGINX, os.X_OK):
            raise RuntimeError('ARCHX_TEST_NGINX must name an executable nginx binary')
        if not shutil.which('openssl'):
            raise RuntimeError('openssl is required')
        cls.temp = tempfile.TemporaryDirectory(prefix='archx-nginx-')
        cls.addClassCleanup(cls.temp.cleanup)
        root = Path(cls.temp.name)
        cls.cert = root / 'cert.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(root / 'key.pem'), '-out', str(cls.cert), '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.origin = BoundedDemoServer(('127.0.0.1', 0), Handler)
        cls.origin.engine = Engine(policy(override={'max_requests':1}), secret=b'tls-test-only')
        cls.origin.trusted_proxies = trusted_networks(['127.0.0.1/32'])
        cls.thread = threading.Thread(target=cls.origin.serve_forever,
                                      kwargs={'poll_interval':0.02}, daemon=True)
        cls.thread.start()
        cls.addClassCleanup(cls.thread.join, 3)
        cls.addClassCleanup(cls.origin.server_close)
        cls.addClassCleanup(cls.origin.shutdown)
        # The ephemeral port is released before nginx binds; failure to bind is a
        # test failure, not a reason to connect to an unrelated process.
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
    server {{
        listen 127.0.0.1:{cls.port} ssl;
        server_name localhost;
        ssl_certificate {root}/cert.pem;
        ssl_certificate_key {root}/key.pem;
        location / {{
            proxy_pass http://127.0.0.1:{cls.origin.server_port};
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
        cls.nginx_log = open(root / 'process.log', 'wb')
        cls.addClassCleanup(cls.nginx_log.close)
        cls.nginx = subprocess.Popen([NGINX, '-p', str(root), '-c', str(config), '-g', 'daemon off;'],
                                     stdout=cls.nginx_log, stderr=subprocess.STDOUT)
        cls.addClassCleanup(cls.stop_nginx)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if cls.nginx.poll() is not None:
                raise RuntimeError('nginx exited during startup')
            try:
                # Verify the certificate and endpoint, not merely port liveness.
                conn = http.client.HTTPSConnection('localhost', cls.port, timeout=0.5,
                         context=ssl.create_default_context(cafile=str(cls.cert)))
                conn.request('GET', '/api/v2/config')
                response = conn.getresponse()
                response.read()
                conn.close()
                if response.status == 200:
                    break
            except (OSError, http.client.HTTPException):
                time.sleep(0.05)
        else:
            raise RuntimeError('nginx TLS endpoint did not start')

    @classmethod
    def stop_nginx(cls):
        if cls.nginx.poll() is None:
            cls.nginx.terminate()
            try:
                cls.nginx.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.nginx.kill()
                cls.nginx.wait(timeout=5)

    def post(self, source, headers, seed, *, direct=False):
        if direct:
            conn = http.client.HTTPConnection('127.0.0.1', self.origin.server_port, timeout=3,
                                              source_address=(source, 0) if source else None)
        else:
            conn = http.client.HTTPSConnection('localhost', self.port, timeout=3,
                    context=ssl.create_default_context(cafile=str(self.cert)), source_address=(source, 0))
        data = json.dumps({'signals': {'machine_id': synthetic_signal('machine_id', seed)}}).encode()
        try:
            conn.putrequest('POST', '/api/v2/check')
            conn.putheader('Content-Type', 'application/json')
            conn.putheader('Content-Length', str(len(data)))
            for name, value in headers:
                conn.putheader(name, value)
            conn.endheaders(data)
            response = conn.getresponse()
            status = response.status
            response.read()
            return status
        finally:
            conn.close()

    def test_forged_duplicate_and_chained_forwarding_cannot_change_peer(self):
        # Distinct loopback source IPs emulate independently connected clients.
        # All forged forms must use the real transport peer's shared IP quota.
        cases = [
            [('X-Forwarded-For', '192.0.2.21')],
            [('X-Forwarded-For', '192.0.2.22'), ('X-Forwarded-For', '192.0.2.23')],
            [('X-Forwarded-For', '192.0.2.24, 192.0.2.25')],
            [('Forwarded', 'for=192.0.2.26'), ('X-Real-IP', '192.0.2.27')],
        ]
        for index, headers in enumerate(cases):
            with self.subTest(headers=headers):
                peer = f'127.0.0.{index + 2}'
                self.assertEqual(self.post(peer, [], f'baseline-{index}'), 200)
                self.assertEqual(self.post(peer, headers, f'forgery-{index}'), 429)
        # A new peer has an independent quota.
        self.assertEqual(self.post('127.0.0.20', [], 'independent'), 200)

    def test_untrusted_direct_peer_cannot_use_forwarded_header(self):
        peer = '127.0.0.31'
        self.assertEqual(self.post(peer, [], 'untrusted-1', direct=True), 200)
        self.assertEqual(self.post(peer, [('X-Forwarded-For', '198.51.100.43')], 'untrusted-2', direct=True), 429)

    def test_self_signed_certificate_requires_explicit_trust(self):
        conn = http.client.HTTPSConnection('localhost', self.port, timeout=3,
                                           context=ssl.create_default_context())
        try:
            with self.assertRaises(ssl.SSLCertVerificationError):
                conn.request('GET', '/api/v2/config')
        finally:
            conn.close()

    def test_loopback_origin_is_not_isolated_from_local_processes(self):
        # This negative result is intentional: a local process bypasses nginx
        # and impersonates different peers. Never treat loopback as a security
        # boundary against untrusted local users or processes.
        self.assertEqual(self.post(None, [('X-Forwarded-For', '198.51.100.41')], 'direct-1', direct=True), 200)
        self.assertEqual(self.post(None, [('X-Forwarded-For', '198.51.100.42')], 'direct-2', direct=True), 200)


if __name__ == '__main__':
    unittest.main(verbosity=2)
