"""Connection admission tests using only synthetic loopback HTTP traffic."""
import http.client
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
import socket
import sys
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from bounded_server import BoundedDemoServer
from engine import Engine, policy
from server import Handler


class ObservedServer(BoundedDemoServer):
    def __init__(self, *args, **kwargs):
        self.admitted = threading.Event()
        super().__init__(*args, **kwargs)

    def process_request(self, request, address):
        super().process_request(request, address)
        with self.lock:
            if request in self.active:
                self.admitted.set()


class BoundaryTests(unittest.TestCase):
    def start_server(self, **kwargs):
        server = ObservedServer(('127.0.0.1', 0), Handler, **kwargs)
        server.engine = Engine(policy(), secret=b'synthetic-test')
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval':0.02}, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def http(self, server, method, path, body=None):
        con = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=2)
        try:
            headers = {'Content-Type':'application/json'} if body is not None else {}
            con.request(method, path, body, headers)
            response = con.getresponse()
            response.read()
            return response.status
        finally:
            con.close()

    def test_configuration_rejects_invalid_or_unbounded_values(self):
        for settings in ({'max_connections':0}, {'max_connections':1025},
                         {'connection_rate':float('nan')}, {'connection_rate':0},
                         {'connection_burst':0}, {'connection_deadline':float('inf')},
                         {'connection_deadline':301}):
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                ObservedServer(('127.0.0.1', 0), Handler, **settings)

    def test_global_quota_covers_get_challenge_and_post_and_recovers(self):
        now = [100.0]
        server = self.start_server(connection_rate=1, connection_burst=3, clock=lambda: now[0])
        self.assertEqual(self.http(server, 'GET', '/'), 200)
        self.assertEqual(self.http(server, 'GET', '/api/v2/challenge'), 404)
        self.assertEqual(self.http(server, 'POST', '/unknown', '{}'), 404)
        with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
            self.http(server, 'GET', '/api/info')
        now[0] += 1
        self.assertEqual(self.http(server, 'GET', '/api/info'), 200)

    def test_slow_client_is_bounded_and_deadline_recovers_slot(self):
        server = self.start_server(max_connections=1, connection_rate=100, connection_burst=20,
                                   connection_deadline=0.6)
        slow = socket.create_connection(('127.0.0.1', server.server_port), timeout=2)
        self.addCleanup(slow.close)
        slow.sendall(b'GET / HTTP/1.1\r\nHost: example\r\nX-Slow: ')
        self.assertTrue(server.admitted.wait(2))
        with server.lock:
            self.assertEqual(len(server.active), 1)
        with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
            self.http(server, 'GET', '/')
        # Continue sending more often than the per-operation idle timeout. The
        # absolute deadline still closes the socket and releases the worker.
        stopped = threading.Event()
        def dribble():
            try:
                while not stopped.wait(0.08):
                    slow.sendall(b'a')
            except OSError:
                stopped.set()
        sender = threading.Thread(target=dribble, daemon=True)
        sender.start()
        self.assertTrue(stopped.wait(3), 'absolute connection deadline did not close slow client')
        sender.join(1)
        end = time.monotonic() + 2
        while time.monotonic() < end:
            with server.lock:
                if not server.active:
                    break
            time.sleep(0.01)
        else:
            self.fail('worker did not recover after socket deadline')
        self.assertEqual(self.http(server, 'GET', '/'), 200)

    def test_many_slow_connections_cannot_exceed_worker_limit(self):
        server = self.start_server(max_connections=2, connection_rate=10000,
                                   connection_burst=100, connection_deadline=5)
        held = []
        for _ in range(2):
            conn = socket.create_connection(('127.0.0.1', server.server_port), timeout=2)
            self.addCleanup(conn.close)
            conn.sendall(b'GET / HTTP/1.1\r\nHost: x\r\nX-Slow: ')
            held.append(conn)
        end = time.monotonic() + 2
        while time.monotonic() < end:
            with server.lock:
                if len(server.active) == 2:
                    break
            time.sleep(0.01)
        else:
            self.fail('slow test connections did not occupy both slots')
        def rejected(_):
            try:
                self.http(server, 'GET', '/')
                return False
            except (http.client.RemoteDisconnected, ConnectionResetError):
                return True
        with ThreadPoolExecutor(max_workers=12) as pool:
            self.assertTrue(all(pool.map(rejected, range(24))))
        with server.lock:
            self.assertEqual(len(server.active), 2)
        for conn in held:
            conn.close()
        end = time.monotonic() + 2
        while time.monotonic() < end:
            with server.lock:
                if not server.active:
                    break
            time.sleep(0.01)
        else:
            self.fail('slots did not recover after disconnect')
        self.assertEqual(self.http(server, 'GET', '/'), 200)

    def test_worker_start_failure_releases_slot_and_socket(self):
        with ObservedServer(('127.0.0.1', 0), Handler, max_connections=1) as server:
            request, peer = socket.socketpair()
            self.addCleanup(peer.close)
            with patch.object(ThreadingHTTPServer, 'process_request', side_effect=RuntimeError('synthetic failure')):
                with self.assertRaises(RuntimeError):
                    server.process_request(request, ('127.0.0.1', 1))
            self.assertEqual(request.fileno(), -1)
            self.assertFalse(server.active)

    def test_deadline_does_not_claim_to_cancel_stalled_application(self):
        entered, release = threading.Event(), threading.Event()
        class StallHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                entered.set()
                release.wait(3)
            def log_message(self, format, *args):
                pass
        server = ObservedServer(('127.0.0.1', 0), StallHandler, max_connections=1,
                                connection_deadline=0.2, connection_rate=100, connection_burst=10)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval':0.02}, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.addCleanup(release.set)
        conn = socket.create_connection(('127.0.0.1', server.server_port), timeout=2)
        self.addCleanup(conn.close)
        conn.sendall(b'GET / HTTP/1.0\r\n\r\n')
        self.assertTrue(entered.wait(2))
        conn.settimeout(2)
        self.assertEqual(conn.recv(1), b'')  # deadline closed the socket
        with server.lock:
            self.assertEqual(len(server.active), 1)  # application still running
        with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
            self.http(server, 'GET', '/')
        release.set()
        end = time.monotonic() + 2
        while time.monotonic() < end:
            with server.lock:
                if not server.active:
                    break
            time.sleep(0.01)
        else:
            self.fail('worker did not release after application completed')

    def test_http_pipelining_does_not_bypass_connection_quota(self):
        server = self.start_server(connection_rate=1, connection_burst=1, clock=lambda: 100.0)
        with socket.create_connection(('127.0.0.1', server.server_port), timeout=2) as sock:
            sock.settimeout(2)
            sock.sendall(b'GET /api/v2/config HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n'
                         b'GET /api/info HTTP/1.1\r\nHost: x\r\n\r\n')
            chunks = []
            while True:
                try:
                    part = sock.recv(4096)
                except ConnectionResetError:
                    break
                if not part:
                    break
                chunks.append(part)
        self.assertEqual(b''.join(chunks).count(b'HTTP/1.0 200 OK'), 1)
        with self.assertRaises((http.client.RemoteDisconnected, ConnectionResetError)):
            self.http(server, 'GET', '/api/info')


if __name__ == '__main__':
    unittest.main(verbosity=2)
