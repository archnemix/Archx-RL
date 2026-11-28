"""Synthetic bounded Waitress queue experiment; not a deployment certificate."""
import importlib.metadata
import socket
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'integrations/wsgi'))
from archx_wsgi.ingress import _bounded_dispatcher

try:
    AVAILABLE = importlib.metadata.version('waitress') == '3.0.2'
except importlib.metadata.PackageNotFoundError:
    AVAILABLE = False


class FakeRequest:
    def __init__(self, fail=False): self.closed, self.fail = False, fail
    def close(self):
        self.closed = True
        if self.fail: raise OSError('synthetic close error')


class FakeServer:
    def __init__(self): self.triggers = 0
    def pull_trigger(self): self.triggers += 1


class FakeTask:
    def __init__(self):
        self.requests = [FakeRequest(True), FakeRequest()]
        self.saved = self.requests[:]
        self.server = FakeServer()
        self.cancelled = False
    def cancel(self):
        self.cancelled = True
        self.requests = []


@unittest.skipUnless(AVAILABLE, 'requires optional Waitress 3.0.2')
class DispatcherTests(unittest.TestCase):
    def test_parallel_enqueue_refuses_excess_without_leaking_requests(self):
        dispatcher = _bounded_dispatcher()
        # Model four running workers without launching them so the queue
        # remains stable while concurrent producers contend for admission.
        dispatcher.threads = {0, 1, 2, 3}
        tasks = [FakeTask() for _ in range(256)]
        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(dispatcher.add_task, tasks))
        self.assertEqual(len(dispatcher.queue), 16)
        accepted = [task for task in tasks if not task.cancelled]
        rejected = [task for task in tasks if task.cancelled]
        self.assertEqual((len(accepted), len(rejected)), (16, 240))
        self.assertTrue(all(all(req.closed for req in task.saved) and task.server.triggers == 1
                            for task in rejected))
        with dispatcher.lock:
            dispatcher.queue.popleft()
        recovered = FakeTask()
        dispatcher.add_task(recovered)
        self.assertFalse(recovered.cancelled)
        self.assertEqual(len(dispatcher.queue), 16)
        dispatcher.stop_count = 4
        stopped = FakeTask()
        dispatcher.add_task(stopped)
        self.assertTrue(stopped.cancelled)

    def test_real_waitress_saturation_closed_clients_and_recovery(self):
        from waitress.server import create_server
        release, all_running = threading.Event(), threading.Event()
        count, guard = [0], threading.Lock()
        def application(environ, start):
            if environ['PATH_INFO'] == '/hold':
                with guard:
                    count[0] += 1
                    if count[0] == 4: all_running.set()
                if not release.wait(12): raise RuntimeError('synthetic gate timed out')
            body = b'ok'
            start('200 OK', [('Content-Length', '2')])
            return [body]
        dispatcher = _bounded_dispatcher()
        dispatcher.set_thread_count(4)
        server = create_server(application, _dispatcher=dispatcher, host='127.0.0.1', port=0,
                               connection_limit=64, channel_timeout=10, cleanup_interval=1,
                               recv_bytes=8192, channel_request_lookahead=0)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        clients = []
        self.addCleanup(lambda: self.cleanup(server, dispatcher, thread, release, clients))
        address = ('127.0.0.1', server.effective_port)
        def connect(path):
            client = socket.create_connection(address, timeout=3)
            client.settimeout(3)
            clients.append(client)
            client.sendall(f'GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n'.encode())
            return client
        for _ in range(4): connect('/hold')
        self.assertTrue(all_running.wait(4))
        for _ in range(16): connect('/queued')
        deadline = time.monotonic() + 4
        while True:
            with dispatcher.lock: pending = len(dispatcher.queue)
            if pending == 16: break
            if time.monotonic() >= deadline: self.fail(f'Expected 16 queued channels, got {pending}')
            threading.Event().wait(.01)
        # Closing a client does not immediately remove its pending task from
        # Waitress. Further connections must not grow the dispatcher queue.
        clients[4].close()
        for _ in range(20):
            client = connect('/excess')
            try:
                response = client.recv(256)
            except (ConnectionResetError, BrokenPipeError):
                response = b''
            self.assertEqual(response, b'')
            with dispatcher.lock: self.assertLessEqual(len(dispatcher.queue), 16)
            client.close()
        release.set()
        deadline = time.monotonic() + 5
        while True:
            with dispatcher.lock: pending = len(dispatcher.queue)
            if pending == 0: break
            if time.monotonic() >= deadline: self.fail('Queue failed to drain')
            threading.Event().wait(.01)
        recovery = connect('/recovery')
        self.assertIn(b'200 OK', recovery.recv(256))

    @staticmethod
    def cleanup(server, dispatcher, thread, release, clients):
        release.set()
        for client in clients:
            try: client.close()
            except OSError: pass
        dispatcher.shutdown(timeout=4)
        server.close()
        thread.join(timeout=5)
        if thread.is_alive(): raise AssertionError('Synthetic Waitress loop failed to stop')


if __name__ == '__main__': unittest.main(verbosity=2)
