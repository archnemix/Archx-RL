"""Bounded connection admission for the private HTTP demonstration.

This is not a production HTTP server: limits are local to one process, and
socket deadlines cannot cancel a stalled application or external dependency.
"""
import math
import socket
import threading
import time
from http.server import ThreadingHTTPServer


class BoundedDemoServer(ThreadingHTTPServer):
    # Threads that are still in application code must not hold shutdown forever.
    daemon_threads = True
    request_queue_size = 64  # OS may apply its own lower backlog limit

    def __init__(self, address, handler, *, max_connections=32,
                 connection_rate=25.0, connection_burst=50, connection_deadline=15.0,
                 clock=time.monotonic):
        if (type(max_connections) is not int or not 1 <= max_connections <= 1024 or
            type(connection_burst) is not int or not 1 <= connection_burst <= 100000 or
            type(connection_rate) not in (int, float) or not math.isfinite(connection_rate) or not 0 < connection_rate <= 100000 or
            type(connection_deadline) not in (int, float) or not math.isfinite(connection_deadline) or not 0 < connection_deadline <= 300):
            raise ValueError('Invalid connection admission configuration')
        self.max_connections = max_connections
        self.connection_rate = connection_rate
        self.connection_burst = connection_burst
        self.connection_deadline = connection_deadline
        self.clock = clock
        self.lock = threading.Lock()
        self.active = {}  # accepted socket -> absolute monotonic deadline
        self.tokens = float(connection_burst)
        self.last_refill = clock()
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        # Runs in the accept loop: charge every accepted connection, regardless
        # of path/method, including attempts rejected due to concurrency.
        with self.lock:
            now = self.clock()
            elapsed = max(0.0, now - self.last_refill)
            self.tokens = min(self.connection_burst, self.tokens + elapsed * self.connection_rate)
            self.last_refill = max(self.last_refill, now)
            allowed = self.tokens >= 1
            if allowed:
                self.tokens -= 1
                allowed = len(self.active) < self.max_connections
            if allowed:
                self.active[request] = now + self.connection_deadline
        if not allowed:
            # Do not block the accept loop sending an overload response to a
            # potentially slow client. Rejected connections are simply closed.
            self.shutdown_request(request)
            return
        try:
            request.settimeout(min(10.0, self.connection_deadline))
            super().process_request(request, client_address)
        except BaseException:
            with self.lock:
                self.active.pop(request, None)
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self.lock:
                self.active.pop(request, None)

    def service_actions(self):
        # A single accept-loop sweep enforces an absolute socket deadline, even
        # for a client sending bytes just before each idle timeout. It does not
        # terminate application code or cancel an outbound provider request.
        now = self.clock()
        with self.lock:
            overdue = [sock for sock, deadline in self.active.items() if deadline <= now]
            for sock in overdue:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def handle_error(self, request, client_address):
        # Avoid printing attacker-supplied paths, headers or raw body data.
        pass
