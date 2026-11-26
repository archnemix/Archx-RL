"""Process-local WSGI admission wrapper, not an HTTP server or authentication.

The outer server/proxy must independently bound accepted sockets, request
headers/bodies, queues and deadlines. One process owns these limits; they do
not coordinate across workers. A stalled application can retain a permit.
"""
import math
import threading
import time


class _HeldResponse:
    """Retain the permit through lazy WSGI iteration and close exactly once."""
    def __init__(self, iterable, release):
        self.iterable = iterable
        self.release = release
        self.iterator = None
        self.closed = False
        self.guard = threading.Lock()

    def __iter__(self):
        return self

    def __next__(self):
        if self.closed:
            raise StopIteration
        try:
            if self.iterator is None:
                self.iterator = iter(self.iterable)
            return next(self.iterator)
        except BaseException:
            self.close()
            raise

    def close(self):
        with self.guard:
            if self.closed:
                return
            self.closed = True
        try:
            closer = getattr(self.iterable, 'close', None)
            if closer is not None:
                closer()
        finally:
            self.release()


class BoundaryGate:
    def __init__(self, application, *, max_inflight, requests_per_second, burst, clock=time.monotonic,
                 readiness_probe=None, health_routes=False):
        if not callable(application) or not callable(clock):
            raise ValueError('application and clock must be callable')
        if type(health_routes) is not bool or (readiness_probe is not None and not callable(readiness_probe)):
            raise ValueError('invalid health configuration')
        if readiness_probe is not None:
            try: ready = readiness_probe() is True
            except Exception: ready = False
            if not ready: raise ValueError('readiness probe failed at startup')
        self.readiness_probe, self.health_routes = readiness_probe, health_routes
        if type(max_inflight) is not int or not 1 <= max_inflight <= 1024:
            raise ValueError('max_inflight must be an integer from 1 to 1024')
        if type(burst) is not int or not 1 <= burst <= 100000:
            raise ValueError('burst must be an integer from 1 to 100000')
        if (type(requests_per_second) not in (int, float) or not math.isfinite(requests_per_second)
                or not 0 < requests_per_second <= 100000):
            raise ValueError('invalid request rate')
        now = clock()
        if type(now) not in (int, float) or not math.isfinite(now):
            raise ValueError('invalid monotonic clock')
        self.application = application
        self.max_inflight, self.rate, self.burst = max_inflight, requests_per_second, burst
        self.clock = clock
        self.tokens, self.last_refill = float(burst), now
        self.condition = threading.Condition()
        self.active = 0
        self.draining = False

    def _enter(self):
        with self.condition:
            if self.draining:
                return False
            try:
                now = self.clock()
                if type(now) not in (int, float) or not math.isfinite(now):
                    return False
            except Exception:
                return False
            self.tokens = min(self.burst, self.tokens + max(0, now-self.last_refill)*self.rate)
            self.last_refill = max(self.last_refill, now)
            if self.tokens < 1:
                return False
            self.tokens -= 1  # rejected concurrency attempts also consume a token
            if self.active >= self.max_inflight:
                return False
            self.active += 1
            return True

    def _leave(self):
        with self.condition:
            self.active -= 1
            self.condition.notify_all()

    def stop_accepting(self):
        """Permanently deny new calls. Existing iterables must finish or close."""
        with self.condition:
            self.draining = True
            self.condition.notify_all()

    def _local_ready(self, discount=0):
        with self.condition:
            if self.draining or self.active-discount >= self.max_inflight:
                return False
            try:
                now = self.clock()
                if type(now) not in (int, float) or not math.isfinite(now):
                    return False
            except Exception:
                return False
            available = min(self.burst, self.tokens + max(0, now-self.last_refill)*self.rate)
            return available >= 1

    def _dependency_ready(self):
        if self.readiness_probe is None: return True
        try: return self.readiness_probe() is True
        except Exception: return False

    def is_ready(self):
        """Instantaneous local readiness and optional host dependency probe."""
        return self._local_ready() and self._dependency_ready() and self._local_ready()

    def wait_drained(self, timeout):
        """Wait for existing calls; False means work is still running."""
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout < 0 or timeout > 300:
            raise ValueError('invalid drain timeout')
        with self.condition:
            return self.condition.wait_for(lambda: self.active == 0, timeout)

    def __call__(self, environ, start_response):
        if not self._enter():
            body = b'{"error":"unavailable"}'
            start_response('503 Service Unavailable', [('Content-Type','application/json'),
                           ('Content-Length',str(len(body))), ('Cache-Control','no-store'), ('Retry-After','1')])
            return [body]
        try:
            path = environ.get('PATH_INFO') if environ.get('REQUEST_METHOD') == 'GET' and self.health_routes else None
            if path in ('/health/live','/health/ready'):
                ready = path == '/health/live' or (self._local_ready(discount=1) and self._dependency_ready() and self._local_ready(discount=1))
                body = b'{"status":"ok"}' if ready else b'{"status":"unavailable"}'
                start_response('200 OK' if ready else '503 Service Unavailable',
                               [('Content-Type','application/json'),('Content-Length',str(len(body))),('Cache-Control','no-store')])
                self._leave()
                return [body]
            if not self._dependency_ready():
                body = b'{"error":"unavailable"}'
                start_response('503 Service Unavailable',[('Content-Type','application/json'),('Content-Length',str(len(body))),('Cache-Control','no-store'),('Retry-After','1')])
                self._leave()
                return [body]
            result = self.application(environ, start_response)
            return _HeldResponse(result, self._leave)
        except BaseException:
            self._leave()
            raise
