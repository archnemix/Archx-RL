"""Single-process WSGI admission and host decision enforcement.

This is not an HTTP server, authentication system or trusted proxy. The host
must bound network connections, queues, request sizes and timeouts separately.
"""
import math
import threading
import time


class _HeldResponse:
    def __init__(self, response, release):
        self.response = response
        self.release = release
        self.iterator = None
        self.closed = False
        self.lock = threading.RLock()

    def __iter__(self):
        return self

    def __next__(self):
        # Serialize iteration and close so a concurrent close cannot release a
        # permit while the underlying iterator is still executing.
        with self.lock:
            if self.closed:
                raise StopIteration
            try:
                if self.iterator is None:
                    self.iterator = iter(self.response)
                return next(self.iterator)
            except BaseException:
                self.close()
                raise

    def close(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
        try:
            close = getattr(self.response, 'close', None)
            if close is not None:
                close()
        finally:
            self.release()


class ProtectedApplication:
    """Enforce a host-owned principal, authorization and gate before one WSGI app.

    Each admitted request consumes a token and an in-flight permit. Permits
    for allowed responses are retained until iteration finishes or the server
    calls close(). The request gate must return a plain dict with a recognized
    decision; malformed results, exceptions and missing principals fail closed.
    """
    def __init__(self, application, *, resolve_principal, authorize, evaluate,
                 operation, max_inflight, requests_per_second, burst, clock=time.monotonic):
        if any(not callable(fn) for fn in (application, resolve_principal, authorize, evaluate, clock)):
            raise ValueError('Application, host hooks and clock must be callable')
        if (not isinstance(operation, str) or not 1 <= len(operation) <= 128 or
                any(ord(c) < 32 or ord(c) == 127 for c in operation)):
            raise ValueError('Invalid fixed operation')
        if type(max_inflight) is not int or not 1 <= max_inflight <= 1024:
            raise ValueError('Invalid in-flight bound')
        if type(burst) is not int or not 1 <= burst <= 100000:
            raise ValueError('Invalid burst')
        if (type(requests_per_second) not in (int, float) or not math.isfinite(requests_per_second)
                or not 0 < requests_per_second <= 100000):
            raise ValueError('Invalid request rate')
        now = clock()
        if type(now) not in (int, float) or not math.isfinite(now):
            raise ValueError('Invalid monotonic clock')
        self.application, self.resolve_principal = application, resolve_principal
        self.authorize, self.evaluate, self.operation = authorize, evaluate, operation
        self.max_inflight, self.rate, self.burst = max_inflight, requests_per_second, burst
        self.clock, self.last, self.tokens = clock, now, float(burst)
        self.active = 0
        self.lock = threading.Lock()

    def _enter(self):
        with self.lock:
            try:
                now = self.clock()
                if type(now) not in (int, float) or not math.isfinite(now):
                    return False
                elapsed = max(0.0, now - self.last)
                self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
                self.last = max(self.last, now)
            except Exception:
                return False
            if self.tokens < 1:
                return False
            self.tokens -= 1
            if self.active >= self.max_inflight:
                return False
            self.active += 1
            return True

    def _leave(self):
        with self.lock:
            self.active -= 1

    @staticmethod
    def _response(start_response, status, retry=None):
        body = b'{"error":"request_not_allowed"}'
        headers = [('Content-Type', 'application/json'), ('Content-Length', str(len(body))),
                   ('Cache-Control', 'no-store')]
        if retry is not None:
            headers.append(('Retry-After', str(retry)))
        start_response(status, headers)
        return [body]

    def __call__(self, environ, start_response):
        if not self._enter():
            return self._response(start_response, '503 Service Unavailable', 1)
        held = False
        try:
            failure = None
            try:
                principal = self.resolve_principal(environ)
                authorized = False if principal is None else self.authorize(principal, self.operation)
                if authorized is not True:
                    failure = ('403 Forbidden' if authorized is False else '503 Service Unavailable', None)
                else:
                    result = self.evaluate(environ, principal)
                    if type(result) is not dict or type(result.get('decision')) is not str:
                        failure = ('503 Service Unavailable', 1)
                    elif result['decision'] != 'allow':
                        status = {'invalid':'400 Bad Request', 'challenge':'403 Forbidden',
                                  'rate_limited':'429 Too Many Requests', 'capacity_exceeded':'503 Service Unavailable',
                                  'storage_error':'503 Service Unavailable'}.get(result['decision'], '503 Service Unavailable')
                        retry = result.get('retry_after_seconds')
                        if status.startswith(('429', '503')):
                            retry = retry if type(retry) is int and 1 <= retry <= 86400 else 1
                        else:
                            retry = None
                        failure = (status, retry)
            except Exception:
                # Never serialize or log exception details, request input or principal.
                failure = ('503 Service Unavailable', 1)
            if failure:
                return self._response(start_response, *failure)
            response = self.application(environ, start_response)
            wrapped = _HeldResponse(response, self._leave)
            held = True
            return wrapped
        finally:
            if not held:
                self._leave()
