"""Single-process integration tests with synthetic request data and identities."""
import http.client
import io
import json
import logging
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock
from wsgiref.simple_server import make_server, WSGIRequestHandler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'integrations/wsgi'))
sys.path.insert(0, str(ROOT / 'demo'))
from archx_wsgi import ProtectedApplication
from engine import Engine, policy
from service import RequestService, parse_json
from signal_validation import synthetic_signal


class WSGIPackageTests(unittest.TestCase):
    def setUp(self):
        self.actions = []
        self.statuses = []
        self.time = [100.0]
        self.gate = RequestService(Engine(policy(override={'max_requests':1}), secret=b'synthetic-wsgi-gate'))
        def protected(environ, start):
            self.actions.append('executed')
            start('200 OK', [('Content-Length', '2')])
            return [b'ok']
        def evaluate(environ, principal):
            length = int(environ['CONTENT_LENGTH'])
            return self.gate.check(parse_json(environ['wsgi.input'].read(length)), environ['REMOTE_ADDR'])
        self.app = ProtectedApplication(protected, resolve_principal=lambda e:e.get('host.principal'),
                     authorize=lambda p, op:p == 'trusted' and op == 'synthetic.read',
                     evaluate=evaluate, operation='synthetic.read', max_inflight=2,
                     requests_per_second=10, burst=100, clock=lambda:self.time[0])

    def environ(self, seed='one', principal='trusted', path='/protected'):
        body = json.dumps({'signals':{'machine_id':synthetic_signal('machine_id', seed)}}).encode()
        e = {'REQUEST_METHOD':'POST', 'PATH_INFO':path, 'REMOTE_ADDR':'192.0.2.1',
             'CONTENT_LENGTH':str(len(body)), 'wsgi.input':io.BytesIO(body),
             'HTTP_X_PRINCIPAL':'trusted', 'HTTP_X_OPERATION':'admin'}
        if principal is not None: e['host.principal'] = principal
        return e

    def request(self, app, env):
        response = []
        output = app(env, lambda status, headers: response.append((status, headers)))
        try: body = b''.join(output)
        finally:
            close = getattr(output, 'close', None)
            if close: close()
        return response[0], body

    def test_real_gate_authorization_allow_and_deny_do_not_fall_through(self):
        self.assertEqual(self.request(self.app, self.environ(principal=None))[0][0], '403 Forbidden')
        self.assertEqual(self.request(self.app, self.environ(principal='wrong'))[0][0], '403 Forbidden')
        self.assertEqual(self.actions, [])
        self.assertEqual(self.request(self.app, self.environ('one'))[0][0], '200 OK')
        (status, headers), _ = self.request(self.app, self.environ('two'))
        self.assertEqual(status, '429 Too Many Requests')
        self.assertTrue(any(k == 'Retry-After' and int(v) > 0 for k, v in headers))
        self.assertEqual(self.actions, ['executed'])

    def test_errors_and_unrecognized_decisions_fail_closed_without_logging_data(self):
        marker = 'private-synthetic-marker-123456'
        captured = io.StringIO()
        handler = logging.StreamHandler(captured)
        root = logging.getLogger(); root.addHandler(handler)
        self.addCleanup(root.removeHandler, handler)
        def fail(*args): raise RuntimeError(marker)
        def raw(*args): return {'decision':'unrecognized', 'reason':marker}
        callbacks = (fail, raw, lambda *args: None, lambda *args: {'decision':True},
                     lambda *args: {'decision':'storage_error','reason':marker})
        for callback in callbacks:
            with self.subTest(callback=callback), mock.patch.object(self.app, 'evaluate', callback):
                (status, _), body = self.request(self.app, self.environ())
                self.assertEqual(status, '503 Service Unavailable')
                self.assertNotIn(marker.encode(), body)
        with mock.patch.object(self.app, 'resolve_principal', fail):
            self.assertEqual(self.request(self.app, self.environ())[0][0], '503 Service Unavailable')
        with mock.patch.object(self.app, 'authorize', lambda *_:1):
            self.assertEqual(self.request(self.app, self.environ())[0][0], '503 Service Unavailable')
        self.assertNotIn(marker, captured.getvalue())
        self.assertEqual(self.actions, [])

    def test_all_nonallow_categories_fail_closed(self):
        expected = {'invalid':'400 Bad Request', 'challenge':'403 Forbidden',
                    'rate_limited':'429 Too Many Requests', 'capacity_exceeded':'503 Service Unavailable',
                    'storage_error':'503 Service Unavailable', 'unknown':'503 Service Unavailable'}
        for decision, status in expected.items():
            with self.subTest(decision=decision), mock.patch.object(self.app, 'evaluate', return_value={'decision':decision}):
                self.assertEqual(self.request(self.app, self.environ())[0][0], status)
        self.assertEqual(self.actions, [])

    def test_invalid_runtime_clock_fails_closed_and_recovers(self):
        self.time[0] = float('nan')
        self.assertEqual(self.request(self.app, self.environ())[0][0], '503 Service Unavailable')
        self.assertEqual(self.actions, [])
        self.time[0] = 101.0
        self.assertEqual(self.request(self.app, self.environ())[0][0], '200 OK')

    def test_synthetic_identifier_not_in_captured_logs_or_denials(self):
        raw = synthetic_signal('machine_id', 'raw-log-regression')
        capture = io.StringIO(); handler = logging.StreamHandler(capture)
        root = logging.getLogger(); previous = root.level
        root.setLevel(logging.DEBUG); root.addHandler(handler)
        self.addCleanup(root.setLevel, previous)
        self.addCleanup(root.removeHandler, handler)
        env = self.environ('raw-log-regression')
        self.assertIn(raw.encode(), env['wsgi.input'].getvalue())
        self.assertEqual(self.request(self.app, env)[0][0], '200 OK')
        _, response = self.request(self.app, self.environ('raw-log-regression'))
        self.assertNotIn(raw.encode(), response)
        self.assertNotIn(raw, capture.getvalue())

    def test_loopback_wsgi_host_enforces_the_real_gate(self):
        class Quiet(WSGIRequestHandler):
            def log_message(self, *args): pass
        def trusted_host(env, start):
            # This is trusted server middleware, not a client-controlled header.
            env['host.principal'] = 'trusted'
            return self.app(env, start)
        server = make_server('127.0.0.1', 0, trusted_host, handler_class=Quiet)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval':0.02}, daemon=True)
        thread.start()
        try:
            def send(seed):
                raw = json.dumps({'signals':{'machine_id':synthetic_signal('machine_id',seed)}})
                conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=2)
                try:
                    conn.request('POST', '/protected', raw, {'Content-Type':'application/json', 'X-Principal':'attacker'})
                    reply = conn.getresponse(); status = reply.status; reply.read(); return status
                finally: conn.close()
            self.assertEqual(send('loopback-a'), 200)
            self.assertEqual(send('loopback-b'), 429)
            self.assertEqual(self.actions, ['executed'])
        finally:
            server.shutdown(); server.server_close(); thread.join(2)

    def test_lazy_response_holds_permit_until_close_and_recovers(self):
        closed = []
        class Stream:
            def __iter__(self): yield b'x'
            def close(self): closed.append(True)
        def action(env, start): start('200 OK', []); return Stream()
        app = ProtectedApplication(action, resolve_principal=lambda e:True, authorize=lambda *a:True,
                                   evaluate=lambda *a:{'decision':'allow'}, operation='read',
                                   max_inflight=1, requests_per_second=100, burst=10, clock=lambda:self.time[0])
        output = app({}, lambda *a:None)
        self.assertEqual(self.request(app, {})[0][0], '503 Service Unavailable')
        self.assertEqual(next(iter(output)), b'x')
        output.close(); output.close()
        self.assertEqual(closed, [True])
        self.assertEqual(self.request(app, {})[0][0], '200 OK')

    def test_mixed_routes_rate_limit_and_recovery(self):
        app = ProtectedApplication(lambda env,start: (start('200 OK', []), [b'ok'])[1],
                                   resolve_principal=lambda e:True, authorize=lambda *a:True,
                                   evaluate=lambda *a:{'decision':'allow'}, operation='read',
                                   max_inflight=1, requests_per_second=1, burst=2, clock=lambda:self.time[0])
        for route in ('/', '/challenge'):
            self.assertEqual(self.request(app, {'PATH_INFO':route})[0][0], '200 OK')
        self.assertEqual(self.request(app, {'PATH_INFO':'/unknown'})[0][0], '503 Service Unavailable')
        self.time[0] += 1
        self.assertEqual(self.request(app, {'PATH_INFO':'/protected'})[0][0], '200 OK')

    def test_exception_and_start_response_release_the_permit(self):
        def action(env, start):
            if env.get('fail'): raise RuntimeError('synthetic protected failure')
            start('200 OK', []); return [b'ok']
        app = ProtectedApplication(action, resolve_principal=lambda e:True, authorize=lambda *a:True,
                                   evaluate=lambda *a:{'decision':'allow'}, operation='read',
                                   max_inflight=1, requests_per_second=100, burst=10, clock=lambda:self.time[0])
        with self.assertRaises(RuntimeError): app({'fail':True}, lambda *a:None)
        with self.assertRaises(RuntimeError): app({}, lambda *a: (_ for _ in ()).throw(RuntimeError()))
        self.assertEqual(self.request(app, {})[0][0], '200 OK')

    def test_concurrent_close_does_not_release_a_running_iterator(self):
        entered, release, closed = threading.Event(), threading.Event(), threading.Event()
        def stream():
            entered.set()
            release.wait(3)
            yield b'x'
        app = ProtectedApplication(lambda e,s: (s('200 OK', []),stream())[1],
                                   resolve_principal=lambda e:True, authorize=lambda *a:True,
                                   evaluate=lambda *a:{'decision':'allow'}, operation='read',
                                   max_inflight=1, requests_per_second=100, burst=10, clock=lambda:self.time[0])
        response = app({}, lambda *a:None)
        worker = threading.Thread(target=lambda: next(response))
        worker.start()
        self.assertTrue(entered.wait(2))
        closer = threading.Thread(target=lambda: (response.close(), closed.set()))
        closer.start()
        try:
            self.assertFalse(closed.wait(0.05))
            self.assertEqual(self.request(app, {})[0][0], '503 Service Unavailable')
        finally:
            release.set(); worker.join(3); closer.join(3)
        self.assertTrue(closed.is_set())
        self.assertEqual(app.active, 0)

    def test_iteration_failure_releases_permit(self):
        class Broken:
            def __iter__(self): raise RuntimeError('iteration failure')
            def close(self): pass
        app = ProtectedApplication(lambda e,s: (s('200 OK', []),Broken())[1],
                                   resolve_principal=lambda e:True, authorize=lambda *a:True,
                                   evaluate=lambda *a:{'decision':'allow'}, operation='read',
                                   max_inflight=1, requests_per_second=100, burst=10, clock=lambda:self.time[0])
        response = app({}, lambda *a:None)
        with self.assertRaises(RuntimeError): next(iter(response))
        response.close()
        self.assertEqual(app.active, 0)
        another = app({}, lambda *a:None)
        another.close()
        self.assertEqual(app.active, 0)

    def test_parallel_calls_cannot_exceed_inflight_bound(self):
        entered, release = threading.Event(), threading.Event()
        def gate(*args): entered.set(); release.wait(2); return {'decision':'allow'}
        app = ProtectedApplication(lambda e,s: (s('200 OK', []),[b'ok'])[1],
                                   resolve_principal=lambda e:True, authorize=lambda *a:True,
                                   evaluate=gate, operation='read', max_inflight=1,
                                   requests_per_second=100, burst=10, clock=lambda:self.time[0])
        result=[]
        thread=threading.Thread(target=lambda:result.append(self.request(app, {})[0][0]))
        thread.start()
        try:
            self.assertTrue(entered.wait(2))
            self.assertEqual(self.request(app, {})[0][0], '503 Service Unavailable')
        finally:
            release.set(); thread.join(3)
        self.assertFalse(thread.is_alive()); self.assertEqual(result, ['200 OK'])

    def test_invalid_settings_rejected(self):
        base = dict(resolve_principal=lambda e:True, authorize=lambda *a:True,
                    evaluate=lambda *a:{'decision':'allow'}, operation='read', max_inflight=1,
                    requests_per_second=1, burst=1)
        for key, value in (('max_inflight',0), ('burst',0), ('requests_per_second',float('nan')),
                           ('operation','bad\noperation'), ('evaluate',None), ('clock',lambda:float('inf'))):
            with self.subTest(key=key), self.assertRaises(ValueError):
                ProtectedApplication(lambda e,s:[], **{**base,key:value})


if __name__ == '__main__': unittest.main(verbosity=2)
