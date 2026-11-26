"""Synthetic WSGI admission and drain tests; no deployment support claim."""
import sys
import threading
import http.client
from wsgiref.simple_server import make_server
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'examples/python'))
sys.path.insert(0, str(ROOT/'demo'))
from boundary_wsgi import BoundaryGate
from gated_wsgi import create_application, QuietHandler
from engine import Engine, policy
from service import RequestService


class BoundaryTests(unittest.TestCase):
    @staticmethod
    def app(environ, start_response):
        start_response('200 OK', [('Content-Type','text/plain')])
        return [b'ok']

    def invoke(self, gate, method='GET', path='/'):
        statuses = []
        result = gate({'REQUEST_METHOD':method,'PATH_INFO':path}, lambda status,headers: statuses.append(status))
        body = b''.join(result)
        if hasattr(result, 'close'): result.close()
        return statuses[0],body

    def test_invalid_configuration_and_bad_clock_fail_closed(self):
        for options in ({'max_inflight':0}, {'max_inflight':True}, {'max_inflight':1025},
                        {'burst':0}, {'burst':True}, {'requests_per_second':float('nan')},
                        {'requests_per_second':0}):
            config={'max_inflight':1,'requests_per_second':1,'burst':1}; config.update(options)
            with self.subTest(options=options), self.assertRaises(ValueError): BoundaryGate(self.app,**config)
        now=[100.0]
        gate=BoundaryGate(self.app,max_inflight=1,requests_per_second=1,burst=1,clock=lambda:now[0])
        now[0]=float('nan')
        self.assertFalse(gate.is_ready())
        self.assertEqual(self.invoke(gate)[0], '503 Service Unavailable')
        now[0]=100
        self.assertTrue(gate.is_ready())
        self.assertEqual(self.invoke(gate)[0], '200 OK')
        self.assertFalse(gate.is_ready())

    def test_rate_covers_all_paths_and_refills_without_backwards_clock_refill(self):
        now=[100.0]
        gate=BoundaryGate(self.app,max_inflight=3,requests_per_second=1,burst=3,clock=lambda:now[0])
        for method,path in [('GET','/'),('GET','/api/v2/challenge'),('POST','/protected')]:
            self.assertEqual(self.invoke(gate,method,path)[0], '200 OK')
        now[0]=90.0
        self.assertEqual(self.invoke(gate)[0], '503 Service Unavailable')
        now[0]=100.0
        self.assertEqual(self.invoke(gate)[0], '503 Service Unavailable')
        now[0]=101.0
        self.assertEqual(self.invoke(gate)[0], '200 OK')

    def test_permit_held_until_iterable_closed_or_exhausted(self):
        gate=BoundaryGate(self.app,max_inflight=1,requests_per_second=100,burst=10)
        statuses=[]; pending=gate({},lambda status,headers:statuses.append(status))
        self.assertEqual(statuses,['200 OK'])
        self.assertFalse(gate.is_ready())
        self.assertEqual(self.invoke(gate)[0], '503 Service Unavailable')
        pending.close(); pending.close()
        self.assertTrue(gate.is_ready())
        self.assertEqual(gate.active,0)
        self.assertEqual(self.invoke(gate)[0], '200 OK')

    def test_faults_release_permit_without_false_response(self):
        def bad_app(environ,start): raise RuntimeError('synthetic error')
        gate=BoundaryGate(bad_app,max_inflight=1,requests_per_second=100,burst=10)
        with self.assertRaises(RuntimeError): gate({},lambda *args:None)
        self.assertEqual(gate.active,0)
        def broken_iter(environ,start):
            start('200 OK',[])
            def generate():
                yield b'first'
                raise RuntimeError('synthetic iteration failure')
            return generate()
        gate.application=broken_iter
        result=gate({},lambda *args:None)
        self.assertEqual(next(result),b'first')
        with self.assertRaises(RuntimeError): next(result)
        self.assertEqual(gate.active,0)
        class BrokenClose:
            def __iter__(self): return iter([b'ok'])
            def close(self): raise RuntimeError('synthetic close failure')
        gate.application=lambda env,start: BrokenClose()
        result=gate({},lambda *args:None)
        with self.assertRaises(RuntimeError): result.close()
        self.assertEqual(gate.active,0)
        result.close()  # idempotent, no double release

    def test_concurrent_slow_application_bounded_and_recovers(self):
        entered=threading.Event(); release=threading.Event(); lock=threading.Lock(); counts=[0,0]
        def slow(environ,start):
            with lock:
                counts[0]+=1; counts[1]=max(counts[1],counts[0]); entered.set()
            try:
                release.wait(3)
                start('200 OK',[]); return [b'ok']
            finally:
                with lock: counts[0]-=1
        gate=BoundaryGate(slow,max_inflight=1,requests_per_second=10000,burst=100)
        with ThreadPoolExecutor(max_workers=12) as pool:
            first=pool.submit(self.invoke,gate)
            self.assertTrue(entered.wait(2))
            others=list(pool.map(lambda _:self.invoke(gate),range(20)))
            self.assertTrue(all(status=='503 Service Unavailable' for status,_ in others))
            release.set(); self.assertEqual(first.result()[0],'200 OK')
        self.assertEqual(counts[1],1)
        self.assertEqual(self.invoke(gate)[0], '200 OK')

    def test_drain_blocks_new_work_and_wait_reports_inflight(self):
        gate=BoundaryGate(self.app,max_inflight=1,requests_per_second=100,burst=10)
        self.assertTrue(gate.is_ready())
        pending=gate({},lambda *args:None)
        self.assertFalse(gate.is_ready())
        gate.stop_accepting(); self.assertFalse(gate.is_ready())
        self.assertFalse(gate.wait_drained(0))
        self.assertEqual(self.invoke(gate)[0], '503 Service Unavailable')
        pending.close(); self.assertTrue(gate.wait_drained(0))
        self.assertEqual(self.invoke(gate)[0], '503 Service Unavailable')
        for value in (-1,301,float('nan'),True):
            with self.assertRaises(ValueError): gate.wait_drained(value)

    def test_optional_health_startup_failure_and_dependency_transitions(self):
        state={'ready':True}
        for bad in (lambda:False, lambda:'yes'):
            with self.assertRaises(ValueError):
                BoundaryGate(self.app,max_inflight=2,requests_per_second=100,burst=20,readiness_probe=bad)
        with self.assertRaises(ValueError):
            BoundaryGate(self.app,max_inflight=2,requests_per_second=100,burst=20,health_routes='yes')
        calls=[]
        def app(env,start): calls.append('operation'); return self.app(env,start)
        def readiness():
            if state['ready']=='error': raise RuntimeError('private dependency failure')
            return state['ready']
        gate=BoundaryGate(app,max_inflight=2,requests_per_second=100,burst=20,readiness_probe=readiness,health_routes=True)
        self.assertEqual(self.invoke(gate,'GET','/health/live')[0],'200 OK')
        self.assertEqual(self.invoke(gate,'GET','/health/ready')[0],'200 OK')
        self.assertEqual(self.invoke(gate,'POST','/protected')[0],'200 OK')
        for bad in (False,'error','not-a-bool'):
            state['ready']=bad
            self.assertFalse(gate.is_ready())
            self.assertEqual(self.invoke(gate,'GET','/health/live')[0],'200 OK')
            status,body=self.invoke(gate,'GET','/health/ready')
            self.assertEqual(status,'503 Service Unavailable'); self.assertNotIn(b'private',body)
            self.assertEqual(self.invoke(gate,'POST','/protected')[0],'503 Service Unavailable')
        state['ready']=True
        self.assertTrue(gate.is_ready())
        self.assertEqual(self.invoke(gate,'POST','/protected')[0],'200 OK')
        self.assertEqual(calls,['operation','operation'])
        gate.stop_accepting()
        self.assertEqual(self.invoke(gate,'GET','/health/live')[0],'503 Service Unavailable')
        self.assertEqual(self.invoke(gate,'POST','/protected')[0],'503 Service Unavailable')
        self.assertTrue(gate.wait_drained(0))

    def test_draining_rejects_new_requests_while_admitted_probe_finishes(self):
        entered=threading.Event(); release=threading.Event(); calls=[]; probe_calls=[0]
        def probe():
            probe_calls[0]+=1
            if probe_calls[0]>1: entered.set(); release.wait(3)
            return True
        def app(env,start): calls.append('admitted-before-drain'); return self.app(env,start)
        gate=BoundaryGate(app,max_inflight=2,requests_per_second=100,burst=20,readiness_probe=probe)
        with ThreadPoolExecutor(max_workers=1) as pool:
            existing=pool.submit(self.invoke,gate,'POST','/protected')
            self.assertTrue(entered.wait(2)); gate.stop_accepting()
            self.assertFalse(gate.wait_drained(0))
            self.assertEqual(self.invoke(gate,'POST','/protected')[0],'503 Service Unavailable')
            release.set(); self.assertEqual(existing.result()[0],'200 OK')
        self.assertEqual(calls,['admitted-before-drain'])
        self.assertTrue(gate.wait_drained(0))

    def test_health_routes_share_admission_and_do_not_shadow_by_default(self):
        gate=BoundaryGate(self.app,max_inflight=1,requests_per_second=1,burst=1,clock=lambda:100,health_routes=True)
        self.assertEqual(self.invoke(gate,'GET','/health/live')[0],'200 OK')
        self.assertEqual(self.invoke(gate,'GET','/health/ready')[0],'503 Service Unavailable')
        bare=BoundaryGate(self.app,max_inflight=1,requests_per_second=100,burst=10)
        self.assertEqual(self.invoke(bare,'GET','/health/live'),('200 OK',b'ok'))

    def test_loopback_health_and_shutdown_never_run_denied_operations(self):
        state={'ready':True}; calls=[]
        def app(env,start): calls.append('operation'); return self.app(env,start)
        gate=BoundaryGate(app,max_inflight=2,requests_per_second=10000,burst=100,
                          readiness_probe=lambda:state['ready'],health_routes=True)
        server=make_server('127.0.0.1',0,gate,handler_class=QuietHandler)
        thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
        def request(method,path):
            conn=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=3)
            try:
                conn.request(method,path); result=conn.getresponse(); result.read(); return result.status
            finally: conn.close()
        try:
            self.assertEqual(request('GET','/health/live'),200)
            self.assertEqual(request('GET','/health/ready'),200)
            state['ready']=False
            self.assertEqual(request('GET','/health/live'),200)
            self.assertEqual(request('GET','/health/ready'),503)
            self.assertEqual(request('POST','/protected'),503)
            state['ready']=True
            self.assertEqual(request('POST','/protected'),200)
            gate.stop_accepting()
            self.assertEqual(request('POST','/protected'),503)
            self.assertEqual(request('GET','/health/ready'),503)
            self.assertTrue(gate.wait_drained(0))
            self.assertEqual(calls,['operation'])
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_gate_wraps_host_routes_before_auth_or_protected_operation(self):
        calls=[]
        app=create_application(RequestService(Engine(policy(),secret=b'synthetic')),
                               lambda: calls.append('operation'))
        gate=BoundaryGate(app,max_inflight=1,requests_per_second=1,burst=1,clock=lambda:100)
        environ={'REMOTE_ADDR':'192.0.2.1','REQUEST_METHOD':'GET','PATH_INFO':'/api/v2/config'}
        statuses=[]; result=gate(environ,lambda status,headers:statuses.append(status))
        b''.join(result); result.close()
        self.assertEqual(statuses,['200 OK'])
        environ['REQUEST_METHOD']='POST'; environ['PATH_INFO']='/protected'
        statuses=[]; response=gate(environ,lambda status,headers:statuses.append(status))
        self.assertEqual(statuses,['503 Service Unavailable']); self.assertEqual(calls,[])
        self.assertEqual(b''.join(response),b'{"error":"unavailable"}')


if __name__=='__main__': unittest.main(verbosity=2)
