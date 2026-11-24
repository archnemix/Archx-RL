"""Test that a host enforces decisions before its protected operation."""
import io
import http.client
import threading
from wsgiref.simple_server import make_server
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'demo'))
sys.path.insert(0,str(ROOT/'examples/python'))
from engine import Engine, policy
from gated_wsgi import create_application, QuietHandler
from service import RequestService
from signal_validation import synthetic_signal


class HostIntegrationTests(unittest.TestCase):
    def test_host_only_runs_operation_for_allowed_request(self):
        actions=[]
        gate=RequestService(Engine(policy(override={'max_requests':1}),secret=b'host-test'))
        app=create_application(gate,lambda: actions.append('called') or {'ok':True})
        def post(body):
            data=json.dumps(body).encode()
            environ={'REMOTE_ADDR':'192.0.2.1','REQUEST_METHOD':'POST','PATH_INFO':'/protected',
                     'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(data)),'wsgi.input':io.BytesIO(data)}
            response=[]
            payload=b''.join(app(environ,lambda status,headers:response.append((status,headers))))
            return response[0],json.loads(payload)
        allowed=post({'signals':{'machine_id':synthetic_signal('machine_id','one')}})
        self.assertEqual(allowed[0][0],'200 OK'); self.assertEqual(allowed[1]['data'],{'ok':True})
        denied=post({'signals':{'machine_id':synthetic_signal('machine_id','two')}})
        self.assertEqual(denied[0][0],'429 Too Many Requests')
        self.assertTrue(any(k=='Retry-After' for k,v in denied[0][1]))
        self.assertEqual(actions,['called'])

    def test_loopback_wsgi_http_enforces_gate(self):
        actions=[]
        app=create_application(RequestService(Engine(policy(override={'max_requests':1}),secret=b'host-test')),
                               lambda:actions.append('called') or {'ok':True})
        server=make_server('127.0.0.1',0,app,handler_class=QuietHandler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            def send(seed):
                body=json.dumps({'signals':{'machine_id':synthetic_signal('machine_id',seed)}})
                con=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
                con.request('POST','/protected',body,{'Content-Type':'application/json'})
                response=con.getresponse();status=response.status;response.read();con.close();return status
            self.assertEqual(send('one'),200)
            self.assertEqual(send('two'),429)
            self.assertEqual(actions,['called'])
        finally:
            server.shutdown();server.server_close();thread.join()

    def test_sealed_host_request_is_single_use(self):
        try:
            from nacl.public import PrivateKey
            from sealed_payload import seal
            from replay import MemoryReplay
        except ImportError:
            self.skipTest('install demo/requirements-secure.txt to test encryption')
        engine=Engine(policy(override={'max_requests':10}),secret=b'host-test')
        replay=MemoryReplay(engine.secret,engine.clock)
        key=PrivateKey.generate();gate=RequestService(engine,sealed_key=bytes(key),replay=replay)
        actions=[];app=create_application(gate,lambda:actions.append('called') or {'ok':True})
        body={'signals':{'machine_id':synthetic_signal('machine_id','sealed')},'nonce':gate.challenge('192.0.2.1')['nonce']}
        raw=json.dumps(seal(body,bytes(key.public_key))).encode()
        def send():
            environ={'REMOTE_ADDR':'192.0.2.1','REQUEST_METHOD':'POST','PATH_INFO':'/protected',
                     'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(raw)),'wsgi.input':io.BytesIO(raw)}
            statuses=[];payload=b''.join(app(environ,lambda status,headers:statuses.append(status)))
            return statuses[0],json.loads(payload)
        self.assertEqual(send()[0],'200 OK')
        status,result=send();self.assertEqual(status,'400 Bad Request');self.assertEqual(result['reason'],'replay_rejected')
        self.assertEqual(actions,['called'])

    def test_malformed_input_is_denied_and_charged(self):
        actions=[]
        gate=RequestService(Engine(policy(override={'max_requests':1}),secret=b'host-test'))
        app=create_application(gate,lambda:actions.append('called'))
        def send(raw):
            environ={'REMOTE_ADDR':'192.0.2.2','REQUEST_METHOD':'POST','PATH_INFO':'/protected',
                     'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(raw)),'wsgi.input':io.BytesIO(raw)}
            statuses=[]
            b''.join(app(environ,lambda status,headers:statuses.append(status)))
            return statuses[0]
        self.assertEqual(send(b'{"x":1,"x":2}'),'400 Bad Request')
        self.assertEqual(send(b'{}'),'429 Too Many Requests')
        self.assertEqual(actions,[])


if __name__ == '__main__': unittest.main(verbosity=2)
