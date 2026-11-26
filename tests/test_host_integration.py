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

    def test_host_principal_and_operation_are_independent_of_forged_signals(self):
        actions, authorizations = [], []
        engine = Engine(policy(override={'max_requests':10}), secret=b'host-test')
        def resolve(environ):
            # A real host must authenticate and set this itself; HTTP headers
            # and submitted signals are not trusted principal context.
            return environ.get('host.authenticated_principal')
        def authorize(principal, operation):
            authorizations.append((principal, operation))
            return principal == 'trusted-principal' and operation == 'synthetic.read'
        app = create_application(RequestService(engine), lambda: actions.append('called') or {'ok':True},
                                 resolve_principal=resolve, authorize=authorize)
        def send(seed, trusted=None):
            raw=json.dumps({'signals':{'machine_id':synthetic_signal('machine_id',seed)}}).encode()
            environ={'REMOTE_ADDR':'192.0.2.1','REQUEST_METHOD':'POST','PATH_INFO':'/protected',
                     'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(raw)),'wsgi.input':io.BytesIO(raw),
                     'HTTP_X_AUTHENTICATED_PRINCIPAL':'trusted-principal'}
            if trusted is not None: environ['host.authenticated_principal']=trusted
            statuses=[]
            payload=b''.join(app(environ, lambda status, headers: statuses.append(status)))
            return statuses[0], json.loads(payload)
        self.assertEqual(send('victim')[0], '403 Forbidden')
        self.assertEqual(send('other')[0], '403 Forbidden')
        self.assertEqual(send('victim', 'different-principal')[0], '403 Forbidden')
        self.assertEqual(len(engine.observations), 0)  # rejected before signal enrollment
        self.assertEqual(send('victim', 'trusted-principal')[0], '200 OK')
        self.assertEqual(actions, ['called'])
        self.assertEqual(authorizations, [('different-principal', 'synthetic.read'), ('trusted-principal', 'synthetic.read')])

    def test_operation_identity_is_host_configured_not_client_controlled(self):
        actions=[]; seen=[]
        gate=RequestService(Engine(policy(override={'max_requests':10}),secret=b'host-test'))
        def authorize(principal,operation):
            seen.append((principal,operation))
            return principal == 'trusted' and operation == 'invoice.read'
        app=create_application(gate,lambda:actions.append('called') or {'ok':True},
            resolve_principal=lambda env:env.get('host.authenticated_principal'),
            authorize=authorize,operation='invoice.read')
        raw=json.dumps({'signals':{'machine_id':synthetic_signal('machine_id','operation')}}).encode()
        env={'REMOTE_ADDR':'192.0.2.1','REQUEST_METHOD':'POST','PATH_INFO':'/protected',
             'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(raw)),'wsgi.input':io.BytesIO(raw),
             'host.authenticated_principal':'trusted','HTTP_X_OPERATION':'invoice.delete'}
        statuses=[]; b''.join(app(env,lambda status,headers:statuses.append(status)))
        self.assertEqual(statuses,['200 OK']);self.assertEqual(seen,[('trusted','invoice.read')]);self.assertEqual(actions,['called'])
        for invalid in ('', 'x'*129, 'read\nadmin', None, 1):
            with self.subTest(operation=invalid):
                with self.assertRaises(ValueError): create_application(gate,operation=invalid)

    def test_host_authorization_and_cross_account_poisoning_are_separate(self):
        # Entitlement is host-owned; accepted fabricated signals still poison
        # the shared machine bucket even when account/principal changes.
        actions=[]
        gate=RequestService(Engine(policy(override={'max_requests':1}),secret=b'host-test'))
        app=create_application(gate,lambda: actions.append('executed') or {'ok':True},
            resolve_principal=lambda env:env.get('host.authenticated_principal'),
            authorize=lambda principal,operation: principal in ('attacker','victim') and operation == 'synthetic.read')
        signal=synthetic_signal('machine_id','victim-shared')
        def send(principal, ip, account):
            payload=json.dumps({'account':account,'signals':{'machine_id':signal}}).encode()
            environ={'REMOTE_ADDR':ip,'REQUEST_METHOD':'POST','PATH_INFO':'/protected',
                     'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(payload)),
                     'wsgi.input':io.BytesIO(payload),'HTTP_X_AUTHENTICATED_PRINCIPAL':'victim'}
            if principal is not None: environ['host.authenticated_principal']=principal
            statuses=[]
            body=b''.join(app(environ,lambda status,headers:statuses.append(status)))
            return statuses[0],json.loads(body)
        self.assertEqual(send(None,'192.0.2.1','victim')[0],'403 Forbidden')
        self.assertEqual(send('unauthorized','192.0.2.1','victim')[0],'403 Forbidden')
        self.assertEqual(actions,[])
        self.assertEqual(send('attacker','192.0.2.1','attacker-account')[0],'200 OK')
        victim=send('victim','192.0.2.2','rotated-account')
        self.assertEqual(victim[0],'429 Too Many Requests')
        self.assertEqual(victim[1]['decision'],'rate_limited')
        self.assertEqual(actions,['executed'])

    def test_loopback_spoofed_principal_header_is_not_host_context(self):
        actions=[]
        engine=Engine(policy(),secret=b'host-test')
        app=create_application(RequestService(engine), lambda: actions.append('called') or {'ok':True},
                               resolve_principal=lambda env:env.get('host.authenticated_principal'),
                               authorize=lambda principal,operation:principal == 'trusted' and operation == 'synthetic.read')
        # Simulates a trusted upstream middleware, not a client-controlled header.
        trusted=[False]
        def host(environ, start_response):
            if trusted[0]: environ['host.authenticated_principal']='trusted'
            return app(environ,start_response)
        server=make_server('127.0.0.1',0,host,handler_class=QuietHandler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            def send():
                raw=json.dumps({'signals':{'machine_id':synthetic_signal('machine_id','victim')}})
                con=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
                try:
                    con.request('POST','/protected',raw,{'Content-Type':'application/json','Host-Authenticated-Principal':'trusted'})
                    response=con.getresponse();status=response.status;response.read();return status
                finally: con.close()
            self.assertEqual(send(),403)
            self.assertEqual(actions,[])
            trusted[0]=True
            self.assertEqual(send(),200)
            self.assertEqual(actions,['called'])
        finally:
            server.shutdown();server.server_close();thread.join()

    def test_host_authorization_failures_do_not_fall_through_or_leak(self):
        actions=[]
        engine=Engine(policy(),secret=b'host-test')
        def invoke(resolve, authorize):
            app=create_application(RequestService(engine), lambda:actions.append('called'),
                                   resolve_principal=resolve, authorize=authorize)
            raw=b'{}'
            environ={'REMOTE_ADDR':'192.0.2.1','REQUEST_METHOD':'POST','PATH_INFO':'/protected',
                     'CONTENT_TYPE':'application/json','CONTENT_LENGTH':str(len(raw)),'wsgi.input':io.BytesIO(raw)}
            statuses=[]; payload=b''.join(app(environ, lambda status, headers:statuses.append(status)))
            return statuses[0],payload
        def broken(*args): raise RuntimeError('synthetic-private-marker')
        for resolve, authorize in ((broken, lambda p,o:True), (lambda e:'principal', broken),
                                   (lambda e:'principal', lambda p,o:'yes')):
            status,payload=invoke(resolve,authorize)
            self.assertEqual(status, '503 Service Unavailable')
            self.assertNotIn(b'synthetic-private-marker', payload)
        self.assertEqual(actions, [])
        self.assertEqual(len(engine.observations), 0)
        with self.assertRaises(ValueError):
            create_application(RequestService(engine), resolve_principal=lambda e:'principal')

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
