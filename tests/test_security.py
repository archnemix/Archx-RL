"""Test optional security integrations and request-service enforcement."""
import base64
import http.client
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from unittest.mock import patch
from io import StringIO
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'demo'))
from engine import Engine,policy
from replay import MemoryReplay
from service import RequestService
from sqlite_engine import SQLiteEngine
from security import refresh_ipsum, Reputation, Turnstile
from server import Handler
from signal_validation import synthetic_signal

class Response:
    def __init__(self,data): self.data=data
    def __enter__(self): return self
    def __exit__(self,*args): pass
    def read(self,n): return self.data[:n]
class Opener:
    def __init__(self,doc): self.doc=doc;self.requests=[]
    def open(self,req,timeout): self.requests.append(req);return Response(json.dumps(self.doc).encode())

class SecurityTests(unittest.TestCase):
    def test_ip_storage_modes_persist_only_device_hashes(self):
        with tempfile.TemporaryDirectory() as d:
            signal=synthetic_signal('machine_id','secret'); ip='192.0.2.31'
            for mode in ('hash','raw'):
                path=os.path.join(d,mode)
                settings=policy(override={'ip_storage':mode}); e=SQLiteEngine(path,settings,secret=b's'*32)
                e.check({'signals':{'machine_id':signal}},ip)
                with e.connect() as con: rows=str(con.execute('select name,token from signals').fetchall())+str(con.execute('select key from windows').fetchall())
                self.assertNotIn(signal,rows);self.assertEqual(ip in rows,mode=='raw')
                self.assertEqual(e.check({'signals':{'machine_id':signal}},ip)['relation'],'related')
                if mode=='raw':
                    with self.assertRaises(ValueError): SQLiteEngine(path,policy(),secret=b's'*32)
            with self.assertRaises(ValueError):policy(override={'machine_id_storage':'raw'})
            with self.assertRaises(ValueError):policy(override={'ip_storage':'raw-all'})
    def test_feed_refresh_cache_staleness_and_failed_update(self):
        with tempfile.TemporaryDirectory() as d:
            path=os.path.join(d,'ips.json')
            doc={'encoding':'base64','content':base64.b64encode(b'192.0.2.1\n2001:db8::1\n').decode()}
            with patch('security.time.time',return_value=100): self.assertEqual(refresh_ipsum(path,3,Opener(doc)),2)
            rep=Reputation(path,100,clock=lambda:150)
            self.assertEqual(rep.lookup('192.0.2.1')['status'],'listed')
            self.assertEqual(rep.lookup('192.0.2.2')['status'],'not_listed')
            old=Path(path).read_bytes()
            with self.assertRaises(ValueError): refresh_ipsum(path,3,Opener({'encoding':'base64','content':'invalid!'}))
            self.assertEqual(old,Path(path).read_bytes())
            rep.clock=lambda:201;self.assertEqual(rep.lookup('192.0.2.1')['status'],'stale')
            Path(path).write_text('{bad');self.assertEqual(rep.lookup('192.0.2.1')['status'],'unavailable')
    def test_turnstile_verification(self):
        doc={'success':True,'hostname':'example.com','action':'check'}; opener=Opener(doc)
        t=Turnstile('site','secret','example.com','check',opener)
        self.assertEqual(t.verify('x'),'valid');self.assertEqual(t.verify(''),'invalid');self.assertEqual(t.verify('x'*2049),'invalid')
        self.assertNotIn('secret',opener.requests[0].full_url)
        doc['action']='wrong';self.assertEqual(t.verify('x'),'invalid')
        doc['action']='check';doc['hostname']='evil.com';self.assertEqual(t.verify('x'),'invalid')
        doc['success']=False;self.assertEqual(t.verify('x'),'invalid')
        doc['error-codes']=['internal-error'];self.assertEqual(t.verify('x'),'unavailable')
        class Down:
            def open(self,*args,**kwargs): raise TimeoutError()
        t.opener=Down();self.assertEqual(t.verify('x'),'unavailable')

class KeyTests(unittest.TestCase):
    def test_key_creation_and_permissions(self):
        try:
            from sealed_payload import create_keys, read_key, seal, unseal
            import nacl.public
        except ImportError: self.skipTest('install demo/requirements-secure.txt to test encryption')
        with tempfile.TemporaryDirectory() as d:
            private=Path(d)/'private';public=Path(d)/'public'
            create_keys(private,public)
            self.assertEqual(os.stat(private).st_mode & 0o777,0o600)
            box=seal({'signals':{}},read_key(public))
            self.assertEqual(json.loads(unseal(box,read_key(private,private=True))),{'signals':{}})
            with self.assertRaises(FileExistsError): create_keys(private,public)
            os.chmod(private,0o644)
            with self.assertRaises(ValueError): read_key(private,private=True)


class ServiceIntegrationTests(unittest.TestCase):
    def test_ip_is_charged_once_per_request_under_concurrency(self):
        body={'signals':{'machine_id':synthetic_signal('machine_id','parallel')}}
        with tempfile.TemporaryDirectory() as d:
            settings=policy(override={'max_requests':5})
            engines=[Engine(settings,secret=b'x'*32),SQLiteEngine(os.path.join(d,'db'),settings,b'x'*32)]
            for engine in engines:
                with self.subTest(engine=type(engine).__name__):
                    service=RequestService(engine)
                    with ThreadPoolExecutor(max_workers=12) as pool:
                        results=list(pool.map(lambda _:service.check(body,'192.0.2.1')['decision'],range(20)))
                    self.assertEqual(results.count('allow'),5)
                    self.assertEqual(results.count('rate_limited'),15)

    def test_unverified_or_blocked_request_cannot_poison_device_buckets(self):
        signal=synthetic_signal('machine_id','victim')
        body={'signals':{'machine_id':signal},'turnstile_token':'bad'}
        class Verifier:
            sitekey='site';action='test';result='invalid'
            def verify(self,token): return self.result
        class ReputationStub:
            def lookup(self,ip): return {'status':'listed'}
        with tempfile.TemporaryDirectory() as d:
            settings=policy(override={'max_requests':1})
            engines=[Engine(settings,secret=b'x'*32),SQLiteEngine(os.path.join(d,'db'),settings,b'x'*32)]
            for engine in engines:
                with self.subTest(engine=type(engine).__name__):
                    verifier=Verifier();service=RequestService(engine,turnstile=verifier)
                    for peer in ('192.0.2.1','192.0.2.2'):
                        self.assertEqual(service.check(body,peer)['reason'],'turnstile_invalid')
                    verifier.result='valid'
                    self.assertEqual(service.check({**body,'turnstile_token':'fresh'},'192.0.2.3')['decision'],'allow')
                    self.assertEqual(service.check({**body,'turnstile_token':'fresh'},'192.0.2.3')['decision'],'rate_limited')
                    other={'signals':{'machine_id':synthetic_signal('machine_id','other')},'turnstile_token':'fresh'}
                    blocked=RequestService(engine,turnstile=verifier,reputation=ReputationStub(),reputation_mode='block')
                    self.assertEqual(blocked.check(other,'192.0.2.4')['reason'],'reputation_blocked')
                    self.assertEqual(service.check(other,'192.0.2.5')['decision'],'allow')

class HttpSecurityTests(unittest.TestCase):
    def setUp(self):
        self.httpd=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.httpd.engine=Engine(policy(override={'max_requests':100}),secret=b'x'*32)
        self.thread=threading.Thread(target=self.httpd.serve_forever,daemon=True);self.thread.start()
    def tearDown(self): self.httpd.shutdown();self.httpd.server_close();self.thread.join()
    def request(self,body):
        c=http.client.HTTPConnection('127.0.0.1',self.httpd.server_address[1],timeout=5)
        c.request('POST','/api/v2/check',json.dumps(body),{'Content-Type':'application/json'}); r=c.getresponse();res=(r.status,json.loads(r.read()));c.close();return res
    def test_turnstile_required_and_reputation_modes(self):
        t=Turnstile('site','secret','example.com','check',Opener({'success':True,'hostname':'example.com','action':'check'}))
        self.httpd.turnstile=t
        body={'signals':{'machine_id':synthetic_signal('machine_id','one')}}
        self.assertEqual(self.request(body)[0],403)
        body['turnstile_token']='token';self.assertEqual(self.request(body)[0],200)
        class Rep:
            status='listed'
            def lookup(self,ip): return {'status':self.status}
        self.httpd.reputation=Rep(); self.httpd.reputation_mode='block';self.httpd.reputation_stale='open'
        self.assertEqual(self.request(body)[1]['reason'],'reputation_blocked')
        self.httpd.reputation_mode='observe';self.assertEqual(self.request(body)[1]['reputation']['status'],'listed')
        self.httpd.reputation.status='stale';self.httpd.reputation_stale='closed';self.assertEqual(self.request(body)[0],503)
        self.httpd.reputation_stale='open';self.assertEqual(self.request(body)[0],200)
    def get(self,path):
        c=http.client.HTTPConnection('127.0.0.1',self.httpd.server_address[1],timeout=5)
        c.request('GET',path); r=c.getresponse(); res=(r.status,json.loads(r.read())); c.close();return res
    def test_sealed_transport_and_plaintext_rejected(self):
        try:
            from nacl.public import PrivateKey
            from sealed_payload import seal
        except ImportError: self.skipTest('install demo/requirements-secure.txt to test encryption')
        key=PrivateKey.generate();self.httpd.sealed_key=bytes(key)
        self.httpd.replay=MemoryReplay(self.httpd.engine.secret,self.httpd.engine.clock)
        raw={'signals':{'machine_id':synthetic_signal('machine_id','secret')}}
        nonce=self.get('/api/v2/challenge')[1]['nonce']
        box=seal({**raw,'nonce':nonce},bytes(key.public_key));self.assertNotIn(raw['signals']['machine_id'],json.dumps(box))
        self.assertEqual(self.request(raw)[0],400)
        with ThreadPoolExecutor(max_workers=10) as pool:
            results=list(pool.map(lambda _:self.request(box), range(15)))
        self.assertEqual(sum(status==200 for status,body in results),1)
        self.assertEqual(sum(status==400 and body['reason']=='replay_rejected' for status,body in results),14)
        status,replayed=self.request(box);self.assertEqual(status,400);self.assertEqual(replayed['reason'],'replay_rejected')
        other=PrivateKey.generate(); self.assertEqual(self.request(seal(raw,bytes(other.public_key)))[0],400)
        from client import main as client_main
        with tempfile.TemporaryDirectory() as d:
            public=Path(d)/'pub'; public.write_text(bytes(key.public_key).hex())
            out=StringIO()
            with patch('sys.argv',['client.py','--url',f'http://127.0.0.1:{self.httpd.server_address[1]}/api/v2/check','--server-public-key',str(public),'--confirm-send-raw']), patch('client.collect',return_value=raw['signals']), patch('sys.stdout',out):
                self.assertEqual(client_main(),0)
            self.assertEqual(json.loads(out.getvalue())['decision'],'allow')
            self.httpd.sealed_key=None
            out=StringIO()
            with patch('sys.argv',['client.py','--url',f'http://127.0.0.1:{self.httpd.server_address[1]}/api/v2/check','--server-public-key',str(public),'--confirm-send-raw']), patch('client.collect',return_value=raw['signals']), patch('sys.stdout',out):
                self.assertEqual(client_main(),1)
            self.assertIn('downgrade',out.getvalue())
            self.httpd.sealed_key=bytes(key)
        ciphertext=bytearray(base64.b64decode(box['ciphertext']));ciphertext[-1]^=1
        box['ciphertext']=base64.b64encode(ciphertext).decode();self.assertEqual(self.request(box)[0],400)

if __name__=='__main__': unittest.main(verbosity=2)
