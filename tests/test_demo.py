"""Test the Python policy engine, Linux client, and HTTP demo."""
import hashlib
import http.client
import json
import os
import socket
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from http.server import ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'demo'))
from engine import Engine, policy, load_geo
from signal_validation import normalize_signal, synthetic_signal
import server
from server import Handler, scenario
from client import collect, endpoint, main, storage
from unittest.mock import patch
from io import StringIO

def tok(n): return hashlib.sha256(n.encode()).hexdigest()[:32]
def req(account='a', **values): return {'account':account, 'signals':{'machine_id':tok('m'),**values}}

class DemoDefaultsTests(unittest.TestCase):
    def test_default_bind_is_loopback_and_explicit_override_works(self):
        for args, expected in [([], '127.0.0.1'), (['--host', '0.0.0.0'], '0.0.0.0')]:
            with self.subTest(args=args), patch.object(sys, 'argv', ['server.py'] + args), \
                 patch('server.BoundedDemoServer') as constructor, patch('sys.stdout', new_callable=StringIO):
                server.main()
                self.assertEqual(constructor.call_args.args[0][0], expected)

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.now=[1700000000.0]
        self.e=Engine(policy(override={'max_requests':100}), secret=b'secret', clock=lambda:self.now[0])
    def test_any_match_with_rotated_ip_and_shared_ip(self):
        self.assertEqual(self.e.check(req(), '192.0.2.1')['relation'],'new')
        r=self.e.check(req('b'),'198.51.100.1');self.assertEqual(r['relation'],'related');self.assertIn('machine_id',r['matched_signals'])
        r=self.e.check({'account':'c','signals':{'machine_id':tok('different')}},'192.0.2.1')
        self.assertEqual(r['relation'],'related');self.assertEqual(r['matched_signals'],['ip'])
    def test_missing_required_and_optional(self):
        self.assertEqual(self.e.check({'account':'a','signals':{}},'192.0.2.1')['reason'],'missing_required')
        self.assertEqual(self.e.check(req(),'192.0.2.2')['decision'],'allow')
        with self.assertRaises(ValueError): self.e.check(req(disk_serial=tok('d')),'192.0.2.3')
    def test_account_not_required_and_legacy_account_is_ignored(self):
        payload={'signals':{'machine_id':tok('m')}}
        self.assertEqual(self.e.check(payload,'192.0.2.1')['decision'],'allow')
        payload['account']='legacy-name'
        self.assertEqual(self.e.check(payload,'198.51.100.1')['relation'],'related')
    def test_configurable_messages(self):
        opts={'max_requests':1,'messages':{'missing_required':'Ask the service for help.', 'rate_limited':'Please take a short break.', 'capacity_exceeded':'Busy now.'}}
        e=Engine(policy(override=opts),secret=b'secret',clock=lambda:self.now[0])
        self.assertEqual(e.check({'signals':{}},'192.0.2.1')['message'],'Ask the service for help.')
        self.assertEqual(e.check({'signals':{}},'192.0.2.1')['message'],'Please take a short break.')
        e=Engine(policy(override=opts),secret=b'secret',clock=lambda:self.now[0],max_entries=1)
        self.assertEqual(e.check({'signals':{'machine_id':tok('m')}},'192.0.2.1')['message'],'Busy now.')
        for bad in ({'messages':{'unknown':'x'}},{'messages':{'rate_limited':''}},{'messages':{'rate_limited':'x\ny'}},{'messages':'bad'}):
            with self.assertRaises(ValueError): policy(override=bad)
    def test_forged_signal_can_exhaust_victim_bucket(self):
        e=Engine(policy(override={'max_requests':2}),secret=b'secret',clock=lambda:self.now[0])
        data={'signals':{'machine_id':synthetic_signal('machine_id','victim')}}
        for ip in ('192.0.2.1','192.0.2.2'): self.assertEqual(e.check(data,ip)['decision'],'allow')
        self.assertEqual(e.check(data,'198.51.100.1')['decision'],'rate_limited')
    def test_optional_can_match(self):
        self.e.check(req(product_uuid=synthetic_signal('product_uuid','u')),'192.0.2.1')
        r=self.e.check({'account':'x','signals':{'machine_id':tok('other'),'product_uuid':synthetic_signal('product_uuid','u')}},'192.0.2.2')
        self.assertEqual(r['matched_signals'],['product_uuid'])
    def test_min_matches_and_inconclusive(self):
        e=Engine(policy('standard'),secret=b'secret',clock=lambda:self.now[0])
        e.check(req(),'192.0.2.1')
        self.assertEqual(e.check(req(),'192.0.2.2')['relation'],'below_threshold')
        self.assertEqual(e.check(req(),'192.0.2.1')['relation'],'related')
    def test_rate_limit_ip_and_machine_independent(self):
        e=Engine(policy(override={'max_requests':2,'window_seconds':60}),secret=b'secret',clock=lambda:self.now[0])
        self.assertEqual(e.check(req(),'192.0.2.1')['decision'],'allow')
        self.assertEqual(e.check(req('b'),'192.0.2.2')['decision'],'allow')
        self.assertEqual(e.check(req('c'),'192.0.2.3')['decision'],'rate_limited')
        self.now[0]+=61
        self.assertEqual(e.check(req('d'),'192.0.2.3')['decision'],'allow')
        e.check({'account':'z','signals':{'machine_id':tok('z')}},'192.0.2.1')
        e.check({'account':'z2','signals':{'machine_id':tok('z2')}},'192.0.2.1')
        self.assertEqual(e.check({'account':'z3','signals':{'machine_id':tok('z3')}},'192.0.2.1')['decision'],'rate_limited')
    def test_shared_ip_warning(self):
        e=Engine(policy(override={'max_requests':1}),secret=b'secret',clock=lambda:self.now[0])
        e.check(req(),'192.0.2.1')
        self.assertEqual(e.check({'account':'other','signals':{'machine_id':tok('other')}},'192.0.2.1')['decision'],'rate_limited')
    def test_timezone_and_clock(self):
        e=Engine(policy(override={'timezone_enforce':True,'max_requests':100}),secret=b'secret',clock=lambda:self.now[0],geo=load_geo([{'network':'192.0.2.0/24','timezones':['Asia/Karachi']}]))
        r=e.check({**req(),'timezone':'Asia/Karachi','timestamp':self.now[0]-60},'192.0.2.1');self.assertEqual(r['timezone'],'consistent');self.assertEqual(r['clock'],'ok')
        r=e.check({**req(),'timezone':'America/New_York'},'192.0.2.1');self.assertEqual(r['reason'],'timezone_mismatch')
        r=e.check({**req(),'timezone':'Asia/Karachi','timestamp':self.now[0]-301},'192.0.2.1');self.assertEqual(r['reason'],'clock_out_of_range')
        r=e.check({**req(),'timezone':'America/New_York'},'198.51.100.2');self.assertEqual(r['timezone'],'unknown');self.assertEqual(r['decision'],'allow')
        with self.assertRaises(ValueError):e.check({**req(),'timezone':'No/SuchZone'},'192.0.2.1')
    def test_concurrency_atomic(self):
        e=Engine(policy(override={'max_requests':5}),secret=b'secret',clock=lambda:self.now[0])
        with ThreadPoolExecutor(max_workers=20) as pool: out=list(pool.map(lambda i:e.check(req(str(i)),'192.0.2.1')['decision'],range(100)))
        self.assertEqual(out.count('allow'),5);self.assertEqual(out.count('rate_limited'),95)
    def test_capacity_closed(self):
        e=Engine(policy(override={'max_requests':100}),secret=b'secret',clock=lambda:self.now[0],max_entries=2)
        self.assertEqual(e.check(req(),'192.0.2.1')['decision'],'allow')
        self.assertEqual(e.check(req('b'),'192.0.2.2')['decision'],'capacity_exceeded')
    def test_bad_config_and_schema(self):
        for o in [False, 0, 'bad', {'min_matches':0},{'required':['wrong']},{'max_requests':0},{'required':['machine_id'],'conditional':['machine_id']},{'timezone_enforce':'yes'}]:
            with self.assertRaises(ValueError):policy(override=o)
        for data in [{'account':'x','signals':{'machine_id':'raw-id'}}, {'account':'x','signals':{'machine_id':tok('x')},'ip':'1.2.3.4'}]:
            with self.assertRaises(ValueError):self.e.check(data,'192.0.2.1')
    def test_no_raw_values_stored(self):
        x=req();self.e.check(x,'192.0.2.1')
        self.assertNotIn(x['signals']['machine_id'],str((self.e.observations.records, self.e.observations.snapshots, self.e.observations.postings)));self.assertNotIn('192.0.2.1',str((self.e.observations.records, self.e.observations.snapshots, self.e.observations.postings)))
    def test_simulation_isolated(self):
        out=scenario('basic');self.assertEqual(out['events'][2]['matched_signals'],['ip']);self.assertTrue(any(e['decision']=='rate_limited' for e in out['events']))
    def test_native_collector(self):
        ids=collect({'machine_id','product_uuid','board_serial'})
        for name, value in ids.items(): self.assertEqual(value, normalize_signal(name,value))
        self.assertEqual(ids, collect({'machine_id','product_uuid','board_serial'}))

class RawSignalTests(unittest.TestCase):
    def test_formats_and_normalization(self):
        for name in ('machine_id','installation_id','product_uuid','board_serial','product_serial','chassis_serial','disk_serial','disk_wwn','filesystem_uuid','partition_uuid','gpu_uuid','mac_address'):
            val=synthetic_signal(name,'sample')
            self.assertEqual(normalize_signal(name,'  '+val.upper()+'  '),normalize_signal(name,val))
            for bad in ('', 'unknown', '0', 'x\nattack', 'é'*4, 'x'*129):
                with self.subTest(name=name,bad=bad):
                    with self.assertRaises(ValueError): normalize_signal(name,bad)
        self.assertEqual(normalize_signal('filesystem_uuid','ABCD-1234'),'abcd-1234')
        self.assertEqual(normalize_signal('partition_uuid','AABBCCDD-01'),'aabbccdd-01')
        self.assertEqual(normalize_signal('disk_wwn','0x123456789abcdef0'),'123456789abcdef0')
        for name,value in [('machine_id','0'*32),('product_uuid','00000000-0000-0000-0000-000000000000'),('mac_address','01:00:00:00:00:01'),('board_serial','to be filled by o.e.m.')]:
            with self.assertRaises(ValueError): normalize_signal(name,value)
    def test_fabrication_and_replay_remain_possible(self):
        e=Engine(policy(override={'max_requests':100}),secret=b'secret')
        first=synthetic_signal('machine_id','fabricated-1'); other=synthetic_signal('machine_id','fabricated-2')
        self.assertEqual(e.check({'account':'a','signals':{'machine_id':first}},'192.0.2.1')['decision'],'allow')
        self.assertEqual(e.check({'account':'b','signals':{'machine_id':first}},'192.0.2.2')['relation'],'related')
        self.assertNotEqual(e.check({'account':'c','signals':{'machine_id':other}},'192.0.2.3')['relation'],'related')
    def test_endpoint_restricts_transport(self):
        self.assertEqual(endpoint('https://example.test/api/v2/check'),'https://example.test/api/v2/config')
        self.assertEqual(endpoint('http://127.0.0.1:8000/api/v2/check'),'http://127.0.0.1:8000/api/v2/config')
        for bad in ('http://example.test/api/v2/check','https://example.test/api/v1/check','https://user:pass@example.test/api/v2/check'):
            with self.assertRaises(ValueError): endpoint(bad)
    def test_storage_collects_only_requested_columns(self):
        class Result:
            stdout='{"blockdevices":[{"type":"disk","serial":"demo-serial-1"}]}'
        with patch('client.subprocess.run',return_value=Result()) as call:
            self.assertEqual(storage({'disk_serial'}),{'disk_serial':['demo-serial-1']})
        self.assertEqual(call.call_args.args[0],['lsblk','-J','-o','TYPE,SERIAL'])
    def test_missing_required_client_message(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def read(self,*args): return b'{"protocol":"raw-v2","required":["machine_id"],"conditional":[],"missing_required_message":"Contact the service for required information."}'
        class Opener:
            def open(self,*args,**kwargs): return Response()
        output=StringIO()
        with patch('sys.argv',['client.py','--confirm-send-raw']), patch('client.collect',return_value={}), patch('client.urllib.request.build_opener',return_value=Opener()), patch('sys.stdout',output):
            self.assertEqual(main(),2)
        result=json.loads(output.getvalue())
        self.assertEqual(result['missing'],['machine_id']); self.assertEqual(result['message'],'Contact the service for required information.')

class HttpTests(unittest.TestCase):
    def setUp(self):
        self.httpd=ThreadingHTTPServer(('127.0.0.1',0),Handler);self.httpd.engine=Engine(policy(override={'max_requests':3}),secret=b'secret')
        self.thread=threading.Thread(target=self.httpd.serve_forever,daemon=True);self.thread.start();self.port=self.httpd.server_address[1]
    def tearDown(self): self.httpd.shutdown();self.httpd.server_close();self.thread.join()
    def request(self, path, body, headers=None):
        con=http.client.HTTPConnection('127.0.0.1',self.port,timeout=5);con.request('POST',path,body,headers or {'Content-Type':'application/json'});r=con.getresponse();data=r.read();con.close();return r.status,json.loads(data)
    def test_endpoint_and_forward_header_ignored(self):
        a=req(); b={'account':'b','signals':{'machine_id':tok('other')}}
        self.assertEqual(self.request('/api/v2/check',json.dumps(a))[0],200)
        status,data=self.request('/api/v2/check',json.dumps(b),{'Content-Type':'application/json','X-Forwarded-For':'198.51.100.1'})
        self.assertEqual(status,200);self.assertEqual(data['matched_signals'],['ip'])
    def test_client_real_http_with_synthetic_signal(self):
        value=synthetic_signal('machine_id','client-sample')
        output=StringIO()
        argv=['client.py','--url',f'http://127.0.0.1:{self.port}/api/v2/check','--confirm-send-raw']
        with patch('sys.argv',argv), patch('client.collect',return_value={'machine_id':value}), patch('sys.stdout',output):
            self.assertEqual(main(),0)
        self.assertEqual(json.loads(output.getvalue())['decision'],'allow')
        self.assertNotIn(value,str((self.httpd.engine.observations.records, self.httpd.engine.observations.snapshots, self.httpd.engine.observations.postings)))
    def test_client_confirmation_blocks_send(self):
        output=StringIO()
        argv=['client.py','--url',f'http://127.0.0.1:{self.port}/api/v2/check']
        with patch('sys.argv',argv), patch('client.collect',return_value={'machine_id':synthetic_signal('machine_id','consent')}), patch('sys.stdout',output):
            self.assertEqual(main(),2)
        info=json.loads(output.getvalue())
        self.assertEqual(info['reason'],'confirmation_required')
        self.assertIn('machine_id',info['requested']); self.assertEqual(info['available'],['machine_id'])
        self.assertEqual(info['recipient'],f'http://127.0.0.1:{self.port}/api/v2/check')
        self.assertEqual(len(self.httpd.engine.observations),0)
    def test_malformed_and_duplicate_charged(self):
        for _ in range(3):self.assertEqual(self.request('/api/v2/check','{"account":"x", "account":"y"}')[0],400)
        self.assertEqual(self.request('/api/v2/check','{}')[0],429)
    def test_invalid_raw_values_are_charged(self):
        for _ in range(3): self.assertEqual(self.request('/api/v2/check',json.dumps({'account':'a','signals':{'machine_id':'1'}}))[0],400)
        self.assertEqual(self.request('/api/v2/check',json.dumps(req()))[0],429)
    def test_configurable_invalid_message_and_no_account(self):
        self.httpd.engine=Engine(policy(override={'messages':{'invalid_request':'Please fix the request.'}}),secret=b'secret')
        status,body=self.request('/api/v2/check',json.dumps({'signals':{'machine_id':'1'}}))
        self.assertEqual(status,400);self.assertEqual(body['message'],'Please fix the request.')
        status,body=self.request('/api/v2/check',json.dumps({'signals':{'machine_id':tok('m')}}))
        self.assertEqual(status,200);self.assertEqual(body['decision'],'allow')
    def test_non_json_number_rejected_and_charged(self):
        status, _ = self.request('/api/v2/check', '{"account":"x","signals":{},"timestamp":NaN}')
        self.assertEqual(status,400)
    def test_truncated_valid_json_is_rejected(self):
        body=json.dumps(req()).encode()
        sock=socket.create_connection(('127.0.0.1',self.port),timeout=5)
        try:
            headers=f'POST /api/v2/check HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {len(body)+10}\r\n\r\n'.encode()
            sock.sendall(headers+body);sock.shutdown(socket.SHUT_WR)
            response=http.client.HTTPResponse(sock);response.begin();response.read()
            self.assertEqual(response.status,400)
        finally: sock.close()
    def test_duplicate_content_length_rejected(self):
        con=http.client.HTTPConnection('127.0.0.1',self.port,timeout=5)
        con.putrequest('POST','/api/v2/check')
        con.putheader('Content-Type','application/json');con.putheader('Content-Length','2');con.putheader('Content-Length','2');con.endheaders();con.send(b'{}')
        res=con.getresponse();res.read();con.close();self.assertEqual(res.status,400)
    def test_retry_after_header(self):
        for _ in range(3): self.request('/api/v2/check',json.dumps(req()))
        con=http.client.HTTPConnection('127.0.0.1',self.port,timeout=5)
        con.request('POST','/api/v2/check',json.dumps(req()),{'Content-Type':'application/json'})
        res=con.getresponse();self.assertEqual(res.status,429);self.assertGreater(int(res.getheader('Retry-After')),0);res.read();con.close()
    def test_survey_history_endpoint(self):
        con=http.client.HTTPConnection('127.0.0.1',self.port,timeout=5); con.request('GET','/api/info')
        res=con.getresponse(); payload=json.loads(res.read()); con.close()
        self.assertEqual(res.status,200); self.assertIsInstance(payload['survey_history'],list)
    def test_demo_endpoint(self):
        status,data=self.request('/api/demo/run','{"preset":"basic"}');self.assertEqual(status,200);self.assertEqual(len(data['events']),8)

if __name__=='__main__': unittest.main(verbosity=2)
