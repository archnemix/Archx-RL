import hashlib
import http.client
import json
import threading
from http.server import ThreadingHTTPServer
import multiprocessing
import os
import random
import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'demo'))
from engine import Engine, policy
from signal_validation import synthetic_signal
from sqlite_engine import SQLiteEngine
from server import Handler

SECRET = b'synthetic-persistent-test-secret-0123456789'
def tok(s): return hashlib.sha256(s.encode()).hexdigest()[:32]
def req(account='a', **values): return {'account':account,'signals':{'machine_id':tok('machine'),**values}}
def child(db, queue):
    try:
        e=SQLiteEngine(db,policy(override={'max_requests':5}),SECRET,clock=lambda:1700000000.0)
        queue.put([e.check(req(str(i)),'192.0.2.1')['decision'] for i in range(10)])
    except Exception as exc: queue.put(['error:'+str(exc)])

class PersistentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.path=str(Path(self.tmp.name)/'state.sqlite'); self.now=[1700000000.0]
    def tearDown(self): self.tmp.cleanup()
    def engine(self, **opts):
        return SQLiteEngine(self.path,policy(override=opts or None),SECRET,clock=lambda:self.now[0])
    def test_restarts_and_history_retention(self):
        e=self.engine(window_seconds=60,history_seconds=3600,max_requests=2)
        self.assertEqual(e.check(req(),'192.0.2.1')['relation'],'new')
        e=self.engine(window_seconds=60,history_seconds=3600,max_requests=2)
        self.assertEqual(e.check(req('b'),'198.51.100.1')['relation'],'related')
        self.assertEqual(e.check(req('c'),'203.0.113.1')['decision'],'rate_limited')
        self.now[0]+=61
        self.assertEqual(e.check(req('d'),'203.0.113.2')['relation'],'related')
        self.now[0]+=3601
        self.assertEqual(e.check(req('e'),'203.0.113.3')['relation'],'new')
    def test_wrong_secret_and_policy_fail_closed(self):
        self.engine()
        with self.assertRaises(ValueError): SQLiteEngine(self.path,policy(),b'x'*32)
        with self.assertRaises(ValueError): SQLiteEngine(self.path,policy('hard'),SECRET)
        with self.assertRaises(ValueError): SQLiteEngine(self.path,policy(),b'short')
    def test_old_schema_rejected(self):
        self.engine()
        with sqlite3.connect(self.path) as db: db.execute("UPDATE meta SET value='2' WHERE name='schema'")
        with self.assertRaisesRegex(ValueError,'schema'): self.engine()
    def test_private_permissions_and_symlink(self):
        self.engine()
        self.assertEqual(os.stat(self.path).st_mode & 0o777,0o600)
        os.chmod(self.path,0o644)
        with self.assertRaises(ValueError):self.engine()
        link=str(Path(self.tmp.name)/'link.sqlite');os.symlink(self.path,link)
        with self.assertRaises(OSError): SQLiteEngine(link,policy(),SECRET)
    def test_atomic_threads_across_instances(self):
        self.engine(max_requests=5)
        engines=[self.engine(max_requests=5) for _ in range(4)]
        with ThreadPoolExecutor(max_workers=20) as pool:
            results=list(pool.map(lambda i:engines[i%4].check(req(str(i)),'192.0.2.1')['decision'],range(60)))
        self.assertEqual(results.count('allow'),5)
        self.assertEqual(results.count('rate_limited'),55)
    def test_atomic_processes(self):
        self.engine(max_requests=5)
        ctx=multiprocessing.get_context('spawn'); queue=ctx.Queue()
        workers=[ctx.Process(target=child,args=(self.path,queue)) for _ in range(4)]
        for p in workers:p.start()
        results=[]
        for p in workers:results.extend(queue.get(timeout=30))
        for p in workers:p.join(30);self.assertEqual(p.exitcode,0)
        queue.close()
        self.assertEqual(results.count('allow'),5,results)
        self.assertEqual(results.count('rate_limited'),35,results)
    def test_no_raw_request_data_stored(self):
        e=self.engine(); item=req('sensitive-account')
        e.check(item,'192.0.2.1')
        with sqlite3.connect(self.path) as db:
            dump=''.join(db.iterdump())
        self.assertNotIn('sensitive-account',dump);self.assertNotIn('192.0.2.1',dump)
        self.assertNotIn(item['signals']['machine_id'],dump)
    def test_repeat_snapshot_does_not_grow_history(self):
        e=self.engine(max_requests=100)
        for i in range(30): self.assertEqual(e.check(req(str(i)),'192.0.2.1')['decision'],'allow')
        with sqlite3.connect(self.path) as db: count=db.execute('SELECT count(*) FROM observations').fetchone()[0]
        self.assertEqual(count,1)
    def test_missing_database_returns_storage_error(self):
        e=self.engine();os.unlink(self.path)
        self.assertEqual(e.check(req(),'192.0.2.1')['decision'],'storage_error')
        self.assertFalse(os.path.exists(self.path))
    def test_database_failure_rolls_back_partial_charges(self):
        e=self.engine()
        with sqlite3.connect(self.path) as db: db.execute('DROP TABLE signals')
        self.assertEqual(e.check(req(),'192.0.2.1')['decision'],'storage_error')
        with sqlite3.connect(self.path) as db: self.assertEqual(db.execute('SELECT count(*) FROM windows').fetchone()[0],0)
    def test_missing_required_charged_and_not_enrolled(self):
        e=self.engine(max_requests=2)
        self.assertEqual(e.check({'account':'a','signals':{}},'192.0.2.1')['decision'],'invalid')
        self.assertEqual(e.check(req(),'192.0.2.1')['relation'],'new')
        self.assertEqual(e.check(req(),'192.0.2.1')['decision'],'rate_limited')
    def test_capacity_fail_closed(self):
        e=SQLiteEngine(self.path,policy(override={'max_requests':100,'history_seconds':3600}),SECRET,clock=lambda:self.now[0],max_entries=2)
        self.assertEqual(e.check(req(),'192.0.2.1')['decision'],'allow')
        self.assertEqual(e.check(req('b'),'192.0.2.1')['decision'],'allow')
        self.assertEqual(e.check(req('c'),'192.0.2.2')['decision'],'capacity_exceeded')
    def test_http_restart_preserves_limit(self):
        def server():
            httpd=ThreadingHTTPServer(('127.0.0.1',0),Handler);httpd.engine=self.engine(max_requests=1)
            thread=threading.Thread(target=httpd.serve_forever,daemon=True);thread.start()
            return httpd,thread
        def request(httpd):
            con=http.client.HTTPConnection('127.0.0.1',httpd.server_address[1],timeout=5)
            con.request('POST','/api/v2/check',json.dumps(req()),{'Content-Type':'application/json'})
            result=con.getresponse();status=result.status;body=json.loads(result.read());con.close();return status,body
        s,t=server()
        try:self.assertEqual(request(s)[0],200)
        finally:s.shutdown();s.server_close();t.join()
        s,t=server()
        try:self.assertEqual(request(s)[0],429)
        finally:s.shutdown();s.server_close();t.join()
    def test_malformed_requests_share_ip_bucket(self):
        e=self.engine(max_requests=1)
        self.assertIsNone(e.reject_malformed('192.0.2.1'))
        self.assertEqual(e.check(req(),'192.0.2.1')['decision'],'rate_limited')
    def test_messages_can_change_without_resetting_persisted_limits(self):
        first=self.engine(max_requests=1)
        self.assertEqual(first.check({'signals':{'machine_id':tok('m')}},'192.0.2.1')['decision'],'allow')
        changed=self.engine(max_requests=1,messages={'rate_limited':'Custom wait message.'})
        result=changed.check({'signals':{'machine_id':tok('m')}},'192.0.2.1')
        self.assertEqual(result['decision'],'rate_limited'); self.assertEqual(result['message'],'Custom wait message.')
    def test_forged_signal_can_exhaust_victim_bucket(self):
        e=self.engine(max_requests=2); data={'signals':{'machine_id':synthetic_signal('machine_id','victim')}}
        for ip in ('192.0.2.1','192.0.2.2'): self.assertEqual(e.check(data,ip)['decision'],'allow')
        self.assertEqual(e.check(data,'198.51.100.1')['decision'],'rate_limited')
    def test_memory_and_database_modelled_history_and_capacity_agree(self):
        rng = random.Random(223711)
        p = policy('standard', override={'max_requests':10000, 'history_seconds':60, 'window_seconds':3})
        memory = Engine(p, secret=SECRET, clock=lambda:self.now[0], max_entries=12)
        db = SQLiteEngine(self.path, p, SECRET, clock=lambda:self.now[0], max_entries=12)
        payloads = []
        for step in range(450):
            self.now[0] += rng.choice((0, 1, 2, 10))
            if payloads and rng.random() < .3:
                payload, ip = rng.choice(payloads)
            else:
                signals = {'machine_id':synthetic_signal('machine_id', str(rng.randrange(10)))}
                if rng.random() < .6: signals['product_uuid'] = synthetic_signal('product_uuid', str(rng.randrange(6)))
                if rng.random() < .3: signals['board_serial'] = synthetic_signal('board_serial', str(rng.randrange(5)))
                payload, ip = {'signals':signals}, '192.0.2.' + str(rng.randrange(1, 9))
                payloads.append((payload, ip))
            a, b = memory.check(payload, ip), db.check(payload, ip)
            self.assertEqual(a, b, 'divergence at synthetic step ' + str(step))

    def test_memory_and_database_agree(self):
        p=policy(override={'max_requests':100})
        memory=Engine(p,secret=SECRET,clock=lambda:self.now[0])
        db=SQLiteEngine(self.path,p,SECRET,clock=lambda:self.now[0])
        requests=[(req(), '192.0.2.1'),(req('b'),'198.51.100.1'),({'account':'c','signals':{'machine_id':tok('different')}},'192.0.2.1'),(req('d',product_uuid=synthetic_signal('product_uuid','uuid')),'203.0.113.5')]
        for data,ip in requests:
            a,b=memory.check(data,ip),db.check(data,ip)
            for k in ('decision','relation','matched_signals'): self.assertEqual(a[k],b[k])

if __name__=='__main__': unittest.main(verbosity=2)
