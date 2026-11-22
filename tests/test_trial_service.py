import json
import multiprocessing
import os
import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'demo'))
from engine import Engine, policy
from signal_validation import synthetic_signal
from sqlite_engine import SQLiteEngine
from trial_service import TrialService

SECRET=b'synthetic-trial-test-secret-0123456789'

def activate_in_child(db, output, index):
    try:
        engine=SQLiteEngine(db,policy(override={'max_requests':100}),SECRET,clock=lambda:1700000000.0)
        service=TrialService(engine,signal_retention_seconds=60)
        result=service.activate(authenticated_account='same-account',offer='same-offer',idempotency_key='key-'+str(index),
                                signals={'machine_id':synthetic_signal('machine_id','same-device')},peer='192.0.2.1')
        output.put(result)
    except Exception as exc:
        output.put({'decision':'error','reason':str(exc)})

class TrialTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.db=str(Path(self.tmp.name)/'state.sqlite')
        self.now=[1700000000.0]
        self.settings=policy(override={'max_requests':100})
        self.engine=SQLiteEngine(self.db,self.settings,SECRET,clock=lambda:self.now[0])
        self.service=TrialService(self.engine,signal_retention_seconds=60)
    def tearDown(self): self.tmp.cleanup()
    def act(self, account='user-a', offer='trial-a', idem='action-a', seed='device-a', peer='192.0.2.1', service=None, signals=None):
        if signals is None: signals={'machine_id':synthetic_signal('machine_id',seed)}
        return (service or self.service).activate(authenticated_account=account,offer=offer,idempotency_key=idem,signals=signals,peer=peer)
    def test_activation_retry_conflicts_and_account_uniqueness(self):
        self.assertEqual(self.act()['decision'],'activated')
        self.assertEqual(self.act(peer='198.51.100.1')['reason'],'idempotent_replay')
        self.assertEqual(self.act(seed='other')['reason'],'idempotency_key_reused')
        self.assertEqual(self.act(offer='other')['reason'],'idempotency_key_reused')
        self.assertEqual(self.act(idem='new-key')['decision'],'already_used')
        with sqlite3.connect(self.db) as db: self.assertEqual(db.execute('SELECT count(*) FROM trial_entitlements').fetchone()[0],1)
    def test_status_tracks_authoritative_local_entitlement(self):
        self.assertEqual(self.service.status(authenticated_account='user-a',offer='trial-a')['decision'],'not_active')
        self.act()
        self.assertEqual(self.service.status(authenticated_account='user-a',offer='trial-a')['decision'],'active')
        self.assertEqual(self.service.status(authenticated_account='user-b',offer='trial-a')['decision'],'not_active')
        self.assertEqual(self.service.status(authenticated_account='user-a',offer='trial-b')['decision'],'not_active')
        os.unlink(self.db)
        self.assertEqual(self.service.status(authenticated_account='user-a',offer='trial-a')['decision'],'storage_error')
    def test_device_related_only_actual_activations_and_only_same_offer(self):
        # An earlier request alone cannot poison the successful-activation table.
        self.engine.check({'account':'fake','signals':{'machine_id':synthetic_signal('machine_id','device-b')}},'203.0.113.1')
        self.assertEqual(self.act(seed='device-b')['decision'],'activated')
        self.assertEqual(self.act(account='user-b',idem='b',seed='device-b',peer='198.51.100.1')['decision'],'review')
        self.assertEqual(self.act(account='user-b',idem='c',seed='device-b',offer='another',peer='198.51.100.1')['decision'],'activated')
        self.assertEqual(self.act(account='user-c',idem='d',seed='device-c')['decision'],'activated') # shared IP alone
    def test_expired_signal_does_not_block_new_activation(self):
        self.assertEqual(self.act()['decision'],'activated')
        self.now[0]+=61
        self.assertEqual(self.act(account='user-b',idem='b',peer='198.51.100.1')['decision'],'activated')
        self.assertEqual(self.act(idem='new')['decision'],'already_used') # entitlement stays
    def test_absent_required_and_timezone_do_not_activate(self):
        self.assertEqual(self.act(signals={})['reason'],'missing_required')
        with self.assertRaises(ValueError): self.act(signals={'machine_id':'1'})
        with sqlite3.connect(self.db) as db: self.assertEqual(db.execute('SELECT count(*) FROM trial_entitlements').fetchone()[0],0)
    def test_concurrent_activations_are_atomic(self):
        services=[TrialService(SQLiteEngine(self.db,self.settings,SECRET,clock=lambda:self.now[0]),signal_retention_seconds=60) for _ in range(4)]
        with ThreadPoolExecutor(max_workers=12) as pool:
            out=list(pool.map(lambda i:self.act(idem='key-'+str(i),service=services[i%4]),range(20)))
        self.assertEqual(sum(x['reason']=='created' for x in out),1)
        self.assertEqual(sum(x['decision']=='already_used' for x in out),19)
    def test_concurrent_processes_activate_once(self):
        ctx=multiprocessing.get_context('spawn'); queue=ctx.Queue()
        children=[ctx.Process(target=activate_in_child,args=(self.db,queue,i)) for i in range(4)]
        for child in children: child.start()
        out=[queue.get(timeout=30) for _ in children]
        for child in children:
            child.join(30); self.assertEqual(child.exitcode,0)
        queue.close()
        self.assertEqual(sum(x['reason']=='created' for x in out),1,out)
        self.assertEqual(sum(x['decision']=='already_used' for x in out),3,out)
    def test_concurrent_related_accounts_reviewed(self):
        with ThreadPoolExecutor(max_workers=10) as pool:
            out=list(pool.map(lambda i:self.act(account='user-'+str(i),idem='key-'+str(i),peer='192.0.2.'+str(i+1)),range(10)))
        self.assertEqual(sum(x['decision']=='activated' for x in out),1)
        self.assertEqual(sum(x['decision']=='review' for x in out),9)
    def test_restart_and_policy_compatibility(self):
        self.act()
        service=TrialService(SQLiteEngine(self.db,self.settings,SECRET,clock=lambda:self.now[0]),signal_retention_seconds=60)
        self.assertEqual(self.act(service=service)['reason'],'idempotent_replay')
        with self.assertRaisesRegex(ValueError,'Trial policy'): TrialService(self.engine,related_action='observe',signal_retention_seconds=60)
    def test_missing_table_does_not_reinitialize_existing_ledger(self):
        self.act()
        with sqlite3.connect(self.db) as db: db.execute('DROP TABLE trial_signals')
        with self.assertRaisesRegex(ValueError,'inconsistent'): TrialService(self.engine,signal_retention_seconds=60)
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM trial_entitlements').fetchone()[0],1)
    def test_failure_rolls_back_rate_and_entitlement(self):
        with sqlite3.connect(self.db) as db: db.execute('DROP TABLE trial_signals')
        self.assertEqual(self.act()['decision'],'storage_error')
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM trial_entitlements').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM windows').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT count(*) FROM observations').fetchone()[0],0)
    def test_no_raw_identifiers_in_database(self):
        machine=synthetic_signal('machine_id','unique-value')
        self.act(account='sensitive-account',offer='sensitive-offer',idem='sensitive-idempotency',signals={'machine_id':machine})
        with sqlite3.connect(self.db) as db: dump=''.join(db.iterdump())
        for value in ('sensitive-account','sensitive-offer','sensitive-idempotency',machine,'192.0.2.1'): self.assertNotIn(value,dump)
    def test_fail_closed_capacity_and_database_removal(self):
        with self.assertRaises(ValueError): TrialService(self.engine,signal_retention_seconds=60,max_entitlements=1)
        os.unlink(self.db)
        self.assertEqual(self.act()['decision'],'storage_error')
    def test_entitlement_capacity_stops_new_activation(self):
        with tempfile.TemporaryDirectory() as root:
            e=SQLiteEngine(str(Path(root)/'cap.sqlite'),self.settings,SECRET,clock=lambda:self.now[0])
            service=TrialService(e,max_entitlements=1)
            self.assertEqual(self.act(service=service)['decision'],'activated')
            self.assertEqual(self.act(account='b',idem='b',seed='b',service=service)['decision'],'capacity_exceeded')
            self.assertEqual(self.act(service=service)['reason'],'idempotent_replay')
            with sqlite3.connect(e.db_path) as db: self.assertEqual(db.execute('SELECT count(*) FROM trial_entitlements').fetchone()[0],1)
    def test_observe_mode_allows_but_reports_match(self):
        with tempfile.TemporaryDirectory() as root:
            e=SQLiteEngine(str(Path(root)/'other.sqlite'),self.settings,SECRET,clock=lambda:self.now[0])
            service=TrialService(e,related_action='observe')
            self.assertEqual(self.act(service=service)['decision'],'activated')
            out=self.act(account='other',idem='b',peer='198.51.100.1',service=service)
            self.assertEqual(out['decision'],'activated');self.assertTrue(out['prior_signal_match'])
    def test_idempotency_key_and_offer_validation(self):
        for bad in ('', 'x\nunsafe', 'x'*129):
            with self.assertRaises(ValueError): self.act(idem=bad)

class PoisonTests(unittest.TestCase):
    def test_replayed_victim_identifier_can_exhaust_unverified_signal_bucket(self):
        settings=policy(override={'max_requests':2})
        with tempfile.TemporaryDirectory() as root:
            engines=[Engine(settings,secret=SECRET,clock=lambda:1700000000),SQLiteEngine(str(Path(root)/'state.sqlite'),settings,SECRET,clock=lambda:1700000000)]
            for engine in engines:
                signal=synthetic_signal('machine_id','victim')
                for i in range(2):
                    self.assertEqual(engine.check({'account':'attacker','signals':{'machine_id':signal}},f'192.0.2.{i+1}')['decision'],'allow')
                self.assertEqual(engine.check({'account':'victim','signals':{'machine_id':signal}},'198.51.100.1')['decision'],'rate_limited')

if __name__=='__main__': unittest.main(verbosity=2)
