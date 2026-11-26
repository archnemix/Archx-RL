"""Synthetic explicit idle maintenance; no claims about backup/WAL erasure."""
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'demo'))
from engine import Engine, policy
from sqlite_engine import SQLiteEngine
from signal_validation import synthetic_signal
from maintenance import IdleCleanup

SECRET=b'synthetic-idle-maintenance-secret-1234567'

def body(i): return {'signals':{'machine_id':synthetic_signal('machine_id',str(i))}}

def counts(e,mode):
    if mode=='memory': return len(e.windows),len(e.observations)
    with sqlite3.connect(e.db_path) as con:
        return tuple(con.execute('SELECT count(*) FROM '+table).fetchone()[0] for table in ('windows','observations'))

class CleanupTests(unittest.TestCase):
    def test_idle_batches_expire_only_old_rows_in_both_engines(self):
        for mode in ('memory','sqlite'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                now=[1000]; settings=policy(override={'max_requests':1000,'window_seconds':60,'history_seconds':60})
                e=Engine(settings,secret=SECRET,clock=lambda:now[0]) if mode=='memory' else SQLiteEngine(Path(tmp)/'state.sqlite',settings,SECRET,clock=lambda:now[0])
                for i in range(130): self.assertEqual(e.check(body(i),'192.0.2.1')['decision'],'allow')
                now[0]=1030
                self.assertEqual(e.check(body('live'),'198.51.100.1')['decision'],'allow')
                before=counts(e,mode); self.assertEqual(before,(133,131))
                now[0]=1060
                for _ in range(3):
                    pending=e.cleanup_expired(); after=counts(e,mode)
                    self.assertLessEqual(before[0]-after[0],64); self.assertLessEqual(before[1]-after[1],64)
                    before=after
                self.assertEqual(before,(2,1)); self.assertEqual(pending,{'windows_pending':False,'observations_pending':False})
                self.assertEqual(e.check(body('live'),'198.51.100.1')['relation'],'related')

    def test_sqlite_fault_rolls_back_batch_and_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            now=[1000]; e=SQLiteEngine(Path(tmp)/'state.sqlite',policy(override={'history_seconds':60}),SECRET,clock=lambda:now[0])
            e.check(body('old'),'192.0.2.1'); before=counts(e,'sqlite'); now[0]=1100
            with patch.object(e,'_prune_observations',side_effect=sqlite3.OperationalError('synthetic private failure')):
                with self.assertRaises(sqlite3.OperationalError): e.cleanup_expired()
            self.assertEqual(counts(e,'sqlite'),before)
            self.assertEqual(e.cleanup_expired(),{'windows_pending':False,'observations_pending':False})
            self.assertEqual(counts(e,'sqlite'),(0,0))

    def test_concurrent_maintenance_is_serialized_and_invalid_clock_fails(self):
        for mode in ('memory','sqlite'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                now=[1000]; settings=policy(override={'max_requests':1000,'window_seconds':1,'history_seconds':60})
                e=Engine(settings,secret=SECRET,clock=lambda:now[0]) if mode=='memory' else SQLiteEngine(Path(tmp)/'state.sqlite',settings,SECRET,clock=lambda:now[0])
                for i in range(100): e.check(body(i),'192.0.2.1')
                now[0]=1060
                with ThreadPoolExecutor(max_workers=8) as pool: list(pool.map(lambda _:e.cleanup_expired(),range(8)))
                self.assertEqual(counts(e,mode),(0,0))
                now[0]=float('nan')
                with self.assertRaises(ValueError): e.cleanup_expired()

    def test_worker_starts_runs_retries_and_stops_without_leaking_errors(self):
        ready=threading.Event()
        class Fake:
            calls=0
            def cleanup_expired(self):
                self.calls+=1
                if self.calls==1: raise RuntimeError('secret identifier')
                ready.set(); return {'windows_pending':False,'observations_pending':False}
        worker=IdleCleanup(Fake(),.1)
        self.assertFalse(worker.status()['started'])
        worker.start()
        self.assertTrue(ready.wait(3))
        self.assertTrue(worker.stop(2))
        status=worker.status(); self.assertGreaterEqual(status['cycles'],2)
        self.assertFalse(status['last_failed']); self.assertFalse(status['alive'])
        self.assertNotIn('secret identifier',str(status))
        with self.assertRaises(RuntimeError): worker.start()
        for value in (0,True,float('nan'),86401):
            with self.assertRaises(ValueError): IdleCleanup(Fake(),value)
        for value in (-1,301,True,float('inf')):
            with self.assertRaises(ValueError): worker.stop(value)

    def test_stop_reports_stalled_work_without_claiming_cancellation(self):
        entered=threading.Event(); release=threading.Event()
        class Stalled:
            def cleanup_expired(self): entered.set(); release.wait(3); return {}
        worker=IdleCleanup(Stalled(),.1); worker.start(); self.assertTrue(entered.wait(2))
        self.assertFalse(worker.stop(0)); release.set(); self.assertTrue(worker.stop(2))

if __name__=='__main__': unittest.main(verbosity=2)
