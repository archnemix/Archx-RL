"""Synthetic IP/device quota thresholds; no identity or recovery guarantee."""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'demo'))
from engine import Engine, policy
from sqlite_engine import SQLiteEngine
from service import RequestService
from signal_validation import synthetic_signal
sys.path.insert(0,str(ROOT/'tools'))
from nat_quota_simulation import run as simulate_nat

SECRET=b'synthetic-separate-quota-test-secret-123'

def body(seed): return {'signals':{'machine_id':synthetic_signal('machine_id',seed)}}

class QuotaTests(unittest.TestCase):
    def test_validation_and_defaults(self):
        for key in ('ip_max_requests','device_max_requests'):
            for value in (False,0,10001,1.2,'2'):
                with self.subTest(key=key,value=value), self.assertRaises(ValueError): policy(override={key:value})
        settings=policy(override={'max_requests':7})
        e=Engine(settings,secret=SECRET)
        self.assertEqual(e._quota('ip'),7); self.assertEqual(e._quota('machine_id'),7)
        self.assertNotIn('ip_max_requests',settings) # existing persisted policy hashes stay compatible

    def test_ip_device_limits_and_service_precharge_parity(self):
        for mode in ('memory','sqlite'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                p=policy(override={'max_requests':5,'ip_max_requests':3,'device_max_requests':2})
                e=Engine(p,secret=SECRET,clock=lambda:1000) if mode=='memory' else SQLiteEngine(Path(tmp)/'state.sqlite',p,SECRET,clock=lambda:1000)
                svc=RequestService(e)
                # Repeated device behind different IPs hits device threshold.
                self.assertEqual(svc.check(body('same'),'192.0.2.1')['decision'],'allow')
                self.assertEqual(svc.check(body('same'),'192.0.2.2')['decision'],'allow')
                self.assertEqual(svc.check(body('same'),'192.0.2.3')['decision'],'rate_limited')
                # A shared IP limits a third device only after 3 precharges.
                self.assertEqual(svc.check(body('nat1'),'198.51.100.1')['decision'],'allow')
                self.assertEqual(svc.check(body('nat2'),'198.51.100.1')['decision'],'allow')
                self.assertEqual(svc.check(body('nat3'),'198.51.100.1')['decision'],'allow')
                self.assertEqual(svc.check(body('nat4'),'198.51.100.1')['decision'],'rate_limited')
                # Invalid requests also consume the IP threshold.
                for _ in range(3): self.assertIsNone(e.reject_malformed('203.0.113.1'))
                self.assertEqual(e.reject_malformed('203.0.113.1')['decision'],'rate_limited')

    def test_synthetic_shared_ip_simulation(self):
        for mode in ('memory','sqlite'):
            report=simulate_nat(mode)
            self.assertEqual([r['allowed'] for r in report['scenarios']],[5,15,30])
            self.assertEqual([r['rate_limited'] for r in report['scenarios']],[25,15,0])
            self.assertTrue(any('not a real-world' in item for item in report['limitations']))

    def test_sqlite_policy_changes_fail_closed_on_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'state.sqlite'
            original=policy(override={'max_requests':5,'ip_max_requests':3,'device_max_requests':2})
            e=SQLiteEngine(path,original,SECRET,clock=lambda:1000)
            self.assertEqual(e.check(body('same'),'192.0.2.1')['decision'],'allow')
            again=SQLiteEngine(path,original,SECRET,clock=lambda:1000)
            self.assertEqual(again.check(body('same'),'192.0.2.1')['decision'],'allow')
            self.assertEqual(again.check(body('same'),'192.0.2.1')['decision'],'rate_limited')
            changed=policy(override={'max_requests':5,'ip_max_requests':4,'device_max_requests':2})
            with self.assertRaisesRegex(ValueError,'policy'): SQLiteEngine(path,changed,SECRET)


if __name__=='__main__': unittest.main(verbosity=2)
