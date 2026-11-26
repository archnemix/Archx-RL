"""Structural and behavioral tests for synthetic benchmark, not timing SLOs."""
import importlib.util
import json
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from traffic_matrix_benchmark import run, run_case

class TrafficMatrixTests(unittest.TestCase):
    @unittest.skipUnless(importlib.util.find_spec('nacl'), 'install demo/requirements-secure.txt')
    def test_matrix_decisions_accounting_and_recovery(self):
        report=run(3)
        self.assertEqual(len(report['cases']),48)
        self.assertEqual(len({(r['mode'],r['state'],r['transport'],r['traffic']) for r in report['cases']}),48)
        for row in report['cases']:
            expected=('rate_limited' if row['traffic']=='rate_limited' else 'invalid' if row['traffic']=='invalid'
                      else 'capacity_exceeded' if row['state']=='saturated' else 'allow')
            self.assertEqual(row['outcomes'],{expected:3},row)
            self.assertEqual(row['errors'],0)
            self.assertEqual(row['generator_max_outstanding'],1)
            self.assertEqual(row['recovery_after_synthetic_expiry'],'allow')
            if row['transport']=='http':
                self.assertGreaterEqual(row['handler_peak_at_start'],1)
                self.assertEqual(row['configured_listen_backlog'],64)
                if row['listen_queue_samples']:
                    self.assertGreaterEqual(row['listen_queue_max_observed'],0)
            else:
                self.assertIsNone(row['listen_queue_samples'])
            self.assertLessEqual(row['latency_ms']['p95'],row['latency_ms']['max'])
        self.assertNotIn('127.0.0.1',json.dumps(report))
        self.assertTrue(any('not measured' in x for x in report['limitations']))

    def test_rejects_bad_arguments(self):
        for args in (('bad','empty','http','allow',1),('memory','unknown','http','allow',1),
                     ('memory','empty','http','bad',1),('memory','empty','direct','allow',0),
                     ('memory','empty','direct','allow',True)):
            with self.assertRaises(ValueError): run_case(*args)

if __name__=='__main__': unittest.main(verbosity=2)
