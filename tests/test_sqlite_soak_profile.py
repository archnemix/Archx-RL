"""Short invariant smoke for the timed synthetic profile, not a durability proof."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from sqlite_soak_profile import run

class SQLiteSoakTests(unittest.TestCase):
    def test_mixed_contention_faults_and_recovery(self):
        r=run(seconds=1,nonce_count=8)
        w=r['aggregate']['writer']; attempts=r['writer_attempts']
        self.assertGreater(attempts,0)
        self.assertEqual(w.get('allow',0),min(100,attempts))
        self.assertEqual(w.get('rate_limited',0),max(0,attempts-100))
        self.assertEqual(r['window_counts'],[attempts,attempts])
        self.assertEqual(r['aggregate']['replay'],{'consumed':8,'rejected':8})
        fault=r['aggregate']['fault']
        self.assertGreater(fault['storage_error'],0)
        self.assertEqual(fault['storage_error'],fault['replay_unavailable'])
        self.assertEqual(set(fault),{'storage_error','replay_unavailable'})
        self.assertEqual(r['pending_before_recovery'],1)
        self.assertTrue(r['reserved_consumed_after_fault'])
        self.assertFalse(r['reserved_replay_after_recovery'])
        self.assertGreater(r['aggregate']['reader']['reads'],0)
        for name,plan in r['query_plans'].items():
            self.assertTrue(any('INDEX' in line for line in plan),name)
        self.assertEqual(len(r['passive_checkpoint_while_pinned']),3)

    def test_invalid_configuration(self):
        for seconds, count in ((0,8),(31,8),(True,8),(1,True),(1,1)):
            with self.assertRaises(ValueError): run(seconds,count)

if __name__=='__main__': unittest.main(verbosity=2)
