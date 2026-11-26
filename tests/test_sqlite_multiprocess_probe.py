"""Short synthetic contention smoke; does not replace sustained soak testing."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from sqlite_multiprocess_probe import run

class SQLiteMultiprocessProbeTests(unittest.TestCase):
    def test_mixed_workers_preserve_quota_and_single_use(self):
        result=run(30)
        self.assertEqual(result['journal'],'wal')
        self.assertEqual(result['aggregate']['writer'],{'allow':100,'rate_limited':20})
        self.assertEqual(result['aggregate']['reader'],{'reads':60})
        self.assertEqual(result['aggregate']['replay'],{'consumed':1,'rejected':1})
        self.assertEqual(result['window_counts'],[120,120])
        self.assertEqual(result['pending_challenges'],0)
        self.assertNotIn('192.0.2.1',str(result))

    def test_arguments(self):
        for bad in (True,0,1001,0.5):
            with self.assertRaises(ValueError): run(bad)

if __name__=='__main__': unittest.main(verbosity=2)
