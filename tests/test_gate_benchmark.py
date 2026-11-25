"""Structural tests for the synthetic benchmark; never assert host performance."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
from gate_benchmark import measure, percentile, run


class BenchmarkTests(unittest.TestCase):
    def test_nearest_rank_percentile(self):
        self.assertIsNone(percentile([], .5))
        self.assertEqual(percentile([4_000_000,1_000_000,3_000_000,2_000_000], .5), 2)
        self.assertEqual(percentile([4_000_000,1_000_000,3_000_000,2_000_000], .99), 4)

    def test_each_mode_and_traffic_shape(self):
        for mode in ('memory', 'sqlite'):
            for shape in ('unique', 'shared-ip', 'duplicate'):
                with self.subTest(mode=mode, shape=shape):
                    report = run(mode, shape, 8, 20, 2, 4)
                    measurements = report['measurements']
                    self.assertEqual(measurements['requests'], 20)
                    self.assertEqual(sum(measurements['decisions'].values()), 20)
                    self.assertEqual(measurements['decisions']['allow'], 20)
                    self.assertEqual(measurements['exceptions'], 0)
                    self.assertLessEqual(measurements['peak_submitted_uncollected'], 4)
                    for metric in ('queue_wait_ms','gate_call_ms','submit_to_complete_ms'):
                        t = measurements[metric]
                        self.assertLessEqual(t['p50'], t['p95'])
                        self.assertLessEqual(t['p95'], t['p99'])
                        self.assertLessEqual(t['p99'], t['max'])
                    self.assertEqual(report['recovery']['at_capacity'], 'capacity_exceeded')
                    self.assertEqual(report['recovery']['after_expiry'], 'allow')
                    self.assertNotIn('2001:db8:', json.dumps(report))
                    self.assertNotIn('synthetic-secret', json.dumps(report))
                    self.assertTrue(any('no agreed performance budgets' in v for v in report['limitations']))

    def test_exception_count_is_sanitized(self):
        class Failing:
            def check(self, body, peer): raise RuntimeError('private benchmark exception marker')
        report = measure(Failing(), 11, 'unique', 2, 4)
        self.assertEqual(report['exceptions'], 11)
        self.assertEqual(report['decisions']['unexpected'], 11)
        self.assertLessEqual(report['peak_submitted_uncollected'], 4)
        self.assertNotIn('private benchmark exception marker', json.dumps(report))

    def test_invalid_cli_limits_rejected(self):
        for args in (['--workers','0'], ['--population','5001'], ['--requests','0'],
                     ['--workers','4','--max-outstanding','3']):
            p = subprocess.run([sys.executable, str(ROOT/'tools/gate_benchmark.py'), *args], capture_output=True)
            self.assertEqual(p.returncode, 2)


if __name__ == '__main__': unittest.main(verbosity=2)
