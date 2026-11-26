"""Check measurement accounting and bounded recovery, never host latency budgets."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from expiry_benchmark import run
from cleanup_backlog_benchmark import run as run_both_cleanup


class ExpiryBenchmarkTests(unittest.TestCase):
    def test_backlog_batches_and_recovery(self):
        for population in (1, 64, 65, 150):
            with self.subTest(population=population):
                report = run(population, 3)
                self.assertEqual(report['expired_removed'], 3 * population)
                self.assertEqual(report['peak_observations'], population)
                self.assertEqual(report['peak_expiry_heap_entries'], population)
                self.assertEqual(report['max_removed_per_check'], min(population, 64))
                self.assertEqual(report['decisions']['allow'], 3)
                self.assertEqual(report['decisions'].get('capacity_exceeded', 0), 3 * ((population - 1) // 64))
                self.assertEqual(report['recovery_relations'], ['new'] * 3)
                timing = report['check_latency_ms']
                self.assertLessEqual(timing['p50'], timing['p95'])
                self.assertLessEqual(timing['p95'], timing['p99'])
                self.assertLessEqual(timing['p99'], timing['max'])
                self.assertNotIn('192.0.2.1', json.dumps(report))
                self.assertNotIn('synthetic-benchmark-only', json.dumps(report))

    def test_combined_backlog_measurements(self):
        for mode in ('memory', 'sqlite'):
            for size in (1, 64, 65, 150):
                with self.subTest(mode=mode, size=size):
                    report = run_both_cleanup(mode, size)
                    self.assertEqual(report['decisions']['allow'], 1)
                    self.assertEqual(report['decisions'].get('capacity_exceeded', 0), 2 * ((size - 1) // 64))
                    self.assertEqual(report['max_windows_removed_per_check'], min(size,64))
                    self.assertEqual(report['max_observations_removed_per_check'], min(size,64))
                    self.assertEqual(report['recovery_relation'], 'new')
                    self.assertNotIn('192.0.2.1', json.dumps(report))
                    self.assertNotIn('synthetic-expiry-benchmark-secret', json.dumps(report))

    def test_invalid_args(self):
        for args in (['--population', '0'], ['--population', '10001'], ['--waves', '0'], ['--waves', '21']):
            result = subprocess.run([sys.executable, str(ROOT / 'tools/expiry_benchmark.py'), *args], capture_output=True)
            self.assertEqual(result.returncode, 2)


if __name__ == '__main__': unittest.main(verbosity=2)
