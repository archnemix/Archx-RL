"""Structural and no-excess-admission checks, never host-specific latency budgets."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from contention_benchmark import run
from index_match_benchmark import run as run_index_comparison


class ContentionBenchmarkTests(unittest.TestCase):
    def test_hot_key_serialization_both_modes(self):
        for mode in ('memory', 'sqlite'):
            for workers in (1, 4):
                with self.subTest(mode=mode, workers=workers):
                    report = run(mode, workers, 15, 7)
                    self.assertEqual(report['decisions'], {'allow':7, 'rate_limited':workers * 15 - 7})
                    for field in ('check_latency_ms', 'serialization_wait_ms', 'serialization_held_ms'):
                        metrics = report[field]
                        self.assertLessEqual(metrics['p50'], metrics['p95'])
                        self.assertLessEqual(metrics['p95'], metrics['p99'])
                        self.assertLessEqual(metrics['p99'], metrics['max'])
                    self.assertNotIn('192.0.2.1', json.dumps(report))
                    self.assertNotIn('synthetic-contention-only', json.dumps(report))

    def test_sparse_index_comparison(self):
        report = run_index_comparison(128, 7)
        self.assertEqual(report['population'], 128)
        self.assertEqual(report['matching_observations'], 1)
        for field in ('linear_match_ms', 'indexed_match_ms'):
            self.assertLessEqual(report[field]['p50'], report[field]['p99'])
        for population, samples in ((0, 1), (10001, 1), (1, 0), (1, 1001)):
            with self.assertRaises(ValueError): run_index_comparison(population, samples)

    def test_invalid_parameters(self):
        for args in (['--workers', '0'], ['--workers', '17'], ['--per-worker', '0'], ['--quota', '10001']):
            result = subprocess.run([sys.executable, str(ROOT / 'tools/contention_benchmark.py'), *args], capture_output=True)
            self.assertEqual(result.returncode, 2)


if __name__ == '__main__': unittest.main(verbosity=2)
