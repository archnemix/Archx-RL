"""Deterministic model checks for bounded synthetic observation indexing."""
import random
import sys
import unittest
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from observation_index import ObservationIndex
from engine import Engine, policy
from signal_validation import synthetic_signal


class Oracle:
    """Simple linear reference; independent of index implementation."""
    def __init__(self, capacity):
        self.capacity = capacity
        self.records = []  # [expiry, snapshot]

    def prune(self, now):
        self.records = [r for r in self.records if r[0] > now]

    def match(self, tokens, threshold):
        best = []
        possible = False
        for _, previous in self.records:
            matching = [k for k, v in tokens.items() if previous.get(k) == v]
            if len(matching) > len(best):
                best = matching
            possible |= len(set(tokens) & set(previous)) >= threshold
        return ('related' if len(best) >= threshold else
                'new' if not self.records else
                'below_threshold' if possible else 'inconclusive'), best

    def enroll(self, tokens, expires):
        for row in self.records:
            if row[1] == tokens:
                row[0] = expires
                return None
        if len(self.records) == self.capacity:
            return min(row[0] for row in self.records)
        self.records.append([expires, dict(tokens)])
        return None


class ObservationTests(unittest.TestCase):
    def assert_consistent(self, index):
        self.assertLessEqual(len(index.records), index.capacity)
        self.assertEqual(len(index.records), len(index.snapshots))
        self.assertEqual(sum(index.shapes.values()), len(index.records))
        self.assertEqual(sum(map(len, index.postings.values())),
                         sum(len(tokens) for _, tokens in index.records.values()))
        for obs_id, (_, tokens) in index.records.items():
            self.assertEqual(index.snapshots[tuple(sorted(tokens.items()))], obs_id)
            for pair in tokens.items(): self.assertIn(obs_id, index.postings[pair])
        for pair, ids in index.postings.items():
            self.assertTrue(ids)
            for obs_id in ids: self.assertIn(pair, index.records[obs_id][1].items())

    def test_randomized_against_linear_oracle(self):
        rng = random.Random(874563)
        for capacity in (1, 3, 11, 43):
            index, oracle = ObservationIndex(capacity), Oracle(capacity)
            now = 0
            for step in range(2500):
                now += rng.choice((0, 0, 0, 1, 2, 20))
                index.prune(now); oracle.prune(now)
                if oracle.records and rng.random() < 0.4:
                    tokens = dict(rng.choice(oracle.records)[1])
                    if rng.random() < .35: tokens['ip'] = 'ip' + str(rng.randrange(6))
                else:
                    names = rng.sample(['machine_id', 'product_uuid', 'board_serial', 'ip'], rng.randrange(1, 5))
                    tokens = {name:'v'+str(rng.randrange(7)) for name in names}
                threshold = rng.randrange(1, 6)
                self.assertEqual(index.match(tokens, threshold), oracle.match(tokens, threshold), (capacity, step))
                expires = now + rng.randrange(1, 35)
                self.assertEqual(index.enroll(tokens, expires), oracle.enroll(tokens, expires), (capacity, step))
                self.assert_consistent(index)

    def test_no_cross_observation_aggregation_and_ties(self):
        index = ObservationIndex(4)
        index.enroll({'machine_id':'a','product_uuid':'x'}, 100)
        index.enroll({'machine_id':'b','product_uuid':'y'}, 100)
        self.assertEqual(index.match({'machine_id':'a','product_uuid':'y'}, 2), ('below_threshold',['machine_id']))
        self.assertEqual(index.match({'product_uuid':'y','machine_id':'a'}, 2), ('below_threshold',['machine_id']))

    def test_capacity_refresh_and_expiry(self):
        index = ObservationIndex(2)
        a, b, c = {'ip':'a'}, {'ip':'b'}, {'ip':'c'}
        self.assertIsNone(index.enroll(a, 10)); self.assertIsNone(index.enroll(b, 20))
        self.assertEqual(index.enroll(c, 40), 10)
        self.assertIsNone(index.enroll(a, 30))
        self.assertEqual(index.enroll(c, 40), 20)
        index.prune(20)
        self.assertIsNone(index.enroll(c, 40)); self.assertEqual(len(index), 2)
        self.assertEqual(index.match(b, 1)[0], 'below_threshold')
        index.prune(40); self.assertEqual(len(index), 0)
        self.assertEqual(index.postings, {}); self.assertEqual(index.snapshots, {}); self.assertEqual(index.shapes, {})

    def test_concurrent_duplicate_requests_keep_one_snapshot(self):
        e = Engine(policy(override={'max_requests':1000}), secret=b'synthetic', clock=lambda:1000, max_entries=16)
        data = {'signals':{'machine_id':synthetic_signal('machine_id', 'model')}}
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: e.check(data, '192.0.2.1'), range(300)))
        self.assertEqual(sum(result['relation'] == 'new' for result in results), 1)
        self.assertEqual(sum(result['relation'] == 'related' for result in results), 299)
        self.assertEqual(len(e.observations), 1)
        self.assert_consistent(e.observations)

    def test_history_capacity_denies_without_eviction_and_retry(self):
        now = [1000]
        e = Engine(policy(override={'max_requests':100,'window_seconds':1,'history_seconds':60}), secret=b'synthetic', clock=lambda:now[0], max_entries=3)
        entries = [({'signals':{'machine_id':synthetic_signal('machine_id', str(i))}}, f'192.0.2.{i+1}') for i in range(4)]
        for data, ip in entries[:3]:
            self.assertEqual(e.check(data, ip)['decision'], 'allow'); now[0] += 2
        data, ip = entries[3]
        denied = e.check(data, ip)
        self.assertEqual(denied['decision'], 'capacity_exceeded'); self.assertEqual(denied['retry_after_seconds'], 54)
        self.assertEqual(len(e.observations), 3)
        now[0] += 2
        self.assertEqual(e.check(*entries[0])['relation'], 'related')
        now[0] = 1063
        self.assertEqual(e.check(data, ip)['decision'], 'allow')
        self.assert_consistent(e.observations)

    def test_invalid_capacity(self):
        for capacity in (0, -1, True, 1.0):
            with self.assertRaises(ValueError): ObservationIndex(capacity)


if __name__ == '__main__': unittest.main(verbosity=2)
