"""Deterministic reference-model traces for the prototype's two backends.

Synthetic single-threaded evidence, not a distributed or production claim.
The reference uses semantic tuples, not production HMACs or database queries.
"""
import ipaddress
import math
import random
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import Engine, policy
from signal_validation import synthetic_signal
from sqlite_engine import SQLiteEngine

SECRET = b'fixed-synthetic-limiter-model-secret-only'


class Reference:
    def __init__(self, settings, capacity):
        self.p = settings
        self.capacity = capacity
        self.windows = {}
        self.observations = []  # [expiry, ordered list of (name, semantic value)]

    @staticmethod
    def ip(peer):
        value = ipaddress.ip_address(peer)
        return str(value.ipv4_mapped or value) if isinstance(value, ipaddress.IPv6Address) else str(value)

    def prune(self, now, history=False):
        self.windows = {k: v for k, v in self.windows.items()
                        if v[0] + self.p['window_seconds'] > now}
        if history:
            self.observations = [row for row in self.observations if row[0] > now]

    def charge(self, pairs, now, precharged=False):
        # Distinct semantic identities cannot collide in this reference; the
        # production HMAC collision rule is covered separately by unit tests.
        limits = {}
        for name, value in pairs:
            if precharged and name == 'ip': continue
            setting = 'ip_max_requests' if name == 'ip' else 'device_max_requests'
            limits[(name, value)] = self.p.get(setting, self.p['max_requests'])
        if len(self.windows) + sum(key not in self.windows for key in limits) > self.capacity:
            return ('capacity_exceeded', self.p['window_seconds'])
        retry = 0
        challenge = False
        for key, limit in limits.items():
            start, count = self.windows.get(key, (now, 0))
            count += 1
            self.windows[key] = (start, count)
            if count > limit: retry = max(retry, math.ceil(self.p['window_seconds'] - (now - start)))
            if key[0] == 'ip' and self.p.get('ip_challenge_after', limit) < count:
                challenge = True
        if retry: return ('rate_limited', retry)
        if challenge: return ('challenge', None)
        return None

    def malformed(self, peer, now):
        self.prune(now)
        return self.charge([('ip', self.ip(peer))], now)

    def reset(self, peer):
        key = ('ip', self.ip(peer))
        return self.windows.pop(key, None) is not None

    def check(self, raw, peer, now, precharged=False):
        self.prune(now, history=True)
        pairs = list(raw['signals'].items()) + [('ip', self.ip(peer))]
        failure = self.charge(pairs, now, precharged)
        if failure: return failure + (None, None)
        if 'machine_id' not in raw['signals']: return ('invalid', None, None, None)
        # The oldest observation wins a tie; matching never combines records.
        matches = [[name for name, value in pairs if (name, value) in snapshot]
                   for _, snapshot in self.observations]
        best = max(matches, key=len, default=[])
        if len(best) >= self.p['min_matches']:
            relation = 'related'
        elif not self.observations:
            relation = 'new'
        elif any(len({name for name, _ in pairs} & {name for name, _ in snapshot}) >= self.p['min_matches']
                 for _, snapshot in self.observations):
            relation = 'below_threshold'
        else:
            relation = 'inconclusive'
        canonical = frozenset(pairs)
        existing = next((row for row in self.observations if frozenset(row[1]) == canonical), None)
        if existing is not None:
            existing[0] = now + self.p['history_seconds']
        elif len(self.observations) >= self.capacity:
            earliest = min(row[0] for row in self.observations)
            return ('capacity_exceeded', max(1, math.ceil(earliest - now)), None, None)
        else:
            self.observations.append([now + self.p['history_seconds'], pairs])
        return ('allow', 0, relation, best)


def fields(result):
    if result is None: return None
    return (result['decision'], result.get('retry_after_seconds'),
            result.get('relation') if result['decision'] == 'allow' else None,
            result.get('matched_signals'))


class ModelTests(unittest.TestCase):
    def test_expiry_capacity_and_longest_retry_boundaries(self):
        settings = policy(override={'max_requests': 1, 'window_seconds': 10, 'history_seconds': 60})
        clock = [1000.0]
        with tempfile.TemporaryDirectory() as tmp:
            engines = [Engine(settings, SECRET, clock=lambda: clock[0], max_entries=2),
                       SQLiteEngine(Path(tmp) / 'state.sqlite', settings, SECRET,
                                    clock=lambda: clock[0], max_entries=2)]
            a = {'signals': {'machine_id': synthetic_signal('machine_id', 'a')}}
            b = {'signals': {'machine_id': synthetic_signal('machine_id', 'b')}}
            for e in engines: self.assertEqual(e.check(a, '192.0.2.1')['decision'], 'allow')
            # At capacity a new device cannot partially charge the existing IP.
            for e in engines: self.assertEqual(e.check(b, '192.0.2.1')['decision'], 'capacity_exceeded')
            for e in engines: self.assertEqual(e.check(a, '192.0.2.1')['retry_after_seconds'], 10)
            clock[0] += 9.25
            for e in engines: self.assertEqual(e.check(a, '192.0.2.1')['retry_after_seconds'], 1)
            clock[0] += 0.75  # exact expiration of the original fixed window
            for e in engines: self.assertEqual(e.check(a, '192.0.2.1')['decision'], 'allow')

    def test_longest_retry_when_bucket_starts_differ(self):
        settings = policy(override={'max_requests': 1, 'window_seconds': 10, 'history_seconds': 60})
        clock = [1000.0]
        with tempfile.TemporaryDirectory() as tmp:
            engines = [Engine(settings, SECRET, clock=lambda: clock[0]),
                       SQLiteEngine(Path(tmp) / 'state.sqlite', settings, SECRET, clock=lambda: clock[0])]
            raw = {'signals': {'machine_id': synthetic_signal('machine_id', 'retry')}}
            for e in engines: self.assertEqual(e.check(raw, '192.0.2.1')['decision'], 'allow')
            clock[0] += 3
            for e in engines: self.assertEqual(e.check(raw, '192.0.2.2')['retry_after_seconds'], 7)
            clock[0] += 1
            # Device started at 1000; second IP started at 1003.
            for e in engines: self.assertEqual(e.check(raw, '192.0.2.2')['retry_after_seconds'], 9)

    def test_seeded_mixed_traces_against_independent_model(self):
        # Sizes stay below the 64-item per-call cleanup budget, so this model
        # intentionally does not model cleanup-busy admission.
        for seed in range(12):
            with self.subTest(seed=seed), tempfile.TemporaryDirectory() as tmp:
                rng = random.Random(seed)
                now = [1700000000.0]
                settings = policy(override={'max_requests': 4, 'ip_max_requests': 3,
                    'device_max_requests': 2, 'ip_challenge_after': 2,
                    'window_seconds': 7, 'history_seconds': 60, 'min_matches': 2})
                capacity = 8 if seed % 2 else 24
                ref = Reference(settings, capacity)
                memory = Engine(settings, SECRET, clock=lambda: now[0], max_entries=capacity)
                path = Path(tmp) / 'state.sqlite'
                def persistent():
                    return SQLiteEngine(path, settings, SECRET, clock=lambda: now[0], max_entries=capacity)
                disk = persistent()
                peers = ['192.0.2.1', '192.0.2.2', '192.0.2.3', '::ffff:192.0.2.1', '2001:db8::1']
                devices = [synthetic_signal('machine_id', str(i)) for i in range(5)]
                products = [synthetic_signal('product_uuid', str(i)) for i in range(3)]
                for step in range(250):
                    op = rng.randrange(10)
                    peer = rng.choice(peers)
                    if op == 0:
                        now[0] += rng.choice((0.25, 1, 7, 30, 61))
                        continue
                    if op == 1:
                        expected = ref.reset(peer)
                        self.assertEqual(memory.reset_ip_window(peer), expected, (seed, step, 'memory reset'))
                        self.assertEqual(disk.reset_ip_window(peer), expected, (seed, step, 'disk reset'))
                        continue
                    if op == 2:
                        expected = ref.malformed(peer, now[0])
                        expected = None if expected is None else expected + (None, None)
                        self.assertEqual(fields(memory.reject_malformed(peer)), expected, (seed, step, 'memory malformed'))
                        self.assertEqual(fields(disk.reject_malformed(peer)), expected, (seed, step, 'disk malformed'))
                        continue
                    if op == 3:
                        disk = persistent()  # restart retains the SQLite state
                        continue
                    if op == 4:
                        for backend in (memory, disk):
                            with self.assertRaises(ValueError): backend.check({'signals': {'machine_id': 'bad'}}, peer)
                        continue
                    signals = {}
                    if rng.randrange(5): signals['machine_id'] = rng.choice(devices)
                    if rng.randrange(2): signals['product_uuid'] = rng.choice(products)
                    raw = {'signals': signals}
                    precharged = op == 5
                    expected = ref.check(raw, peer, now[0], precharged)
                    self.assertEqual(fields(memory.check(raw, peer, _ip_precharged=precharged)), expected,
                                     (seed, step, 'memory check'))
                    self.assertEqual(fields(disk.check(raw, peer, _ip_precharged=precharged)), expected,
                                     (seed, step, 'disk check'))


if __name__ == '__main__': unittest.main(verbosity=2)
