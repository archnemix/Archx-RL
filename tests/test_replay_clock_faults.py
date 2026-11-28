"""Replay clock faults must not delete or consume outstanding challenges."""
import copy
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import policy
from replay import MemoryReplay, SQLiteReplay, ReplayUnavailable
from sqlite_engine import SQLiteEngine

SECRET = b'synthetic-replay-clock-test-secret'
PEER = '192.0.2.1'


class ReplayClockFaultTests(unittest.TestCase):
    def test_faults_fail_closed_and_preserve_pending_state(self):
        for mode in ('memory', 'sqlite'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                now = [1000.0]
                engine = SQLiteEngine(str(Path(tmp) / 'state.sqlite'), policy(), SECRET, clock=lambda: now[0])
                store = (MemoryReplay(SECRET, lambda: now[0], ttl=10) if mode == 'memory'
                         else SQLiteReplay(engine, ttl=10))
                token = store.issue(PEER)
                def state():
                    if mode == 'memory': return copy.deepcopy(store.pending)
                    with sqlite3.connect(engine.db_path) as con:
                        return con.execute('SELECT token,peer,expires FROM replay_challenges_v1').fetchall()
                before = state()
                for bad in (float('nan'), float('inf'), float('-inf'), True, None,
                            '1000', 10 ** 1000, 1e300):
                    with self.subTest(clock=repr(bad)[:20]):
                        now[0] = bad
                        with self.assertRaises(ReplayUnavailable): store.issue(PEER)
                        self.assertEqual(state(), before)
                        with self.assertRaises(ReplayUnavailable): store.consume(token, PEER)
                        self.assertEqual(state(), before)
                        with self.assertRaises(ValueError): store.cleanup_expired()
                        self.assertEqual(state(), before)
                now[0] = 1001.0
                self.assertTrue(store.consume(token, PEER))
                self.assertFalse(store.consume(token, PEER))

    def test_configuration_rejects_invalid_types_and_values(self):
        for kwargs in ({'clock': None}, {'ttl': True}, {'ttl': float('nan')},
                       {'ttl': float('inf')}, {'ttl': 0}, {'ttl': 301},
                       {'capacity': True}, {'capacity': 1.5}, {'per_peer': True},
                       {'capacity': 1, 'per_peer': 2}):
            with self.subTest(kwargs=kwargs):
                config = {'clock': lambda: 1000.0}
                config.update(kwargs)
                with self.assertRaises(ValueError): MemoryReplay(SECRET, **config)

    def test_service_maps_clock_error_to_unavailable(self):
        from engine import Engine
        from service import RequestService
        now = [1000.0]
        engine = Engine(policy(), secret=SECRET, clock=lambda: now[0])
        replay = MemoryReplay(SECRET, lambda: now[0])
        service = RequestService(engine, sealed_key=object(), replay=replay)
        token = service.challenge(PEER)['nonce']
        now[0] = float('nan')
        result = service.challenge(PEER)
        self.assertEqual((result['decision'], result['reason']), ('storage_error', 'replay_unavailable'))
        now[0] = 1001.0
        self.assertTrue(replay.consume(token, PEER))

    def test_clock_exception_does_not_leak_or_mutate(self):
        for mode in ('memory', 'sqlite'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                state = {'fail': False}
                def clock():
                    if state['fail']: raise RuntimeError('sensitive clock detail')
                    return 1000.0
                engine = SQLiteEngine(str(Path(tmp) / 'state.sqlite'), policy(), SECRET, clock=clock)
                store = MemoryReplay(SECRET, clock) if mode == 'memory' else SQLiteReplay(engine)
                token = store.issue(PEER)
                state['fail'] = True
                with self.assertRaises(ReplayUnavailable) as cm: store.consume(token, PEER)
                self.assertNotIn('sensitive', str(cm.exception))
                state['fail'] = False
                self.assertTrue(store.consume(token, PEER))


if __name__ == '__main__': unittest.main(verbosity=2)
