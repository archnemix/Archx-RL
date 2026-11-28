"""Synthetic replay nonce generator failures must not overwrite live state."""
import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import policy
from replay import MemoryReplay, SQLiteReplay, ReplayUnavailable
from sqlite_engine import SQLiteEngine

SECRET = b'synthetic-replay-rng-fault-test-secret'
TOKEN = 'A' * 43
PEER = '192.0.2.1'


class ReplayRngFaultTests(unittest.TestCase):
    def test_collision_cannot_overwrite_pending_nonce(self):
        for mode in ('memory', 'sqlite'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                engine = SQLiteEngine(Path(tmp) / 'state.sqlite', policy(), SECRET, clock=lambda: 1000)
                store = (MemoryReplay(SECRET, lambda: 1000) if mode == 'memory' else SQLiteReplay(engine))
                with mock.patch('replay.secrets.token_urlsafe', return_value=TOKEN):
                    token = store.issue(PEER)
                    with self.assertRaises(ReplayUnavailable): store.issue('192.0.2.2')
                self.assertFalse(store.consume(token, '192.0.2.2'))
                self.assertTrue(store.consume(token, PEER))
                self.assertFalse(store.consume(token, PEER))

    def test_collision_race_admits_only_one_challenge(self):
        for mode in ('memory', 'sqlite'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                engine = SQLiteEngine(Path(tmp) / 'state.sqlite', policy(), SECRET, clock=lambda: 1000)
                store = (MemoryReplay(SECRET, lambda: 1000) if mode == 'memory' else SQLiteReplay(engine))
                def attempt(_):
                    try: return store.issue(PEER)
                    except ReplayUnavailable: return None
                with mock.patch('replay.secrets.token_urlsafe', return_value=TOKEN), ThreadPoolExecutor(max_workers=12) as pool:
                    results = list(pool.map(attempt, range(24)))
                self.assertEqual(results.count(TOKEN), 1)
                self.assertEqual(results.count(None), 23)
                self.assertTrue(store.consume(TOKEN, PEER))
                self.assertFalse(store.consume(TOKEN, PEER))

    def test_invalid_generator_result_and_exception_fail_closed(self):
        for mode in ('memory', 'sqlite'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                engine = SQLiteEngine(Path(tmp) / 'state.sqlite', policy(), SECRET, clock=lambda: 1000)
                store = (MemoryReplay(SECRET, lambda: 1000) if mode == 'memory' else SQLiteReplay(engine))
                for bad in (None, 123, 'short', '!' * 43, 'é' * 43):
                    with self.subTest(bad=repr(bad)[:20]), mock.patch('replay.secrets.token_urlsafe', return_value=bad):
                        with self.assertRaises(ReplayUnavailable): store.issue(PEER)
                with mock.patch('replay.secrets.token_urlsafe', side_effect=OSError('private entropy details')):
                    with self.assertRaises(ReplayUnavailable) as result: store.issue(PEER)
                    self.assertNotIn('private entropy', str(result.exception))
                if mode == 'memory': self.assertEqual(store.pending, {})
                else:
                    with sqlite3.connect(engine.db_path) as con:
                        self.assertEqual(con.execute('SELECT count(*) FROM replay_challenges_v1').fetchone(), (0,))
                nonce = store.issue(PEER)
                self.assertTrue(store.consume(nonce, PEER))


if __name__ == '__main__': unittest.main(verbosity=2)
