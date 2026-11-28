"""Synthetic tests of the offline, empty-store-only rotation experiment."""
import sqlite3
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from empty_key_rotation import rotate_empty_key
from engine import policy
from replay import SQLiteReplay, ReplayUnavailable
from signal_validation import synthetic_signal
from sqlite_engine import SQLiteEngine

OLD = b'old-synthetic-pseudonym-secret-0123456789'
NEW = b'new-synthetic-pseudonym-secret-0123456789'
PEER = '192.0.2.10'


class RotationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'state.sqlite'
        self.now = [1000.0]
        self.settings = policy(override={'max_requests': 1, 'window_seconds': 10, 'history_seconds': 60})
        self.old = self.engine(OLD)
        self.request = {'signals': {'machine_id': synthetic_signal('machine_id', 'rotation')}}

    def engine(self, secret):
        return SQLiteEngine(self.path, self.settings, secret, clock=lambda: self.now[0])

    def test_empty_transition_restart_refused_rollback_and_eventual_reverse(self):
        # Replay schema and its marker are allowed if empty.
        replay = SQLiteReplay(self.old)
        stale = self.engine(OLD)
        rotate_empty_key(self.old, NEW)
        with self.assertRaises(ValueError): self.engine(OLD)
        self.assertEqual(stale.check(self.request, PEER)['decision'], 'storage_error')
        with self.assertRaises(ReplayUnavailable): replay.issue(PEER)
        current = self.engine(NEW)
        self.assertEqual(current.check(self.request, PEER)['decision'], 'allow')
        with self.assertRaisesRegex(ValueError, 'empty store'): rotate_empty_key(current, OLD)
        self.assertEqual(self.engine(NEW).check(self.request, PEER)['decision'], 'rate_limited')
        self.now[0] += 61
        self.assertEqual(current.cleanup_expired(), {'windows_pending': False, 'observations_pending': False})
        rotate_empty_key(current, OLD)
        with self.assertRaises(ValueError): self.engine(NEW)
        self.assertEqual(self.engine(OLD).check(self.request, PEER)['decision'], 'allow')

    def test_refuses_all_state_even_when_expired_until_explicit_cleanup(self):
        self.assertEqual(self.old.check(self.request, PEER)['decision'], 'allow')
        replay = SQLiteReplay(self.old, ttl=3)
        nonce = replay.issue(PEER)
        with self.assertRaisesRegex(ValueError, 'empty store'): rotate_empty_key(self.old, NEW)
        self.assertTrue(replay.consume(nonce, PEER))
        self.assertEqual(self.old.check(self.request, PEER)['decision'], 'rate_limited')
        self.now[0] += 61
        with self.assertRaisesRegex(ValueError, 'empty store'): rotate_empty_key(self.old, NEW)
        self.old.cleanup_expired()
        replay.issue(PEER)
        with self.assertRaisesRegex(ValueError, 'empty store'): rotate_empty_key(self.old, NEW)
        self.now[0] += 4
        with self.assertRaisesRegex(ValueError, 'empty store'): rotate_empty_key(self.old, NEW)
        replay.cleanup_expired()
        rotate_empty_key(self.old, NEW)
        self.engine(NEW)

    def test_rejects_unknown_or_incomplete_metadata_and_objects(self):
        for alteration in ("CREATE TABLE extra (x TEXT)", "CREATE TRIGGER surprise AFTER UPDATE ON meta BEGIN SELECT 1; END",
                           "INSERT INTO meta VALUES ('unknown', '1')", "INSERT INTO meta VALUES ('replay_schema_v1', '1')"):
            with self.subTest(alteration=alteration), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'state.sqlite'
                engine = SQLiteEngine(path, self.settings, OLD, clock=lambda: self.now[0])
                with engine.connect() as con: con.execute(alteration)
                with self.assertRaisesRegex(ValueError, 'Unknown or incomplete'): rotate_empty_key(engine, NEW)
                with sqlite3.connect(path) as con:
                    saved = con.execute("SELECT value FROM meta WHERE name='key_check'").fetchone()[0]
                self.assertEqual(saved, engine._persistent_checks['key_check'])

    def test_waiting_rotation_observes_a_committed_writer(self):
        writer = self.old.connect()
        self.addCleanup(writer.close)
        self.old._begin_writer(writer)
        started = threading.Event()
        def rotate():
            started.set()
            rotate_empty_key(self.old, NEW)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(rotate)
            self.assertTrue(started.wait(3))
            writer.execute('INSERT INTO windows(key,start,count) VALUES(?,?,?)', ('synthetic-key', self.now[0], 1))
            writer.commit()
            with self.assertRaisesRegex(ValueError, 'empty store'): future.result(timeout=10)
        self.engine(OLD)
        with self.assertRaises(ValueError): self.engine(NEW)

    def test_transaction_failure_does_not_change_key(self):
        connect = self.old.connect
        def deny_update():
            con = connect()
            def auth(action, table, column, _database, _source):
                return sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_UPDATE and table == 'meta' else sqlite3.SQLITE_OK
            con.set_authorizer(auth)
            return con
        with patch.object(self.old, 'connect', side_effect=deny_update):
            with self.assertRaises(sqlite3.DatabaseError): rotate_empty_key(self.old, NEW)
        self.engine(OLD)
        with self.assertRaises(ValueError): self.engine(NEW)

    def test_rejects_invalid_or_unchanged_key(self):
        for secret in (None, b'short', OLD, 'synthetic-string'):
            with self.subTest(secret_type=type(secret).__name__):
                with self.assertRaises(ValueError): rotate_empty_key(self.old, secret)
        self.engine(OLD)


if __name__ == '__main__': unittest.main(verbosity=2)
