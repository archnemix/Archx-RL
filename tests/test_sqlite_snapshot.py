"""Synthetic SQLite snapshot tests; not a supported restore workflow."""
import os
import shutil
import sqlite3
import stat
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import policy
from replay import SQLiteReplay
from signal_validation import synthetic_signal
from sqlite_engine import SQLiteEngine
from sqlite_snapshot import snapshot

SECRET = b'synthetic-snapshot-secret-0123456789'


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.settings = policy(override={'max_requests': 2})
        self.clock = lambda: 1700000000.0
        self.engine = SQLiteEngine(self.root / 'live.sqlite', self.settings, SECRET, clock=self.clock)
        self.replay = SQLiteReplay(self.engine)
        self.peer = '192.0.2.42'
        self.request = {'signals': {'machine_id': synthetic_signal('machine_id', 'snapshot')}}

    def test_snapshot_contains_wal_state_and_does_not_overwrite(self):
        anchor = self.engine.connect()
        self.addCleanup(anchor.close)
        anchor.execute('SELECT count(*) FROM meta').fetchone()
        self.assertEqual(self.engine.check(self.request, self.peer)['decision'], 'allow')
        token = self.replay.issue(self.peer)
        self.assertGreater(Path(str(self.engine.db_path) + '-wal').stat().st_size, 0)
        path = self.root / 'snapshot.sqlite'
        snapshot(self.engine, path)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertFalse(Path(str(path) + '-wal').exists())
        with sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True) as con:
            self.assertEqual(con.execute('PRAGMA integrity_check').fetchone(), ('ok',))
            self.assertEqual(con.execute('SELECT count(*) FROM windows').fetchone()[0], 2)
            self.assertEqual(con.execute('SELECT count(*) FROM observations').fetchone()[0], 1)
            self.assertEqual(con.execute('SELECT count(*) FROM replay_challenges_v1').fetchone()[0], 1)
        # Inspect a separate clone so the published snapshot stays unchanged;
        # this verifies contents only, not safety of restoring stale state.
        clone = self.root / 'inspection.sqlite'
        fd = os.open(clone, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'wb') as out, path.open('rb') as source:
            shutil.copyfileobj(source, out)
        inspection = SQLiteEngine(clone, self.settings, SECRET, clock=self.clock)
        inspect_replay = SQLiteReplay(inspection)
        self.assertTrue(inspect_replay.consume(token, self.peer))
        self.assertFalse(inspect_replay.consume(token, self.peer))
        self.assertEqual(inspection.check(self.request, self.peer)['relation'], 'related')
        self.assertEqual(inspection.check(self.request, self.peer)['decision'], 'rate_limited')
        before = path.read_bytes()
        with self.assertRaises(FileExistsError): snapshot(self.engine, path)
        self.assertEqual(path.read_bytes(), before)
        self.assertTrue(self.replay.consume(token, self.peer))
        # The snapshot is already stale and still contains the consumed token.
        with sqlite3.connect('file:' + str(path) + '?mode=ro', uri=True) as con:
            self.assertEqual(con.execute('SELECT count(*) FROM replay_challenges_v1').fetchone()[0], 1)
        self.assertFalse(list(self.root.glob('.archx-snapshot-*')))

    def test_existing_live_path_and_symlink_are_not_replaced(self):
        live = Path(self.engine.db_path)
        with self.assertRaises(FileExistsError): snapshot(self.engine, live)
        link = self.root / 'link.sqlite'
        link.symlink_to(live)
        with self.assertRaises(FileExistsError): snapshot(self.engine, link)
        self.assertTrue(link.is_symlink())
        self.assertEqual(self.engine.check(self.request, self.peer)['decision'], 'allow')

    def test_rejects_unsafe_or_symlink_directory(self):
        unsafe = self.root / 'unsafe'; unsafe.mkdir(mode=0o755); unsafe.chmod(0o755)
        with self.assertRaises(ValueError): snapshot(self.engine, unsafe / 'snapshot.sqlite')
        safe = self.root / 'safe'; safe.mkdir(mode=0o700)
        link = self.root / 'dirlink'; link.symlink_to(safe, target_is_directory=True)
        with self.assertRaises(ValueError): snapshot(self.engine, link / 'snapshot.sqlite')
        self.assertFalse(list(safe.iterdir()))

    def test_invalid_metadata_and_io_failure_leave_no_snapshot(self):
        target = self.root / 'snapshot.sqlite'
        with self.engine.connect() as con: con.execute("UPDATE meta SET value='bad' WHERE name='policy_check'")
        with self.assertRaises(sqlite3.DatabaseError): snapshot(self.engine, target)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.root.glob('.archx-snapshot-*')))
        # Re-establish the test fixture's own metadata before injecting an
        # unrelated no-space publication error.
        with self.engine.connect() as con:
            con.execute("UPDATE meta SET value=? WHERE name='policy_check'", (self.engine._persistent_checks['policy_check'],))
        with patch('sqlite_snapshot.os.link', side_effect=OSError('synthetic link failure')):
            with self.assertRaises(OSError): snapshot(self.engine, target)
        self.assertFalse(target.exists())
        self.assertFalse(list(self.root.glob('.archx-snapshot-*')))
        self.assertEqual(self.engine.check(self.request, self.peer)['decision'], 'allow')

    def test_directory_sync_failure_after_publication_is_ambiguous(self):
        target = self.root / 'snapshot.sqlite'
        real_fsync = os.fsync
        calls = []
        def injected(fd):
            calls.append(fd)
            if len(calls) == 2: raise OSError('synthetic directory sync failure')
            return real_fsync(fd)
        with patch('sqlite_snapshot.os.fsync', side_effect=injected):
            with self.assertRaises(OSError): snapshot(self.engine, target)
        self.assertTrue(target.exists())  # no false promise of rollback
        with sqlite3.connect('file:' + str(target) + '?mode=ro', uri=True) as con:
            self.assertEqual(con.execute('PRAGMA integrity_check').fetchone(), ('ok',))
        self.assertFalse(list(self.root.glob('.archx-snapshot-*')))

    def test_waiting_snapshot_includes_committed_writer(self):
        lock = self.engine.connect()
        self.addCleanup(lock.close)
        self.engine._begin_writer(lock)
        entered = threading.Event()
        target = self.root / 'snapshot.sqlite'
        def worker():
            entered.set(); snapshot(self.engine, target)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(worker)
            self.assertTrue(entered.wait(3))
            lock.execute('INSERT INTO windows VALUES(?,?,?)', ('synthetic-write', self.clock(), 1))
            lock.commit()
            future.result(timeout=10)
        with sqlite3.connect('file:' + str(target) + '?mode=ro', uri=True) as con:
            self.assertEqual(con.execute('SELECT count(*) FROM windows').fetchone(), (1,))


if __name__ == '__main__': unittest.main(verbosity=2)
