"""Demonstrate unsafe rollback of a SQLite snapshot; not a restore procedure."""
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import policy
from replay import SQLiteReplay
from signal_validation import synthetic_signal
from sqlite_engine import SQLiteEngine


class RestoreRiskTest(unittest.TestCase):
    def test_online_snapshot_can_rollback_limits_and_replay_consumption(self):
        # The Python SQLite backup API captures a consistent database including
        # WAL frames. A consistent snapshot is NOT a current security state.
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        tmp = temp.name
        source, snapshot, restored = (Path(tmp) / name for name in ('active.sqlite', 'snapshot.sqlite', 'restored.sqlite'))
        settings = policy(override={'max_requests': 2})
        secret = b'synthetic-restore-test-secret-0123456789'
        clock = lambda: 1700000000.0
        engine = SQLiteEngine(source, settings, secret, clock=clock)
        replay = SQLiteReplay(engine)
        anchor = engine.connect()  # keep WAL available while subsequent writes commit
        self.addCleanup(anchor.close)
        anchor.execute('SELECT count(*) FROM meta').fetchone()
        peer = '192.0.2.1'
        def request(seed): return {'signals': {'machine_id': synthetic_signal('machine_id', seed)}}
        self.assertEqual(engine.check(request('first'), peer)['decision'], 'allow')
        nonce = replay.issue(peer)
        self.assertGreater(Path(str(source) + '-wal').stat().st_size, 0)
        # Create a private test destination; never overwrite the live store.
        fd = os.open(snapshot, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(snapshot)) as destination:
            anchor.backup(destination)
            self.assertEqual(destination.execute('PRAGMA integrity_check').fetchone(), ('ok',))
        self.assertEqual(engine.check(request('second'), peer)['decision'], 'allow')
        self.assertTrue(replay.consume(nonce, peer))
        self.assertEqual(engine.check(request('third'), peer)['decision'], 'rate_limited')
        self.assertFalse(replay.consume(nonce, peer))
        # Simulate restoring that consistent but stale snapshot to a new
        # private location. It loses subsequent quota and replay changes.
        fd = os.open(restored, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(snapshot)) as backup, closing(sqlite3.connect(restored)) as destination:
            backup.backup(destination)
        stale = SQLiteEngine(restored, settings, secret, clock=clock)
        self.assertEqual(stale.check(request('third'), peer)['decision'], 'allow')
        self.assertTrue(SQLiteReplay(stale).consume(nonce, peer))


if __name__ == '__main__': unittest.main(verbosity=2)
