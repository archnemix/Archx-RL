"""Deterministic contention regressions for in-memory and SQLite state clocks."""
import sqlite3
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import Engine, policy
from signal_validation import synthetic_signal
from sqlite_engine import SQLiteEngine

SECRET = b'synthetic-state-clock-test-secret-01234567'
PEER = '192.0.2.1'
BODY = {'signals': {'machine_id': synthetic_signal('machine_id', 'state-clock-test')}}


class StateClockTests(unittest.TestCase):
    def check_delayed(self, mode, malformed):
        now = [1700000000.0]
        settings = policy(override={'max_requests': 1, 'window_seconds': 60, 'history_seconds': 120})
        with tempfile.TemporaryDirectory() as tmp:
            if mode == 'memory':
                engine = Engine(settings, secret=SECRET, clock=lambda: now[0])
            else:
                path = str(Path(tmp) / 'state.sqlite')
                engine = SQLiteEngine(path, settings, SECRET, clock=lambda: now[0])
            started = threading.Event()
            if mode == 'memory':
                # Observe that input preparation has completed while the lock is held.
                attribute = 'ip_key' if malformed else 'prepare'
                original = getattr(engine, attribute)
                def observed(*args, **kwargs):
                    result = original(*args, **kwargs)
                    started.set()
                    return result
                patch = mock.patch.object(engine, attribute, side_effect=observed)
                engine.lock.acquire()
                release = engine.lock.release
            else:
                # Hold a real SQLite writer until the request starts BEGIN IMMEDIATE.
                holder = sqlite3.connect(path, isolation_level=None)
                holder.execute('BEGIN IMMEDIATE')
                connect = engine.connect
                class ObservedConnection:
                    def __init__(self, con): self.con = con
                    def execute(self, sql, *args):
                        if sql == 'BEGIN IMMEDIATE': started.set()
                        return self.con.execute(sql, *args)
                    def __getattr__(self, name): return getattr(self.con, name)
                patch = mock.patch.object(engine, 'connect', side_effect=lambda: ObservedConnection(connect()))
                def release():
                    holder.rollback()
                    holder.close()
            def call():
                return engine.reject_malformed(PEER) if malformed else engine.check(BODY, PEER)
            with patch, ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(call)
                try:
                    self.assertTrue(started.wait(3), 'request did not reach the lock')
                    now[0] += 61
                finally:
                    release()
                first = future.result(timeout=6)
            if malformed:
                self.assertIsNone(first)
            else:
                self.assertEqual(first['decision'], 'allow')
            if not malformed:
                if mode == 'memory':
                    expiry = next(iter(engine.observations.records.values()))[0]
                else:
                    with sqlite3.connect(path) as db:
                        expiry = db.execute('SELECT expires FROM observations').fetchone()[0]
                self.assertEqual(expiry, now[0] + 120)
            second = call()
            self.assertEqual(second['decision'], 'rate_limited')
            self.assertEqual(second['retry_after_seconds'], 60)
            now[0] += 60
            final = call()
            if malformed:
                self.assertIsNone(final)
            else:
                self.assertEqual(final['decision'], 'allow')

    def test_memory_valid_request_wait(self): self.check_delayed('memory', False)
    def test_memory_malformed_request_wait(self): self.check_delayed('memory', True)
    def test_sqlite_valid_request_wait(self): self.check_delayed('sqlite', False)
    def test_sqlite_malformed_request_wait(self): self.check_delayed('sqlite', True)


if __name__ == '__main__': unittest.main(verbosity=2)
