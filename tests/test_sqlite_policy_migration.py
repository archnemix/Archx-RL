"""Narrow offline policy migration for the SQLite prototype, not restore safety."""
import ipaddress
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import policy
from policy_migration import tighten_policy
from replay import ReplayUnavailable, SQLiteReplay
from signal_validation import synthetic_signal
from sqlite_engine import SQLiteEngine, persistent_checks

SECRET = b'synthetic-migration-secret-0123456789'
NOW = 1700000000.0


class PolicyMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = str(Path(self.tmp.name) / 'state.sqlite')
        self.old_policy = policy(override={'max_requests': 5})
        self.engine = self.open(self.old_policy)

    def open(self, settings):
        return SQLiteEngine(self.path, settings, SECRET, clock=lambda: NOW)

    @staticmethod
    def request(seed):
        return {'signals': {'machine_id': synthetic_signal('machine_id', seed)}}

    def snapshot(self):
        with sqlite3.connect(self.path) as con:
            return tuple(tuple(con.execute('SELECT * FROM ' + name + ' ORDER BY 1'))
                         for name in ('windows', 'observations', 'signals', 'replay_challenges_v1'))

    def test_tightening_preserves_state_and_stale_workers_fail_closed(self):
        old_worker = self.open(self.old_policy)
        replay = SQLiteReplay(self.engine)
        nonce = replay.issue('192.0.2.1')
        for seed in ('one', 'two'):
            self.assertEqual(self.engine.check(self.request(seed), '192.0.2.1')['decision'], 'allow')
        before = self.snapshot()
        new_policy = policy(override={'max_requests': 1})
        tighten_policy(self.engine, new_policy)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(old_worker.reject_malformed('192.0.2.2')['decision'], 'storage_error')
        self.assertEqual(old_worker.check(self.request('other'), '192.0.2.2')['decision'], 'storage_error')
        with self.assertRaises(ValueError): self.open(self.old_policy)
        current = self.open(new_policy)
        self.assertEqual(current.check(self.request('three'), '192.0.2.1')['decision'], 'rate_limited')
        self.assertTrue(SQLiteReplay(current).consume(nonce, '192.0.2.1'))
        self.assertFalse(SQLiteReplay(current).consume(nonce, '192.0.2.1'))
        self.assertEqual(self.open(new_policy).check(self.request('four'), '192.0.2.1')['decision'], 'rate_limited')
        # A reverse migration would weaken quotas and is explicitly rejected.
        with self.assertRaises(ValueError): tighten_policy(current, self.old_policy)

    def test_stale_replay_cannot_issue_consume_cleanup_or_initialize(self):
        stale = SQLiteReplay(self.engine)
        peer = '192.0.2.9'
        nonce = stale.issue(peer)
        before = self.snapshot()
        target = policy(override={'max_requests': 1})
        tighten_policy(self.engine, target)
        for operation in (lambda: stale.issue(peer), lambda: stale.consume(nonce, peer),
                          stale.cleanup_expired, lambda: SQLiteReplay(self.engine)):
            with self.subTest(operation=operation), self.assertRaises(ReplayUnavailable):
                operation()
        self.assertEqual(self.snapshot(), before)
        current = SQLiteReplay(self.open(target))
        self.assertTrue(current.consume(nonce, peer))
        self.assertFalse(current.consume(nonce, peer))

    def test_replay_waiter_checks_metadata_after_acquiring_writer_lock(self):
        stale = SQLiteReplay(self.engine)
        nonce = stale.issue('192.0.2.1')
        target = policy(override={'max_requests': 1})
        waiting = threading.Event()
        done = threading.Event()
        errors = []
        original_connect = self.engine.connect
        class Traced:
            def __init__(self): self.con = original_connect()
            def __getattr__(self, name): return getattr(self.con, name)
            def execute(self, sql, *args):
                if sql == 'BEGIN IMMEDIATE': waiting.set()
                return self.con.execute(sql, *args)
        holder = original_connect()
        holder.execute('BEGIN IMMEDIATE')
        def consume():
            try: stale.consume(nonce, '192.0.2.1')
            except Exception as exc: errors.append(exc)
            finally: done.set()
        try:
            with mock.patch.object(self.engine, 'connect', side_effect=Traced):
                thread = threading.Thread(target=consume)
                thread.start()
                self.assertTrue(waiting.wait(2))
                self.assertFalse(done.is_set())
                # Commit the same metadata change as migration while the stale
                # replay operation is waiting on the SQLite writer lock.
                holder.execute("UPDATE meta SET value=? WHERE name='policy_check'",
                               (persistent_checks(SECRET, target)['policy_check'],))
                holder.commit()
                self.assertTrue(done.wait(6))
                thread.join(2)
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], ReplayUnavailable)
            self.assertTrue(SQLiteReplay(self.open(target)).consume(nonce, '192.0.2.1'))
        finally:
            holder.close()

    def test_replay_secret_mutation_fails_closed(self):
        store = SQLiteReplay(self.engine)
        nonce = store.issue('192.0.2.1')
        before = self.snapshot()
        store.secret = b'changed-synthetic-replay-secret'
        for operation in (lambda: store.issue('192.0.2.1'),
                          lambda: store.consume(nonce, '192.0.2.1'), store.cleanup_expired):
            with self.subTest(operation=operation), self.assertRaises(ReplayUnavailable):
                operation()
        self.assertEqual(self.snapshot(), before)
        self.assertTrue(SQLiteReplay(self.engine).consume(nonce, '192.0.2.1'))

    def test_rejects_semantic_changes_and_quota_weakening(self):
        invalid = [
            policy(override={'max_requests': 6}),
            policy(override={'max_requests': 4, 'ip_max_requests': 6}),
            policy(override={'max_requests': 4, 'device_max_requests': 6}),
            policy(override={'max_requests': 4, 'window_seconds': 120}),
            policy(override={'max_requests': 4, 'history_seconds': 7200}),
            policy(override={'max_requests': 4, 'required': []}),
            policy(override={'max_requests': 4, 'ip_storage': 'raw'}),
            {'max_requests': 1},
        ]
        for target in invalid:
            with self.subTest(target=target), self.assertRaises(ValueError):
                tighten_policy(self.engine, target)
        self.assertEqual(self.open(self.old_policy).check(self.request('valid'), '192.0.2.1')['decision'], 'allow')

    def test_explicit_quotas_and_challenge_cannot_be_weakened(self):
        original = policy(override={'max_requests': 5, 'ip_max_requests': 4,
                                    'device_max_requests': 3, 'ip_challenge_after': 2})
        # Create a separate store with explicit overrides.
        other = SQLiteEngine(str(Path(self.tmp.name) / 'other.sqlite'), original, SECRET)
        for candidate in (
            policy(override={'max_requests': 5, 'ip_max_requests': 5, 'device_max_requests': 3, 'ip_challenge_after': 2}),
            policy(override={'max_requests': 5, 'ip_max_requests': 4, 'device_max_requests': 4, 'ip_challenge_after': 2}),
            policy(override={'max_requests': 5, 'ip_max_requests': 4, 'device_max_requests': 3}),
            policy(override={'max_requests': 5, 'ip_max_requests': 4, 'device_max_requests': 3, 'ip_challenge_after': 3}),
        ):
            with self.subTest(target=candidate), self.assertRaises(ValueError): tighten_policy(other, candidate)
        tighten_policy(other, policy(override={'max_requests': 4, 'ip_max_requests': 3,
                                                'device_max_requests': 2, 'ip_challenge_after': 1}))

    def test_failed_update_rolls_back_without_changing_metadata(self):
        original_connect = self.engine.connect
        class Fault:
            def __init__(self): self.con = original_connect()
            def __getattr__(self, name): return getattr(self.con, name)
            def execute(self, sql, *args):
                result = self.con.execute(sql, *args)
                if sql.startswith('UPDATE meta'): raise sqlite3.OperationalError('synthetic fault after update')
                return result
        with mock.patch.object(self.engine, 'connect', side_effect=Fault):
            with self.assertRaises(sqlite3.OperationalError):
                tighten_policy(self.engine, policy(override={'max_requests': 1}))
        self.assertEqual(self.open(self.old_policy).check(self.request('still-valid'), '192.0.2.1')['decision'], 'allow')
        with self.assertRaises(ValueError): self.open(policy(override={'max_requests': 1}))

    def test_mutating_engine_policy_or_secret_fails_closed(self):
        self.engine.settings['max_requests'] = 1
        self.assertEqual(self.engine.check(self.request('mutated'), '192.0.2.1')['decision'], 'storage_error')
        self.engine.settings['max_requests'] = 5
        self.engine.secret = b'a-different-secret-of-32-bytes!!'
        self.assertEqual(self.engine.reject_malformed('192.0.2.1')['decision'], 'storage_error')

    def test_migration_waits_for_writer_and_keeps_its_charge(self):
        acquired, waiting = threading.Event(), threading.Event()
        con = self.engine.connect()
        con.execute('BEGIN IMMEDIATE')
        key = self.engine.ip_key(ipaddress.ip_address('192.0.2.77'))
        con.execute('INSERT INTO windows(key,start,count) VALUES(?,?,?)', (key, NOW, 1))
        real_connect = self.engine.connect
        class Traced:
            def __init__(self): self.con = real_connect()
            def __getattr__(self, name): return getattr(self.con, name)
            def execute(self, sql, *args):
                if sql == 'BEGIN IMMEDIATE': waiting.set()
                return self.con.execute(sql, *args)
        errors = []
        target = policy(override={'max_requests': 1})
        def run():
            try: tighten_policy(self.engine, target)
            except Exception as exc: errors.append(exc)
            finally: acquired.set()
        try:
            with mock.patch.object(self.engine, 'connect', side_effect=Traced):
                thread = threading.Thread(target=run)
                thread.start()
                self.assertTrue(waiting.wait(2))
                self.assertFalse(acquired.is_set())
                con.commit()
                self.assertTrue(acquired.wait(6))
                thread.join(2)
            self.assertEqual(errors, [])
            self.assertEqual(self.open(target).reject_malformed('192.0.2.77')['decision'], 'rate_limited')
        finally:
            con.close()


if __name__ == '__main__': unittest.main(verbosity=2)
