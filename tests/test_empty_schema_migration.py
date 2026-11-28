"""Offline empty-store migration across historical schema 2 and current 3."""
import hashlib
import hmac
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import policy
from empty_schema_migration import migrate_empty_schema
from sqlite_engine import SQLiteEngine, EXPECTED_SCHEMA, persistent_checks

SECRET = b'synthetic-schema-migration-secret-0123'
SETTINGS = policy()


def historical_fixture(path):
    # The exact schema-2 CREATE definitions and metadata formula are from the
    # predecessor of commit 7ad21f1; no live identifiers are used.
    with sqlite3.connect(path) as con:
        for sql in EXPECTED_SCHEMA.values(): con.execute(sql)
        checks = persistent_checks(SECRET, SETTINGS)
        checks['schema'] = '2'
        checks['policy_check'] = hashlib.sha256(json.dumps(
            SETTINGS, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        con.executemany('INSERT INTO meta(name,value) VALUES(?,?)', checks.items())
    os.chmod(path, 0o600)


class EmptySchemaMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'state.sqlite'
        historical_fixture(self.path)

    def tearDown(self): self.tmp.cleanup()

    def metadata(self):
        with sqlite3.connect(self.path) as con:
            return dict(con.execute('SELECT name,value FROM meta'))

    def test_frozen_historical_engine_upgrade_and_empty_rollback(self):
        # Run original historical code out of process so its module names and
        # global state cannot collide with the current engine.
        historical = Path(__file__).resolve().parent / 'fixtures/historical_schema2'
        script = ("from engine import policy; from sqlite_engine import SQLiteEngine; "
                  "import sys; SQLiteEngine(sys.argv[1], policy(), "
                  "b'synthetic-schema-migration-secret-0123')")
        def old_open():
            return subprocess.run([sys.executable, '-c', script, str(self.path)], cwd=historical,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        self.path.unlink()
        result = old_open()
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
        migrate_empty_schema(self.path, SECRET, SETTINGS, source=2, target=3)
        SQLiteEngine(self.path, SETTINGS, SECRET)
        self.assertNotEqual(old_open().returncode, 0)
        migrate_empty_schema(self.path, SECRET, SETTINGS, source=3, target=2)
        result = old_open()
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))

    def test_upgrade_restart_refuse_rollback_with_state_then_empty_rollback(self):
        with self.assertRaises(ValueError): SQLiteEngine(self.path, SETTINGS, SECRET)
        original = self.metadata()
        migrate_empty_schema(self.path, SECRET, SETTINGS, source=2, target=3)
        self.assertEqual(self.metadata(), persistent_checks(SECRET, SETTINGS))
        engine = SQLiteEngine(self.path, SETTINGS, SECRET, clock=lambda: 1000)
        self.assertIsNone(engine.reject_malformed('192.0.2.1'))
        with self.assertRaises(ValueError):
            migrate_empty_schema(self.path, SECRET, SETTINGS, source=3, target=2)
        self.assertTrue(engine.reset_ip_window('192.0.2.1'))
        migrate_empty_schema(self.path, SECRET, SETTINGS, source=3, target=2)
        self.assertEqual(self.metadata(), original)
        with self.assertRaises(ValueError): SQLiteEngine(self.path, SETTINGS, SECRET)
        migrate_empty_schema(self.path, SECRET, SETTINGS, source=2, target=3)
        SQLiteEngine(self.path, SETTINGS, SECRET)

    def test_active_and_expired_rows_are_refused_without_mutation(self):
        for table, values in (
                ('windows', ('key', 1.0, 1)),
                ('observations', (1, 1.0, 'fingerprint'))):
            with self.subTest(table=table):
                with sqlite3.connect(self.path) as con:
                    con.execute(f'INSERT INTO {table} VALUES ({",".join("?" for _ in values)})', values)
                before = self.metadata()
                with self.assertRaises(ValueError): migrate_empty_schema(self.path, SECRET, SETTINGS, source=2, target=3)
                self.assertEqual(self.metadata(), before)
                with sqlite3.connect(self.path) as con: con.execute(f'DELETE FROM {table}')

    def test_unknown_objects_metadata_wrong_secret_and_settings_fail_closed(self):
        before = self.metadata()
        for secret, settings in ((b'wrong' * 10, SETTINGS),
                                 (SECRET, policy(override={'max_requests': 7})),
                                 (SECRET, policy(override={'ip_storage': 'hash'}))):
            with self.subTest(settings=settings, secret=secret):
                with self.assertRaises(ValueError): migrate_empty_schema(self.path, secret, settings, source=2, target=3)
                self.assertEqual(self.metadata(), before)
        with sqlite3.connect(self.path) as con: con.execute('CREATE TABLE unknown (value TEXT)')
        with self.assertRaises(ValueError): migrate_empty_schema(self.path, SECRET, SETTINGS, source=2, target=3)
        self.assertEqual(self.metadata(), before)
        with sqlite3.connect(self.path) as con:
            con.execute('DROP TABLE unknown')
            con.execute("INSERT INTO meta VALUES ('unknown', 'value')")
        with self.assertRaises(ValueError): migrate_empty_schema(self.path, SECRET, SETTINGS, source=2, target=3)
        self.assertEqual(self.metadata()['schema'], '2')

    def test_symlink_permissions_and_invalid_directions_rejected(self):
        link = self.path.parent / 'link.sqlite'
        link.symlink_to(self.path)
        for path, source, target in ((link, 2, 3), (self.path, 2, 2), (self.path, True, 3),
                                     (self.path, 1, 3), (self.path.parent / 'missing', 2, 3)):
            with self.subTest(path=path, source=source):
                with self.assertRaises((ValueError, OSError)): migrate_empty_schema(path, SECRET, SETTINGS, source=source, target=target)
        os.chmod(self.path, 0o644)
        with self.assertRaises(ValueError): migrate_empty_schema(self.path, SECRET, SETTINGS, source=2, target=3)
        os.chmod(self.path, 0o600)
        self.assertEqual(self.metadata()['schema'], '2')

    def test_refuses_replay_objects_and_orphan_signals(self):
        with sqlite3.connect(self.path) as con:
            con.execute("INSERT INTO signals VALUES (1, 'machine_id', 'synthetic')")
        with self.assertRaises(ValueError): migrate_empty_schema(self.path, SECRET, SETTINGS, source=2, target=3)
        with sqlite3.connect(self.path) as con: con.execute('DELETE FROM signals')
        migrate_empty_schema(self.path, SECRET, SETTINGS, source=2, target=3)
        from replay import SQLiteReplay
        SQLiteReplay(SQLiteEngine(self.path, SETTINGS, SECRET))
        with self.assertRaises(ValueError): migrate_empty_schema(self.path, SECRET, SETTINGS, source=3, target=2)
        self.assertEqual(self.metadata()['schema'], '3')

    def test_waiting_migration_observes_committed_writer_and_refuses(self):
        started = threading.Event()
        holder = sqlite3.connect(self.path, isolation_level=None)
        holder.execute('BEGIN IMMEDIATE')
        holder.execute("INSERT INTO windows VALUES ('synthetic', 1, 1)")
        actual = sqlite3.connect
        class ObservedConnection:
            def __init__(self, con): self.con = con
            def execute(self, sql, *args):
                if sql == 'BEGIN IMMEDIATE': started.set()
                return self.con.execute(sql, *args)
            def __getattr__(self, name): return getattr(self.con, name)
        with mock.patch('empty_schema_migration.sqlite3.connect', side_effect=lambda *a, **kw: ObservedConnection(actual(*a, **kw))), ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(migrate_empty_schema, self.path, SECRET, SETTINGS, source=2, target=3)
            try:
                self.assertTrue(started.wait(3))
            finally:
                holder.commit()
                holder.close()
            with self.assertRaises(ValueError): future.result(timeout=6)
        self.assertEqual(self.metadata()['schema'], '2')
        with sqlite3.connect(self.path) as con:
            self.assertEqual(con.execute('SELECT count(*) FROM windows').fetchone(), (1,))

    def test_injected_update_failure_rolls_back(self):
        original = self.metadata()
        actual = sqlite3.connect
        class FaultConnection:
            def __init__(self, con): self.con, self.updates = con, 0
            def execute(self, sql, *args):
                if sql.startswith('UPDATE meta'):
                    self.updates += 1
                    if self.updates == 2:
                        raise sqlite3.OperationalError('synthetic second-update fault')
                return self.con.execute(sql, *args)
            def __getattr__(self, name): return getattr(self.con, name)
        with mock.patch('empty_schema_migration.sqlite3.connect', side_effect=lambda *a, **kw: FaultConnection(actual(*a, **kw))):
            with self.assertRaises(sqlite3.OperationalError): migrate_empty_schema(self.path, SECRET, SETTINGS, source=2, target=3)
        self.assertEqual(self.metadata(), original)


if __name__ == '__main__': unittest.main(verbosity=2)
