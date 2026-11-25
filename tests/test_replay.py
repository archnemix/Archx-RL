"""Test single-use challenge bounds, expiry, persistence and concurrency."""
import os
import multiprocessing
import sqlite3
import sys
import threading
import tempfile
import unittest
from unittest import mock
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import policy
from replay import MemoryReplay, SQLiteReplay, ReplayUnavailable
from sqlite_engine import SQLiteEngine


def consume_in_process(path, token, queue):
    engine = SQLiteEngine(path, policy(), b'x' * 32, clock=lambda: 1000.0)
    store = SQLiteReplay(engine)
    queue.put(store.consume(token, '192.0.2.1'))


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / 'state.sqlite')
        self.now = [1000.0]
        self.secret = b'x' * 32

    def tearDown(self):
        self.tmp.cleanup()

    def stores(self):
        engine = SQLiteEngine(self.path, policy(), self.secret, clock=lambda: self.now[0])
        return [MemoryReplay(self.secret, lambda: self.now[0], ttl=10, capacity=3, per_peer=2),
                SQLiteReplay(engine, ttl=10, capacity=3, per_peer=2)]

    def test_single_use_expiry_peer_and_capacity(self):
        for store in self.stores():
            with self.subTest(store=type(store).__name__):
                one = store.issue('192.0.2.1')
                two = store.issue('::ffff:192.0.2.1')
                with self.assertRaises(ReplayUnavailable): store.issue('192.0.2.1')
                store.issue('192.0.2.2')
                with self.assertRaises(ReplayUnavailable): store.issue('192.0.2.3')
                self.assertFalse(store.consume(one, '192.0.2.2'))
                self.assertTrue(store.consume(one, '192.0.2.1'))
                self.assertFalse(store.consume(one, '192.0.2.1'))
                self.assertFalse(store.consume('invalid', '192.0.2.1'))
                self.now[0] += 10
                self.assertFalse(store.consume(two, '192.0.2.1'))
                self.assertTrue(store.issue('192.0.2.1'))
                self.now[0] += 10

    def test_sqlite_restart_and_concurrent_consumption(self):
        engine = SQLiteEngine(self.path, policy(), self.secret, clock=lambda: self.now[0])
        store = SQLiteReplay(engine)
        token = store.issue('192.0.2.1')
        restarted = SQLiteReplay(SQLiteEngine(self.path, policy(), self.secret, clock=lambda: self.now[0]))
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(lambda _: restarted.consume(token, '192.0.2.1'), range(30)))
        self.assertEqual(results.count(True), 1)
        with sqlite3.connect(self.path) as con:
            data = ''.join(con.iterdump())
        self.assertNotIn(token, data)
        self.assertNotIn('192.0.2.1', data)

    def test_concurrent_processes_share_replay_state(self):
        engine = SQLiteEngine(self.path, policy(), self.secret, clock=lambda: self.now[0])
        token = SQLiteReplay(engine).issue('192.0.2.1')
        ctx = multiprocessing.get_context('spawn'); queue = ctx.Queue()
        processes = [ctx.Process(target=consume_in_process, args=(self.path,token,queue)) for _ in range(4)]
        for proc in processes: proc.start()
        results = [queue.get(timeout=30) for _ in processes]
        for proc in processes:
            proc.join(30); self.assertEqual(proc.exitcode,0)
        queue.close()
        self.assertEqual(results.count(True),1)

    def assert_delayed_replay(self, mode, operation):
        peer = '192.0.2.1'
        if mode == 'memory':
            store = MemoryReplay(self.secret, lambda: self.now[0], ttl=10)
        else:
            engine = SQLiteEngine(self.path, policy(), self.secret, clock=lambda: self.now[0])
            store = SQLiteReplay(engine, ttl=10)
        token = store.issue(peer) if operation == 'consume' else None
        started = threading.Event()
        if mode == 'memory':
            class ObservedLock:
                def __init__(self): self.lock = threading.Lock()
                def __enter__(self):
                    started.set()
                    self.lock.acquire()
                def __exit__(self, *args): self.lock.release()
            lock = ObservedLock()
            lock.lock.acquire()
            store.lock = lock
            patch = mock.patch.object(store, 'lock', lock)
            release = lock.lock.release
        else:
            holder = sqlite3.connect(self.path, isolation_level=None)
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
        def request():
            return store.issue(peer) if operation == 'issue' else store.consume(token, peer)
        with patch, ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(request)
            try:
                self.assertTrue(started.wait(3), 'request did not reach the lock')
                self.now[0] += 10
            finally:
                release()
            result = future.result(timeout=6)
        if operation == 'consume':
            self.assertFalse(result, 'expired challenge must not be accepted after waiting')
            self.assertFalse(store.consume(token, peer))
        else:
            self.now[0] += 9
            self.assertTrue(store.consume(result, peer), 'new challenge must not expire during its pre-issuance wait')
            self.assertFalse(store.consume(result, peer))

    def test_memory_challenge_issue_wait(self): self.assert_delayed_replay('memory', 'issue')
    def test_memory_challenge_consume_wait(self): self.assert_delayed_replay('memory', 'consume')
    def test_sqlite_challenge_issue_wait(self): self.assert_delayed_replay('sqlite', 'issue')
    def test_sqlite_challenge_consume_wait(self): self.assert_delayed_replay('sqlite', 'consume')

    def test_storage_failure_closed(self):
        engine = SQLiteEngine(self.path, policy(), self.secret, clock=lambda: self.now[0])
        store = SQLiteReplay(engine)
        token = store.issue('192.0.2.1')
        os.unlink(self.path)
        with self.assertRaises(ReplayUnavailable): store.consume(token, '192.0.2.1')
        with self.assertRaises(ReplayUnavailable): store.issue('192.0.2.1')


if __name__ == '__main__':
    unittest.main(verbosity=2)
