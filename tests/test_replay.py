"""Test single-use challenge bounds, expiry, persistence and concurrency."""
import os
import multiprocessing
import sqlite3
import sys
import tempfile
import unittest
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

    def test_storage_failure_closed(self):
        engine = SQLiteEngine(self.path, policy(), self.secret, clock=lambda: self.now[0])
        store = SQLiteReplay(engine)
        token = store.issue('192.0.2.1')
        os.unlink(self.path)
        with self.assertRaises(ReplayUnavailable): store.consume(token, '192.0.2.1')
        with self.assertRaises(ReplayUnavailable): store.issue('192.0.2.1')


if __name__ == '__main__':
    unittest.main(verbosity=2)
