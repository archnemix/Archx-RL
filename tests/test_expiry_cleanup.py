"""Synthetic bounded window cleanup, parity and reference-model checks."""
import random
import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import CLEANUP_BUDGET, Engine, policy
from sqlite_engine import SQLiteEngine
from signal_validation import synthetic_signal

SECRET = b'synthetic-expiry-cleanup-test-secret-1234'
PEER = '192.0.2.1'
BODY = {'signals': {'machine_id': synthetic_signal('machine_id', 'expired-victim')}}


class WindowCleanupTests(unittest.TestCase):
    def test_heap_and_exact_expiry_match_simple_model(self):
        rng = random.Random(813234)
        e = Engine(policy(override={'window_seconds':60}), secret=SECRET, max_entries=50)
        model = {}
        now = 1000.0
        for _ in range(5000):
            now += rng.choice((-5, 0, 0, 1, 2, 30))
            model = {key: row for key, row in model.items() if row[0] > now-60}
            self.assertFalse(e._prune_windows(now)) # at most 50 entries
            key = str(rng.randrange(50))
            expected = model.setdefault(key, [now,0]); expected[1] += 1
            e._window(key, now)[1] += 1
            self.assertEqual(e.windows, model)
            self.assertEqual(len(e.window_expiries), len(model))
            self.assertEqual(len(e.window_expiries.positions), len(model))
            for index, (start, item) in enumerate(e.window_expiries.heap):
                self.assertEqual(e.window_expiries.positions[item], index)
                self.assertEqual(e.windows[item][0], start)
                if index: self.assertLessEqual(e.window_expiries.heap[(index-1)//2], (start, item))

    def test_window_backlog_fails_closed_without_charging_then_recovers(self):
        for mode in ('memory', 'sqlite'):
            for malformed in (False, True):
                with self.subTest(mode=mode, malformed=malformed), tempfile.TemporaryDirectory() as tmp:
                    now = 1000.0
                    p = policy(override={'window_seconds':60, 'max_requests':1000})
                    if mode == 'memory':
                        e = Engine(p, secret=SECRET, clock=lambda:now, max_entries=200)
                    else:
                        e = SQLiteEngine(Path(tmp)/'state.sqlite', p, SECRET, clock=lambda:now, max_entries=200)
                    peer = e.ip_key(PEER)
                    victim = e.token('machine_id', BODY['signals']['machine_id'])
                    keys = [victim] + ['synthetic-expired-'+str(i) for i in range(149)]
                    rows = [(key, now-60, 17) for key in keys] + [(peer, now, 1)]
                    if mode == 'memory':
                        for key, start, count in rows: e._new_window(key, start)[1] = count
                    else:
                        with sqlite3.connect(e.db_path) as con:
                            con.executemany('INSERT INTO windows(key,start,count) VALUES(?,?,?)', rows)
                    def state():
                        if mode == 'memory': return {key:tuple(row) for key,row in e.windows.items()}
                        with sqlite3.connect(e.db_path) as con:
                            return {key:(start,count) for key,start,count in con.execute('SELECT key,start,count FROM windows')}
                    def call(): return e.reject_malformed(PEER) if malformed else e.check(BODY, PEER)
                    for expected_expired in (150-CLEANUP_BUDGET, 150-2*CLEANUP_BUDGET):
                        result = call()
                        self.assertEqual((result['decision'], result['retry_after_seconds']), ('capacity_exceeded',1))
                        saved = state()
                        self.assertEqual(sum(start <= now-60 for start, _ in saved.values()),expected_expired)
                        self.assertEqual(saved[peer], (now,1)) # no charge while stale entries remain
                        self.assertEqual(len(saved), expected_expired+1)
                        if mode == 'memory': self.assertEqual(len(e.window_expiries),len(saved))
                    result = call()
                    if malformed: self.assertIsNone(result)
                    else: self.assertEqual((result['decision'],result['relation']),('allow','new'))
                    saved = state()
                    self.assertEqual(saved[peer], (now,2))
                    if not malformed: self.assertEqual(saved[victim], (now,1)) # not 18
                    self.assertFalse(any(start <= now-60 for start,_ in saved.values()))
                    if mode == 'memory': self.assertEqual(len(e.window_expiries),len(saved))

    def test_concurrent_requests_cannot_match_backlog_or_over_admit(self):
        for mode in ('memory','sqlite'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                now = 1000.0
                p = policy(override={'window_seconds':60, 'max_requests':1000})
                e = Engine(p, secret=SECRET, clock=lambda:now, max_entries=200) if mode == 'memory' else SQLiteEngine(Path(tmp)/'state.sqlite', p, SECRET, clock=lambda:now, max_entries=200)
                target = e.token('machine_id', BODY['signals']['machine_id'])
                if mode == 'memory':
                    for i in range(150):
                        token = target if i == 149 else 'synthetic-'+str(i)
                        e._new_window(token, now-60)[1] = 7
                        e.observations.enroll({'machine_id':token,'ip':'synthetic-'+str(i)},now-1)
                else:
                    with sqlite3.connect(e.db_path) as con:
                        for i in range(150):
                            token = target if i == 149 else 'synthetic-'+str(i)
                            con.execute('INSERT INTO windows(key,start,count) VALUES (?,?,?)',(token,now-60,7))
                            cur = con.execute('INSERT INTO observations(expires,fingerprint) VALUES (?,?)',(now-1,str(i)))
                            con.executemany('INSERT INTO signals(observation_id,name,token) VALUES (?,?,?)',[(cur.lastrowid,'machine_id',token),(cur.lastrowid,'ip','synthetic-'+str(i))])
                with ThreadPoolExecutor(max_workers=8) as pool:
                    results = list(pool.map(lambda _: e.check(BODY, PEER), range(32)))
                self.assertEqual(sum(r['decision']=='capacity_exceeded' for r in results),4)
                allowed = [r for r in results if r['decision']=='allow']
                self.assertEqual(len(allowed),28)
                self.assertEqual(sum(r['relation']=='new' for r in allowed),1)
                self.assertEqual(sum(r['relation']=='related' for r in allowed),27)


if __name__ == '__main__': unittest.main(verbosity=2)
