"""Injected clock faults must not expire live quota or history state."""
import copy
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import Engine, policy
from service import RequestService, status_for
from signal_validation import synthetic_signal
from sqlite_engine import SQLiteEngine

SECRET = b'synthetic-engine-clock-test-secret-32'
PEER = '192.0.2.1'
BODY = {'signals': {'machine_id': synthetic_signal('machine_id', 'clock-fault-test')}}


class EngineClockFaultTests(unittest.TestCase):
    def test_invalid_clock_does_not_delete_or_charge_state(self):
        for mode in ('memory', 'sqlite'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                now = [1000.0]
                settings = policy(override={'max_requests': 1, 'window_seconds': 60, 'history_seconds': 120})
                engine = (Engine(settings, SECRET, clock=lambda: now[0]) if mode == 'memory' else
                          SQLiteEngine(Path(tmp) / 'state.sqlite', settings, SECRET, clock=lambda: now[0]))
                self.assertEqual(engine.check(BODY, PEER)['decision'], 'allow')
                def state():
                    if mode == 'memory':
                        return (copy.deepcopy(engine.windows), copy.deepcopy(engine.observations.records))
                    with sqlite3.connect(engine.db_path) as con:
                        return (con.execute('SELECT * FROM windows ORDER BY key').fetchall(),
                                con.execute('SELECT * FROM observations ORDER BY id').fetchall(),
                                con.execute('SELECT * FROM signals ORDER BY observation_id,name').fetchall())
                before = state()
                for bad in (float('nan'), float('inf'), float('-inf'), True, None,
                            '1000', 10 ** 1000, 1e17, 1e300):
                    with self.subTest(clock=repr(bad)[:20]):
                        now[0] = bad
                        self.assertEqual(engine.reject_malformed(PEER)['decision'], 'storage_error')
                        self.assertEqual(state(), before)
                        self.assertEqual(engine.check(BODY, PEER)['decision'], 'storage_error')
                        self.assertEqual(state(), before)
                        with self.assertRaises(ValueError): engine.cleanup_expired()
                        self.assertEqual(state(), before)
                now[0] = 1001.0
                self.assertEqual(engine.check(BODY, PEER)['decision'], 'rate_limited')

    def test_clock_failure_after_input_preparation_fails_closed(self):
        for mode in ('memory', 'sqlite'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                samples = [1000.0, float('inf')]
                def clock(): return samples.pop(0)
                settings = policy()
                engine = (Engine(settings, SECRET, clock=clock) if mode == 'memory' else
                          SQLiteEngine(Path(tmp) / 'state.sqlite', settings, SECRET, clock=clock))
                self.assertEqual(engine.check(BODY, PEER)['decision'], 'storage_error')
                if mode == 'memory': self.assertEqual(engine.windows, {})
                else:
                    with sqlite3.connect(engine.db_path) as con:
                        self.assertEqual(con.execute('SELECT count(*) FROM windows').fetchone()[0], 0)

    def test_clock_exception_is_sanitized_and_state_recovers(self):
        for mode in ('memory', 'sqlite'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                state = {'fail': False}
                def clock():
                    if state['fail']: raise RuntimeError('sensitive internal detail')
                    return 1000.0
                settings = policy(override={'max_requests': 1})
                engine = (Engine(settings, SECRET, clock=clock) if mode == 'memory' else
                          SQLiteEngine(Path(tmp) / 'state.sqlite', settings, SECRET, clock=clock))
                self.assertEqual(engine.check(BODY, PEER)['decision'], 'allow')
                state['fail'] = True
                result = engine.check(BODY, PEER)
                self.assertEqual(result['decision'], 'storage_error')
                self.assertNotIn('sensitive', str(result))
                state['fail'] = False
                self.assertEqual(engine.check(BODY, PEER)['decision'], 'rate_limited')

    def test_service_maps_preparation_clock_failure_to_503(self):
        samples = [1000.0, float('nan')]
        engine = Engine(policy(), SECRET, clock=lambda: samples.pop(0))
        result = RequestService(engine).check(BODY, PEER)
        self.assertEqual(result['decision'], 'storage_error')
        self.assertEqual(status_for(result), 503)


if __name__ == '__main__': unittest.main(verbosity=2)
