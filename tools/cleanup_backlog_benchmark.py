#!/usr/bin/env python3
"""Synthetic expiry backlog draining in the two prototype stores, not a capacity test."""
import argparse
import json
import platform
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import Engine, policy
from sqlite_engine import SQLiteEngine
from signal_validation import synthetic_signal
from gate_benchmark import timings

SECRET = b'synthetic-expiry-benchmark-secret-0123456789'


def run(mode, population):
    if mode not in ('memory','sqlite') or type(population) is not int or not 1 <= population <= 10000:
        raise ValueError('mode must be memory or sqlite, population must be 1..10000')
    now = 1000.0
    body = {'signals':{'machine_id':synthetic_signal('machine_id','backlog-target')}}
    with tempfile.TemporaryDirectory(prefix='archx-cleanup-profile-') as tmp:
        p = policy(override={'window_seconds':60, 'max_requests':10000})
        e = Engine(p, secret=SECRET, clock=lambda:now, max_entries=population+8) if mode == 'memory' else SQLiteEngine(Path(tmp)/'state.sqlite', p, SECRET, clock=lambda:now, max_entries=population+8)
        target = e.token('machine_id', body['signals']['machine_id'])
        if mode == 'memory':
            for i in range(population):
                token = target if i == population-1 else 'synthetic-'+str(i)
                e._new_window(token, now-60)[1] = 3
                e.observations.enroll({'machine_id':token, 'ip':'synthetic-'+str(i)}, now-1)
        else:
            with sqlite3.connect(e.db_path) as con:
                for i in range(population):
                    token = target if i == population-1 else 'synthetic-'+str(i)
                    con.execute('INSERT INTO windows(key,start,count) VALUES (?,?,?)', (token, now-60, 3))
                    cur = con.execute('INSERT INTO observations(expires,fingerprint) VALUES (?,?)', (now-1, str(i)))
                    con.executemany('INSERT INTO signals(observation_id,name,token) VALUES (?,?,?)', [(cur.lastrowid,'machine_id',token),(cur.lastrowid,'ip','synthetic-'+str(i))])
        def stale():
            if mode == 'memory':
                return (sum(row[0] <= now-60 for row in e.windows.values()),
                        sum(row[0] <= now for row in e.observations.records.values()))
            with sqlite3.connect(e.db_path) as con:
                return (con.execute('SELECT count(*) FROM windows WHERE start <= ?', (now-60,)).fetchone()[0],
                        con.execute('SELECT count(*) FROM observations WHERE expires <= ?', (now,)).fetchone()[0])
        durations, decisions = [], {}
        last_window, last_history = stale()
        max_window = max_history = 0
        while True:
            start = time.perf_counter_ns()
            result = e.check(body, '192.0.2.1')
            durations.append(time.perf_counter_ns() - start)
            decision = result['decision']; decisions[decision] = decisions.get(decision, 0) + 1
            windows, history = stale() # outside recorded duration, but may warm caches
            max_window = max(max_window, last_window-windows)
            max_history = max(max_history, last_history-history)
            last_window, last_history = windows, history
            if decision == 'allow':
                if result['relation'] != 'new' or windows or history: raise RuntimeError('stale state used')
                break
            if decision != 'capacity_exceeded' or len(durations) > population*2+2: raise RuntimeError('unexpected decision')
    return {'schema':1,'mode':mode,'expired_windows_seeded':population,'expired_observations_seeded':population,
            'requests':len(durations),'decisions':decisions,'recovery_relation':'new',
            'max_windows_removed_per_check':max_window,'max_observations_removed_per_check':max_history,
            'check_latency_ms':timings(durations),
            'environment':{'system':platform.system(),'architecture':platform.machine(),'python':platform.python_version()},
            'limitations':['synthetic sequential in-process backlog, no network or production capacity claim',
                           'preload excluded; stale-count queries outside timings can affect cache state',
                           'per-check times include other gate and SQLite transaction work; no latency budget or idle cleanup']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=('memory','sqlite'),default='memory')
    parser.add_argument('--population',type=int,default=5000)
    args=parser.parse_args()
    try: report=run(args.mode,args.population)
    except ValueError as exc: parser.error(str(exc))
    print(json.dumps(report,sort_keys=True))

if __name__=='__main__': main()
