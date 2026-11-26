#!/usr/bin/env python3
"""Timed, synthetic single-host SQLite mixed-process profile, not production capacity."""
import argparse
import collections
import json
import multiprocessing as mp
import os
import platform
import sqlite3
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'demo'))
from engine import policy
from metrics import ServiceMetrics
from replay import SQLiteReplay, ReplayUnavailable
from signal_validation import synthetic_signal
from sqlite_engine import SQLiteEngine

SECRET=b'synthetic-sqlite-soak-secret-at-least-32-bytes'
SETTINGS=policy(override={'max_requests':100})
PEER='192.0.2.1'
BODY={'signals':{'machine_id':synthetic_signal('machine_id','synthetic-soak')}}


def worker(path, kind, seconds, nonces, reserved, barrier, queue):
    try:
        metrics=ServiceMetrics()
        engine=SQLiteEngine(path,SETTINGS,SECRET,clock=lambda:1000,metrics=metrics)
        replay=SQLiteReplay(engine) if kind in ('replay','fault') else None
        if kind=='fault':
            engine.connect=lambda: sqlite3.connect(Path(path).as_uri()+'?mode=ro',uri=True,timeout=5,isolation_level=None)
        barrier.wait(30)
        start=time.monotonic(); cpu=time.process_time(); counts=collections.Counter(); lat=[]
        if kind=='replay':
            # Both consumers attempt each token, staggered across the run.
            for i,token in enumerate(nonces):
                target=start+seconds*i/len(nonces)
                delay=target-time.monotonic()
                if delay > 0: time.sleep(delay)
                t=time.perf_counter(); ok=replay.consume(token,PEER); lat.append(time.perf_counter()-t)
                counts['consumed' if ok else 'rejected']+=1
        else:
            while time.monotonic()-start < seconds:
                t=time.perf_counter()
                if kind=='writer':
                    counts[engine.check(BODY,PEER)['decision']]+=1
                elif kind=='reader':
                    with closing(sqlite3.connect(Path(path).as_uri()+'?mode=ro',uri=True,timeout=5)) as con:
                        con.execute('SELECT count(*) FROM windows').fetchone(); counts['reads']+=1
                else:
                    result=engine.check(BODY,PEER)
                    counts['storage_error' if result['decision']=='storage_error' else 'unexpected_decision']+=1
                    try:
                        replay.consume(reserved,PEER)
                        counts['unexpected_replay_result']+=1
                    except ReplayUnavailable:
                        counts['replay_unavailable']+=1
                lat.append(time.perf_counter()-t)
                if kind=='fault': time.sleep(.1)
        lat.sort()
        def percentile(p): return round(lat[min(len(lat)-1,int((len(lat)-1)*p))]*1000,3) if lat else None
        queue.put({'kind':kind,'counts':dict(counts),'operations':len(lat),'elapsed_seconds':round(time.monotonic()-start,3),
                   'cpu_seconds':round(time.process_time()-cpu,3),'p50_ms':percentile(.5),'p95_ms':percentile(.95),
                   'p99_ms':percentile(.99),'max_ms':percentile(1),'serialization_wait':metrics.snapshot()['serialization_wait_seconds']})
    except BaseException as exc:
        queue.put({'kind':kind,'error':type(exc).__name__})


def run(seconds=8, nonce_count=40):
    if type(seconds) not in (int,float) or not 1 <= seconds <= 30 or type(nonce_count) is not int or not 2 <= nonce_count <= 100:
        raise ValueError('invalid synthetic workload')
    ctx=mp.get_context('spawn')
    with tempfile.TemporaryDirectory(prefix='archx-soak-') as tmp:
        path=str(Path(tmp)/'state.sqlite')
        e=SQLiteEngine(path,SETTINGS,SECRET,clock=lambda:1000)
        replay=SQLiteReplay(e,capacity=200,per_peer=200)
        nonces=[replay.issue(PEER) for _ in range(nonce_count)]
        reserved=replay.issue(PEER)
        # Deliberately pin a read snapshot throughout the run to observe WAL growth.
        anchor=sqlite3.connect(path,timeout=5,isolation_level=None)
        anchor.execute('BEGIN')
        anchor.execute('SELECT count(*) FROM windows').fetchone()
        kinds=['writer']*4+['reader']*2+['replay']*2+['fault']
        barrier=ctx.Barrier(len(kinds)); queue=ctx.Queue()
        processes=[ctx.Process(target=worker,args=(path,k,seconds,nonces,reserved,barrier,queue)) for k in kinds]
        started=time.monotonic()
        for proc in processes: proc.start()
        try:
            results=[queue.get(timeout=90) for _ in processes]
            for proc in processes: proc.join(90)
            if any(proc.is_alive() or proc.exitcode != 0 for proc in processes): raise RuntimeError('synthetic worker failed')
        finally:
            for proc in processes:
                if proc.is_alive(): proc.terminate(); proc.join()
            queue.close(); queue.join_thread()
        if any('error' in r for r in results): raise RuntimeError('worker errors '+str(results))
        aggregates={k:dict(sum((collections.Counter(r['counts']) for r in results if r['kind']==k),collections.Counter())) for k in set(kinds)}
        writer_count=sum(aggregates['writer'].values())
        wal_bytes=os.path.getsize(path+'-wal') if os.path.exists(path+'-wal') else 0
        # Checkpoint from another connection while the old snapshot remains pinned.
        with closing(sqlite3.connect(path,timeout=5,isolation_level=None)) as checkpoint_con:
            checkpoint=list(checkpoint_con.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone())
        anchor.rollback()
        remaining=anchor.execute('SELECT count(*) FROM replay_challenges_v1').fetchone()[0]
        window_counts=sorted(r[0] for r in anchor.execute('SELECT count FROM windows'))
        query_plans={
            'window_cleanup':[r[3] for r in anchor.execute('EXPLAIN QUERY PLAN SELECT key FROM windows WHERE start <= ? ORDER BY start LIMIT ?', (940,64))],
            'history_cleanup':[r[3] for r in anchor.execute('EXPLAIN QUERY PLAN SELECT id FROM observations WHERE expires <= ? ORDER BY expires LIMIT ?', (1000,64))],
            'signal_lookup':[r[3] for r in anchor.execute('EXPLAIN QUERY PLAN SELECT observation_id FROM signals WHERE name=? AND token=?',('machine_id','synthetic'))],
            'replay_expiry':[r[3] for r in anchor.execute('EXPLAIN QUERY PLAN SELECT token FROM replay_challenges_v1 WHERE expires <= ?', (1000,))]}
        checkpoint_after_release=list(anchor.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone())
        anchor.close()
        # The read-only injected failure must not have consumed its reserved token.
        recovered=replay.consume(reserved,PEER)
        replayed=replay.consume(reserved,PEER)
        return {'schema':1,'description':'timed synthetic single-host multiprocess experiment; not a deployment or fault-durability certification',
                'environment':{'system':platform.system(),'machine':platform.machine(),'python':platform.python_version(),'sqlite':sqlite3.sqlite_version},
                'requested_seconds':seconds,'total_wall_seconds':round(time.monotonic()-started,3),
                'workers':results,'aggregate':aggregates,'writer_attempts':writer_count,'window_counts':window_counts,
                'pending_before_recovery':remaining,'reserved_consumed_after_fault':recovered,'reserved_replay_after_recovery':replayed,
                'journal':'WAL','wal_size_bytes_before_checkpoint':wal_bytes,'passive_checkpoint_while_pinned':checkpoint,
                'passive_checkpoint_after_release':checkpoint_after_release,'query_plans':query_plans,
                'limitations':['one temporary local WAL store with fixed synthetic keys and clock and one deliberately pinned read snapshot; no production load claims',
                               'writer operations each open a new engine connection; replay and read operations also churn connections',
                               'read-only injected write failure is not disk full, power loss, fsync failure or process death',
                               'the SQLite busy timeout is not an end-to-end deadline; readers and writers may outlive the requested interval']}

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--seconds',type=float,default=8)
    parser.add_argument('--nonces',type=int,default=40)
    args=parser.parse_args()
    print(json.dumps(run(seconds=args.seconds,nonce_count=args.nonces),indent=2))
