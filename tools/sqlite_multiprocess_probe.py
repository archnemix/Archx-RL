#!/usr/bin/env python3
"""Short synthetic same-host SQLite reader/writer/replay probe, not a soak test."""
import collections
import json
import multiprocessing as mp
import platform
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'demo'))
from engine import policy
from replay import SQLiteReplay
from signal_validation import synthetic_signal
from sqlite_engine import SQLiteEngine

SECRET=b'synthetic-multiprocess-profile-secret-1234'
SETTINGS=policy(override={'max_requests':100})
BODY={'signals':{'machine_id':synthetic_signal('machine_id','synthetic-shared')}}
PEER='192.0.2.1'


def worker(path, kind, iterations, nonce, barrier, queue):
    try:
        engine=SQLiteEngine(path,SETTINGS,SECRET,clock=lambda:1000)
        replay=SQLiteReplay(engine) if kind=='replay' else None
        barrier.wait(30)
        start=time.monotonic()
        outcomes=collections.Counter()
        if kind=='writer':
            for _ in range(iterations): outcomes[engine.check(BODY,PEER)['decision']]+=1
        elif kind=='reader':
            for _ in range(iterations):
                # Read-only application-independent snapshot of aggregate row count.
                with sqlite3.connect(Path(path).as_uri()+'?mode=ro',uri=True,timeout=5) as con:
                    con.execute('SELECT count(*) FROM windows').fetchone(); outcomes['reads']+=1
        else:
            outcomes['consumed' if replay.consume(nonce,PEER) else 'rejected']+=1
        queue.put({'kind':kind,'outcomes':dict(outcomes),'elapsed_seconds':round(time.monotonic()-start,3)})
    except BaseException as exc:
        queue.put({'kind':kind,'error':type(exc).__name__})


def run(iterations=100):
    if type(iterations) is not int or not 1 <= iterations <= 1000: raise ValueError('invalid iterations')
    ctx=mp.get_context('spawn')
    with tempfile.TemporaryDirectory(prefix='archx-sqlite-probe-') as tmp:
        path=str(Path(tmp)/'synthetic.sqlite')
        engine=SQLiteEngine(path,SETTINGS,SECRET,clock=lambda:1000)
        replay=SQLiteReplay(engine); nonce=replay.issue(PEER)
        kinds=['writer']*4+['reader']*2+['replay']*2
        barrier=ctx.Barrier(len(kinds)); queue=ctx.Queue()
        processes=[ctx.Process(target=worker,args=(path,kind,iterations,nonce,barrier,queue)) for kind in kinds]
        start=time.monotonic()
        for p in processes: p.start()
        try:
            results=[queue.get(timeout=60) for _ in processes]
            for p in processes: p.join(60)
            if any(p.is_alive() or p.exitcode != 0 for p in processes): raise RuntimeError('worker failed or timed out')
        finally:
            for p in processes:
                if p.is_alive(): p.terminate(); p.join()
            queue.close(); queue.join_thread()
        if any('error' in item for item in results): raise RuntimeError('synthetic worker failure: '+str(results))
        aggregate={kind:dict(sum((collections.Counter(x['outcomes']) for x in results if x['kind']==kind),collections.Counter())) for kind in ('writer','reader','replay')}
        with sqlite3.connect(path) as con:
            journal=con.execute('PRAGMA journal_mode').fetchone()[0]
            window_counts=sorted(row[0] for row in con.execute('SELECT count FROM windows'))
            remaining=con.execute('SELECT count(*) FROM replay_challenges_v1').fetchone()[0]
        return {'environment':{'system':platform.system(),'machine':platform.machine(),'python':platform.python_version(),'sqlite':sqlite3.sqlite_version},
                'description':'short local spawn-process synthetic probe, no network; not production workload or sustained soak',
                'writers':4,'readers':2,'replay_consumers':2,'iterations_per_writer_or_reader':iterations,
                'elapsed_seconds':round(time.monotonic()-start,3),'journal':journal,'aggregate':aggregate,
                'window_counts':window_counts,'pending_challenges':remaining,
                'worker_elapsed_seconds':{kind:sorted(x['elapsed_seconds'] for x in results if x['kind']==kind) for kind in ('writer','reader','replay')}}

if __name__=='__main__': print(json.dumps(run(),indent=2))
