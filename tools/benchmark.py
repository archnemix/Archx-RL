#!/usr/bin/env python3
"""Small repeatable synthetic single-process benchmark; not a production load test."""
import hashlib
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'demo'))
from engine import Engine, policy
from sqlite_engine import SQLiteEngine

def measure(factory, n=200):
    e=factory(); samples=[]
    machine=hashlib.sha256(b'synthetic-machine').hexdigest()[:32]
    for i in range(n):
        data={'account':str(i),'signals':{'machine_id':machine}}
        start=time.perf_counter()
        decision=e.check(data, f'198.18.0.{i%250+1}')['decision']
        samples.append((time.perf_counter()-start)*1000)
        if decision!='allow': raise RuntimeError('Unexpected benchmark decision')
    samples.sort()
    return {'requests':n,'median_ms':round(statistics.median(samples),3),'p95_ms':round(samples[int(n*.95)-1],3), 'max_ms':round(samples[-1],3)}

p=policy(override={'max_requests':10000})
secret=b'synthetic-benchmark-secret-0123456789'
with tempfile.TemporaryDirectory() as d:
    memory=measure(lambda:Engine(p,secret=secret,clock=lambda:1700000000.0))
    sqlite=measure(lambda:SQLiteEngine(str(Path(d)/'benchmark.sqlite'),p,secret,clock=lambda:1700000000.0))
print(json.dumps({'description':'synthetic single-process sequential microbenchmark; runner-specific, not a capacity target','memory':memory,'sqlite':sqlite},sort_keys=True))
