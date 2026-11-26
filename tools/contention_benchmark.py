#!/usr/bin/env python3
"""Profile synthetic hot-key contention; not a production load test."""
import argparse
import json
import platform
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import Engine, policy
from sqlite_engine import SQLiteEngine
from signal_validation import synthetic_signal
from gate_benchmark import timings


class Recorder:
    def __init__(self):
        self.guard = threading.Lock()
        self.wait, self.held = [], []

    def add(self, wait, held):
        with self.guard:
            self.wait.append(wait)
            self.held.append(held)


class ProfiledLock:
    def __init__(self, recorder):
        self.lock, self.recorder = threading.Lock(), recorder

    def __enter__(self):
        start = time.perf_counter_ns()
        self.lock.acquire()
        self.acquired = time.perf_counter_ns()
        self.waited = self.acquired - start
        return self

    def __exit__(self, *_):
        held = time.perf_counter_ns() - self.acquired
        waited = self.waited
        self.lock.release()
        self.recorder.add(waited, held)


class ProfiledConnection:
    """Only for this benchmark: timestamp successful SQLite writer boundary."""
    def __init__(self, inner, recorder):
        self.inner, self.recorder = inner, recorder
        self.acquired = None
        self.waited = 0

    def execute(self, sql, *args):
        start = time.perf_counter_ns() if sql == 'BEGIN IMMEDIATE' else None
        result = self.inner.execute(sql, *args)
        if start is not None:
            self.acquired = time.perf_counter_ns()
            self.waited = self.acquired - start
        return result

    def finish(self, action):
        try:
            return action()
        finally:
            if self.acquired is not None:
                self.recorder.add(self.waited, time.perf_counter_ns() - self.acquired)
                self.acquired = None

    def executemany(self, sql, args): return self.inner.executemany(sql, args)
    def commit(self): return self.finish(self.inner.commit)
    def rollback(self): return self.finish(self.inner.rollback)
    def close(self): return self.inner.close()


def run(mode, workers, per_worker, quota):
    if mode not in ('memory', 'sqlite') or type(workers) is not int or not 1 <= workers <= 16:
        raise ValueError('mode must be memory or sqlite; workers must be 1..16')
    if type(per_worker) is not int or not 1 <= per_worker <= 500 or type(quota) is not int or not 1 <= quota <= 10000:
        raise ValueError('per-worker must be 1..500; quota must be 1..10000')
    recorder = Recorder()
    settings = policy(override={'max_requests':quota})
    body = {'signals': {'machine_id': synthetic_signal('machine_id', 'contention')}}
    with tempfile.TemporaryDirectory(prefix='archx-contention-') as directory:
        if mode == 'memory':
            engine = Engine(settings, secret=b'synthetic-contention-only', clock=lambda:1000)
            engine.lock = ProfiledLock(recorder)
        else:
            engine = SQLiteEngine(Path(directory)/'state.sqlite', settings, b'synthetic-contention-only-secret-32-bytes', clock=lambda:1000)
            connect = engine.connect
            engine.connect = lambda: ProfiledConnection(connect(), recorder)
        barrier = threading.Barrier(workers)
        def work(_):
            local_decisions, local_latencies = {}, []
            barrier.wait(timeout=10)
            for i in range(per_worker):
                start = time.perf_counter_ns()
                result = engine.check(body, '192.0.2.1')
                local_latencies.append(time.perf_counter_ns() - start)
                decision = result['decision']
                local_decisions[decision] = local_decisions.get(decision, 0) + 1
            return local_decisions, local_latencies
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(work, range(workers)))
    decisions, latencies = {}, []
    for counts, elapsed in results:
        for k, v in counts.items(): decisions[k] = decisions.get(k, 0) + v
        latencies.extend(elapsed)
    total = workers * per_worker
    if decisions.get('allow', 0) != min(quota, total) or decisions.get('rate_limited', 0) != max(0, total-quota):
        raise RuntimeError('synthetic quota invariant failed')
    if len(recorder.wait) != total or len(recorder.held) != total:
        raise RuntimeError('missing serialization measurement')
    return {'schema':1, 'mode':mode, 'workers':workers, 'requests':total, 'quota':quota,
            'decisions':decisions, 'check_latency_ms':timings(latencies),
            'serialization_wait_ms':timings(recorder.wait), 'serialization_held_ms':timings(recorder.held),
            'environment':{'system':platform.system(), 'architecture':platform.machine(), 'python':platform.python_version()},
            'limitations':['synthetic in-process hot-key workload, no network, multi-process, or production capacity claim',
                           'instrumentation adds overhead; SQLite wait measures BEGIN IMMEDIATE including API overhead and held includes commit',
                           'bounded closed-loop workers; not an open-loop arrival process or a wall-clock guarantee']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('memory', 'sqlite'), default='memory')
    parser.add_argument('--workers', type=int, default=8)
    parser.add_argument('--per-worker', type=int, default=50)
    parser.add_argument('--quota', type=int, default=100)
    args = parser.parse_args()
    try: result = run(args.mode, args.workers, args.per_worker, args.quota)
    except ValueError as exc: parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))

if __name__ == '__main__': main()
