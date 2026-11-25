#!/usr/bin/env python3
"""Closed-loop synthetic in-process gate benchmark; not a capacity certification.

The generator caps submitted-but-uncollected work. No network, real IDs or
external providers are involved. Timings include generator/host overhead.
"""
import argparse
import json
import math
import os
import platform
import resource
import sys
import tempfile
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import Engine, policy
from service import RequestService
from signal_validation import synthetic_signal
from sqlite_engine import SQLiteEngine

DECISIONS = ('allow', 'invalid', 'challenge', 'rate_limited', 'capacity_exceeded', 'storage_error', 'unexpected')
SECRET = b'benchmark-only-synthetic-secret-not-for-use'


def percentile(values, fraction):
    if not values: return None
    ordered = sorted(values)
    return round(ordered[max(0, math.ceil(fraction * len(ordered)) - 1)] / 1e6, 3)


def timings(values):
    return {'p50':percentile(values, .50), 'p95':percentile(values, .95),
            'p99':percentile(values, .99), 'max':percentile(values, 1.0)}


def sample(index, scenario, *, preload=False):
    if preload:
        seed, host = 'preload-'+str(index), index+1
        address = f'2001:db8:1::{host:x}'
    elif scenario == 'duplicate':
        seed, address = 'duplicate', '2001:db8:2::1'
    elif scenario == 'shared-ip':
        seed, address = 'load-'+str(index), '2001:db8:2::1'
    else:
        seed, address = 'load-'+str(index), f'2001:db8:2::{index+1:x}'
    return {'signals':{'machine_id':synthetic_signal('machine_id', seed)}}, address


def create_engine(mode, path, settings, capacity, clock=None):
    if mode == 'memory':
        return Engine(settings, secret=SECRET, max_entries=capacity, clock=clock)
    return SQLiteEngine(path, settings, SECRET, max_entries=capacity, clock=clock)


def measure(gate, count, scenario, workers, max_outstanding):
    """Run a closed-loop load; outstanding includes running and queued calls."""
    counts = dict.fromkeys(DECISIONS, 0)
    queue_ns, call_ns, total_ns = [], [], []
    peak_outstanding, exceptions = 0, 0

    def task(body, peer, submitted):
        started = time.perf_counter_ns()
        error = False
        try:
            decision = gate.check(body, peer).get('decision')
            if type(decision) is not str or decision not in counts: decision = 'unexpected'
        except Exception:
            decision, error = 'unexpected', True
        ended = time.perf_counter_ns()
        return decision, error, started-submitted, ended-started, ended-submitted

    begin, cpu_begin = time.perf_counter_ns(), time.process_time_ns()
    next_index = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending = set()
        while next_index < count or pending:
            while next_index < count and len(pending) < max_outstanding:
                data, peer = sample(next_index, scenario)
                submitted = time.perf_counter_ns()
                pending.add(executor.submit(task, data, peer, submitted))
                next_index += 1
                peak_outstanding = max(peak_outstanding, len(pending))
            done, pending = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                decision, error, q, c, t = future.result()
                counts[decision] += 1
                exceptions += int(error)
                queue_ns.append(q); call_ns.append(c); total_ns.append(t)
    elapsed = time.perf_counter_ns() - begin
    cpu = time.process_time_ns() - cpu_begin
    return {'requests':count, 'decisions':counts, 'exceptions':exceptions,
            'elapsed_seconds':round(elapsed/1e9, 6), 'process_cpu_seconds':round(cpu/1e9, 6),
            'completed_per_second':round(count/(elapsed/1e9), 2) if elapsed else None,
            'peak_submitted_uncollected':peak_outstanding,
            'queue_wait_ms':timings(queue_ns), 'gate_call_ms':timings(call_ns),
            'submit_to_complete_ms':timings(total_ns)}


def recovery(mode, directory):
    """Synthetic clock: reject distinct history at capacity, then expire it."""
    now = [1700000000.0]
    settings = policy(override={'max_requests':100, 'window_seconds':1, 'history_seconds':60})
    engine = create_engine(mode, os.path.join(directory, 'recovery.sqlite'), settings, 4, lambda:now[0])
    for i in range(4):
        body, peer = sample(i, 'unique', preload=True)
        if engine.check(body, peer)['decision'] != 'allow': raise RuntimeError('Synthetic recovery setup failed')
        now[0] += 2
    body, peer = sample(12, 'unique')
    denied = engine.check(body, peer)
    now[0] += 59
    recovered = engine.check(body, peer)
    return {'at_capacity':denied['decision'], 'retry_after_seconds':denied.get('retry_after_seconds'),
            'after_expiry':recovered['decision'], 'clock_advance_seconds':59}


def run(mode, scenario, population, count, workers, max_outstanding):
    settings = policy(override={'max_requests':10000, 'history_seconds':3600})
    capacity = 2 * (population + count) + 8
    with tempfile.TemporaryDirectory(prefix='archx-synthetic-benchmark-') as directory:
        engine = create_engine(mode, os.path.join(directory, 'gate.sqlite'), settings, capacity)
        for i in range(population):
            body, peer = sample(i, scenario, preload=True)
            if engine.check(body, peer)['decision'] != 'allow': raise RuntimeError('Synthetic preload failed')
        metrics = measure(RequestService(engine), count, scenario, workers, max_outstanding)
        recovery_result = recovery(mode, directory)
    # ru_maxrss units differ across OSes. The single-host benchmark is Linux-only.
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss if sys.platform.startswith('linux') else None
    return {'schema':1, 'mode':mode, 'scenario':scenario, 'preloaded_observations':population,
            'max_entries':capacity, 'workers':workers, 'max_outstanding':max_outstanding,
            'measurements':metrics, 'process_peak_rss_kib':rss, 'recovery':recovery_result,
            'environment':{'system':platform.system(), 'architecture':platform.machine(), 'python':platform.python_version()},
            'limitations':['synthetic in-process closed-loop load; not HTTP, TLS, real clients or production capacity',
                           'process CPU includes generator; peak RSS is process-lifetime high-water, not a per-run delta',
                           'submitted-uncollected work includes running tasks and is not a server queue measurement',
                           'no agreed performance budgets or pass/fail capacity targets']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('memory','sqlite'), default='memory')
    parser.add_argument('--scenario', choices=('unique','shared-ip','duplicate'), default='unique')
    parser.add_argument('--population', type=int, default=100)
    parser.add_argument('--requests', type=int, default=200)
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--max-outstanding', type=int, default=16)
    args = parser.parse_args()
    if not (0 <= args.population <= 5000 and 1 <= args.requests <= 5000 and
            1 <= args.workers <= 32 and args.workers <= args.max_outstanding <= 128):
        parser.error('population 0..5000, requests 1..5000, workers 1..32, and workers <= max-outstanding <= 128 required')
    print(json.dumps(run(args.mode, args.scenario, args.population, args.requests, args.workers, args.max_outstanding), sort_keys=True))

if __name__ == '__main__': main()
