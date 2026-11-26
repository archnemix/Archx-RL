#!/usr/bin/env python3
"""Synthetic sequential expiry backlog measurements, not a production capacity test."""
import argparse
import json
import math
import platform
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import Engine, policy
from signal_validation import synthetic_signal


def run(population, waves):
    if type(population) is not int or not 1 <= population <= 10000:
        raise ValueError('population must be 1..10000')
    if type(waves) is not int or not 1 <= waves <= 20:
        raise ValueError('waves must be 1..20')
    now = 1000
    data = {'signals': {'machine_id': synthetic_signal('machine_id', 'expiry-benchmark')}}
    elapsed, removed, decisions, recovery_relations = [], [], {}, []
    max_heap = max_records = 0
    for wave in range(waves):
        engine = Engine(policy(override={'max_requests':10000}), secret=b'synthetic-benchmark-only',
                        clock=lambda:now, max_entries=population * 2 + 8)
        target = engine.token('machine_id', data['signals']['machine_id'])
        # Isolated synthetic preloading avoids timing setup and allows arbitrary
        # expiry backlog size independent of the separate rate-window capacity.
        for i in range(population):
            token = target if i == population - 1 else engine.token('machine_id', str(i))
            engine.observations.enroll({'machine_id':token, 'ip':'synthetic-'+str(i)}, now - 1)
            engine._new_window('synthetic-window-'+str(i), now)[1] = 1
        max_heap = max(max_heap, len(engine.observations.expiries))
        max_records = max(max_records, len(engine.observations))
        while True:
            before = len(engine.observations)
            start = time.perf_counter_ns()
            result = engine.check(data, '192.0.2.1')
            elapsed.append(time.perf_counter_ns() - start)
            decision = result['decision']
            decisions[decision] = decisions.get(decision, 0) + 1
            # Last successful check enrolls exactly one new observation.
            removed.append(before - len(engine.observations) + (decision == 'allow'))
            if decision == 'allow':
                recovery_relations.append(result['relation'])
                break
            if decision != 'capacity_exceeded' or len(elapsed) > waves * (math.ceil(population / 64) + 1):
                raise RuntimeError('unexpected backlog behavior')
    ordered = sorted(elapsed)
    percentile = lambda p: round(ordered[max(0, math.ceil(p * len(ordered)) - 1)] / 1e6, 3)
    return {'schema':1, 'population_per_wave':population, 'waves':waves,
            'expired_removed':sum(removed), 'max_removed_per_check':max(removed),
            'peak_observations':max_records, 'peak_expiry_heap_entries':max_heap,
            'decisions':decisions, 'recovery_relations':recovery_relations,
            'check_latency_ms':{'p50':percentile(.5), 'p95':percentile(.95),
                                'p99':percentile(.99), 'max':percentile(1)},
            'environment':{'system':platform.system(), 'architecture':platform.machine(),
                           'python':platform.python_version()},
            'limitations':['synthetic seeded in-process sequential checks; excludes preload, HTTP, TLS and concurrent load',
                           'each wave includes a synthetic live rate-window population; latency includes indexed window checking and all check work',
                           'runner-specific measurement, not a production capacity result or performance budget',
                           'idle expiry does not run; stale state remains bounded by configured capacity']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--population', type=int, default=1000)
    parser.add_argument('--waves', type=int, default=5)
    args = parser.parse_args()
    try: report = run(args.population, args.waves)
    except ValueError as exc: parser.error(str(exc))
    print(json.dumps(report, sort_keys=True))

if __name__ == '__main__': main()
