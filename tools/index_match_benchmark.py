#!/usr/bin/env python3
"""Compare synthetic sparse history matching: old linear loop vs current index."""
import argparse
import json
import platform
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from observation_index import ObservationIndex
from gate_benchmark import timings


def linear_match(records, tokens, threshold):
    # Equivalent matching logic from the pre-index engine; not its eviction,
    # cleanup, enrollment, rate limits or full end-to-end request behavior.
    best = []
    possible = False
    for prior in records:
        matching = [name for name, value in tokens.items() if prior.get(name) == value]
        if len(matching) > len(best): best = matching
        possible |= len(set(tokens) & set(prior)) >= threshold
    relation = ('related' if len(best) >= threshold else
                'below_threshold' if records and possible else
                'inconclusive' if records else 'new')
    return relation, best


def run(population, samples):
    if type(population) is not int or not 1 <= population <= 10000 or type(samples) is not int or not 1 <= samples <= 1000:
        raise ValueError('population and samples out of bounds')
    index, records = ObservationIndex(population), []
    for i in range(population):
        item = {'machine_id':'synthetic-'+str(i), 'ip':'synthetic-'+str(i)}
        index.enroll(item, 2000); records.append(item)
    tokens = dict(records[-1]); threshold = 2
    linear, indexed = [], []
    for _ in range(samples):
        start = time.perf_counter_ns()
        a = linear_match(records, tokens, threshold)
        linear.append(time.perf_counter_ns() - start)
        start = time.perf_counter_ns()
        b = index.match(tokens, threshold)
        indexed.append(time.perf_counter_ns() - start)
        if a != b or b[0] != 'related': raise RuntimeError('matching parity failed')
    return {'schema':1, 'population':population, 'samples':samples,
            'matching_observations':1, 'linear_match_ms':timings(linear), 'indexed_match_ms':timings(indexed),
            'environment':{'system':platform.system(), 'architecture':platform.machine(), 'python':platform.python_version()},
            'limitations':['single-thread synthetic sparse-match microbenchmark; not end-to-end lock or production latency',
                           'pre-index matching loop only; old enrollment and eviction semantics differ and are not compared',
                           'popular shared tokens can still have capacity-sized postings; other critical-section work remains',
                           'setup excluded, host and instrumentation dependent; no agreed performance budget']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--population', type=int, default=5000)
    parser.add_argument('--samples', type=int, default=100)
    args = parser.parse_args()
    try: result = run(args.population, args.samples)
    except ValueError as exc: parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))

if __name__ == '__main__': main()
