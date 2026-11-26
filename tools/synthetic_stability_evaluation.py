#!/usr/bin/env python3
"""Controlled synthetic pair evaluation; labels and change rates are assumptions."""
import argparse
import json
import math
import random
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import Engine, policy
from signal_validation import synthetic_signal

FIELDS = ('machine_id', 'product_uuid', 'board_serial')
SCENARIOS = ('stable', 'shared_nat', 'cloned_vm', 'reinstall', 'permissions', 'hardware_change', 'full_rotation', 'forged_replay')


def wilson(successes, total):
    if not total: return None
    z = 1.959963984540054
    p = successes / total
    divisor = 1 + z*z / total
    center = (p + z*z/(2*total))/divisor
    half = z*math.sqrt(p*(1-p)/total + z*z/(4*total*total))/divisor
    return [round(max(0, center-half), 4), round(min(1, center+half), 4)]


def sample(scenario, rng, index):
    # Each case is isolated. Pseudorandom assumptions vary conditions, not people.
    base = {name: synthetic_signal(name, f'base-{index}') for name in FIELDS}
    other = {name: synthetic_signal(name, f'other-{index}') for name in FIELDS}
    current = dict(base)
    first_ip, second_ip = '192.0.2.1', '198.51.100.1'
    expected_same = scenario in ('stable', 'reinstall', 'permissions', 'hardware_change', 'full_rotation')
    if scenario == 'stable':
        if rng.random() < .5: second_ip = first_ip
    elif scenario == 'shared_nat':
        current = other; second_ip = first_ip
        if rng.random() < .1: current['board_serial'] = base['board_serial']
    elif scenario == 'cloned_vm':
        # Clone copies the machine and product UUID; board sometimes copied too.
        current = other; current['machine_id'] = base['machine_id']; current['product_uuid'] = base['product_uuid']
        if rng.random() < .5: current['board_serial'] = base['board_serial']
    elif scenario == 'reinstall':
        current['machine_id'] = other['machine_id']
        if rng.random() < .5: second_ip = first_ip
        if rng.random() < .25: current['product_uuid'] = other['product_uuid']
    elif scenario == 'permissions':
        if rng.random() < .25: current.pop('machine_id')
        if rng.random() < .5: current.pop('product_uuid')
        if rng.random() < .5: current.pop('board_serial')
    elif scenario == 'hardware_change':
        current['board_serial'] = other['board_serial']
        if rng.random() < .5: current['product_uuid'] = other['product_uuid']
        if rng.random() < .5: second_ip = first_ip
    elif scenario == 'full_rotation':
        current = other
    elif scenario == 'forged_replay':
        pass  # An attacker sends the exact synthetic values; no authenticity assumed.
    else:
        raise ValueError('unknown scenario')
    return base, current, first_ip, second_ip, expected_same


def evaluate(samples=200, seed=4301):
    if type(samples) is not int or not 1 <= samples <= 10000 or type(seed) is not int: raise ValueError('invalid arguments')
    rng = random.Random(seed)
    settings = policy('standard', {'max_requests':10})
    rows = []
    for scenario in SCENARIOS:
        counts = Counter()
        for i in range(samples):
            first, second, ip1, ip2, same = sample(scenario, rng, i)
            engine = Engine(settings, secret=b'synthetic-evaluation-secret', clock=lambda:1000)
            before = engine.check({'signals':first}, ip1)
            if before['decision'] != 'allow': raise RuntimeError('synthetic setup failed')
            after = engine.check({'signals':second}, ip2)
            if after['decision'] != 'allow':
                counts['denied_'+after['decision']] += 1
            else:
                relation = after['relation']
                counts[relation] += 1
                if relation == 'related': counts['same_related' if same else 'different_related'] += 1
                elif relation == 'below_threshold': counts['same_below' if same else 'different_below'] += 1
        # Outcomes do not turn inconclusive or denied into a negative match.
        relevant = counts['same_below'] if same else counts['different_related']
        rows.append({'scenario':scenario,'assumed_pair_label':'same' if same else 'different',
                     'n':samples,'outcomes':dict(sorted(counts.items())),
                     'conditional_model_event':'same_below' if same else 'different_related',
                     'conditional_model_event_count':relevant,
                     'conditional_wilson_95':wilson(relevant,samples)})
    return {'schema':1,'seed':seed,'policy':'Python standard preset; min_matches=2 including IP, 10 requests/60s; independent empty store per pair',
            'sample_size_per_scenario':samples,'scenarios':rows,
            'uncertainty':'Wilson intervals describe simulated event frequencies only under the specified independent random-draw model; they exclude all uncertainty about real populations and do not validate model assumptions.',
            'limitations':['Synthetic labels and change probabilities are assumptions, not verified devices, users or deployment rates.',
                           'Not a representative sample or a real-world false-positive/false-negative estimate.',
                           'Invalid and inconclusive outcomes are reported separately, not classified as negative matches.',
                           'An attacker can forge or replay signal values; rotating all identifiers and IP evades this relation.',
                           'No native collectors, real permissions, clone images, hardware, staging or consented participant data were measured.']}

if __name__ == '__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--samples',type=int,default=200); parser.add_argument('--seed',type=int,default=4301)
    args=parser.parse_args(); print(json.dumps(evaluate(args.samples,args.seed), indent=2))
