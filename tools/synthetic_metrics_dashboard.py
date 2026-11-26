#!/usr/bin/env python3
"""Example local snapshot inspection, not an exporter or production alert policy."""
import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'demo'))
from engine import Engine, policy
from metrics import ServiceMetrics
from replay import MemoryReplay, ReplayUnavailable
from service import RequestService
from signal_validation import synthetic_signal
from sqlite_engine import SQLiteEngine


def alerts(snapshot):
    d,e=snapshot['decisions'],snapshot['events']
    # Example triggers, not rates, baselines, SLOs or production thresholds.
    return {'capacity': d['capacity_exceeded']>0,
            'storage': d['storage_error']>0,
            'replay': e['replay_rejected']+e['replay_unavailable']>0,
            'adapter': e['turnstile_unavailable']+e['reputation_unavailable']>0,
            'contention_at_least_50ms': sum(snapshot['serialization_wait_seconds']['counts'][4:])>0}


def exercise():
    metrics=ServiceMetrics()
    engine=Engine(policy(override={'max_requests':100}), secret=b'synthetic-example-secret', max_entries=1, metrics=metrics)
    svc=RequestService(engine,metrics=metrics)
    body={'signals':{'machine_id':synthetic_signal('machine_id','synthetic')}}
    assert svc.check(body,'192.0.2.1')['decision']=='capacity_exceeded'
    # Replay outcomes are simulated via the real service's sealed-message boundary.
    replay=MemoryReplay(b'synthetic-example-secret',lambda:1000,capacity=1,per_peer=1)
    sealed=RequestService(engine,sealed_key=object(),replay=replay,metrics=metrics)
    replay.issue('192.0.2.2')
    assert sealed.challenge('192.0.2.2')['reason']=='replay_unavailable'
    with patch('service.unseal',return_value=b'{"nonce":"not-a-nonce"}'):
        # separate engine to avoid the capacity test's deliberately tiny store
        engine2=Engine(policy(),secret=b'synthetic-example-secret',metrics=metrics)
        sealed2=RequestService(engine2,sealed_key=object(),replay=replay,metrics=metrics)
        assert sealed2.check({},'192.0.2.3')['reason']=='replay_rejected'
    class BrokenTurnstile:
        def verify(self, token): return 'unavailable'
    adapter=RequestService(Engine(policy(),secret=b'synthetic-example-secret',metrics=metrics), turnstile=BrokenTurnstile(),metrics=metrics)
    assert adapter.check(body,'198.51.100.1')['reason']=='turnstile_unavailable'
    with tempfile.TemporaryDirectory() as tmp:
        persistent=SQLiteEngine(Path(tmp)/'state.sqlite',policy(),b'synthetic-secret-at-least-32-bytes!!',metrics=metrics)
        with patch.object(persistent,'connect',side_effect=__import__('sqlite3').OperationalError('synthetic private storage fault')):
            assert RequestService(persistent,metrics=metrics).check(body,'203.0.113.1')['decision']=='storage_error'
    # Inject one synthetic wait to exercise the alert; not a measured latency.
    metrics.observe_wait(0.051)
    return metrics.snapshot()

if __name__=='__main__':
    snapshot=exercise()
    print(json.dumps({'description':'synthetic process-local demonstration with an injected 51ms wait; alert thresholds are illustrative only',
                      'snapshot':snapshot,'illustrative_alerts':alerts(snapshot)},indent=2))
