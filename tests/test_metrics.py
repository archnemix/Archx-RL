"""Synthetic, fixed-cardinality and privacy tests for optional gate metrics."""
import http.client
import json
import math
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import Engine, policy
from metrics import BOUNDS, DECISIONS, ServiceMetrics
from service import RequestService
from server import Handler
from signal_validation import synthetic_signal


def payload(seed='valid'):
    return {'signals':{'machine_id':synthetic_signal('machine_id', seed)}}


class MetricsTests(unittest.TestCase):
    def test_fixed_schema_buckets_and_privacy(self):
        metrics = ServiceMetrics()
        markers = ['192.0.2.14', 'privacy-marker', 'secret', 'principal', 'turnstile-token']
        for marker in markers:
            metrics.observe(marker, float('nan'))
        for i, value in enumerate(BOUNDS): metrics.observe(DECISIONS[i % len(DECISIONS)], value)
        metrics.observe('allow', 99.0)
        metrics.observe(None, -1)
        metrics.observe([], math.inf)
        metrics.observe('allow', 10**1000)
        snap = metrics.snapshot()
        self.assertEqual(set(snap), {'schema','scope','decisions','duration_seconds'})
        self.assertEqual(set(snap['decisions']), set(DECISIONS))
        self.assertEqual(snap['duration_seconds']['counts'], [1] * (len(BOUNDS) + 1))
        self.assertEqual(snap['duration_seconds']['unknown'], len(markers) + 3)
        for marker in markers: self.assertNotIn(marker, json.dumps(snap))
        snap['decisions']['allow'] = -1; snap['duration_seconds']['counts'][0] = -1
        self.assertGreaterEqual(metrics.snapshot()['decisions']['allow'], 0)
        self.assertEqual(metrics.snapshot()['duration_seconds']['counts'][0], 1)

    def test_check_records_once_and_handles_concurrency(self):
        metrics = ServiceMetrics()
        engine = Engine(policy(override={'max_requests':1000}), secret=b'synthetic', max_entries=4096)
        gate = RequestService(engine, metrics=metrics)
        data = payload('privacy-marker')
        with ThreadPoolExecutor(max_workers=20) as executor:
            decisions = list(executor.map(lambda _: gate.check(data, '192.0.2.14')['decision'], range(200)))
        self.assertEqual(decisions.count('allow'), 200)
        snap = metrics.snapshot()
        self.assertEqual(snap['decisions']['allow'], 200)
        self.assertEqual(sum(snap['decisions'].values()), 200)
        self.assertEqual(sum(snap['duration_seconds']['counts']) + snap['duration_seconds']['unknown'], 200)
        serialized = json.dumps(snap)
        self.assertNotIn('192.0.2.14', serialized)
        self.assertNotIn(data['signals']['machine_id'], serialized)

    def test_known_decisions_and_exception_observed_without_changing_outcome(self):
        metrics = ServiceMetrics()
        engine = Engine(policy(override={'max_requests':1}), secret=b'synthetic')
        gate = RequestService(engine, metrics=metrics)
        self.assertEqual(gate.check(payload(), '192.0.2.1')['decision'], 'allow')
        self.assertEqual(gate.check(payload(), '192.0.2.1')['decision'], 'rate_limited')
        self.assertEqual(gate.check({'signals':{}}, '192.0.2.2')['decision'], 'invalid')
        with patch.object(engine, 'reject_malformed', side_effect=RuntimeError('private failure text')):
            with self.assertRaises(RuntimeError): gate.check(payload(), '192.0.2.3')
        snap = metrics.snapshot()
        for decision in ('allow','rate_limited','invalid','unexpected'): self.assertEqual(snap['decisions'][decision], 1)
        self.assertNotIn('private failure text', json.dumps(snap))

    def test_metrics_failure_never_changes_gate_behavior(self):
        metrics = ServiceMetrics()
        engine = Engine(policy(override={'max_requests':5}), secret=b'synthetic')
        gate = RequestService(engine, metrics=metrics)
        with patch.object(metrics, 'observe', side_effect=RuntimeError('metrics down')):
            self.assertEqual(gate.check(payload(), '192.0.2.1')['decision'], 'allow')
            with patch.object(engine, 'reject_malformed', side_effect=ValueError('gate failure')):
                with self.assertRaisesRegex(ValueError, 'gate failure'): gate.check(payload(), '192.0.2.2')
        with self.assertRaises(ValueError): RequestService(engine, metrics=object())
        class BrokenDict(dict):
            def get(self, key, default=None): raise RuntimeError('unsupported inspection')
        value = BrokenDict(decision='allow')
        with patch.object(gate, '_check', return_value=value):
            self.assertIs(gate.check({}, '192.0.2.3'), value)
        self.assertEqual(metrics.snapshot()['decisions']['unexpected'], 1)

    def test_http_handler_uses_opt_in_shared_collector_not_parse_errors(self):
        httpd = ThreadingHTTPServer(('127.0.0.1',0), Handler)
        httpd.engine = Engine(policy(override={'max_requests':10}), secret=b'synthetic')
        httpd.metrics = ServiceMetrics()
        thread = threading.Thread(target=httpd.serve_forever, daemon=True); thread.start()
        def post(body):
            client = http.client.HTTPConnection('127.0.0.1',httpd.server_address[1], timeout=5)
            try:
                client.request('POST','/api/v2/check',body,{'Content-Type':'application/json'})
                response = client.getresponse(); response.read(); return response.status
            finally: client.close()
        try:
            self.assertEqual(post(json.dumps(payload())), 200)
            self.assertEqual(post('bad json'), 400)
            self.assertEqual(post(json.dumps({'signals':{}})), 400)
            self.assertEqual(httpd.metrics.snapshot()['decisions']['allow'], 1)
            self.assertEqual(httpd.metrics.snapshot()['decisions']['invalid'], 1)
            self.assertEqual(sum(httpd.metrics.snapshot()['decisions'].values()), 2)
        finally:
            httpd.shutdown(); httpd.server_close(); thread.join()


if __name__ == '__main__': unittest.main(verbosity=2)
