"""JSON decoding must not manufacture non-finite floats from exponent overflow."""
import http.client
import json
import math
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from service import parse_json


class JsonNumberTests(unittest.TestCase):
    def test_nonfinite_numbers_fail_at_every_depth(self):
        for payload in (b'1e999', b'-1e999', b'1E+10000', b'{"timestamp":1e999}',
                        b'{"nested":[0,{"x":-1e999}]}', b'NaN', b'Infinity', b'-Infinity'):
            with self.subTest(payload=payload), self.assertRaisesRegex(ValueError, '^Invalid JSON$'):
                parse_json(payload)

    def test_http_overflow_is_rejected_and_charged_as_malformed(self):
        from engine import Engine, policy
        from server import Handler
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        server.engine = Engine(policy(override={'max_requests': 1}), secret=b'synthetic')
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            def request():
                conn = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
                try:
                    conn.request('POST', '/api/v2/check', b'{"timestamp":1e999}',
                                 {'Content-Type': 'application/json'})
                    response = conn.getresponse()
                    return response.status, json.loads(response.read())
                finally: conn.close()
            status, result = request()
            self.assertEqual((status, result['reason']), (400, 'invalid_request'))
            self.assertEqual(request()[0], 429)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_finite_numbers_preserved_and_duplicate_keys_rejected(self):
        self.assertEqual(parse_json(b'{"n":1.25e2,"zero":-0.0,"tiny":1e-999}'),
                         {'n': 125.0, 'zero': -0.0, 'tiny': 0.0})
        self.assertTrue(math.copysign(1, parse_json(b'-0.0')) < 0)
        with self.assertRaisesRegex(ValueError, '^Invalid JSON$'):
            parse_json(b'{"x":{"a":1,"a":2}}')


if __name__ == '__main__': unittest.main(verbosity=2)
