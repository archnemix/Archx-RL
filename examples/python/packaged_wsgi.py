#!/usr/bin/env python3
"""Synthetic local-only example; never expose it as a production service.

A host must implement real authentication, authorization, trusted transport,
network admission, input limits and operational review. This example's fixed
principal and private WSGI development server are not security boundaries.
"""
import io
import sys
from pathlib import Path
from wsgiref.simple_server import make_server, WSGIRequestHandler

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'integrations/wsgi'))
sys.path.insert(0, str(ROOT / 'demo'))
from archx_wsgi import ProtectedApplication
from engine import Engine, policy
from service import RequestService, parse_json


def create_example():
    gate = RequestService(Engine(policy(), secret=b'synthetic-example-secret'))
    def protected(environ, start):
        body = b'{"result":"synthetic"}'
        start('200 OK', [('Content-Type','application/json'), ('Content-Length',str(len(body)))])
        return [body]
    def evaluate(environ, principal):
        peer = environ['REMOTE_ADDR']  # supplied by this local server, not a forwarded header
        try:
            length = environ.get('CONTENT_LENGTH', '')
            if not length.isascii() or not length.isdecimal() or not 0 < int(length) <= 8192:
                raise ValueError('invalid length')
            raw = environ['wsgi.input'].read(int(length))
            if len(raw) != int(length): raise ValueError('incomplete body')
            body = parse_json(raw)
            # The wrapped host may need to read the same body after allow.
            environ['wsgi.input'] = io.BytesIO(raw)
            return gate.check(body, peer)
        except (ValueError, TypeError):
            return gate.engine.reject_malformed(peer) or gate.failure('invalid', 'invalid_request')
    return ProtectedApplication(protected,
        resolve_principal=lambda env:env.get('host.example_principal'),
        authorize=lambda principal, op:principal == 'synthetic-principal' and op == 'synthetic.read',
        evaluate=evaluate, operation='synthetic.read', max_inflight=8,
        requests_per_second=10, burst=20)


class QuietHandler(WSGIRequestHandler):
    def log_message(self, *args): pass


if __name__ == '__main__':
    app = create_example()
    def local_host(environ, start):
        # Demo-only fixed identity, NOT authentication; never copy to production.
        environ['host.example_principal'] = 'synthetic-principal'
        return app(environ, start)
    print('Synthetic local-only WSGI example on http://127.0.0.1:8082', flush=True)
    with make_server('127.0.0.1', 8082, local_host, handler_class=QuietHandler) as server:
        server.serve_forever()
