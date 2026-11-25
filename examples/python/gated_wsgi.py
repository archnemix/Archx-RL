#!/usr/bin/env python3
"""Minimal local WSGI host demonstrating how to enforce Archx decisions.

Development example only: production hosts need a suitable HTTP server, TLS,
request limits, a trustworthy client-IP boundary, and their own security review.
The protected operation and input are synthetic; no account or trial is involved.
Optional hooks illustrate a host-owned principal and authorization boundary.
"""
import json
import sys
from http import HTTPStatus
from pathlib import Path
from wsgiref.simple_server import make_server, WSGIRequestHandler

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'demo'))
from engine import Engine, policy
from service import RequestService, parse_json, status_for


def create_application(gate, on_allow=None, *, resolve_principal=None, authorize=None):
    if (resolve_principal is None) != (authorize is None):
        raise ValueError('Both host authorization hooks must be supplied together')
    if resolve_principal is not None and (not callable(resolve_principal) or not callable(authorize)):
        raise ValueError('Host authorization hooks must be callable')
    on_allow = on_allow or (lambda: {'resource':'synthetic protected response'})

    def respond(start_response, status, result):
        body = json.dumps(result,separators=(',',':')).encode('utf-8')
        headers = [('Content-Type','application/json'),('Content-Length',str(len(body))),('Cache-Control','no-store')]
        if status in (429,503) and type(result.get('retry_after_seconds')) is int and result['retry_after_seconds'] > 0:
            headers.append(('Retry-After',str(result['retry_after_seconds'])))
        start_response(f'{status} {HTTPStatus(status).phrase}', headers)
        return [body]

    def application(environ, start_response):
        # REMOTE_ADDR must be a real transport peer supplied by a trusted server.
        # Never substitute an unverified forwarding header here.
        peer = environ['REMOTE_ADDR']
        method, path = environ.get('REQUEST_METHOD'), environ.get('PATH_INFO')
        if method == 'GET' and path == '/api/v2/config':
            status, result = 200, gate.config()
        elif method == 'GET' and path == '/api/v2/challenge':
            result = gate.challenge(peer)
            status = 404 if result is None else status_for(result) if 'decision' in result else 200
            if result is None: result = {'error':'not_found'}
        elif method == 'POST' and path == '/protected':
            # The host, not Archx, must authenticate this principal. It must
            # never populate trusted context from a client-controlled header.
            if resolve_principal is not None:
                try:
                    principal = resolve_principal(environ)
                    approved = False if principal is None else authorize(principal, 'synthetic.read')
                except Exception:
                    return respond(start_response, 503, {'error':'authorization_unavailable'})
                if approved is not True:
                    status = 403 if approved is False else 503
                    return respond(start_response, status, {'error':'forbidden' if status == 403 else 'authorization_unavailable'})
            try:
                if environ.get('CONTENT_TYPE','').split(';',1)[0].strip().lower() != 'application/json':
                    raise ValueError('Invalid content type')
                length_text = environ.get('CONTENT_LENGTH','')
                if not length_text.isascii() or not length_text.isdecimal(): raise ValueError('Invalid length')
                length = int(length_text)
                if not 0 < length <= 8192: raise ValueError('Invalid length')
                raw = environ['wsgi.input'].read(length)
                if len(raw) != length: raise ValueError('Incomplete body')
                envelope = parse_json(raw)
                result = gate.check(envelope, peer)
            except (ValueError, TypeError):
                result = gate.engine.reject_malformed(peer) or gate.failure('invalid','invalid_request')
            status = status_for(result)
            if result['decision'] == 'allow':
                result = {'decision':'allow', 'relation':result['relation'], 'data':on_allow()}
        else:
            status, result = 404, {'error':'not_found'}
        return respond(start_response, status, result)

    return application


class QuietHandler(WSGIRequestHandler):
    def log_message(self, format, *args):
        pass


if __name__ == '__main__':
    # This example is intentionally loopback-only and uses synthetic inputs.
    app = create_application(RequestService(Engine(policy())))
    print('Local WSGI example on http://127.0.0.1:8081', flush=True)
    with make_server('127.0.0.1',8081,app,handler_class=QuietHandler) as server:
        server.serve_forever()
