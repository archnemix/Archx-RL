"""Synthetic Unix-socket WSGI origin for HTTPS tests, NOT production config."""
import io
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'integrations/wsgi'))
sys.path.insert(0, str(ROOT / 'demo'))
from archx_wsgi import ProtectedApplication
from engine import Engine, policy
from service import RequestService, parse_json
from waitress import serve

service = RequestService(Engine(policy(override={'max_requests':1}), secret=b'synthetic-unix-origin'))


def evaluate(env, principal):
    try:
        length = env.get('CONTENT_LENGTH', '')
        if not length.isascii() or not length.isdecimal() or not 0 < int(length) <= 8192:
            raise ValueError('invalid length')
        raw = env['wsgi.input'].read(int(length))
        if len(raw) != int(length): raise ValueError('incomplete body')
        env['wsgi.input'] = io.BytesIO(raw)
        return service.check(parse_json(raw), env['REMOTE_ADDR'])
    except (ValueError, TypeError):
        return service.engine.reject_malformed(env['REMOTE_ADDR']) or service.failure('invalid', 'invalid_request')


def protected(env, start):
    payload = json.dumps({'ok':True}).encode()
    start('200 OK', [('Content-Type','application/json'), ('Content-Length',str(len(payload)))])
    return [payload]


app = ProtectedApplication(protected, resolve_principal=lambda env:'synthetic-test-principal',
    authorize=lambda p,op:p == 'synthetic-test-principal' and op == 'synthetic.read',
    evaluate=evaluate, operation='synthetic.read', max_inflight=2,
    requests_per_second=100, burst=100)
# Only for synthetic tests. The filesystem, not Waitress's 'localhost' peer
# string, must restrict which processes can connect to the Unix socket.
if os.environ.get('ARCHX_TEST_EXPERIMENTAL_INGRESS') == '1':
    from archx_wsgi.ingress import serve_unix
    uid = os.environ.get('ARCHX_TEST_PROXY_UID')
    gid = os.environ.get('ARCHX_TEST_SOCKET_GID')
    serve_unix(app, os.environ['ARCHX_TEST_SOCKET'],
               proxy_uid=None if uid is None else int(uid),
               socket_gid=None if gid is None else int(gid))
else:
    serve(app, unix_socket=os.environ['ARCHX_TEST_SOCKET'], unix_socket_perms='600',
          threads=2, connection_limit=8, backlog=8, max_request_header_size=8192,
          max_request_body_size=8192, trusted_proxy='localhost',
          trusted_proxy_headers='x-forwarded-for', clear_untrusted_proxy_headers=True,
          channel_timeout=3, cleanup_interval=1)
