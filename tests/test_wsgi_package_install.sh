#!/bin/sh
set -eu
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp/source"
cp integrations/wsgi/pyproject.toml "$tmp/source/"
cp -R integrations/wsgi/archx_wsgi "$tmp/source/"
python3 -m pip install --disable-pip-version-check --no-deps --target "$tmp/install" "$tmp/source"
PYTHONPATH="$tmp/install" python3 - <<'PY'
import os
from pathlib import Path
import archx_wsgi
assert Path(archx_wsgi.__file__).is_relative_to(Path(os.environ['PYTHONPATH']))
app = archx_wsgi.ProtectedApplication(
    lambda env,start: (start('200 OK', []),[b'ok'])[1],
    resolve_principal=lambda env:'synthetic', authorize=lambda p,op:True,
    evaluate=lambda env,p:{'decision':'allow'}, operation='synthetic.read',
    max_inflight=1, requests_per_second=1, burst=1)
statuses = []
assert b''.join(app({}, lambda status, headers: statuses.append(status))) == b'ok'
assert statuses == ['200 OK']
print('isolated WSGI package install passed')
PY
