#!/bin/sh
# Install both source packages into isolated temporary targets; Linux only.
set -eu
ROOT=$(pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
mkdir "$tmp/python-src"
cp bindings/python/pyproject.toml "$tmp/python-src/"
cp -R bindings/python/archx_native "$tmp/python-src/"
python3 -m pip install --disable-pip-version-check --no-deps --target "$tmp/python-install" "$tmp/python-src"
PYTHONPATH="$tmp/python-install" ARCHX_BINDING_LIB="$ROOT/build/libarchx.so" python3 - <<'PY'
from pathlib import Path
import os
import archx_native
from archx_native import Core
assert Path(archx_native.__file__).is_relative_to(Path(os.environ['PYTHONPATH']))
config = {'app_id':'install-fixture','pepper':'synthetic','match':{'mode':'threshold','min_matches':1,'signals':{'ip':'required'}}}
with Core(os.environ['ARCHX_BINDING_LIB'], config) as core:
    p = core.profile('192.0.2.1')
    assert core.compare(p,p)['result'] == 'match'
print('isolated Python package loading passed')
PY
archive=$(npm pack ./bindings/node --pack-destination "$tmp" --silent)
npm install --prefix "$tmp/node-install" --no-audit --no-fund "$tmp/$archive"
ARCHX_BINDING_LIB="$ROOT/build/libarchx.so" ARCHX_INSTALLED_BINDING="$tmp/node-install/node_modules/archx-native-experimental" node - <<'JS'
const assert = require('node:assert/strict');
const {Core} = require(process.env.ARCHX_INSTALLED_BINDING);
const config = {app_id:'install-fixture',pepper:'synthetic',match:{mode:'threshold',min_matches:1,signals:{ip:'required'}}};
const core = new Core(process.env.ARCHX_BINDING_LIB, config);
try { const p = core.profile('192.0.2.1'); assert.equal(core.compare(p,p).result, 'match'); }
finally { core.close(); }
console.log('isolated Node package loading passed');
JS
