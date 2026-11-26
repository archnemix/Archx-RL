"""Compare two captures; the caller owns profile storage and request-IP trust."""
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'bindings/python'))
from archx_native import Core

config = {
    'app_id':'matching-demo', 'pepper':os.getenv('ARCHX_PEPPER', 'demo-only-change-me'),
    'match':{'mode':'threshold', 'min_matches':2,
             'signals':{'machine_id':'required', 'product_uuid':'optional', 'ip':'optional'}},
}
with Core(str(ROOT / 'build/libarchx.so'), config) as core:
    # Documentation addresses for illustration, not actual client IPs.
    baseline = core.profile('192.0.2.1')
    current = core.profile('192.0.2.2')
    print(json.dumps(core.compare(baseline, current), indent=2))
