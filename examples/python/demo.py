"""Minimal Linux example. Build the core first and keep the pepper secret."""
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'bindings/python'))
from archx_native import Core

config = {'app_id':'python-demo', 'pepper':os.getenv('ARCHX_PEPPER', 'demo-only-change-me'),
          'rate_limit':{'capacity':2, 'refill_per_sec':0}}
with Core(str(ROOT / 'build/libarchx.so'), config) as core:
    print('collect', core.collect())
    print('identify', core.identify())
    for _ in range(3):
        print('check', core.check('example-user'))
