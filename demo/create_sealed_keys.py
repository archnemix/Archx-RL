#!/usr/bin/env python3
"""Generate a new sealed-box key pair; neither file is overwritten."""
import argparse
from sealed_payload import create_keys
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--private',required=True); p.add_argument('--public',required=True)
a=p.parse_args()
create_keys(a.private,a.public)
print('Created key pair. Distribute the public key through an independently trusted channel.')
