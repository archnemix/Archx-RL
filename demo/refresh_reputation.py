#!/usr/bin/env python3
"""Refresh an operator-controlled IPsum cache (schedule this command externally)."""
import argparse
from security import refresh_ipsum
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--cache',required=True); p.add_argument('--level',type=int,choices=range(1,9),default=3)
args=p.parse_args()
print('Updated cache with',refresh_ipsum(args.cache,args.level),'addresses')
