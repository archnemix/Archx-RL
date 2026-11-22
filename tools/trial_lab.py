#!/usr/bin/env python3
"""Offline example: a host calls the trial service with synthetic principals.

No HTTP, real users, or real identifiers. This local entitlement table is the
example's source of truth; see README for integration and security boundaries.
"""
import json
import sys
import tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'demo'))
from engine import policy
from signal_validation import synthetic_signal
from sqlite_engine import SQLiteEngine
from trial_service import TrialService


def main():
    with tempfile.TemporaryDirectory() as directory:
        engine=SQLiteEngine(str(Path(directory)/'demo.sqlite'),policy(override={'max_requests':100}),
                            b'synthetic-trial-example-secret-0123456789')
        service=TrialService(engine)
        def activate(account, device, key, ip):
            return service.activate(authenticated_account=account,offer='example-trial',idempotency_key=key,
                                    signals={'machine_id':synthetic_signal('machine_id',device)},peer=ip)
        out=[('First activation',activate('synthetic-user-a','synthetic-device-a','request-a','192.0.2.1')),
             ('Safe retry',activate('synthetic-user-a','synthetic-device-a','request-a','192.0.2.1')),
             ('Same account, new request',activate('synthetic-user-a','synthetic-device-a','request-b','192.0.2.1')),
             ('Different account, same device signal',activate('synthetic-user-b','synthetic-device-a','request-c','198.51.100.1')),
             ('Different account and device, shared IP',activate('synthetic-user-c','synthetic-device-c','request-d','192.0.2.1'))]
        print(json.dumps({'notice':'Synthetic offline example; identifiers are not authenticated.',
                          'events':[{'scenario':name,**result} for name,result in out]},indent=2))

if __name__=='__main__': main()
