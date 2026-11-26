#!/usr/bin/env python3
"""Deterministic shared-IP synthetic requests, not real false-positive rates."""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'demo'))
from engine import Engine, policy
from sqlite_engine import SQLiteEngine
from signal_validation import synthetic_signal

SECRET=b'synthetic-nat-simulation-secret-0123456789'


def run(mode):
    if mode not in ('memory','sqlite'): raise ValueError('unknown engine')
    rows=[]
    with tempfile.TemporaryDirectory(prefix='archx-synthetic-nat-') as tmp:
        for ip_limit in (5,15,30):
            p=policy(override={'max_requests':5,'ip_max_requests':ip_limit,'device_max_requests':1})
            e=Engine(p,secret=SECRET,clock=lambda:1000) if mode=='memory' else SQLiteEngine(Path(tmp)/('state-'+str(ip_limit)+'.sqlite'),p,SECRET,clock=lambda:1000)
            decisions=[]
            for i in range(30):
                data={'signals':{'machine_id':synthetic_signal('machine_id','synthetic-'+str(i))}}
                decisions.append(e.check(data,'192.0.2.1')['decision'])
            rows.append({'ip_quota':ip_limit,'device_quota':1,'requests':30,
                         'allowed':decisions.count('allow'),'rate_limited':decisions.count('rate_limited')})
    return {'schema':1,'mode':mode,'scenarios':rows,
            'limitations':['synthetic unique submitted values behind one documentation IP; not verified people or devices',
                           'assumes every request is legitimate solely to illustrate possible collateral denial',
                           'not a real-world false-positive estimate, fraud test or production capacity assessment',
                           'higher IP quotas also permit more abuse; forged/rotating device signals and poisoning remain possible']}

if __name__=='__main__':
    print(json.dumps({'memory':run('memory'),'sqlite':run('sqlite')},sort_keys=True))
