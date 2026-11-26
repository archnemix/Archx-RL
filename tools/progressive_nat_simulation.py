#!/usr/bin/env python3
"""Illustrate synthetic shared-IP requests with optional operator resets."""
import collections
import json
import sys
import tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'demo'))
from engine import Engine,policy
from sqlite_engine import SQLiteEngine
from service import RequestService
from signal_validation import synthetic_signal

SECRET=b'synthetic-progressive-nat-secret-123456789'

def run(mode):
    if mode not in ('memory','sqlite'): raise ValueError('invalid mode')
    rows=[]
    with tempfile.TemporaryDirectory(prefix='archx-synthetic-nat-') as tmp:
        for reset in (False,True):
            p=policy(override={'max_requests':5,'ip_max_requests':5,'device_max_requests':1,'ip_challenge_after':3})
            e=Engine(p,secret=SECRET,clock=lambda:1000) if mode=='memory' else SQLiteEngine(Path(tmp)/f'{int(reset)}.sqlite',p,SECRET,clock=lambda:1000)
            gate=RequestService(e); counts=collections.Counter(); resets=0
            for i in range(30):
                # An explicitly assumed trusted operator approves this intervention;
                # the simulation does not implement real review or authentication.
                if reset and i and i%5==0:
                    if not e.reset_ip_window('192.0.2.1'): raise RuntimeError('missing synthetic IP bucket')
                    resets+=1
                data={'signals':{'machine_id':synthetic_signal('machine_id',f'nat-{i}')}}
                counts[gate.check(data,'192.0.2.1')['decision']]+=1
            rows.append({'operator_reset_every_five':reset,'requests':30,'decisions':dict(counts),'resets':resets})
    return {'mode':mode,'scenarios':rows,'limitations':['all inputs are fabricated; legitimate status, population rates and review approval are assumptions',
              'reset clears a shared IP bucket for everyone, including attackers, and does not clear device buckets',
              'challenge is a host-facing denial, not automatic verification or an authentication proof',
              'not a real-world false-positive rate, production security result or operating procedure']}

if __name__=='__main__': print(json.dumps({'memory':run('memory'),'sqlite':run('sqlite')},indent=2))
