#!/usr/bin/env python3
"""Deterministic local abuse simulations: synthetic inputs only, no real network targets."""
import hashlib
import json
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'demo'))
from engine import Engine, policy

def token(v): return hashlib.sha256(v.encode()).hexdigest()
def hit(e, account, machine, ip):
    return e.check({'account':account,'signals':{'machine_id':token(machine)}},ip)['decision']
def engine(limit=5): return Engine(policy(override={'max_requests':limit}), secret=b'attack-lab-fixed-demo-secret', clock=lambda:1700000000.0)
def report():
    out=[]
    e=engine(); actions=[hit(e,f'user-{i}','same-machine',f'192.0.2.{i+1}') for i in range(40)]
    out.append({'scenario':'same device, rotating IP and accounts','allowed':actions.count('allow'),'rate_limited':actions.count('rate_limited'),'expected':'shared machine bucket limits requests'})
    e=engine(); actions=[hit(e,f'user-{i}',f'device-{i}','192.0.2.1') for i in range(40)]
    out.append({'scenario':'same IP, rotating device and accounts','allowed':actions.count('allow'),'rate_limited':actions.count('rate_limited'),'expected':'shared IP bucket limits requests'})
    e=engine(); actions=[hit(e,f'user-{i}',f'device-{i}',f'192.0.2.{i+1}') for i in range(40)]
    out.append({'scenario':'rotating both device signals and IP','allowed':actions.count('allow'),'rate_limited':actions.count('rate_limited'),'expected':'known bypass: no stable common key'})
    e=engine(1); a=hit(e,'legitimate-a','device-a','192.0.2.1');b=hit(e,'legitimate-b','device-b','192.0.2.1')
    out.append({'scenario':'two unrelated users behind one IP','first':a,'second':b,'expected':'known false positive from shared IP bucket'})
    e=engine();actions=[hit(e,'replayed-account','replayed-machine','192.0.2.1') for _ in range(10)]
    out.append({'scenario':'replay of the same self-reported signal','allowed':actions.count('allow'),'rate_limited':actions.count('rate_limited'),'expected':'bucket limits repetition; the signal is not authenticated'})
    assert (out[0]['allowed'],out[1]['allowed'],out[2]['allowed'],out[3]['second'],out[4]['allowed']) == (5,5,40,'rate_limited',5)
    return {'schema_version':1,'environment':'local in-process synthetic traffic; no external network requests',
            'policy':'basic, 5 requests / 60 seconds unless noted','results':out,
            'limitations':['Client identifiers are forgeable and replayable.','Shared networks may cause false positives.','Rotating all observed identifiers avoids these per-key limits.']}

if __name__=='__main__':
    result=json.dumps(report(),indent=2)+'\n'
    if len(sys.argv)>1 and sys.argv[1]=='--write': Path('reports/attack-lab.json').write_text(result)
    else: print(result,end='')
