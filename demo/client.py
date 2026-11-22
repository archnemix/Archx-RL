#!/usr/bin/env python3
"""Native Linux demo client. Sends pseudonymous, app-scoped signal tokens, not raw IDs."""
import argparse
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.request

from engine import SIGNALS

BAD = {'', 'none', 'unknown', 'n/a', '-', 'not specified', 'to be filled by o.e.m.', 'uninitialized', '0'}

def clean(value):
    value = value.strip().lower()
    if value in BAD or value.replace('-', '') in ('0'*32, 'f'*32) or len(value)>255: return None
    return value

def read(path):
    try: return clean(Path(path).read_text(errors='replace')[:256])
    except OSError: return None

def installation():
    root = Path(os.environ.get('XDG_DATA_HOME') or Path.home()/'.local/share')/'archx-demo'
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(root/'installation-id', os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        value = os.read(fd, 128).decode('ascii', errors='ignore')
        if not re.fullmatch('[0-9a-f]{64}', value):
            import secrets
            value = secrets.token_hex(32)
            os.ftruncate(fd, 0); os.lseek(fd,0,os.SEEK_SET); os.write(fd,value.encode()); os.fsync(fd)
        return value
    finally: os.close(fd)

def storage(selected):
    if not selected.intersection({'disk_serial','disk_wwn','filesystem_uuid','partition_uuid'}): return {}
    try:
        p = subprocess.run(['lsblk','-J','-o','TYPE,SERIAL,WWN,UUID,PARTUUID'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True, timeout=5)
        root = json.loads(p.stdout).get('blockdevices',[])
    except (OSError, subprocess.SubprocessError, ValueError): return {}
    found = {k:[] for k in ('disk_serial','disk_wwn','filesystem_uuid','partition_uuid')}
    def walk(items):
        for item in items:
            for name,key in [('disk_serial','serial'),('disk_wwn','wwn'),('filesystem_uuid','uuid'),('partition_uuid','partuuid')]:
                if name in ('disk_serial','disk_wwn') and item.get('type') != 'disk': continue
                v=clean(str(item.get(key) or ''))
                if v: found[name].append(v)
            walk(item.get('children') or [])
    walk(root)
    return found

def collect(selected, app):
    if not selected <= set(SIGNALS): raise ValueError('Unknown selected signal')
    raw = {}
    paths = {'machine_id':'/etc/machine-id','product_uuid':'/sys/class/dmi/id/product_uuid',
             'board_serial':'/sys/class/dmi/id/board_serial','product_serial':'/sys/class/dmi/id/product_serial',
             'chassis_serial':'/sys/class/dmi/id/chassis_serial'}
    for name in selected & paths.keys():
        value = read(paths[name])
        if name == 'machine_id':
            if not value or not re.fullmatch(r'[0-9a-f]{32}', value): value=read('/var/lib/dbus/machine-id')
            if not value or not re.fullmatch(r'[0-9a-f]{32}', value): value=None
        if value: raw[name] = [value]
    raw.update(storage(selected))
    if 'installation_id' in selected:
        try: raw['installation_id'] = [installation()]
        except OSError: pass
    if 'mac_address' in selected:
        macs=[]
        for p in Path('/sys/class/net').glob('*/address'):
            if p.parent.name == 'lo': continue
            v=read(p)
            if v and re.fullmatch(r'[0-9a-f]{2}(:[0-9a-f]{2}){5}', v) and not (int(v[:2],16)&2): macs.append(v)
        raw['mac_address']=macs
    if 'gpu_uuid' in selected:
        try:
            p=subprocess.run(['nvidia-smi','--query-gpu=uuid','--format=csv,noheader'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True, timeout=5)
            raw['gpu_uuid']=[v for v in (clean(s) for s in p.stdout.splitlines()) if v]
        except (OSError, subprocess.SubprocessError): pass
    # Signal value is the HMAC key, app and signal are the message: no raw ID sent.
    # A public app label gives domain separation, not an authentication secret.
    result={}
    for name, values in raw.items():
        if name not in selected: continue
        hashes=sorted(hmac.new(v.encode(), ('archx-client-v1\0'+app+'\0'+name).encode(), hashlib.sha256).hexdigest() for v in values)
        if hashes: result[name]=hashes[0]
    return result

def system_zone():
    value=os.environ.get('TZ','').lstrip(':')
    if value: return value
    try:
        p=str(Path('/etc/localtime').resolve())
        if '/zoneinfo/' in p: return p.split('/zoneinfo/',1)[1]
    except OSError: pass
    return None

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url',default='http://127.0.0.1:8000/api/v1/check')
    parser.add_argument('--app-id',default='archx-demo')
    parser.add_argument('--account',default='example')
    parser.add_argument('--signals', default='machine_id,product_uuid,board_serial')
    args=parser.parse_args()
    body={'account':args.account,'signals':collect(set(filter(None,args.signals.split(','))),args.app_id), 'timestamp':time.time()}
    zone=system_zone()
    if zone: body['timezone']=zone
    req=urllib.request.Request(args.url, data=json.dumps(body).encode(), headers={'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(req,timeout=10) as res: print(res.read().decode())
    except urllib.error.HTTPError as exc: print(exc.read().decode()); raise SystemExit(1)

if __name__=='__main__': main()
