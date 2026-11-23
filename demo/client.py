#!/usr/bin/env python3
"""Native Linux demo: optionally sends selected raw IDs after user confirmation."""
import argparse
import fcntl
import ipaddress
import stat
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit, urlunsplit

from signal_validation import SIGNALS, normalize_signal

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
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise OSError('Installation ID must be a private regular file')
        value = os.read(fd, 128).decode('ascii', errors='ignore')
        if value and not re.fullmatch('[0-9a-f]{64}', value):
            raise OSError('Invalid installation ID file')
        if not value:
            import secrets
            value = secrets.token_hex(32)
            os.ftruncate(fd, 0); os.lseek(fd,0,os.SEEK_SET); os.write(fd,value.encode()); os.fsync(fd)
        return value
    finally: os.close(fd)

def storage(selected):
    columns = {'disk_serial':'SERIAL','disk_wwn':'WWN','filesystem_uuid':'UUID','partition_uuid':'PARTUUID'}
    chosen = [name for name in columns if name in selected]
    if not chosen: return {}
    try:
        p = subprocess.run(['lsblk','-J','-o',','.join(['TYPE']+[columns[n] for n in chosen])], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=True, timeout=5)
        root = json.loads(p.stdout).get('blockdevices',[])
    except (OSError, subprocess.SubprocessError, ValueError): return {}
    found = {name:[] for name in chosen}
    def walk(items):
        for item in items:
            for name in chosen:
                if name in ('disk_serial','disk_wwn') and item.get('type') != 'disk': continue
                v=clean(str(item.get(columns[name].lower()) or ''))
                if v: found[name].append(v)
            walk(item.get('children') or [])
    walk(root)
    return found

def collect(selected):
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
    # Send selected raw values only. Never write these values to logs or disk.
    result={}
    for name, values in raw.items():
        if name not in selected: continue
        valid=[]
        for value in values:
            try: valid.append(normalize_signal(name, value))
            except ValueError: pass
        if valid: result[name] = sorted(valid)[0]
    return result

def system_zone():
    value=os.environ.get('TZ','').lstrip(':')
    if value: return value
    try:
        p=str(Path('/etc/localtime').resolve())
        if '/zoneinfo/' in p: return p.split('/zoneinfo/',1)[1]
    except OSError: pass
    return None

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def endpoint(url):
    parts = urlsplit(url)
    if parts.scheme not in ('http','https') or not parts.hostname or parts.username or parts.password or parts.fragment or parts.query or parts.path != '/api/v2/check':
        raise ValueError('Expected a URL ending in /api/v2/check')
    if parts.scheme == 'http':
        try: loopback = ipaddress.ip_address(parts.hostname).is_loopback
        except ValueError: loopback = parts.hostname.lower() == 'localhost'
        if not loopback: raise ValueError('Raw device identifiers require HTTPS except on local loopback')
    return urlunsplit((parts.scheme, parts.netloc, '/api/v2/config', '', ''))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url',default='http://127.0.0.1:8000/api/v2/check')
    parser.add_argument('--account',help=argparse.SUPPRESS) # deprecated and ignored
    parser.add_argument('--signals',help='comma-separated subset; required signals are always included')
    parser.add_argument('--confirm-send-raw',action='store_true',help='consent to sending the selected raw identifiers to this server')
    args=parser.parse_args()
    try:
        config_url=endpoint(args.url)
        opener=urllib.request.build_opener(NoRedirect())
        with opener.open(config_url,timeout=10) as response:
            config=json.loads(response.read(8193))
        if not isinstance(config,dict) or config.get('protocol') != 'raw-v2': raise ValueError('Server protocol is not supported')
        required=config.get('required'); conditional=config.get('conditional')
        if not isinstance(required,list) or not isinstance(conditional,list) or any(not isinstance(x,str) or x not in SIGNALS for x in required+conditional): raise ValueError('Invalid server signal policy')
        available=set(required+conditional)
        selected=set(filter(None,args.signals.split(','))) if args.signals is not None else available
        if not selected <= available: raise ValueError('Requested signal is not enabled by the service')
        selected.update(required)
        missing_message=config.get('missing_required_message', 'Your device did not provide information required by this service. Contact the service provider for help.')
        if not isinstance(missing_message,str) or not 1 <= len(missing_message) <= 500 or any(ord(c)<32 or ord(c)==127 for c in missing_message): raise ValueError('Invalid server message')
        signals=collect(selected)
        missing=[name for name in required if name not in signals]
        if missing:
            print(json.dumps({'decision':'invalid','reason':'missing_required','missing':missing,
                  'message':missing_message}))
            return 2
        if not args.confirm_send_raw:
            print(json.dumps({'decision':'not_sent','reason':'confirmation_required',
                  'recipient':args.url,'requested':sorted(selected),'available':sorted(signals),
                  'message':'This service requests raw device identifiers. Review its privacy notice and use --confirm-send-raw to send them.'}))
            return 2
        body={'signals':signals, 'timestamp':time.time()}
        zone=system_zone()
        if zone: body['timezone']=zone
        req=urllib.request.Request(args.url, data=json.dumps(body).encode(), headers={'Content-Type':'application/json'})
        with opener.open(req,timeout=10) as response: print(response.read(8193).decode())
        return 0
    except urllib.error.HTTPError as exc:
        # Server error responses contain status/reason, not submitted identifiers.
        print(exc.read(8193).decode(errors='replace')); return 1
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(json.dumps({'decision':'error','message':str(exc)})); return 1

if __name__=='__main__': raise SystemExit(main())
