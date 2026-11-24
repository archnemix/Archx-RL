"""Optional, bounded IP reputation and Cloudflare Turnstile adapters."""
import base64
import ipaddress
import json
import os
import re
from pathlib import Path
import tempfile
import threading
import time
import urllib.parse
import urllib.request

MAX_FEED=4_000_000

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl): return None


def refresh_ipsum(path, level=3, opener=None):
    """Fetch a daily IPsum level through GitHub's contents API and atomically cache it."""
    if type(level) is not int or not 1 <= level <= 8: raise ValueError('IPsum level must be 1 through 8')
    opener=opener or urllib.request.build_opener(NoRedirect())
    req=urllib.request.Request(f'https://api.github.com/repos/stamparm/ipsum/contents/levels/{level}.txt?ref=master',headers={'Accept':'application/vnd.github+json','User-Agent':'archx-demo'})
    with opener.open(req,timeout=15) as response:
        body=response.read(MAX_FEED*2+1)
    if len(body)>MAX_FEED*2: raise ValueError('IPsum response too large')
    doc=json.loads(body)
    # GitHub's contents endpoint omits base64 for files over one megabyte.
    if doc.get('encoding')=='none':
        sha=doc.get('sha')
        if not isinstance(sha,str) or not re.fullmatch('[0-9a-f]{40}',sha) or type(doc.get('size')) is not int or doc['size']>MAX_FEED: raise ValueError('Invalid IPsum metadata')
        req=urllib.request.Request('https://api.github.com/repos/stamparm/ipsum/git/blobs/'+sha,headers={'Accept':'application/vnd.github+json','User-Agent':'archx-demo'})
        with opener.open(req,timeout=15) as response: body=response.read(MAX_FEED*2+1)
        if len(body)>MAX_FEED*2: raise ValueError('IPsum response too large')
        doc=json.loads(body)
        if doc.get('sha')!=sha: raise ValueError('IPsum blob mismatch')
    if doc.get('encoding')!='base64' or not isinstance(doc.get('content'),str): raise ValueError('Invalid IPsum response')
    raw=base64.b64decode(''.join(doc['content'].split()),validate=True)
    addresses=parse_feed(raw)
    data={'source':f'ipsum-level-{level}', 'updated_at':time.time(), 'addresses':sorted(addresses)}
    path=Path(path)
    fd,tmp=tempfile.mkstemp(prefix='.archx-feed-',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as out:
            json.dump(data,out,separators=(',',':')); out.flush(); os.fsync(out.fileno())
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)
    return len(addresses)


def parse_feed(raw):
    if len(raw)>MAX_FEED: raise ValueError('IPsum feed too large')
    lines=raw.decode('ascii').splitlines()
    if not lines or len(lines)>300000: raise ValueError('Invalid IPsum feed size')
    addresses=set()
    for line in lines:
        if not line or line.startswith('#'): continue
        addresses.add(str(ipaddress.ip_address(line.strip())))
    if not addresses: raise ValueError('Empty IPsum feed')
    return addresses

class Reputation:
    def __init__(self,path,max_age=172800,clock=time.time):
        if not isinstance(max_age,(int,float)) or isinstance(max_age,bool) or not 1<=max_age<=2592000: raise ValueError('Invalid reputation max age')
        self.path=path; self.max_age=max_age; self.clock=clock; self.lock=threading.Lock(); self.signature=None; self.data=None
    def lookup(self,ip):
        with self.lock:
            try:
                st=os.stat(self.path)
                signature=(st.st_ino,st.st_mtime_ns,st.st_size)
                if signature!=self.signature:
                    if st.st_size>MAX_FEED*2: raise ValueError('cache too large')
                    with open(self.path,encoding='utf-8') as f: doc=json.load(f)
                    if not isinstance(doc,dict) or not isinstance(doc.get('addresses'),list) or not isinstance(doc.get('updated_at'),(int,float)) or isinstance(doc['updated_at'],bool): raise ValueError('bad cache')
                    if not isinstance(doc.get('source'),str) or not doc['source'].startswith('ipsum-level-'): raise ValueError('bad source')
                    items=doc['addresses']
                    if not items or len(items)>300000 or any(not isinstance(v,str) or len(v)>45 for v in items): raise ValueError('bad addresses')
                    addresses={str(ipaddress.ip_address(v)) for v in items}
                    self.data=(doc['updated_at'],doc['source'],addresses); self.signature=signature
                updated,source,addresses=self.data
                age=self.clock()-updated
                if not 0 <= age <= self.max_age: return {'status':'stale','source':source}
                address=ipaddress.ip_address(ip)
                if isinstance(address,ipaddress.IPv6Address) and address.ipv4_mapped: address=address.ipv4_mapped
                return {'status':'listed' if str(address) in addresses else 'not_listed','source':source,'updated_at':updated}
            except (OSError,ValueError,TypeError,KeyError,OverflowError):
                self.signature=None; self.data=None
                return {'status':'unavailable'}

class Turnstile:
    def __init__(self,sitekey,secret,hostname,action,opener=None):
        if not all(isinstance(x,str) and 1<=len(x)<=256 and x.isascii() and all(33<=ord(c)<=126 for c in x) for x in (sitekey,secret,hostname,action)): raise ValueError('Turnstile requires sitekey, secret, expected hostname and action')
        if any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-' for c in action): raise ValueError('Invalid Turnstile action')
        if len(action)>32: raise ValueError('Invalid Turnstile action')
        self.sitekey=sitekey; self.secret=secret; self.hostname=hostname.lower(); self.action=action
        self.opener=opener or urllib.request.build_opener(NoRedirect())
    def verify(self,token):
        if not isinstance(token,str) or not 1<=len(token)<=2048: return 'invalid'
        data=urllib.parse.urlencode({'secret':self.secret,'response':token}).encode()
        req=urllib.request.Request('https://challenges.cloudflare.com/turnstile/v0/siteverify',data=data,headers={'Content-Type':'application/x-www-form-urlencoded','User-Agent':'archx-demo'})
        try:
            with self.opener.open(req,timeout=5) as response: raw=response.read(16385)
            if len(raw)>16384: return 'unavailable'
            doc=json.loads(raw)
            if not isinstance(doc,dict) or type(doc.get('success')) is not bool: return 'unavailable'
            if not doc['success']:
                codes=doc.get('error-codes',[])
                if not isinstance(codes,list) or any(c in ('internal-error','missing-input-secret','invalid-input-secret','bad-request') for c in codes): return 'unavailable'
                return 'invalid'
            if not isinstance(doc.get('hostname'),str) or doc['hostname'].lower()!=self.hostname or doc.get('action')!=self.action: return 'invalid'
            return 'valid'
        except (OSError,ValueError,TypeError,TimeoutError): return 'unavailable'
