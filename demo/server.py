#!/usr/bin/env python3
"""Local Archx explorer and request-policy demonstration; not production middleware."""
import argparse
import json
import os
import threading
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler
from bounded_server import BoundedDemoServer
from urllib.parse import urlsplit
from engine import Engine, PRESETS, SIGNALS, policy, load_geo
from sqlite_engine import SQLiteEngine
from signal_validation import synthetic_signal
from sealed_payload import read_key
from replay import MemoryReplay, SQLiteReplay
from service import RequestService, parse_json, status_for
from proxy import client_ip, trusted_networks
from security import Reputation, Turnstile, refresh_ipsum

ROOT=Path(__file__).resolve().parent
SURVEY=ROOT.parent/'.github/archx-runner/runs/linux-permissions.json'


def scenario(preset, override=None):
    # Completely isolated synthetic tests, never touch the live store or external services.
    settings=policy(preset,override)
    engine=Engine(settings,secret=b'demo-simulation-key',clock=lambda:1700000000.0)
    # Supply every selected signal; required-set and threshold behavior remain observable.
    names=settings['required']+settings['conditional']
    def sample(account, changes=None):
        values={n:synthetic_signal(n,'device-a') for n in names}
        if changes:
            for n in changes: values[n]=synthetic_signal(n,'device-b')
        return {'account':account,'signals':values}
    steps=[('First account','192.0.2.1',sample('account-a')),
           ('Same device, new IP','198.51.100.9',sample('account-b')),
           ('New device, shared IP','192.0.2.1',sample('account-c',names)),
           ('Repeated account rotation','192.0.2.1',sample('account-d')),
           ('Repeated account rotation','192.0.2.1',sample('account-e')),
           ('Repeated account rotation','192.0.2.1',sample('account-f')),
           ('Repeated account rotation','192.0.2.1',sample('account-g')),
           ('Repeated account rotation','192.0.2.1',sample('account-h'))]
    result=[]
    for label,ip,data in steps:
        out=engine.check(data,ip)
        result.append({'scenario':label,'decision':out['decision'],'relation':out['relation'],
                       'matched_signals':out.get('matched_signals',[]),'retry_after_seconds':out.get('retry_after_seconds',0)})
    return {'preset':preset,'settings':settings,'events':result, 'notice':'Synthetic data only. IP matches can link unrelated people on shared networks.'}

class Handler(BaseHTTPRequestHandler):
    server_version='ArchxDemo/0.1'
    protocol_version='HTTP/1.0'
    def handle(self):
        # One HTTP request per admitted connection, even if a client pipelines.
        self.close_connection=True
        self.handle_one_request()
    def log_message(self, format, *args): pass # avoid logging identifiers
    def json(self, data, status=200):
        payload=json.dumps(data,separators=(',',':')).encode()
        self.send_response(status); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff');
        if status in (429, 503) and type(data.get('retry_after_seconds')) is int and data['retry_after_seconds'] > 0: self.send_header('Retry-After',str(data['retry_after_seconds']))
        self.send_header('Content-Length',str(len(payload))); self.end_headers(); self.wfile.write(payload)
    def resolved_peer(self):
        return client_ip(self.client_address[0], self.headers.get_all('X-Forwarded-For', []), getattr(self.server,'trusted_proxies',[]))
    def request_service(self):
        return RequestService(self.server.engine, sealed_key=getattr(self.server,'sealed_key',None),
            replay=getattr(self.server,'replay',None), reputation=getattr(self.server,'reputation',None),
            reputation_mode=getattr(self.server,'reputation_mode','observe'),
            reputation_stale=getattr(self.server,'reputation_stale','open'),
            turnstile=getattr(self.server,'turnstile',None), metrics=getattr(self.server,'metrics',None))
    def get_body(self):
        if len(self.headers.get_all('Content-Type', [])) != 1 or self.headers.get('Content-Type','').split(';',1)[0].strip().lower() != 'application/json': raise ValueError('Content-Type must be application/json')
        if self.headers.get_all('Transfer-Encoding', []): raise ValueError('Transfer encoding unsupported')
        lengths=self.headers.get_all('Content-Length', [])
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdecimal(): raise ValueError('Invalid content length')
        try: length=int(lengths[0])
        except ValueError: raise ValueError('Invalid content length') from None
        if not 0 < length <= 8192: raise ValueError('Request must be between 1 and 8192 bytes')
        body=self.rfile.read(length)
        if len(body) != length: raise ValueError('Incomplete request body')
        return parse_json(body)
    def do_GET(self):
        path=urlsplit(self.path).path
        if path=='/api/v2/config':
            return self.json(self.request_service().config())
        if path=='/api/v2/challenge':
            try: peer=self.resolved_peer()
            except ValueError:
                limited=self.server.engine.reject_malformed(self.client_address[0])
                if limited: return self.json(limited,status_for(limited))
                return self.json({'decision':'invalid','reason':'invalid_request','message':self.server.engine.message('invalid_request')},400)
            result=self.request_service().challenge(peer)
            if result is None: return self.json({'error':'not_found'},404)
            return self.json(result,status_for(result) if 'decision' in result else 200)
        if path=='/api/info':
            try: survey=json.loads(SURVEY.read_text())
            except (OSError, ValueError): survey=None
            history=[]
            for file in SURVEY.parent.glob('survey-*.json'):
                try: history.append(json.loads(file.read_text()))
                except (OSError, ValueError): pass
            history.sort(key=lambda item:item.get('tested_at_utc',''), reverse=True)
            return self.json({'policy':self.server.engine.settings,'signals':SIGNALS,'survey':survey, 'survey_history':history, 'storage_mode':'sqlite' if isinstance(self.server.engine,SQLiteEngine) else 'memory', 'notice':'Demo only. TCP peer IP is used unless a trusted sanitizing proxy was explicitly configured.'})
        files={'/':('index.html','text/html; charset=utf-8'),'/style.css':('style.css','text/css; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8'),'/turnstile':('turnstile.html','text/html; charset=utf-8'),'/turnstile.js':('turnstile.js','text/javascript; charset=utf-8'),'/browser-test':('browser-test.html','text/html; charset=utf-8'),'/browser-test.js':('browser-test.js','text/javascript; charset=utf-8')}
        if path == '/browser-client.mjs':
            try: data=(ROOT.parent/'build/browser/archx-client.mjs').read_bytes()
            except OSError: return self.json({'error':'browser_client_not_built'},404)
            self.send_response(200); self.send_header('Content-Type','text/javascript; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Content-Length',str(len(data))); self.end_headers(); self.wfile.write(data)
            return
        if path not in files: return self.json({'error':'not_found'},404)
        name,typ=files[path]; data=(ROOT/'site'/name).read_bytes()
        self.send_response(200); self.send_header('Content-Type',typ); self.send_header('Content-Length',str(len(data))); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'self'; script-src 'self' "+("'wasm-unsafe-eval' " if path=='/browser-test' else '')+"https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; connect-src 'self' https://challenges.cloudflare.com; img-src 'self' data:; base-uri 'none'; frame-ancestors *"); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        path=urlsplit(self.path).path
        peer=self.client_address[0]
        try:
            if path=='/api/v2/check':
                try: peer=self.resolved_peer()
                except ValueError:
                    self.close_connection=True
                    raise
            body=self.get_body()
            if path=='/api/demo/run':
                if not isinstance(body,dict) or set(body)-{'preset','config'}: raise ValueError('Invalid request')
                return self.json(scenario(body.get('preset','basic'),body.get('config')))
            if path=='/api/v2/check':
                result=self.request_service().check(body,peer)
                return self.json(result,status_for(result))
            return self.json({'error':'not_found'},404)
        except (TimeoutError, ConnectionError):
            self.close_connection=True
            return
        except (ValueError, TypeError, KeyError) as e:
            if path == '/api/v2/check':
                limited=self.server.engine.reject_malformed(peer)
                if limited: return self.json(limited,429 if limited['decision']=='rate_limited' else 503)
            return self.json({'error':str(e),'decision':'invalid','reason':'invalid_request','message':self.server.engine.message('invalid_request')},400)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',default='127.0.0.1'); parser.add_argument('--port',type=int,default=8000)
    parser.add_argument('--max-connections',type=int,default=32,help='maximum concurrent accepted handlers (1-1024)')
    parser.add_argument('--connection-rate',type=float,default=25,help='global admitted connection tokens per second')
    parser.add_argument('--connection-burst',type=int,default=50,help='global connection token burst')
    parser.add_argument('--connection-deadline',type=float,default=15,help='absolute socket lifetime in seconds (max 300)')
    parser.add_argument('--preset',choices=list(PRESETS),default='basic'); parser.add_argument('--config',help='JSON policy override file'); parser.add_argument('--geo',help='JSON list of trusted CIDR timezone mappings'); parser.add_argument('--db',help='private SQLite database file (requires ARCHX_DEMO_SECRET of at least 32 bytes)')
    parser.add_argument('--trusted-proxy',action='append',default=[],help='trusted proxy CIDR; must overwrite X-Forwarded-For with one client address')
    parser.add_argument('--sealed-private-key',help='private 32-byte hex key file; requires encrypted check requests')
    parser.add_argument('--reputation-cache',help='IPsum cache populated by refresh_reputation.py')
    parser.add_argument('--reputation-mode',choices=['observe','block'],default='observe')
    parser.add_argument('--reputation-stale',choices=['open','closed'],default='open')
    parser.add_argument('--reputation-max-age',type=int,default=172800)
    parser.add_argument('--reputation-refresh-level',type=int,choices=range(1,9),help='automatically refresh IPsum at startup and periodically')
    parser.add_argument('--reputation-refresh-seconds',type=int,default=86400)
    parser.add_argument('--turnstile-sitekey'); parser.add_argument('--turnstile-hostname'); parser.add_argument('--turnstile-action')
    args=parser.parse_args()
    override=json.loads(Path(args.config).read_text()) if args.config else None
    geo=load_geo(json.loads(Path(args.geo).read_text())) if args.geo else []
    secret=os.getenv('ARCHX_DEMO_SECRET','').encode() or None
    engine = SQLiteEngine(args.db, policy(args.preset,override), secret=secret, geo=geo) if args.db else Engine(policy(args.preset,override),secret=secret,geo=geo)
    try:
        httpd=BoundedDemoServer((args.host,args.port),Handler,max_connections=args.max_connections,
            connection_rate=args.connection_rate,connection_burst=args.connection_burst,
            connection_deadline=args.connection_deadline)
    except ValueError as exc:
        parser.error(str(exc))
    httpd.engine=engine
    try: httpd.trusted_proxies=trusted_networks(args.trusted_proxy)
    except ValueError as exc: parser.error(str(exc))
    httpd.sealed_key=read_key(args.sealed_private_key,private=True) if args.sealed_private_key else None
    if httpd.sealed_key:
        try: import nacl.public
        except ImportError: parser.error('Encrypted mode requires PyNaCl; see demo/requirements-secure.txt')
    httpd.replay = (SQLiteReplay(engine) if isinstance(engine,SQLiteEngine) else MemoryReplay(engine.secret,engine.clock)) if httpd.sealed_key else None
    httpd.reputation=Reputation(args.reputation_cache,args.reputation_max_age) if args.reputation_cache else None
    httpd.reputation_mode=args.reputation_mode; httpd.reputation_stale=args.reputation_stale
    if args.reputation_refresh_level:
        if not args.reputation_cache or not 3600<=args.reputation_refresh_seconds<=2592000: parser.error('Automatic refresh requires a cache and interval between 3600 and 2592000 seconds')
        def refresh_loop():
            while True:
                try: refresh_ipsum(args.reputation_cache,args.reputation_refresh_level)
                except Exception: print('IPsum refresh failed; using configured stale/unavailable policy.',flush=True)
                time.sleep(args.reputation_refresh_seconds)
        threading.Thread(target=refresh_loop,daemon=True).start()
    turnstile_secret=os.getenv('ARCHX_TURNSTILE_SECRET')
    turnstile_values=(args.turnstile_sitekey,turnstile_secret,args.turnstile_hostname,args.turnstile_action)
    if any(turnstile_values) and not all(turnstile_values): parser.error('Turnstile requires sitekey, ARCHX_TURNSTILE_SECRET, expected hostname and action')
    httpd.turnstile=Turnstile(*turnstile_values) if all(turnstile_values) else None
    print(f'Archx demo on http://{args.host}:{args.port} (preset: {args.preset})',flush=True)
    try:
        httpd.serve_forever(poll_interval=0.1)
    finally:
        httpd.server_close()

if __name__=='__main__': main()
