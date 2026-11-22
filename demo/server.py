#!/usr/bin/env python3
"""Local Archx explorer and request-policy demonstration; not production middleware."""
import argparse
import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from engine import Engine, PRESETS, SIGNALS, policy, load_geo

ROOT=Path(__file__).resolve().parent
SURVEY=ROOT.parent/'.github/archx-runner/runs/linux-permissions.json'


def scenario(preset, override=None):
    # Completely isolated synthetic tests, never touch the live store or external services.
    import hashlib
    def t(x): return hashlib.sha256(x.encode()).hexdigest()
    settings=policy(preset,override)
    engine=Engine(settings,secret=b'demo-simulation-key',clock=lambda:1700000000.0)
    # Supply every selected signal; required-set and threshold behavior remain observable.
    names=settings['required']+settings['conditional']
    def sample(account, changes=None):
        values={n:t('device-a-'+n) for n in names}
        if changes:
            for n in changes: values[n]=t('device-b-'+n)
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
    def log_message(self, format, *args): pass # avoid logging identifiers
    def json(self, data, status=200):
        payload=json.dumps(data,separators=(',',':')).encode()
        self.send_response(status); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Content-Length',str(len(payload))); self.end_headers(); self.wfile.write(payload)
    def get_body(self):
        if self.headers.get('Content-Type','').split(';',1)[0].strip().lower() != 'application/json': raise ValueError('Content-Type must be application/json')
        if self.headers.get('Transfer-Encoding'): raise ValueError('Transfer encoding unsupported')
        try: length=int(self.headers.get('Content-Length',''))
        except ValueError: raise ValueError('Invalid content length') from None
        if not 0 < length <= 8192: raise ValueError('Request must be between 1 and 8192 bytes')
        def unique_pairs(pairs):
            result={}
            for key, value in pairs:
                if key in result: raise ValueError('Duplicate key')
                result[key]=value
            return result
        try: return json.loads(self.rfile.read(length), object_pairs_hook=unique_pairs)
        except (UnicodeError, ValueError, RecursionError): raise ValueError('Invalid JSON') from None
    def do_GET(self):
        path=urlsplit(self.path).path
        if path=='/api/info':
            try: survey=json.loads(SURVEY.read_text())
            except (OSError, ValueError): survey=None
            history=[]
            for file in SURVEY.parent.glob('survey-*.json'):
                try: history.append(json.loads(file.read_text()))
                except (OSError, ValueError): pass
            history.sort(key=lambda item:item.get('tested_at_utc',''), reverse=True)
            return self.json({'policy':self.server.engine.settings,'signals':SIGNALS,'survey':survey, 'survey_history':history, 'notice':'Demo only. The server uses the TCP peer IP and does not trust forwarding headers.'})
        files={'/':('index.html','text/html; charset=utf-8'),'/style.css':('style.css','text/css; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8')}
        if path not in files: return self.json({'error':'not_found'},404)
        name,typ=files[path]; data=(ROOT/'site'/name).read_bytes()
        self.send_response(200); self.send_header('Content-Type',typ); self.send_header('Content-Length',str(len(data))); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors *"); self.end_headers(); self.wfile.write(data)
    def do_POST(self):
        path=urlsplit(self.path).path
        try:
            body=self.get_body()
            if path=='/api/demo/run':
                if not isinstance(body,dict) or set(body)-{'preset','config'}: raise ValueError('Invalid request')
                return self.json(scenario(body.get('preset','basic'),body.get('config')))
            if path=='/api/v1/check':
                result=self.server.engine.check(body,self.client_address[0])
                status={'allow':200,'invalid':400,'challenge':403,'rate_limited':429,'capacity_exceeded':503}.get(result['decision'],500)
                return self.json(result,status)
            return self.json({'error':'not_found'},404)
        except (ValueError, TypeError, KeyError) as e:
            if path == '/api/v1/check':
                limited=self.server.engine.reject_malformed(self.client_address[0])
                if limited: return self.json(limited,429 if limited['decision']=='rate_limited' else 503)
            return self.json({'error':str(e)},400)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',default='0.0.0.0'); parser.add_argument('--port',type=int,default=8000)
    parser.add_argument('--preset',choices=list(PRESETS),default='basic'); parser.add_argument('--config',help='JSON policy override file'); parser.add_argument('--geo',help='JSON list of trusted CIDR timezone mappings')
    args=parser.parse_args()
    override=json.loads(Path(args.config).read_text()) if args.config else None
    geo=load_geo(json.loads(Path(args.geo).read_text())) if args.geo else []
    secret=os.getenv('ARCHX_DEMO_SECRET','').encode() or None
    httpd=ThreadingHTTPServer((args.host,args.port),Handler)
    httpd.engine=Engine(policy(args.preset,override),secret=secret,geo=geo)
    print(f'Archx demo on http://{args.host}:{args.port} (preset: {args.preset})',flush=True)
    httpd.serve_forever()

if __name__=='__main__': main()
