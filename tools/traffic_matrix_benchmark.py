#!/usr/bin/env python3
"""Synthetic sequential memory/SQLite, direct/loopback HTTP benchmark matrix."""
import argparse
import collections
import http.client
import json
import os
import platform
import resource
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'demo'),str(ROOT/'tools')]
from engine import Engine, policy
from sqlite_engine import SQLiteEngine
from service import RequestService
from replay import MemoryReplay, SQLiteReplay
from sealed_payload import seal
from signal_validation import synthetic_signal
from bounded_server import BoundedDemoServer
from server import Handler
from gate_benchmark import timings

SECRET=b'synthetic-traffic-matrix-secret-1234567890'
PEER='127.0.0.1'
CAPACITY=64
STATES={'empty':0,'half':31,'saturated':63} # each unique signal plus one IP window
TRAFFIC=('allow','rate_limited','invalid','sealed')

def sample_listen_queue(port):
    """Linux instantaneous established-connection receive queue, not its peak."""
    try:
        for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
            parts=line.split()
            if len(parts)>4 and parts[3]=='0A' and int(parts[1].rsplit(':',1)[1],16)==port:
                return int(parts[4].split(':',1)[1],16)
    except (OSError,ValueError,IndexError): pass
    return None

class MeasuredServer(BoundedDemoServer):
    def __init__(self,*args,**kwargs):
        self.peak_active_at_handler_start=0
        self.queue_samples=0
        self.queue_max_observed=None
        super().__init__(*args,**kwargs)
    def process_request_thread(self, request, client_address):
        depth=sample_listen_queue(self.server_address[1])
        with self.lock:
            self.peak_active_at_handler_start=max(self.peak_active_at_handler_start,len(self.active))
            if depth is not None:
                self.queue_samples+=1
                self.queue_max_observed=max(self.queue_max_observed or 0,depth)
        return super().process_request_thread(request,client_address)

def body(seed): return {'signals':{'machine_id':synthetic_signal('machine_id',str(seed))}}

def cpu_model():
    try:
        for line in Path('/proc/cpuinfo').read_text().splitlines():
            if line.lower().startswith('model name'):
                return line.split(':',1)[1].strip()
    except OSError: pass
    return None

def run_case(mode,state,transport,traffic,count):
    if mode not in ('memory','sqlite') or state not in STATES or transport not in ('direct','http') or traffic not in TRAFFIC:
        raise ValueError('invalid scenario')
    if type(count) is not int or not 1 <= count <= 30: raise ValueError('invalid sample count')
    from nacl.public import PrivateKey
    population=STATES[state]
    threshold=max(1,population) if traffic=='rate_limited' else 10000
    settings=policy(override={'max_requests':10000,'ip_max_requests':threshold,'window_seconds':60,'history_seconds':3600})
    now=[1000]
    with tempfile.TemporaryDirectory(prefix='archx-traffic-matrix-') as tmp:
        engine=Engine(settings,secret=SECRET,clock=lambda:now[0],max_entries=CAPACITY) if mode=='memory' else SQLiteEngine(Path(tmp)/'state.sqlite',settings,SECRET,clock=lambda:now[0],max_entries=CAPACITY)
        for i in range(population):
            if engine.check(body('preload-'+str(i)),PEER)['decision']!='allow': raise RuntimeError('preload failed')
        if traffic=='rate_limited' and not population:
            if engine.check(body('warm'),PEER)['decision']!='allow': raise RuntimeError('warmup failed')
        key=PrivateKey.generate() if traffic=='sealed' else None
        replay=(MemoryReplay(SECRET,lambda:now[0]) if mode=='memory' else SQLiteReplay(engine)) if key else None
        gate=RequestService(engine,sealed_key=bytes(key) if key else None,replay=replay)
        server=None; thread=None
        if transport=='http':
            server=MeasuredServer(('127.0.0.1',0),Handler,max_connections=8,connection_rate=100000,connection_burst=100000)
            server.engine=engine; server.sealed_key=bytes(key) if key else None; server.replay=replay
            thread=threading.Thread(target=lambda:server.serve_forever(poll_interval=.01),daemon=True); thread.start()
        def request(method,path,document=None):
            client=http.client.HTTPConnection('127.0.0.1',server.server_address[1],timeout=10)
            try:
                client.request(method,path,None if document is None else json.dumps(document),{'Content-Type':'application/json'} if document is not None else {})
                response=client.getresponse(); return json.loads(response.read())
            finally: client.close()
        lat=[]; outcomes=collections.Counter(); errors=0
        start=time.perf_counter_ns(); cpu=time.process_time_ns()
        try:
            for i in range(count):
                t=time.perf_counter_ns()
                try:
                    doc={'signals':{}} if traffic=='invalid' else body('request-'+str(i))
                    if key:
                        challenge=request('GET','/api/v2/challenge') if server else gate.challenge(PEER)
                        doc=seal({**doc,'nonce':challenge['nonce']},bytes(key.public_key))
                    result=request('POST','/api/v2/check',doc) if server else gate.check(doc,PEER)
                    decision=result.get('decision','unexpected')
                    if decision not in ('allow','invalid','rate_limited','capacity_exceeded','storage_error','challenge'): decision='unexpected'
                    outcomes[decision]+=1
                except Exception:
                    errors+=1; outcomes['transport_or_client_error']+=1
                lat.append(time.perf_counter_ns()-t)
            elapsed=time.perf_counter_ns()-start; cpu_elapsed=time.process_time_ns()-cpu
        finally:
            if server:
                server.shutdown(); server.server_close(); thread.join(5)
        now[0]=5000
        recovery=engine.check(body('after-expiry'),PEER)['decision']
        return {'mode':mode,'state':state,'transport':transport,'traffic':traffic,'preloaded_observations':population,
                'requests':count,'outcomes':dict(outcomes),'errors':errors,
                'throughput_per_second':round(count/(elapsed/1e9),2),
                'elapsed_seconds':round(elapsed/1e9,5),'process_cpu_seconds':round(cpu_elapsed/1e9,5),
                'latency_ms':timings(lat),'generator_max_outstanding':1,
                'handler_peak_at_start':server.peak_active_at_handler_start if server else None,
                'configured_listen_backlog':server.request_queue_size if server else None,
                'listen_queue_samples':server.queue_samples if server else None,
                'listen_queue_max_observed':server.queue_max_observed if server else None,
                'recovery_after_synthetic_expiry':recovery}

def run(count=20):
    cases=[run_case(m,s,t,c,count) for m in ('memory','sqlite') for s in STATES for t in ('direct','http') for c in TRAFFIC]
    rss=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss if sys.platform.startswith('linux') else None
    return {'schema':1,'environment':{'system':platform.system(),'architecture':platform.machine(),'python':platform.python_version(),
                                      'cpu_model':cpu_model(),'logical_cpus':os.cpu_count()},
            'capacity':CAPACITY,'requests_per_case':count,'cases':cases,'process_peak_rss_kib':rss,
            'limitations':['single-process closed-loop sequential synthetic workload; no real users or external providers',
                           'HTTP is local plaintext loopback, not TLS, proxy or production host',
                           'sealed case includes challenge retrieval, encryption and check per measured operation',
                           'RSS is whole-process lifetime high-water and CPU includes client, server and generator',
                           'Linux listen-queue depth is sampled only at handler start, not continuously; sampling overhead affects timings and may miss peaks',
                           'application/upstream queues are not measured; generator holds one outstanding request',
                           'no reference hardware agreement or production capacity/latency budget']}

if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('--requests',type=int,default=20)
    args=p.parse_args(); print(json.dumps(run(args.requests),indent=2))
