"""Synthetic gradual IP challenge and explicitly host-authorized recovery."""
import io
import json
import random
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'demo'),str(ROOT/'examples/python')]
from engine import Engine, policy
from expiry_heap import ExpiryHeap
from sqlite_engine import SQLiteEngine
from service import RequestService
from signal_validation import synthetic_signal
from gated_wsgi import create_application
sys.path.insert(0,str(ROOT/'tools'))
from progressive_nat_simulation import run as simulate_nat

SECRET=b'synthetic-progressive-test-secret-1234567'

def body(i): return {'signals':{'machine_id':synthetic_signal('machine_id',str(i))}}

class ProgressiveRecoveryTests(unittest.TestCase):
    def test_heap_targeted_removal_against_reference(self):
        rng=random.Random(311); heap=ExpiryHeap(); model={}
        for _ in range(3000):
            key=str(rng.randrange(60))
            if rng.randrange(3):
                expiry=rng.randrange(100); heap.set(key,expiry); model[key]=expiry
            else:
                self.assertEqual(heap.remove(key),key in model); model.pop(key,None)
            self.assertEqual(len(heap),len(model))
            self.assertEqual(heap.peek(),min(((v,k) for k,v in model.items()),default=None))
            for i,item in enumerate(heap.heap):
                self.assertEqual(heap.positions[item[1]],i)
                if i: self.assertLessEqual(heap.heap[(i-1)//2],item)

    def test_progression_and_ip_reset_preserves_device_quota(self):
        for mode in ('memory','sqlite'):
            for through_service in (False,True):
                with self.subTest(mode=mode,through_service=through_service), tempfile.TemporaryDirectory() as tmp:
                    p=policy(override={'max_requests':5,'ip_max_requests':4,'device_max_requests':2,'ip_challenge_after':2})
                    e=Engine(p,secret=SECRET,clock=lambda:1000) if mode=='memory' else SQLiteEngine(Path(tmp)/'state.sqlite',p,SECRET,clock=lambda:1000)
                    gate=RequestService(e) if through_service else e
                    self.assertEqual(gate.check(body('a'),'192.0.2.1')['decision'],'allow')
                    self.assertEqual(gate.check(body('b'),'192.0.2.1')['decision'],'allow')
                    r=gate.check(body('c'),'192.0.2.1'); self.assertEqual((r['decision'],r['reason']),('challenge','rate_challenge'))
                    self.assertEqual(gate.check(body('d'),'192.0.2.1')['decision'],'challenge')
                    self.assertEqual(gate.check(body('e'),'192.0.2.1')['decision'],'rate_limited')
                    self.assertTrue(e.reset_ip_window('::ffff:192.0.2.1'))
                    self.assertFalse(e.reset_ip_window('192.0.2.1'))
                    self.assertEqual(gate.check(body('a'),'192.0.2.1')['decision'],'allow')
                    # Device key remains charged: reset only affects the shared IP.
                    self.assertEqual(gate.check(body('a'),'192.0.2.1')['decision'],'rate_limited')
                    self.assertEqual(gate.check(body('other'),'192.0.2.2')['decision'],'allow')

    def test_nat_simulation_shows_cost_of_soft_challenges_and_explicit_resets(self):
        for mode in ('memory','sqlite'):
            result=simulate_nat(mode)
            self.assertEqual(result['scenarios'][0]['decisions'],{'allow':3,'challenge':2,'rate_limited':25})
            self.assertEqual(result['scenarios'][1]['decisions'],{'allow':18,'challenge':12})
            self.assertEqual(result['scenarios'][1]['resets'],5)
            self.assertTrue(any('including attackers' in item for item in result['limitations']))

    def test_validation_persisted_policy_and_storage_fault(self):
        defaults=policy(override={'max_requests':4})
        self.assertNotIn('ip_challenge_after',defaults)
        e0=Engine(defaults,secret=SECRET)
        self.assertTrue(all(e0.check(body(i),'192.0.2.1')['decision']=='allow' for i in range(4)))
        self.assertEqual(e0.check(body('fifth'),'192.0.2.1')['decision'],'rate_limited')
        for bad in (0,True,4,5,'1'):
            with self.assertRaises(ValueError): policy(override={'max_requests':4,'ip_challenge_after':bad})
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'state.sqlite'; p=policy(override={'ip_max_requests':4,'ip_challenge_after':2})
            e=SQLiteEngine(path,p,SECRET,clock=lambda:1000)
            e.check(body('a'),'192.0.2.1')
            with patch.object(e,'connect',side_effect=sqlite3.OperationalError('synthetic private fault')):
                with self.assertRaises(sqlite3.OperationalError): e.reset_ip_window('192.0.2.1')
            self.assertTrue(e.reset_ip_window('192.0.2.1'))
            changed=policy(override={'ip_max_requests':4,'ip_challenge_after':3})
            with self.assertRaisesRegex(ValueError,'policy'): SQLiteEngine(path,changed,SECRET)

    def test_host_recovery_is_disabled_by_default_and_requires_all_hooks(self):
        e=Engine(policy(),secret=SECRET); gate=RequestService(e)
        with self.assertRaises(ValueError): create_application(gate,approve_recovery=lambda *a:True)
        with self.assertRaises(ValueError): create_application(gate,approve_recovery=lambda *a:True,audit_recovery=lambda *a:True)
        app=create_application(gate)
        env={'REMOTE_ADDR':'192.0.2.1','REQUEST_METHOD':'POST','PATH_INFO':'/recovery'}
        status=[]; b''.join(app(env,lambda s,h:status.append(s)))
        self.assertEqual(status,['404 Not Found'])

    def test_host_non_boolean_or_exceptions_fail_closed_before_reset(self):
        e=Engine(policy(),secret=SECRET); gate=RequestService(e)
        for field in ('principal','authorize','approval','audit'):
            for value in ('nonbool','exception'):
                hooks={'principal':lambda *args:'trusted','authorize':lambda *args:True,
                       'approval':lambda *args:True,'audit':lambda *args:True}
                def invalid(*args):
                    if value=='exception': raise RuntimeError('private marker')
                    return None if field=='principal' else 'yes'
                hooks[field]=invalid
                app=create_application(gate,resolve_principal=hooks['principal'],authorize=hooks['authorize'],
                                       approve_recovery=hooks['approval'],audit_recovery=hooks['audit'])
                env={'REMOTE_ADDR':'192.0.2.1','REQUEST_METHOD':'POST','PATH_INFO':'/recovery'}
                with patch.object(e,'reset_ip_window') as reset:
                    status=[]; payload=b''.join(app(env,lambda s,h:status.append(s)))
                    reset.assert_not_called()
                self.assertTrue(status[0].startswith(('403','503')))
                self.assertNotIn(b'private marker',payload)

    def test_host_recovery_denies_failed_auth_approval_audit_and_storage(self):
        for mode in ('memory','sqlite'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                e=Engine(policy(override={'max_requests':1}),secret=SECRET) if mode=='memory' else SQLiteEngine(Path(tmp)/'state.sqlite',policy(override={'max_requests':1}),SECRET)
                gate=RequestService(e); actions=[]; audit=[]; control={'auth':False,'approval':False,'audit':True}
                app=create_application(gate,lambda:actions.append('operation') or {'ok':True},
                    resolve_principal=lambda env:'trusted-principal',authorize=lambda p,o:control['auth'],
                    approve_recovery=lambda p,o:control['approval'],
                    audit_recovery=lambda p,o:audit.append((p,o)) or control['audit'])
                def send(path,document=None):
                    raw=json.dumps(document or {}).encode()
                    env={'REMOTE_ADDR':'192.0.2.1','REQUEST_METHOD':'POST','PATH_INFO':path,'CONTENT_TYPE':'application/json',
                         'CONTENT_LENGTH':str(len(raw)),'wsgi.input':io.BytesIO(raw),'HTTP_X_FORWARDED_FOR':'198.51.100.9'}
                    status=[]; payload=b''.join(app(env,lambda s,h:status.append(s)))
                    return status[0],json.loads(payload)
                control['auth']=True
                self.assertEqual(send('/protected',body('victim'))[0],'200 OK')
                self.assertEqual(send('/protected',body('different'))[0],'429 Too Many Requests')
                control['auth']=False; self.assertEqual(send('/recovery')[0],'403 Forbidden')
                control['auth']=True; control['approval']=False; self.assertEqual(send('/recovery')[0],'403 Forbidden')
                control['approval']=True; control['audit']=False; self.assertEqual(send('/recovery')[0],'503 Service Unavailable')
                control['audit']=True
                with patch.object(e,'reset_ip_window',side_effect=RuntimeError('secret private failure')):
                    status,result=send('/recovery'); self.assertEqual(status,'503 Service Unavailable'); self.assertNotIn('secret',json.dumps(result))
                status,result=send('/recovery'); self.assertEqual(status,'200 OK'); self.assertNotIn('192.0.2.1',json.dumps(result))
                self.assertEqual(send('/protected',body('different'))[0],'200 OK')
                self.assertEqual(actions,['operation','operation'])
                self.assertTrue(all(op=='synthetic.recovery' for _,op in audit))

if __name__=='__main__': unittest.main(verbosity=2)
