"""Synthetic sealed-v3 key-grace experiment; not a key-management system."""
import ipaddress
import json
import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'demo'))
try:
    from nacl.public import PrivateKey
except ImportError:
    PrivateKey = None
from engine import policy
from replay import SQLiteReplay
from sealed_payload import TransportKeyRing, seal, seal_v3, unseal, unseal_v3
from service import RequestService
from signal_validation import synthetic_signal
from sqlite_engine import SQLiteEngine


@unittest.skipUnless(PrivateKey, 'PyNaCl is required for the optional transport experiment')
class TransportRotationTests(unittest.TestCase):
    def setUp(self):
        # Fixed synthetic values are test fixtures only, never deployment keys.
        self.old = PrivateKey(bytes(range(32)))
        self.new = PrivateKey(bytes(range(32, 64)))
        self.ring = TransportKeyRing({'old': bytes(self.old), 'new': bytes(self.new)})

    def test_key_id_is_cryptographically_bound_and_protocol_does_not_downgrade(self):
        payload = {'signals': {'machine_id': synthetic_signal('machine_id', 'v3')}}
        old_box = seal_v3(payload, 'old', bytes(self.old.public_key))
        self.assertEqual(json.loads(unseal_v3(old_box, self.ring)), payload)
        # Even two names mapped to the same underlying key cannot be swapped.
        alias = TransportKeyRing({'old': bytes(self.old), 'alias': bytes(self.old)})
        with self.assertRaisesRegex(ValueError, '^Invalid encrypted request$'):
            unseal_v3(dict(old_box, key_id='alias'), alias)
        cases = [dict(old_box, key_id='new'), dict(old_box, key_id='missing'),
                 dict(old_box, key_id='bad/key'), dict(old_box, version='sealed-v2'),
                 dict(old_box, ciphertext='not!base64'), dict(old_box, extra='x'),
                 seal(payload, bytes(self.old.public_key))]
        for box in cases:
            with self.subTest(box=box), self.assertRaisesRegex(ValueError, '^Invalid encrypted request$'):
                unseal_v3(box, self.ring)
        with self.assertRaisesRegex(ValueError, '^Invalid encrypted request$'):
            unseal(old_box, bytes(self.old))
        self.assertEqual(json.loads(unseal(seal(payload, bytes(self.old.public_key)), bytes(self.old))), payload)

    def test_bounded_key_ring_and_inputs(self):
        for value in ({}, {'bad/key': bytes(self.old)}, {'bad': b'x'},
                      {str(i): bytes(self.old) for i in range(9)}, [], None):
            with self.subTest(value=value), self.assertRaises(ValueError): TransportKeyRing(value)
        for key_id in ('', 'x'*33, 'a.b', 'a\0b', 'é', None):
            with self.subTest(key_id=key_id), self.assertRaises(ValueError):
                seal_v3({}, key_id, bytes(self.old.public_key))
        with self.assertRaises(ValueError): seal_v3({'x':'z'*9000}, 'old', bytes(self.old.public_key))
        with self.assertRaises(ValueError): seal_v3({}, 'old', b'short')
        source = {'old': bytes(self.old)}
        copied = TransportKeyRing(source)
        source.clear()
        box = seal_v3({'ok': True}, 'old', bytes(self.old.public_key))
        self.assertEqual(json.loads(unseal_v3(box, copied)), {'ok': True})
        self.assertNotIn(bytes(self.old).hex(), repr(copied))

    def test_concurrent_old_and_new_keys_share_nonce_and_quota_state(self):
        secret = b'synthetic-rotation-secret-at-least-32-bytes'
        settings = policy(override={'max_requests': 100})
        peer = '192.0.2.44'
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / 'state.sqlite')
            def service(keys):
                engine = SQLiteEngine(path, settings, secret, clock=lambda: 1700000000.0)
                return RequestService(engine, sealed_key=TransportKeyRing(keys), replay=SQLiteReplay(engine))
            old = service({'old': bytes(self.old)})
            new = service({'new': bytes(self.new)})
            nonce = old.challenge(peer)['nonce']
            body = {'nonce': nonce, 'signals': {'machine_id': synthetic_signal('machine_id', 'rotation-race')}}
            boxes = [(old, seal_v3(body, 'old', bytes(self.old.public_key))),
                     (new, seal_v3(body, 'new', bytes(self.new.public_key)))]
            with ThreadPoolExecutor(max_workers=16) as pool:
                results = list(pool.map(lambda item: item[0].check(item[1], peer), boxes * 12))
            self.assertEqual(sum(result['decision'] == 'allow' for result in results), 1)
            self.assertEqual(sum(result.get('reason') == 'replay_rejected' for result in results), 23)
            # Rebuilding either service must not resurrect a consumed nonce.
            restarted = service({'old': bytes(self.old), 'new': bytes(self.new)})
            self.assertEqual(restarted.check(boxes[0][1], peer)['reason'], 'replay_rejected')
            self.assertEqual(restarted.check(boxes[1][1], peer)['reason'], 'replay_rejected')
            with sqlite3.connect(path) as con:
                ip_key = restarted.engine.ip_key(ipaddress.ip_address(peer))
                self.assertEqual(con.execute('SELECT count FROM windows WHERE key=?', (ip_key,)).fetchone(), (26,))

    def test_grace_restart_replay_and_rollback_preserve_sqlite_limits(self):
        secret = b'synthetic-rotation-secret-at-least-32-bytes'
        settings = policy(override={'max_requests': 3})
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / 'state.sqlite')
            def service(keys):
                engine = SQLiteEngine(path, settings, secret, clock=lambda: 1700000000.0)
                return RequestService(engine, sealed_key=TransportKeyRing(keys), replay=SQLiteReplay(engine))
            def box(gate, peer, name, key, seed, nonce=None):
                nonce = nonce or gate.challenge(peer)['nonce']
                return seal_v3({'nonce': nonce, 'signals': {'machine_id': synthetic_signal('machine_id', seed)}},
                               name, bytes(key.public_key))
            old = service({'old': bytes(self.old)})
            self.assertEqual(old.config()['protocol'], 'sealed-v3')
            first = box(old, '192.0.2.10', 'old', self.old, 'first')
            self.assertEqual(old.check(first, '192.0.2.10')['decision'], 'allow')
            pending = box(old, '192.0.2.10', 'old', self.old, 'grace')
            used = box(old, '192.0.2.11', 'old', self.old, 'used')
            self.assertEqual(old.check(used, '192.0.2.11')['decision'], 'allow')
            # Reconstruct engine and replay store as a restart with old+new keys.
            grace = service({'old': bytes(self.old), 'new': bytes(self.new)})
            self.assertEqual(grace.check(used, '192.0.2.11')['reason'], 'replay_rejected')
            self.assertEqual(grace.check(pending, '192.0.2.10')['decision'], 'allow')
            new_box = box(grace, '192.0.2.10', 'new', self.new, 'new')
            self.assertEqual(grace.check(new_box, '192.0.2.10')['decision'], 'allow')
            new_only = service({'new': bytes(self.new)})
            extra = box(new_only, '192.0.2.10', 'new', self.new, 'quota')
            self.assertEqual(new_only.check(extra, '192.0.2.10')['decision'], 'rate_limited')
            nonce = new_only.challenge('192.0.2.20')['nonce']
            old_box = box(new_only, '192.0.2.20', 'old', self.old, 'removed', nonce)
            self.assertEqual(new_only.check(old_box, '192.0.2.20')['decision'], 'invalid')
            valid = box(new_only, '192.0.2.20', 'new', self.new, 'valid', nonce)
            self.assertEqual(new_only.check(valid, '192.0.2.20')['decision'], 'allow')
            # Explicit rollback removes new decryption support, but does not
            # roll back the independent quota/replay store.
            rollback = service({'old': bytes(self.old)})
            self.assertEqual(rollback.check(extra, '192.0.2.10')['decision'], 'rate_limited')
            nonce = rollback.challenge('192.0.2.21')['nonce']
            rejected = box(rollback, '192.0.2.21', 'new', self.new, 'new-removed', nonce)
            self.assertEqual(rollback.check(rejected, '192.0.2.21')['decision'], 'invalid')
            accepted = box(rollback, '192.0.2.21', 'old', self.old, 'old-rollback', nonce)
            self.assertEqual(rollback.check(accepted, '192.0.2.21')['decision'], 'allow')


if __name__ == '__main__': unittest.main(verbosity=2)
