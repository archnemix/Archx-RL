"""ABI-v1 Linux binding contract, shared protocol fixture and ownership faults."""
import ctypes
import hashlib
import hmac
import json
import shutil
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'bindings/python'))
from archx_native import Core, ArchxError

LIB = str(ROOT / 'build/libarchx.so')
FAKE = str(ROOT / 'build/binding_fake.so')
WRONG = str(ROOT / 'build/binding_wrong_abi.so')
FIXTURE = json.loads((ROOT / 'tests/fixtures/native-binding-v1.json').read_text())


class BindingTests(unittest.TestCase):
    def test_shared_protocol_fixture_and_denial(self):
        f = FIXTURE
        # Independently calculate the documented ABI-v1 HMAC inputs.
        def digest(name, value):
            msg = f'archx-profile-v1|fixture-app|{len(name)}:{name}{len(value)}:{value}'.encode()
            return hmac.new(b'synthetic-test-pepper', msg, hashlib.sha256).hexdigest()
        self.assertEqual(f['profiles']['192.0.2.1']['scope'], digest('scope', 'linux'))
        self.assertEqual(f['profiles']['192.0.2.1']['signals']['ip'], digest('ip', '192.0.2.1'))
        with Core(LIB, f['config']) as core:
            a, b, missing = core.profile('192.0.2.1'), core.profile('192.0.2.2'), core.profile()
            self.assertEqual(a, f['profiles']['192.0.2.1'])
            self.assertEqual(b, f['profiles']['192.0.2.2'])
            self.assertEqual(missing, f['profiles']['missing'])
            self.assertEqual(core.compare(a, a), f['results']['match'])
            self.assertEqual(core.compare(a, b), f['results']['changed'])
            self.assertEqual(core.compare(a, missing), f['results']['missing'])
            self.assertEqual([core.check('synthetic-key') for _ in range(3)], f['checks'])
            core.reset('synthetic-key')
            self.assertEqual(core.check('synthetic-key'), f['checks'][0])
            with self.assertRaises(ArchxError): core.profile('invalid-ip')
            with self.assertRaises(ArchxError): core.compare({'invalid':True}, a)
            with self.assertRaises(ArchxError): core.check('x' * 801)
            with self.assertRaises(ValueError): core.check('test\0bad')
            with self.assertRaises(UnicodeError): core.check('\ud800')
            with self.assertRaises(ValueError): core.compare({'bad':float('nan')}, a)
            with self.assertRaises(ValueError): core.check('test', 0)
        core.close()
        with self.assertRaises(ArchxError): core.profile()
        with self.assertRaises(ArchxError): Core(WRONG, f['config'])
        with self.assertRaises(ValueError): Core('relative.so', f['config'])
        with self.assertRaises(ArchxError): Core(LIB, {})

    def test_relocated_library_and_utf8_lengths(self):
        config = dict(FIXTURE['config'], app_id='fixture-café')
        with tempfile.TemporaryDirectory() as tmp:
            relocated = Path(tmp) / 'renamed-library.so'
            shutil.copyfile(LIB, relocated)
            with Core(str(relocated), config) as core:
                p = core.profile('192.0.2.1')
                self.assertEqual(core.compare(p, p)['result'], 'match')

    def test_buffer_freed_on_decode_and_native_errors_and_close_idempotent(self):
        fake = ctypes.CDLL(FAKE)
        fake.fixture_mode.argtypes = (ctypes.c_int,)
        fake.fixture_live.restype = ctypes.c_int
        fake.fixture_core_frees.restype = ctypes.c_int
        prior = fake.fixture_core_frees()
        core = Core(FAKE, {})
        try:
            for mode, exception in ((1, ValueError), (2, ArchxError), (3, ArchxError), (4, ArchxError)):
                fake.fixture_mode(mode)
                with self.assertRaises(exception): core.collect()
                self.assertEqual(fake.fixture_live(), 0)
            fake.fixture_mode(0)
            self.assertEqual(core.collect(), {'ok':True})
            self.assertEqual(fake.fixture_live(), 0)
        finally:
            core.close(); core.close()
        self.assertEqual(fake.fixture_core_frees(), prior + 1)

    def test_concurrent_calls_and_close_are_serialized(self):
        core = Core(LIB, FIXTURE['config'])
        ready = threading.Barrier(9)
        def run(_):
            ready.wait()
            try: return core.profile('192.0.2.1')
            except ArchxError: return 'closed'
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(run, i) for i in range(8)]
            ready.wait()
            core.close()
            results = [f.result() for f in futures]
        self.assertTrue(all(r == 'closed' or r == FIXTURE['profiles']['192.0.2.1'] for r in results))


if __name__ == '__main__': unittest.main(verbosity=2)
