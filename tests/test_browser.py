"""Exercise browser JavaScript and optional real Chromium against Python HTTP."""
import os
import shutil
import subprocess
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'demo'))
from engine import Engine, policy
from replay import MemoryReplay
from server import Handler


class BrowserClientTests(unittest.TestCase):
    def prerequisites(self):
        try:
            from nacl.public import PrivateKey
        except ImportError:
            if os.environ.get('ARCHX_REQUIRE_BROWSER')=='1': self.fail('PyNaCl is required')
            self.skipTest('PyNaCl is required for browser interoperability')
        if not shutil.which('node') or not (ROOT/'build/browser/archx-client.mjs').is_file():
            if os.environ.get('ARCHX_REQUIRE_BROWSER')=='1': self.fail('Node.js and browser client build are required')
            self.skipTest('Build the optional browser client and install Node.js')
        return PrivateKey

    def run_against_server(self, script, success_marker, turnstile=True):
        PrivateKey=self.prerequisites()
        key=PrivateKey.generate()
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        server.engine=Engine(policy(override={'max_requests':100}),secret=b'browser-test')
        server.sealed_key=bytes(key)
        server.replay=MemoryReplay(server.engine.secret,server.engine.clock)
        class Verifier:
            sitekey='synthetic-site-key';action='test'
            def verify(self,token): return 'valid' if token=='synthetic-token' else 'invalid'
        server.turnstile=Verifier() if turnstile else None
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            env={**os.environ,'ARCHX_TEST_ORIGIN':f'http://127.0.0.1:{server.server_address[1]}',
                 'ARCHX_TEST_PUBLIC_KEY':bytes(key.public_key).hex(), 'ARCHX_TEST_WIDGET':'yes' if turnstile else 'no'}
            result=subprocess.run(['node',script],cwd=ROOT,env=env,stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE,text=True,timeout=60)
            self.assertEqual(result.returncode,0,result.stderr+'\n'+result.stdout)
            self.assertIn(success_marker,result.stdout)
            self.assertNotIn('123456789abcdef0123456789abcdef0',str(server.engine.observations))
        finally:
            server.shutdown();server.server_close();thread.join()

    def test_node_javascript_interoperability_with_backend(self):
        self.run_against_server('tests/browser_client_node.mjs','cross-language tests passed')

    def test_real_browser_synthetic_widget_and_encrypted_request(self):
        self.prerequisites()
        if not (ROOT/'demo/browser/node_modules/playwright').is_dir():
            if os.environ.get('ARCHX_REQUIRE_BROWSER')=='1': self.fail('Playwright is required')
            self.skipTest('Install optional browser test dependencies')
        probe=subprocess.run(['node','demo/browser/test-ui.mjs','--check'],cwd=ROOT,
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=15)
        if probe.returncode==77:
            if os.environ.get('ARCHX_REQUIRE_BROWSER')=='1': self.fail('Chromium is required')
            self.skipTest('Chromium is not available')
        self.assertEqual(probe.returncode,0,probe.stderr)
        for turnstile in (False,True):
            with self.subTest(turnstile=turnstile):
                self.run_against_server('demo/browser/test-ui.mjs','browser encrypted UI and replay tests passed',turnstile=turnstile)


if __name__=='__main__': unittest.main(verbosity=2)
