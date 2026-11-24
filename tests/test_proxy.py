"""Verify the opt-in trusted-proxy boundary and forged-header rejection."""
import http.client
import json
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'demo'))
from engine import Engine, policy
from proxy import client_ip, trusted_networks
from server import Handler
from signal_validation import synthetic_signal


class ProxyTests(unittest.TestCase):
    def test_trust_boundary_and_header_validation(self):
        nets = trusted_networks(['192.0.2.1/32', '2001:db8::/32'])
        self.assertEqual(client_ip('198.51.100.1', ['203.0.113.8'], nets), '198.51.100.1')
        self.assertEqual(client_ip('192.0.2.1', ['203.0.113.8'], nets), '203.0.113.8')
        self.assertEqual(client_ip('2001:db8::2', ['::ffff:203.0.113.8'], nets), '203.0.113.8')
        for headers in ([], ['1.2.3.4','2.3.4.5'], ['1.2.3.4, 2.3.4.5'], ['bad'], ['fe80::1%eth0']):
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                client_ip('192.0.2.1', headers, nets)
        for value in (['0.0.0.0/0'], ['::/0'], ['192.0.2.1/24'], ['bad']):
            with self.assertRaises(ValueError): trusted_networks(value)

    def test_http_trusted_proxy_uses_overwritten_single_header(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        server.engine=Engine(policy(override={'max_requests':1}),secret=b'proxy-test')
        server.trusted_proxies=trusted_networks(['127.0.0.1/32'])
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        try:
            def post(ip, seed):
                con=http.client.HTTPConnection('127.0.0.1',server.server_address[1],timeout=5)
                data={'signals':{'machine_id':synthetic_signal('machine_id',seed)}}
                con.request('POST','/api/v2/check',json.dumps(data),{'Content-Type':'application/json','X-Forwarded-For':ip})
                response=con.getresponse(); result=(response.status,json.loads(response.read()));con.close();return result
            self.assertEqual(post('192.0.2.1','a')[0],200)
            self.assertEqual(post('192.0.2.2','b')[0],200)
            self.assertEqual(post('192.0.2.1','c')[0],429)
            self.assertEqual(post('192.0.2.3, 192.0.2.4','d')[0],400)
        finally:
            server.shutdown();server.server_close();thread.join()


if __name__ == '__main__': unittest.main(verbosity=2)
