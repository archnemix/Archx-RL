/* Real Chromium cross-language sealed-v3 test; synthetic data only. */
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
import {chromium} from 'playwright';
const candidates = [process.env.ARCHX_TEST_CHROME, chromium.executablePath(), '/usr/bin/google-chrome', '/usr/bin/chromium'];
const executablePath = candidates.find(path => path && existsSync(path));
if (!executablePath) { console.log('No Chromium executable available'); process.exit(77); }
const origin = process.env.ARCHX_TEST_ORIGIN, publicKey = process.env.ARCHX_TEST_PUBLIC_KEY;
if (!origin || !publicKey) throw new Error('Missing synthetic test configuration');
const browser = await chromium.launch({headless:true, executablePath, args:['--no-sandbox']});
try {
  const page = await browser.newPage();
  let envelope;
  page.on('request', request => {
    if (request.method() === 'POST' && new URL(request.url()).pathname === '/api/v2/check') envelope = request.postData();
  });
  // The dedicated synthetic page permits WASM; it remains a v2-only UI.
  await page.goto(origin+'/browser-test', {waitUntil:'load'});
  const response = await page.evaluate(async publicKey => {
    const {checkEncrypted} = await import('/browser-client.mjs');
    return checkEncrypted({publicKey, keyId:'old', signals:{machine_id:'123456789abcdef0123456789abcdef0'}, turnstileToken:'synthetic-token'});
  }, publicKey);
  assert.equal(response.status, 200);
  assert.equal(response.data.decision, 'allow');
  assert.equal(JSON.parse(envelope).version, 'sealed-v3');
  assert.equal(JSON.parse(envelope).key_id, 'old');
  assert.equal(envelope.includes('123456789abcdef0123456789abcdef0'), false);
  assert.equal(envelope.includes('synthetic-token'), false);
  const replay = await page.evaluate(async value => {
    const response = await fetch('/api/v2/check', {method:'POST', headers:{'Content-Type':'application/json'}, body:value});
    return {status:response.status, data:await response.json()};
  }, envelope);
  assert.equal(replay.status, 400);
  assert.equal(replay.data.reason, 'replay_rejected');
  console.log('Headless browser v3 cross-language tests passed');
} finally { await browser.close(); }
