/* Headless browser integration test with a mocked Turnstile widget. */
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
import {chromium} from 'playwright';

const candidates=[process.env.ARCHX_TEST_CHROME,chromium.executablePath(),'/usr/bin/google-chrome','/usr/bin/chromium','/usr/bin/chromium-browser'];
const executablePath=candidates.find(path=>path && existsSync(path));
if (!executablePath) { console.log('No Chromium executable available'); process.exit(77); }
if (process.argv.includes('--check')) { console.log('Chromium available'); process.exit(0); }
const origin=process.env.ARCHX_TEST_ORIGIN, publicKey=process.env.ARCHX_TEST_PUBLIC_KEY;
if (!origin || !publicKey) throw new Error('Missing synthetic test configuration.');
const browser=await chromium.launch({headless:true,executablePath,args:['--no-sandbox']});
try {
  const page=await browser.newPage();
  const errors=[];let envelope;
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{
    if (request.method()==='POST' && new URL(request.url()).pathname==='/api/v2/check') envelope=request.postData();
  });
  // The real Cloudflare widget is not contacted in this synthetic test.
  if (process.env.ARCHX_TEST_WIDGET==='yes') {
    await page.addInitScript(()=>{
      window.turnstile={render:(_selector,options)=>{queueMicrotask(()=>options.callback('synthetic-token'));return 'synthetic-widget';},reset:()=>{}};
    });
  }
  page.on('request',request=>{
    if (new URL(request.url()).hostname==='challenges.cloudflare.com') errors.push('Unexpected external widget request');
  });
  await page.goto(origin+'/browser-test',{waitUntil:'load'});
  const caps = await page.evaluate(async () => (await import('/browser-client.mjs')).capabilities());
  assert.equal(caps.schema,'archx.capabilities');
  assert.equal(caps.version,1);
  assert.equal(caps.platform,'browser');
  assert.equal(caps.signals.machine_id.status,'unsupported');
  assert.equal(caps.signals.product_uuid.status,'unsupported');
  assert.equal(caps.signals.app_install.status,'not_collected');
  assert.equal(caps.signals.ip.status,'host_provided');
  await page.locator('#public-key').fill(publicKey);
  await page.locator('#check').waitFor({state:'visible'});
  await page.waitForFunction(()=>!document.querySelector('#check').disabled);
  await page.locator('#check').click();
  try { await page.waitForFunction(()=>document.querySelector('#result').textContent==='Decision: allow',null,{timeout:15000}); }
  catch (_) { throw new Error('Browser check failed: '+await page.locator('#result').textContent()+'; page errors: '+errors.join(', ')); }
  assert.ok(envelope,'Expected a POST envelope');
  assert.equal(envelope.includes('123456789abcdef0123456789abcdef0'),false);
  assert.equal(envelope.includes('synthetic-token'),false);
  assert.equal(JSON.parse(envelope).version,'sealed-v2');
  const replay=await page.evaluate(async value=>{
    const response=await fetch('/api/v2/check',{method:'POST',headers:{'Content-Type':'application/json'},body:value});
    return {status:response.status,body:await response.json()};
  },envelope);
  assert.equal(replay.status,400);
  assert.equal(replay.body.reason,'replay_rejected');
  assert.deepEqual(errors,[]);
  console.log('Headless browser encrypted UI and replay tests passed');
} finally { await browser.close(); }
