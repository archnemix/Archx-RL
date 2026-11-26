/* Synthetic Node/browser-client interoperability against a v3 Python gate. */
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';
const origin = process.env.ARCHX_TEST_ORIGIN, publicKey = process.env.ARCHX_TEST_PUBLIC_KEY;
if (!origin || !publicKey) throw new Error('Missing synthetic test configuration');
globalThis.location = new URL(origin);
const nativeFetch = globalThis.fetch;
let envelope, count = 0;
globalThis.fetch = async (path, options={}) => {
  count++;
  if (path === '/api/v2/check') envelope = options.body;
  return nativeFetch(new URL(path, origin), options);
};
const {checkEncrypted} = await import(pathToFileURL(resolve('build/browser/archx-client.mjs')).href);
const signals = {machine_id:'123456789abcdef0123456789abcdef0'};
const result = await checkEncrypted({publicKey, keyId:'old', signals, turnstileToken:'synthetic-token'});
assert.equal(result.status, 200);
assert.equal(result.data.decision, 'allow');
assert.equal(envelope.includes(signals.machine_id), false);
const parsed = JSON.parse(envelope);
assert.equal(parsed.version, 'sealed-v3');
assert.equal(parsed.key_id, 'old');
// Both IDs are mapped to the same key in this synthetic server; the ID is
// nevertheless authenticated inside the ciphertext and cannot be rewritten.
const tampered = await nativeFetch(new URL('/api/v2/check', origin), {
  method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({...parsed, key_id:'alias'})
});
assert.equal(tampered.status, 400);
const replay = await nativeFetch(new URL('/api/v2/check', origin), {
  method:'POST', headers:{'Content-Type':'application/json'}, body:envelope
});
assert.equal(replay.status, 400);
assert.equal((await replay.json()).reason, 'replay_rejected');
await assert.rejects(() => checkEncrypted({publicKey, signals}), /refusing downgrade/);
const before = count;
for (const keyId of ['', 'x'.repeat(33), 'bad/key', 'old\n', 1]) {
  await assert.rejects(() => checkEncrypted({publicKey, keyId, signals}), /key ID/);
}
assert.equal(count, before);
const fetchBefore = globalThis.fetch;
globalThis.fetch = async () => new Response(JSON.stringify({protocol:'sealed-v2'}), {status:200});
await assert.rejects(() => checkEncrypted({publicKey, keyId:'old', signals}), /refusing downgrade/);
globalThis.fetch = fetchBefore;
console.log('Browser JavaScript v3 cross-language tests passed');
