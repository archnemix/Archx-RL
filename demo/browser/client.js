/* Browser sealed-v2/v3 client. Collects and stores no identifiers itself. */
import sodium from 'libsodium-wrappers';

const MAX_RESPONSE = 8192;
const PREFIX = 'archx-sealed-check-v2\0';

/** Capability metadata only: this browser client does not collect native IDs. */
export function capabilities() {
  return {schema:'archx.capabilities', version:1, platform:'browser', signals:{
    machine_id:{kind:'os_install', status:'unsupported'},
    product_uuid:{kind:'firmware', status:'unsupported'},
    board_serial:{kind:'firmware', status:'unsupported'},
    app_install:{kind:'app_install', status:'not_collected'},
    ip:{kind:'network', status:'host_provided'},
  }};
}

function requireSecureOrigin() {
  const url = new URL(globalThis.location.href);
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) {
    throw new Error('Encrypted checks require HTTPS except on local loopback.');
  }
}

async function requestJson(path, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(path, {
      ...options, mode: 'same-origin', credentials: 'omit', cache: 'no-store',
      redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal,
    });
    if (!response.body) throw new Error('Missing server response.');
    const reader = response.body.getReader();
    const chunks = []; let size = 0;
    try {
      while (true) {
        const {value, done} = await reader.read();
        if (done) break;
        size += value.length;
        if (size > MAX_RESPONSE) {
          await reader.cancel();
          throw new Error('Server response is too large.');
        }
        chunks.push(value);
      }
    } finally { reader.releaseLock(); }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    const data = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(bytes));
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('Invalid server response.');
    return {status:response.status, ok:response.ok, data};
  } finally { clearTimeout(timeout); }
}

/** Submit caller-provided signals using an independently trusted public key. */
export async function checkEncrypted({publicKey, keyId, signals, turnstileToken, timezone} = {}) {
  requireSecureOrigin();
  // V3 is explicit: the key ID and public key must come from the same trusted
  // source. Never let an unauthenticated server choose a downgrade or key ID.
  if (keyId !== undefined && (typeof keyId !== 'string' || keyId.length < 1 || keyId.length > 32 || /[^A-Za-z0-9_-]/.test(keyId))) {
    throw new Error('Invalid trusted transport key ID.');
  }
  const version = keyId === undefined ? 'sealed-v2' : 'sealed-v3';
  const prefix = keyId === undefined ? PREFIX : 'archx-sealed-check-v3\0' + String.fromCharCode(keyId.length) + keyId;
  if (typeof publicKey !== 'string' || !/^[0-9a-fA-F]{64}$/.test(publicKey)) {
    throw new Error('Provide an independently trusted 32-byte public key in hex.');
  }
  if (!signals || typeof signals !== 'object' || Array.isArray(signals)) throw new Error('Signals must be an object.');
  if (turnstileToken !== undefined && (typeof turnstileToken !== 'string' || !turnstileToken.length || turnstileToken.length > 2048)) throw new Error('Invalid Turnstile token.');
  if (timezone !== undefined && (typeof timezone !== 'string' || timezone.length > 128)) throw new Error('Invalid timezone.');
  // Snapshot caller-provided values before awaiting; never log or persist them.
  const body = JSON.parse(JSON.stringify({signals, nonce:'A'.repeat(43), timestamp:Date.now()/1000,
    ...(turnstileToken !== undefined ? {turnstile_token:turnstileToken} : {}),
    ...(timezone !== undefined ? {timezone} : {})}));
  if (!body.signals || typeof body.signals !== 'object' || Array.isArray(body.signals)) throw new Error('Signals must be an object.');
  await sodium.ready;
  const encoder = new TextEncoder();
  const previewLength = encoder.encode(prefix + JSON.stringify(body)).length;
  const encodedLength = Math.ceil((previewLength + sodium.crypto_box_SEALBYTES) / 3) * 4;
  const envelopeOverhead = JSON.stringify({version, ...(keyId === undefined ? {} : {key_id:keyId}), ciphertext:''}).length;
  if (previewLength > 6144 || encodedLength + envelopeOverhead > 8192) throw new Error('Request is too large.');
  const config = await requestJson('/api/v2/config');
  if (!config.ok || config.data.protocol !== version) throw new Error('Encrypted mode unavailable; refusing downgrade.');
  const challenge = await requestJson('/api/v2/challenge');
  if (!challenge.ok || typeof challenge.data.nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(challenge.data.nonce)) {
    throw new Error('A fresh server challenge is unavailable.');
  }
  body.nonce = challenge.data.nonce;
  const plaintext = encoder.encode(prefix + JSON.stringify(body));
  const ciphertext = sodium.crypto_box_seal(plaintext, sodium.from_hex(publicKey));
  const envelope = JSON.stringify({version, ...(keyId === undefined ? {} : {key_id:keyId}), ciphertext:sodium.to_base64(ciphertext,sodium.base64_variants.ORIGINAL)});
  if (new TextEncoder().encode(envelope).length > 8192) throw new Error('Request is too large.');
  const result = await requestJson('/api/v2/check', {
    method:'POST', headers:{'Content-Type':'application/json'}, body:envelope,
  });
  return {status:result.status, data:result.data};
}
