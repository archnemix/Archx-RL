'use strict';
// Experimental Linux ABI-v1 binding. Loading an arbitrary shared library
// executes native code with the caller's privileges; choose a trusted path.
const koffi = require('koffi');
const path = require('path');

class ArchxError extends Error {}

function text(value, name) {
  if (typeof value !== 'string' || value.includes('\0') || Buffer.from(value, 'utf8').toString('utf8') !== value)
    throw new TypeError(`${name} must be a NUL-free, well-formed Unicode string`);
  return value;
}
function json(value) {
  const result = JSON.stringify(value, (_key, item) => {
    if (typeof item === 'number' && !Number.isFinite(item)) throw new TypeError('Non-finite JSON number');
    if (typeof item === 'undefined' || typeof item === 'function' || typeof item === 'symbol')
      throw new TypeError('Value must be JSON serializable');
    return item;
  });
  if (typeof result !== 'string') throw new TypeError('Value must be JSON serializable');
  return result;
}

class Core {
  constructor(libraryPath, config) {
    if (typeof libraryPath !== 'string' || !path.isAbsolute(libraryPath)) throw new TypeError('An absolute trusted library path is required');
    const lib = koffi.load(libraryPath);
    this.lib = lib; // Keep the library loaded as long as its functions/handle are in use.
    const abi = lib.func('uint32_t ax_abi_version(void)');
    if (abi() !== 1) throw new ArchxError('Unsupported Archx ABI version');
    this.fn = {
      new: lib.func('void *ax_core_new(const char *config_json, size_t config_len)'),
      free: lib.func('void ax_core_free(void *core)'),
      lastError: lib.func('const char *ax_last_error(void)'),
      bufferFree: lib.func('void ax_buffer_free(void *buf)'),
      collect: lib.func('int ax_collect(void *core, _Out_ void **json, _Out_ size_t *len)'),
      identify: lib.func('int ax_identify(void *core, _Out_ void **json, _Out_ size_t *len)'),
      profile: lib.func('int ax_profile_with_ip(void *core, const char *ip, _Out_ void **json, _Out_ size_t *len)'),
      compare: lib.func('int ax_compare(void *core, const char *a, size_t a_len, const char *b, size_t b_len, _Out_ void **json, _Out_ size_t *len)'),
      check: lib.func('int ax_check(void *core, const char *key, int64_t cost, _Out_ int64_t *remaining, _Out_ int64_t *retry)'),
      reset: lib.func('int ax_reset(void *core, const char *key)')
    };
    const encoded = json(config);
    this.handle = this.fn.new(encoded, Buffer.byteLength(encoded));
    if (!this.handle) throw new ArchxError(this.error());
  }
  error() { return this.fn.lastError() || 'Native operation failed'; }
  requireOpen() { if (!this.handle) throw new ArchxError('Core is closed'); return this.handle; }
  close() { if (this.handle) { this.fn.free(this.handle); this.handle = null; } }
  result(name, ...args) {
    const ptr = [null], length = [0];
    try {
      const status = this.fn[name](this.requireOpen(), ...args, ptr, length);
      if (status !== 0) throw new ArchxError(this.error());
      if (!ptr[0]) throw new ArchxError('Native operation returned no buffer');
      if (!Number.isSafeInteger(length[0]) || length[0] < 0 || length[0] > 1048576) throw new ArchxError('Invalid native buffer length');
      const bytes = koffi.decode(ptr[0], 'uint8_t', length[0]);
      return JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(Uint8Array.from(bytes)));
    } finally {
      if (ptr[0]) this.fn.bufferFree(ptr[0]);
    }
  }
  collect() { return this.result('collect'); }
  capabilities() {
    this.requireOpen();
    if (!this.fn.capabilities) {
      try { this.fn.capabilities = this.lib.func('int ax_collect_capabilities(void *core, _Out_ void **json, _Out_ size_t *len)'); }
      catch (_) { throw new ArchxError('Capability extension unavailable in this library'); }
    }
    return this.result('capabilities');
  }
  identify() { return this.result('identify'); }
  profile(ip = null) { return this.result('profile', ip === null ? null : text(ip, 'ip')); }
  compare(baseline, current) {
    const a = json(baseline), b = json(current);
    return this.result('compare', a, Buffer.byteLength(a), b, Buffer.byteLength(b));
  }
  check(key, cost = 1) {
    text(key, 'key');
    if (!Number.isSafeInteger(cost) || cost < 1) throw new RangeError('cost must be a positive safe integer');
    const remaining = [0], retry = [0];
    const decision = this.fn.check(this.requireOpen(), key, cost, remaining, retry);
    const error = this.fn.lastError();
    if (error) throw new ArchxError(error);
    if (decision !== 0 && decision !== 1) throw new ArchxError('Unexpected native decision');
    return {decision: decision === 0 ? 'allow' : 'rate_limited', remaining:remaining[0], retry_after_ms:retry[0]};
  }
  reset(key) {
    text(key, 'key');
    if (this.fn.reset(this.requireOpen(), key) !== 0) throw new ArchxError(this.error());
  }
}
module.exports = {Core, ArchxError};
