// Run after ./build.sh and (cd examples/node && npm install): node examples/node/demo.js
const koffi = require('koffi');
const path = require('path');
const lib = koffi.load(path.join(__dirname, '../../build/libarchx.so'));
const coreNew = lib.func('void *ax_core_new(const char *config_json, size_t config_len)');
const coreFree = lib.func('void ax_core_free(void *core)');
const lastError = lib.func('const char *ax_last_error(void)');
const bufferFree = lib.func('void ax_buffer_free(void *buf)');
const collect = lib.func('int ax_collect(void *core, _Out_ void **json, _Out_ size_t *len)');
const identify = lib.func('int ax_identify(void *core, _Out_ void **json, _Out_ size_t *len)');
const check = lib.func('int ax_check(void *core, const char *key, int64_t cost, _Out_ int64_t *remaining, _Out_ int64_t *retry)');
const config = JSON.stringify({app_id:'node-demo', pepper:process.env.ARCHX_PEPPER || 'demo-only-change-me', rate_limit:{capacity:2, refill_per_sec:0}});
const core = coreNew(config, Buffer.byteLength(config));
if (!core) throw new Error(lastError());
try {
  for (const [name, fn] of [['collect', collect], ['identify', identify]]) {
    const ptr = [null], len = [0];
    if (fn(core, ptr, len) !== 0) throw new Error(lastError());
    try { console.log(name, JSON.parse(koffi.decode(ptr[0], 'char', len[0]).toString())); }
    finally { bufferFree(ptr[0]); }
  }
  for (let i = 0; i < 3; i++) {
    const remaining = [0], retry = [0];
    const result = check(core, 'example-user', 1, remaining, retry);
    if (lastError()) throw new Error(lastError());
    console.log('check', {decision:result === 0 ? 'allow' : 'deny', remaining:remaining[0], retry_after_ms:retry[0]});
  }
} finally { coreFree(core); }
