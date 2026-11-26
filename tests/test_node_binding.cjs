'use strict';
// ABI-v1 Linux binding contract, shared protocol fixture and ownership faults.
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const root = path.resolve(__dirname, '..');
const {Core, ArchxError} = require('../bindings/node');
const koffi = require('../bindings/node/node_modules/koffi');
const f = require('./fixtures/native-binding-v1.json');
const real = path.join(root, 'build/libarchx.so');
const fakePath = path.join(root, 'build/binding_fake.so');
const wrong = path.join(root, 'build/binding_wrong_abi.so');

const core = new Core(real, f.config);
try {
  const caps = core.capabilities();
  assert.equal(caps.schema, 'archx.capabilities');
  assert.equal(caps.version, 1);
  assert.equal(caps.platform, 'linux');
  assert.equal(caps.signals.machine_id.kind, 'os_install');
  assert.equal(caps.signals.product_uuid.kind, 'firmware');
  assert.equal(caps.signals.app_install.status, 'not_collected');
  assert.equal(caps.signals.ip.status, 'host_provided');
  for (const value of Object.values(caps.signals)) assert.deepEqual(Object.keys(value).sort(), ['kind', 'status']);
  const a = core.profile('192.0.2.1'), b = core.profile('192.0.2.2'), missing = core.profile();
  assert.deepEqual(a, f.profiles['192.0.2.1']);
  assert.deepEqual(b, f.profiles['192.0.2.2']);
  assert.deepEqual(missing, f.profiles.missing);
  assert.deepEqual(core.compare(a, a), f.results.match);
  assert.deepEqual(core.compare(a, b), f.results.changed);
  assert.deepEqual(core.compare(a, missing), f.results.missing);
  assert.deepEqual(Array.from({length:3}, () => core.check('synthetic-key')), f.checks);
  core.reset('synthetic-key');
  assert.deepEqual(core.check('synthetic-key'), f.checks[0]);
  assert.throws(() => core.profile('invalid-ip'), ArchxError);
  assert.throws(() => core.compare({invalid:true}, a), ArchxError);
  assert.throws(() => core.check('x'.repeat(801)), ArchxError);
  assert.throws(() => core.check('key\0bad'), TypeError);
  assert.throws(() => core.check('\ud800'), TypeError);
  assert.throws(() => core.compare({bad:NaN}, a), TypeError);
  assert.throws(() => core.check('key', 0), RangeError);
} finally { core.close(); core.close(); }
assert.throws(() => core.profile(), ArchxError);
assert.throws(() => new Core(wrong, f.config), ArchxError);
assert.throws(() => new Core('relative.so', f.config), TypeError);
assert.throws(() => new Core(real, {}), ArchxError);

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-node-binding-'));
try {
  const relocated = path.join(dir, 'renamed-library.so');
  fs.copyFileSync(real, relocated);
  const utf8Core = new Core(relocated, {...f.config, app_id:'fixture-café'});
  try {
    const p = utf8Core.profile('192.0.2.1');
    assert.equal(utf8Core.compare(p, p).result, 'match');
  } finally { utf8Core.close(); }
} finally { fs.rmSync(dir, {recursive:true, force:true}); }

const fakeLib = koffi.load(fakePath);
const mode = fakeLib.func('void fixture_mode(int n)');
const live = fakeLib.func('int fixture_live(void)');
const frees = fakeLib.func('int fixture_core_frees(void)');
const before = frees();
const fake = new Core(fakePath, {});
try {
  assert.throws(() => fake.capabilities(), /extension unavailable/);
  for (const [m, error] of [[1, SyntaxError], [2, ArchxError], [3, ArchxError], [4, ArchxError]]) {
    mode(m);
    assert.throws(() => fake.collect(), error);
    assert.equal(live(), 0);
  }
  mode(0);
  assert.deepEqual(fake.collect(), {ok:true});
  assert.equal(live(), 0);
} finally { fake.close(); fake.close(); }
assert.equal(frees(), before + 1);
console.log('Node ABI-v1 binding shared fixtures and ownership faults passed');
