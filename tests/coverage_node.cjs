'use strict';
// Exercise the Node binding against a synthetic collector only.
const assert = require('node:assert/strict');
const { Core, ArchxError } = require('../bindings/node');
const lib = process.env.ARCHX_COVERAGE_LIB;
if (!lib) throw new Error('Synthetic test library required');
const config = {app_id:'fixture-app', pepper:'synthetic-test-pepper',
  rate_limit:{capacity:2, refill_per_sec:0},
  match:{mode:'threshold', min_matches:1, signals:{ip:'required'}}};
const c = new Core(lib, config);
try {
  assert.equal(c.capabilities().platform, 'linux'); // fixture uses Linux ABI-v1 scope
  const a = c.profile('192.0.2.1');
  const b = c.profile('192.0.2.2');
  assert.equal(c.compare(a, a).result, 'match');
  assert.equal(c.compare(a, b).result, 'no_match');
  assert.equal(c.check('synthetic-key').decision, 'allow');
  assert.equal(c.check('synthetic-key').decision, 'allow');
  assert.equal(c.check('synthetic-key').decision, 'rate_limited');
  c.reset('synthetic-key');
  assert.throws(() => c.profile('not an IP'), ArchxError);
} finally { c.close(); c.close(); }
assert.throws(() => c.profile(), ArchxError);
console.log('Synthetic Node coverage fixture passed');
