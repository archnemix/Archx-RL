// Build the Linux core and run npm ci --prefix bindings/node first.
const path = require('node:path');
const {Core} = require('../../bindings/node');
const config = {app_id:'node-demo', pepper:process.env.ARCHX_PEPPER || 'demo-only-change-me',
  rate_limit:{capacity:2, refill_per_sec:0}};
const core = new Core(path.resolve(__dirname, '../../build/libarchx.so'), config);
try {
  console.log('collect', core.collect());
  console.log('identify', core.identify());
  for (let i = 0; i < 3; i++) console.log('check', core.check('example-user'));
} finally { core.close(); }
