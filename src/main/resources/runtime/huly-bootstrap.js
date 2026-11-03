'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { setTimeout: delay } = require('node:timers/promises');

async function body(response) {
  const chunks = []; let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length; assert(size <= 65536, 'Native response budget exceeded'); chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}
async function main() {
  const users = JSON.parse(fs.readFileSync('/run/secrets/bootstrap-users.json', 'utf8'));
  assert.equal(users.length, 3);
  assert.deepEqual(users.map(user => user.email), ['owner@localhost.invalid', 'reader@localhost.invalid', 'outsider@localhost.invalid']);
  assert(users.every(user => /^[a-f0-9]{64}$/.test(user.password)));
  const child = spawn(process.execPath, ['--require', '/run/secrets/huly-timers.cjs', '--require', '/run/secrets/huly-loopback.cjs', '/usr/src/app/bundle.js'], {
    stdio: ['ignore', 'inherit', 'inherit'], env: { ...process.env, DISABLE_SIGNUP: 'false', ACCOUNT_PORT: '3000' }
  });
  let exited = false, code = null, interrupted = false;
  const done = new Promise(resolve => {
    child.once('exit', value => { exited = true; code = value; resolve(); });
    child.once('error', () => { exited = true; code = -1; resolve(); });
  });
  const stop = () => { interrupted = true; child.kill('SIGTERM'); };
  process.on('SIGTERM', stop); process.on('SIGINT', stop);
  try {
    let ready = false;
    for (let i = 0; i < 90; i++) {
      assert(!exited && !interrupted, 'Native bootstrap server exited');
      ready = await new Promise(resolve => {
        const socket = net.connect(3000, '127.0.0.1');
        socket.setTimeout(1000); socket.once('connect', () => { socket.destroy(); resolve(true); });
        socket.once('error', () => { socket.destroy(); resolve(false); });
        socket.once('timeout', () => { socket.destroy(); resolve(false); });
      });
      if (ready) break;
      await delay(1000);
    }
    assert(ready, 'Bootstrap readiness exhausted');
    // Native getRegionInfo is read-only, and the RPC router awaits both schema and account migrations.
    // TCP readiness alone does not establish this; never spend a signup write's timeout on migrations.
    const schema = await fetch('http://127.0.0.1:3000/', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: 0, method: 'getRegionInfo', params: {} }), signal: AbortSignal.timeout(300000)
    });
    assert.equal(schema.status, 200);
    const regions = await body(schema); assert(!regions.error && Array.isArray(regions.result));
    console.log('Native account migrations ready; beginning one-shot synthetic signup.');
    for (const user of users) {
      assert(!interrupted && !exited);
      // One request only. A timeout/uncertain write leaves the runtime initializer failed, never replayed.
      const response = await fetch('http://127.0.0.1:3000/', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: 1, method: 'signUp', params: user }), signal: AbortSignal.timeout(120000)
      });
      assert.equal(response.status, 200, 'Native signup status rejected');
      const result = await body(response); assert(!result.error && result.result?.account && result.result?.token, 'Native fixture signup failed');
    }
  } finally {
    if (!exited) child.kill('SIGTERM');
    await Promise.race([done, delay(15000)]);
    if (!exited) { child.kill('SIGKILL'); await done; }
    process.off('SIGTERM', stop); process.off('SIGINT', stop);
    assert(!interrupted && code === 0, 'Native bootstrap shutdown failed');
  }
  console.log('Three native synthetic identities provisioned; no credentials emitted.');
}
main().catch(() => { console.error('Huly bootstrap failed; retain state and reconcile, never replay.'); process.exitCode = 1; });
