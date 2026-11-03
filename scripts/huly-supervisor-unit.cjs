'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const { EventEmitter } = require('node:events');
async function start(badInput = false) {
  const process = new EventEmitter(), child = new EventEmitter(), server = new EventEmitter();
  const output = [], signals = [], timers = []; let binds = 0, spawns = 0, closes = 0;
  process.env = { HULY_DB_CONNECTION: 'postgresql://huly:' + '1'.repeat(64) + '@' + (badInput ? 'cockroach' : '127.0.0.1') + ':26257/huly?sslmode=disable' };
  process.stdout = process.stderr = { write: text => output.push(text) };
  child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.kill = signal => signals.push(signal);
  server.close = () => { closes++; };
  server.listen = (port, host, callback) => { binds++; assert.equal(host, '127.0.0.1'); assert.equal(port, 26257); queueMicrotask(callback); };
  const module = {};
  function requireMock(name) {
    if (name === 'node:assert/strict') return assert;
    if (name === 'node:net') return { createServer: callback => { server.accept = callback; return server; } };
    if (name === 'node:tls') return {};
    if (name === 'node:fs') return { readFileSync: () => Buffer.from('unit-ca') };
    if (name === 'node:child_process') return { spawn: (program, args, options) => {
      spawns++; assert.equal(program, '/usr/local/bin/hulykvs'); assert.equal(args.length, 0);
      assert.equal(options.stdio.join(','), 'ignore,pipe,pipe'); return child;
    } };
    throw Error('Unexpected module');
  }
  requireMock.main = module;
  const filename = path.join(__dirname, '../src/main/resources/runtime/huly-kvs-proxy.cjs');
  await vm.runInNewContext(fs.readFileSync(filename, 'utf8'), {
    Buffer, URL, process, module, require: requireMock, console: { error: text => output.push(text) },
    setTimeout: fn => { const timer = { fn }; timers.push(timer); return timer; }, clearTimeout: timer => { if (timer) timer.cleared = true; }
  }, { filename });
  return { process, child, server, output, signals, timers, binds: () => binds, spawns: () => spawns, closes: () => closes };
}
test('supervisor starts only fixed loopback bridge and handles ordinary native shutdown', async () => {
  const f = await start(); assert.equal(f.binds(), 1); assert.equal(f.spawns(), 1); assert.equal(f.server.maxConnections, 32);
  f.process.emit('SIGTERM'); f.process.emit('SIGINT'); assert.deepEqual(f.signals, ['SIGTERM']);
  f.child.emit('exit', 0, null); assert.equal(f.process.exitCode, 0); assert(f.timers[0].cleared); assert(f.closes() >= 1);
  let denied = false; f.server.accept({ destroy: () => { denied = true; } }); assert(denied);
});
test('unexpected zero exit and spawn errors are failures, not healthy termination', async () => {
  const f = await start(); f.child.emit('exit', 0, null); assert.equal(f.process.exitCode, 1);
  const g = await start(); g.child.emit('error', Error('unit-spawn-error')); assert.equal(g.process.exitCode, 1); assert(g.closes() > 0);
});
test('forced termination cannot be normalized to success', async () => {
  const f = await start(); f.process.emit('SIGTERM'); f.timers[0].fn();
  assert.deepEqual(f.signals, ['SIGTERM', 'SIGKILL']); f.child.emit('exit', null, 'SIGKILL'); assert.equal(f.process.exitCode, 1);
  const g = await start(); g.process.emit('SIGTERM'); g.child.emit('exit', null, 'SIGTERM'); assert.equal(g.process.exitCode, 143);
  const h = await start(); h.process.emit('SIGINT'); h.child.emit('exit', null, 'SIGINT'); assert.equal(h.process.exitCode, 1);
});
test('invalid DSN fails before bind or process creation', async () => {
  const f = await start(true); assert.equal(f.process.exitCode, 1); assert.equal(f.binds(), 0); assert.equal(f.spawns(), 0);
});
test('runtime listener errors remain failures and child diagnostics are sanitized', async () => {
  const f = await start(); f.child.stdout.emit('data', Buffer.from('connection=postgresql://huly:' + '1'.repeat(64) + '@127.0.0.1/huly\n'));
  f.child.stdout.emit('end'); assert(!f.output.join('').includes('1'.repeat(64)));
  f.server.emit('error', Error('unit-listener-error')); f.child.emit('exit', 0, null); assert.equal(f.process.exitCode, 1);
});
