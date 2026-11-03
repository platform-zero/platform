'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');
const path = require('node:path');
const resources = path.join(__dirname, '../src/main/resources/runtime');
const read = name => fs.readFileSync(path.join(resources, name), 'utf8');
async function bootstrap(options = {}) {
  const requests = [], logs = [], signals = [], child = new EventEmitter(), process = new EventEmitter();
  let spawns = 0;
  process.env = {}; process.execPath = '/unit/node';
  child.kill = signal => { signals.push(signal); child.emit('exit', options.exitCode ?? 0); };
  const users = ['owner', 'reader', 'outsider'].map((id, n) => ({ email: id + '@localhost.invalid', password: String(n + 1).repeat(64), firstName: 'Synthetic', lastName: id }));
  if (options.badInput) users.pop();
  const context = { Buffer, AbortSignal, process, console: { log: (...args) => logs.push(args.join(' ')), error: (...args) => logs.push(args.join(' ')) },
    require(name) {
      if (name === 'node:assert/strict') return assert;
      if (name === 'node:fs') return { readFileSync: () => JSON.stringify(users) };
      if (name === 'node:net') return { connect: () => { const socket = new EventEmitter(); socket.setTimeout = socket.destroy = () => {}; queueMicrotask(() => socket.emit('connect')); return socket; } };
      if (name === 'node:child_process') return { spawn: (program, args, configuration) => {
        spawns++; assert(args.includes('/run/secrets/huly-loopback.cjs')); assert(args.includes('/run/secrets/huly-timers.cjs'));
        assert.equal(configuration.env.DISABLE_SIGNUP, 'false'); return child;
      } };
      if (name === 'node:timers/promises') return { setTimeout: async () => {} };
      throw Error('Unexpected module');
    },
    async fetch(url, request) {
      assert.equal(url, 'http://127.0.0.1:3000/'); const data = JSON.parse(request.body); requests.push(data);
      if (options.timeout && data.method === 'signUp') throw Error('Ambiguous write');
      if (options.interrupt && data.method === 'signUp') process.emit('SIGTERM');
      let result = data.method === 'getRegionInfo' ? { result: [] } : { result: { account: 'unit-account', token: 'unit-token' } };
      if (options.rejectWrite && data.method === 'signUp') result = { error: 'unit-error' };
      const content = options.oversized ? Buffer.alloc(65537) : Buffer.from(JSON.stringify(result));
      return { status: options.rejectSchema ? 500 : 200, body: (async function* () { yield content; })() };
    }
  };
  await vm.runInNewContext(read('huly-bootstrap.js'), context, { filename: path.join(resources, 'huly-bootstrap.js') });
  return { requests, logs, signals, spawns, exitCode: process.exitCode };
}
test('read-only native migration barrier precedes exactly three signup writes and clean close', async () => {
  const result = await bootstrap(); assert.equal(result.exitCode, undefined);
  assert.deepEqual(result.requests.map(r => r.method), ['getRegionInfo', 'signUp', 'signUp', 'signUp']);
  assert.deepEqual(result.signals, ['SIGTERM']); assert.equal(result.spawns, 1);
  assert(!result.logs.join('\n').includes('unit-token'));
});
test('schema refusal and bounded body failure cause no signup writes', async () => {
  for (const options of [{ rejectSchema: true }, { oversized: true }]) {
    const result = await bootstrap(options); assert.equal(result.exitCode, 1);
    assert.deepEqual(result.requests.map(r => r.method), ['getRegionInfo']);
  }
});
test('invalid input causes no spawn or network operation', async () => {
  const result = await bootstrap({ badInput: true }); assert.equal(result.exitCode, 1); assert.equal(result.spawns, 0); assert.equal(result.requests.length, 0);
});
test('ambiguous or rejected signup is never retried', async () => {
  for (const options of [{ timeout: true }, { rejectWrite: true }, { interrupt: true }]) {
    const result = await bootstrap(options); assert.equal(result.exitCode, 1);
    assert.deepEqual(result.requests.map(r => r.method), ['getRegionInfo', 'signUp']);
    assert(!result.logs.some(line => line.startsWith('Three native')));
  }
});
test('unsuccessful child shutdown cannot produce a successful initializer', async () => {
  const result = await bootstrap({ exitCode: 1 }); assert.equal(result.exitCode, 1);
  assert(!result.logs.some(line => line.startsWith('Three native')));
});
test('loopback preload rejects unexpected native listen forms before binding', () => {
  const calls = []; class Server { listen(...args) { calls.push(args); return this; } }
  vm.runInNewContext(read('huly-loopback.cjs'), { require: name => name === 'node:http' ? { Server } : assert }, { filename: path.join(resources, 'huly-loopback.cjs') });
  const server = new Server(); server.listen(3000); assert.equal(calls.length, 1);
  assert.equal(calls[0][0].host, '127.0.0.1'); assert.equal(calls[0][0].port, 3000);
  for (const args of [[3001], [3000, '0.0.0.0'], [{ port: 3000 }]]) assert.throws(() => server.listen(...args));
  assert.equal(calls.length, 1);
});
test('maintenance timers remain scheduled but do not keep closed native services alive', () => {
  let unrefs = 0; const timer = { unref: () => { unrefs++; } }; const args = [];
  const global = { setInterval: (...values) => { args.push(values); return timer; } };
  vm.runInNewContext(read('huly-timers.cjs'), { global }, { filename: path.join(resources, 'huly-timers.cjs') }); const fn = () => {};
  assert.equal(global.setInterval(fn, 3000), timer); assert.equal(unrefs, 1); assert.deepEqual(args, [[fn, 3000]]);
});
async function search(options = {}) {
  const requests = [], logs = [], process = {};
  const credentials = { bootstrap: '1'.repeat(64), admin: '2'.repeat(64), application: '3'.repeat(64) };
  if (options.badInput) credentials.admin = credentials.bootstrap;
  const statuses = [200, 200, 200, 200, 200, 401, 200, 403]; let clock = 0;
  const context = { Buffer, AbortSignal, Date: { now: () => clock }, process, console: { log: text => logs.push(text), error: text => logs.push(text) }, require(name) {
    if (name === 'node:assert/strict') return assert;
    if (name === 'node:timers/promises') return { setTimeout: async () => { clock += 200000; } };
    if (name === 'node:fs') return { readFileSync: file => file.endsWith('.json') ? JSON.stringify(credentials) : Buffer.from('unit-ca') };
    if (name === 'node:https') return { request(configuration, callback) {
      const req = new EventEmitter(); req.setTimeout = () => {}; req.destroy = error => req.emit('error', error);
      req.end = body => {
        requests.push({ configuration, body: body ? JSON.parse(body) : null });
        if (options.ambiguous || requests.length === options.ambiguousAt) { req.emit('error', Error('Ambiguous request')); return; }
        const response = new EventEmitter(); response.statusCode = options.badStatus ? 500 : statuses[requests.length - 1];
        callback(response); response.emit('data', options.oversized ? Buffer.alloc(65537) : Buffer.from(JSON.stringify({ status: 'green', timed_out: !!options.pending, number_of_pending_tasks: 1, tasks: [] }))); response.emit('end');
      }; return req;
    } };
    throw Error('Unexpected module');
  } };
  try { await vm.runInNewContext(read('huly-search-init.js'), context, { filename: path.join(resources, 'huly-search-init.js') }); }
  catch (error) { assert(options.badInput); process.exitCode = 1; }
  return { requests, logs, exitCode: process.exitCode };
}
test('search bootstrap scopes native role, rotates bootstrap and checks native authorization denials', async () => {
  const result = await search(); assert.equal(result.exitCode, undefined); assert.equal(result.requests.length, 8);
  for (const { configuration } of result.requests) {
    assert.equal(configuration.hostname, 'elastic'); assert.equal(configuration.port, 9200); assert.equal(configuration.rejectUnauthorized, true);
    assert.equal(configuration.ca.toString(), 'unit-ca');
  }
  assert.equal(result.requests[0].configuration.method, 'GET');
  assert(result.requests[0].configuration.path.startsWith('/_cluster/health?'));
  assert.equal(result.requests[1].configuration.path, '/_cluster/pending_tasks');
  assert.deepEqual(result.requests[2].body.indices, [{ names: ['huly*'], privileges: ['all'] }]);
  assert.deepEqual(result.requests[3].body.roles, ['huly']);
  assert.equal(result.requests[4].configuration.path, '/_security/user/elastic/_password');
  assert.equal(result.requests[5].configuration.headers.Authorization, result.requests[0].configuration.headers.Authorization);
  assert.equal(result.requests[7].configuration.path, '/_security/user');
});
test('search fails before effects for invalid custody and never retries ambiguous or rejected operations', async () => {
  assert.equal((await search({ badInput: true })).requests.length, 0);
  for (const options of [{ ambiguous: true }, { ambiguousAt: 3 }, { badStatus: true }, { oversized: true }, { pending: true }]) {
    const result = await search(options); assert.equal(result.exitCode, 1); assert.equal(result.requests.length, options.ambiguousAt ?? 1);
    assert(!result.logs.some(line => line.startsWith('Native search application')));
  }
});
