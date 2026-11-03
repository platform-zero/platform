'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { bridge, validateConnection, logSink } = require('../src/main/resources/runtime/huly-kvs-proxy.cjs');
class Socket extends EventEmitter {
  constructor() { super(); this.writes = []; this.pipes = []; this.authorized = true; }
  pause() { this.paused = true; }
  setTimeout(time, fn) { this.timeout = time; if (fn) this.timeoutHandler = fn; return this; }
  write(data) { this.writes.push(data); }
  pipe(other) { this.pipes.push(other); return other; }
  destroy() { if (this.destroyed) return; this.destroyed = true; this.emit('close'); }
}
function fixture() {
  const client = new Socket(), remote = new Socket(), secure = new Socket(), calls = [], tlsCalls = [];
  let closed = 0;
  const finish = bridge(client, Buffer.from('unit-ca'), () => closed++, { connect: options => { calls.push(options); return remote; } }, {
    connect: options => { tlsCalls.push(options); return secure; }
  });
  return { client, remote, secure, calls, tlsCalls, finish, closed: () => closed };
}
test('no native bytes forwarded before PostgreSQL SSL negotiation and verified TLS', () => {
  const f = fixture(); assert(f.client.paused); assert.equal(f.client.pipes.length, 0);
  f.remote.emit('connect'); assert.deepEqual(f.calls, [{ host: 'cockroach', port: 26257 }]);
  assert.deepEqual([...f.remote.writes[0]], [0, 0, 0, 8, 4, 210, 22, 47]);
  f.remote.emit('data', Buffer.from('S')); assert.equal(f.client.pipes.length, 0);
  const options = f.tlsCalls[0]; assert.equal(options.servername, 'cockroach'); assert.equal(options.rejectUnauthorized, true);
  assert.equal(options.minVersion, 'TLSv1.2'); assert.equal(options.ca.toString(), 'unit-ca'); assert.equal(options.socket, f.remote);
  f.secure.emit('secureConnect'); assert.deepEqual(f.client.pipes, [f.secure]); assert.deepEqual(f.secure.pipes, [f.client]);
  assert.equal(f.secure.timeout, 0); f.finish(); assert.equal(f.closed(), 1);
});
test('plaintext fallback, invalid negotiation, failed TLS and handshake timeout never forward or retry', () => {
  for (const data of ['N', 'SS', '']) {
    const f = fixture(); f.remote.emit('data', Buffer.from(data)); assert(f.client.destroyed); assert(f.remote.destroyed);
    assert.equal(f.tlsCalls.length, 0); assert.equal(f.calls.length, 1); assert.equal(f.closed(), 1);
  }
  for (const action of ['unauthorized', 'error', 'timeout']) {
    const f = fixture(); f.remote.emit('data', Buffer.from('S'));
    if (action === 'unauthorized') { f.secure.authorized = false; f.secure.emit('secureConnect'); }
    if (action === 'error') f.secure.emit('error', Error('unit-certificate-error'));
    if (action === 'timeout') f.secure.timeoutHandler();
    assert.equal(f.client.pipes.length, 0); assert(f.client.destroyed); assert(f.secure.destroyed);
    assert.equal(f.calls.length, 1); assert.equal(f.closed(), 1);
  }
});
test('local close and remote failure retire both endpoints exactly once', () => {
  for (const action of ['client-close', 'client-error', 'remote-error', 'remote-close', 'timeout']) {
    const f = fixture();
    if (action === 'client-close') f.client.destroy();
    if (action === 'client-error') f.client.emit('error', Error('unit'));
    if (action === 'remote-error') f.remote.emit('error', Error('unit'));
    if (action === 'remote-close') f.remote.destroy();
    if (action === 'timeout') f.remote.timeoutHandler();
    f.remote.emit('connect'); f.remote.emit('data', Buffer.from('S')); f.finish();
    assert.equal(f.closed(), 1); assert.equal(f.tlsCalls.length, 0); assert.equal(f.remote.writes.length, 0);
    assert(f.remote.destroyed); assert(f.client.destroyed);
  }
});
test('unencrypted native DSN is accepted exclusively on fixed loopback namespace', () => {
  const valid = 'postgresql://huly:' + '1'.repeat(64) + '@127.0.0.1:26257/huly?sslmode=disable';
  validateConnection(valid);
  for (const value of [undefined, valid.replace('127.0.0.1', 'cockroach'), valid.replace('127.0.0.1', 'localhost'),
    valid.replace('26257', '5432'), valid.replace('huly:', 'root:'), valid.replace('/huly?', '/postgres?'),
    valid + '&unexpected=true', valid + '#fragment', valid.replace('1'.repeat(64), 'short')]) assert.throws(() => validateConnection(value));
});
test('native tracing DSNs and split secrets never enter diagnostics; overlong lines stay bounded', () => {
  const output = [], log = logSink(text => output.push(text)), password = 'a'.repeat(64);
  log.chunk(Buffer.from('DEBUG database connection="postgresql://huly:' + password.slice(0, 20)));
  assert.equal(output.length, 0);
  log.chunk(Buffer.from(password.slice(20) + '@127.0.0.1/huly"\n'));
  log.chunk(Buffer.from(password.slice(0, 32))); log.chunk(Buffer.from(password.slice(32) + '\n'));
  log.chunk(Buffer.from('token=eyJunit.payload.signature\n'));
  log.chunk(Buffer.alloc(16385, 65)); log.chunk(Buffer.from('do-not-output\n'));
  log.chunk(Buffer.from('native migration complete')); log.end();
  assert(!output.join('').includes(password)); assert(!output.join('').includes('postgresql://'));
  assert(!output.join('').includes('eyJunit')); assert(!output.join('').includes('do-not-output'));
  assert(output.join('').includes('native migration complete')); assert(output.join('').includes('size limit'));
});
