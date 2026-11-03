'use strict';
const assert = require('node:assert/strict');
const net = require('node:net');
const tls = require('node:tls');
const fs = require('node:fs');
const { spawn } = require('node:child_process');

// A single native local PostgreSQL connection maps to exactly one verified remote TLS
// connection. No SQL parsing, credential logging, buffering for replay or retry exists.
function bridge(client, ca, closed = () => {}, network = net, encryption = tls) {
  client.pause();
  let secure, ended = false;
  const remote = network.connect({ host: 'cockroach', port: 26257 });
  function finish() {
    if (ended) return;
    ended = true; clearTimeout(deadline); client.destroy(); secure?.destroy(); remote.destroy(); closed();
  }
  const deadline = setTimeout(finish, 10000);
  client.on('error', finish); client.on('close', finish);
  remote.on('error', finish); remote.on('close', finish);
  remote.setTimeout(10000, finish);
  remote.once('connect', () => {
    if (ended) return;
    // PostgreSQL SSLRequest, not an application startup/authentication message.
    remote.write(Buffer.from([0, 0, 0, 8, 4, 210, 22, 47]));
  });
  remote.once('data', response => {
    if (ended) return;
    if (response.length !== 1 || response[0] !== 83) { finish(); return; }
    remote.setTimeout(0);
    secure = encryption.connect({ socket: remote, servername: 'cockroach', ca,
      rejectUnauthorized: true, minVersion: 'TLSv1.2' });
    secure.on('error', finish); secure.on('close', finish);
    secure.setTimeout(10000, finish);
    secure.once('secureConnect', () => {
      if (ended) return;
      if (!secure.authorized) { finish(); return; }
      clearTimeout(deadline); secure.setTimeout(0);
      // Native stream backpressure bounds queued bytes; no credentials leave loopback
      // until the backend certificate and hostname have been verified.
      client.pipe(secure); secure.pipe(client);
    });
  });
  return finish;
}
function validateConnection(value) {
  const url = new URL(value);
  assert.equal(url.protocol, 'postgresql:'); assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.port, '26257'); assert.equal(url.username, 'huly');
  assert(/^[a-f0-9]{64}$/.test(url.password)); assert.equal(url.pathname, '/huly');
  assert.equal(url.search, '?sslmode=disable'); assert.equal(url.hash, '');
}
// Upstream hard-codes DEBUG tracing and prints its DSN, ignoring RUST_LOG. Retain
// bounded diagnostics without emitting database credentials or bearer tokens.
function logSink(write) {
  let pending = '', oversized = false;
  const emit = line => write(line.replace(/postgres(?:ql)?:\/\/[^\s"']+/g, '[DATABASE-DSN]')
    .replace(/[a-fA-F0-9]{64}/g, '[SECRET]').replace(/eyJ[A-Za-z0-9_.-]+/g, '[TOKEN]') + '\n');
  function line() { if (oversized) write('[Native KVS log line omitted: size limit]\n'); else emit(pending); pending = ''; oversized = false; }
  return {
    chunk(data) {
      for (const piece of data.toString('utf8').split(/(\n)/)) {
        if (piece === '\n') { line(); continue; }
        if (oversized) continue;
        if (pending.length + piece.length > 16384) { pending = ''; oversized = true; } else pending += piece;
      }
    },
    end() { if (pending || oversized) line(); }
  };
}
async function main() {
  validateConnection(process.env.HULY_DB_CONNECTION);
  const ca = fs.readFileSync('/run/secrets/cr-ca.pem'); assert(ca.length <= 65536);
  const active = new Set(); let stopping = false, timer, forced = false, closing = false;
  const server = net.createServer(client => {
    if (closing) { client.destroy(); return; }
    const close = bridge(client, ca, () => active.delete(close)); active.add(close);
  });
  server.maxConnections = 32;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(26257, '127.0.0.1', resolve); });
  const child = spawn('/usr/local/bin/hulykvs', [], { stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, RUST_LOG: 'warn' } });
  for (const [source, target] of [[child.stdout, process.stdout], [child.stderr, process.stderr]]) {
    const log = logSink(text => target.write(text)); source.on('data', log.chunk); source.on('end', log.end);
  }
  function close() {
    closing = true; clearTimeout(timer); server.close(); for (const finish of active) finish();
  }
  function stop(signal) {
    if (stopping) return;
    stopping = true; closing = true; server.close(); child.kill(signal);
    timer = setTimeout(() => { forced = true; child.kill('SIGKILL'); }, 25000);
  }
  server.on('error', () => { forced = true; stop('SIGTERM'); });
  process.once('SIGTERM', () => stop('SIGTERM')); process.once('SIGINT', () => stop('SIGINT'));
  child.once('error', () => { close(); process.exitCode = 1; console.error('Native KVS could not start; state retained.'); });
  child.once('exit', (code, signal) => {
    close();
    process.exitCode = forced || !stopping ? 1 : (code ?? (signal === 'SIGTERM' ? 143 : 1));
    if (process.exitCode !== 0 && process.exitCode !== 143) console.error('Native KVS exited unsuccessfully; state retained.');
  });
}
module.exports = { bridge, validateConnection, logSink };
if (require.main === module) main().catch(() => { console.error('Native KVS TLS bridge failed; state retained.'); process.exitCode = 1; });
