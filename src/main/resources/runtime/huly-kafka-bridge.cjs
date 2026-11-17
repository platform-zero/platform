'use strict';
/**
 * Fixed Huly V2 Kafka transport. Original Huly bundle speaks native Kafka to
 * 127.0.0.1:9092 only; Redpanda requires its own generation-local client-auth
 * certificate over native mTLS. The broker advertises 127.0.0.1:9092 so every
 * metadata/leader connection returns to this same private container namespace.
 * Bytes are streamed with Node backpressure, never buffered, retried or replayed.
 */
const fs = require('node:fs');
const net = require('node:net');
const tls = require('node:tls');
const { isMainThread } = require('node:worker_threads');
const MAX_CLIENTS = 64;
const HANDSHAKE_MS = 5000;
const PEM = Object.freeze({
  ca: '/run/secrets/huly-rp-ca.pem',
  cert: '/run/secrets/huly-rp-client.pem',
  key: '/run/secrets/huly-rp-client-key.pem',
});

function material(path) {
  const stat = fs.lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o022) !== 0 || stat.size < 128 || stat.size > 16384) {
    throw Error('Unapproved Huly Kafka transport authority');
  }
  return fs.readFileSync(path);
}

function bridge(client, credentials, connect = tls.connect, timer = setTimeout) {
  client.pause();
  let upstream; let closed = false; let deadline;
  const finish = () => {
    if (closed) return;
    closed = true;
    if (deadline) clearTimeout(deadline);
    client.destroy();
    if (upstream) upstream.destroy();
  };
  client.once('error', finish);
  client.once('close', finish);
  try {
    upstream = connect({
      host: 'huly-redpanda', port: 9092, servername: 'huly-redpanda',
      rejectUnauthorized: true, minVersion: 'TLSv1.2',
      ca: credentials.ca, cert: credentials.cert, key: credentials.key,
      highWaterMark: 65536,
    });
  } catch (_) { finish(); return finish; }
  upstream.once('error', finish);
  upstream.once('close', finish);
  deadline = timer(finish, HANDSHAKE_MS);
  upstream.once('secureConnect', () => {
    if (closed) return;
    if (upstream.authorized !== true) { finish(); return; }
    clearTimeout(deadline); deadline = undefined;
    client.setNoDelay(true);
    client.resume();
    // pipe() applies backpressure and forwards each native Kafka byte once.
    client.pipe(upstream); upstream.pipe(client);
  });
  return finish;
}

function start() {
  if (process.env.QUEUE_CONFIG !== '127.0.0.1:9092' || process.env.HULY_KAFKA_BRIDGE !== 'v2') {
    throw Error('Foreign Huly Kafka listener or queue environment');
  }
  const credentials = { ca: material(PEM.ca), cert: material(PEM.cert), key: material(PEM.key) };
  const active = new Set();
  const server = net.createServer({ pauseOnConnect: true }, client => {
    if (active.size >= MAX_CLIENTS || client.remoteAddress !== '127.0.0.1') {
      client.destroy(); return;
    }
    active.add(client);
    client.once('close', () => active.delete(client));
    bridge(client, credentials);
  });
  server.on('error', () => { process.exit(1); });
  server.listen({ host: '127.0.0.1', port: 9092, exclusive: true });
  process.env.HULY_KAFKA_BRIDGE_ROOT_PID = String(process.pid);
  return server;
}

const allowedScript = process.argv[1] === '/usr/src/app/bundle.js' ||
  process.argv[1] === '/app/bundle.js' ||
  process.argv[1] === '/run/secrets/huly-bootstrap.js';
if (allowedScript && isMainThread && !process.env.HULY_KAFKA_BRIDGE_ROOT_PID) start();
// Forked children inherit the root PID marker; Worker threads do not bind again.
module.exports = { bridge, material, start, PEM, MAX_CLIENTS };
