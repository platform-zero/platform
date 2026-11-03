'use strict';
const assert = require('node:assert/strict');
const net = require('node:net');
const tls = require('node:tls');
const fs = require('node:fs');
const { bridge } = require('/run/secrets/huly-kvs-proxy.cjs');
const parameters = Buffer.from('user\0huly\0database\0huly\0client_encoding\0UTF8\0\0');
const header = Buffer.alloc(8); header.writeUInt32BE(parameters.length + 8); header.writeUInt32BE(196608, 4);
const startup = Buffer.concat([header, parameters]);
async function proof(ca, hostname) {
  let failure, response = Buffer.alloc(0), verified = false;
  const server = net.createServer(socket => bridge(socket, ca, () => {}, net, {
    connect(options) {
      const secured = tls.connect({ ...options, servername: hostname });
      secured.on('error', error => { failure = error.code; });
      secured.on('secureConnect', () => { verified = secured.authorized; });
      return secured;
    }
  }));
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    await new Promise((resolve, reject) => {
      const client = net.connect(server.address().port, '127.0.0.1');
      client.setTimeout(12000, () => { client.destroy(); reject(Error('Transport proof timeout')); });
      client.once('connect', () => client.write(startup));
      client.on('data', data => { response = Buffer.concat([response, data]); client.destroy(); });
      client.on('error', reject); client.on('close', resolve);
    });
    return { verified, response, failure };
  } finally { await new Promise(resolve => server.close(resolve)); }
}
(async () => {
  let input = ''; for await (const chunk of process.stdin) { input += chunk; assert(input.length <= 65536); }
  const wrongCa = JSON.parse(input).wrongCa;
  const ca = fs.readFileSync('/run/secrets/cr-ca.pem');
  const valid = await proof(ca, 'cockroach');
  assert(valid.verified && valid.response[0] === 82 && valid.failure === undefined); // Native PostgreSQL authentication challenge, no password sent.
  const wrong = await proof(wrongCa, 'cockroach');
  assert(!wrong.verified && wrong.response.length === 0);
  assert(['SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY'].includes(wrong.failure));
  const hostname = await proof(ca, 'wrong.invalid');
  assert(!hostname.verified && hostname.response.length === 0 && hostname.failure === 'ERR_TLS_CERT_ALTNAME_INVALID');
  const plaintext = await new Promise((resolve, reject) => {
    const client = net.connect(26257, 'cockroach');
    client.setTimeout(5000, () => { client.destroy(); reject(Error('Plaintext denial timeout')); });
    client.once('connect', () => client.write(startup));
    client.once('data', data => { client.destroy(); resolve(data); }); client.on('error', reject);
  });
  assert(plaintext[0] === 69 && /SSL|TLS|secure mode/i.test(plaintext.toString()));
  console.log(JSON.stringify({ verifiedRemoteTls: true, wrongCaDenied: true, wrongHostnameDenied: true, plaintextDatabaseDenied: true, applicationPasswordsSent: 0 }));
})().catch(() => { console.error('Native KVS transport proof failed; no credentials emitted.'); process.exitCode = 1; });
