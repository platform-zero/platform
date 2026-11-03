'use strict';
const assert = require('node:assert/strict');
const https = require('node:https');
const fs = require('node:fs');
const { setTimeout: delay } = require('node:timers/promises');
let phase = 'validate-inputs';
const credentials = JSON.parse(fs.readFileSync('/run/secrets/search-bootstrap.json', 'utf8'));
assert.deepEqual(Object.keys(credentials).sort(), ['admin', 'application', 'bootstrap']);
for (const value of Object.values(credentials)) assert(/^[a-f0-9]{64}$/.test(value));
assert.equal(new Set(Object.values(credentials)).size, 3);
function request(method, path, body, user, password, expected, timeout = 120000) {
  assert(timeout > 0 && timeout <= 120000);
  return new Promise((resolve, reject) => {
    const data = body === null ? '' : JSON.stringify(body);
    const req = https.request({ hostname: 'elastic', port: 9200, path, method,
      ca: fs.readFileSync('/run/secrets/es-ca.pem'), rejectUnauthorized: true, signal: AbortSignal.timeout(timeout),
      headers: { Authorization: 'Basic ' + Buffer.from(user + ':' + password).toString('base64'), 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } }, response => {
      let size = 0; const chunks = [];
      response.on('data', chunk => { size += chunk.length; if (size > 65536) req.destroy(new Error('Response budget exceeded')); else chunks.push(chunk); });
      response.on('end', () => {
        if (response.statusCode === expected) resolve(Buffer.concat(chunks).toString('utf8'));
        else { console.error('Native search HTTP status: ' + response.statusCode); reject(new Error('Native search status rejected')); }
      });
      response.on('error', reject);
    });
    req.setTimeout(timeout, () => req.destroy(new Error('Native search operation timed out')));
    req.on('error', reject); req.end(data); // Never retry a potentially ambiguous administrative write.
  });
}
(async () => {
  phase = 'read-only-cluster-readiness';
  const deadline = Date.now() + 180000; let ready = false;
  while (Date.now() < deadline) {
    const health = JSON.parse(await request('GET', '/_cluster/health?wait_for_status=yellow&wait_for_events=languid&wait_for_no_initializing_shards=true&timeout=90s', null, 'elastic', credentials.bootstrap, 200, Math.min(120000, deadline - Date.now())));
    if (!health.timed_out && ['green', 'yellow'].includes(health.status)) {
      // The health response can count its own wait-for-events task. Inspect the native
      // pending queue separately instead of treating that self-count as failed readiness.
      const pending = JSON.parse(await request('GET', '/_cluster/pending_tasks', null, 'elastic', credentials.bootstrap, 200, Math.min(120000, deadline - Date.now())));
      if (Array.isArray(pending.tasks) && pending.tasks.length === 0) { ready = true; break; }
    }
    await delay(1000); // Retry observations only, never administrative writes.
  }
  assert(ready, 'Native search readiness exhausted');
  phase = 'application-role';
  await request('PUT', '/_security/role/huly', { cluster: ['monitor', 'manage_pipeline'], indices: [{ names: ['huly*'], privileges: ['all'] }] }, 'elastic', credentials.bootstrap, 200);
  phase = 'application-user';
  await request('PUT', '/_security/user/huly', { password: credentials.application, roles: ['huly'] }, 'elastic', credentials.bootstrap, 200);
  phase = 'retire-bootstrap-password';
  await request('POST', '/_security/user/elastic/_password', { password: credentials.admin }, 'elastic', credentials.bootstrap, 200);
  phase = 'authorization-checks';
  await request('GET', '/_security/_authenticate', null, 'elastic', credentials.bootstrap, 401);
  await request('GET', '/_security/_authenticate', null, 'huly', credentials.application, 200);
  await request('GET', '/_security/user', null, 'huly', credentials.application, 403);
  console.log('Native search application role provisioned; bootstrap credential retired.');
})().catch(() => { console.error('Search provisioning failed at ' + phase + '; retain state for reconciliation, never replay.'); process.exitCode = 1; });
