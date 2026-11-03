"""Read-only privilege/network checks in an already prepared canonical core. No provisioning."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import json
import re
import subprocess


def verify_provider(name, pod, environment):
    assert re.fullmatch(r'q-[a-f0-9]{12}-canonical-core', name)
    container = 'p0v3-live-' + name + '-'
    inspected = subprocess.run(pod + ['inspect', container + 'planka', container + 'postgres', container + 'ntfy'],
                               capture_output=True, text=True, env=environment, timeout=30)
    assert inspected.returncode == 0
    app, db, ntfy = json.loads(inspected.stdout)
    networks = lambda c: set(c['NetworkSettings']['Networks'])
    assert networks(app) == {container + 'planka-web', container + 'planka-data'}
    assert networks(db) == {container + 'net', container + 'db-admin', container + 'planka-data'}
    assert networks(ntfy) == {container + 'net'}
    address = ntfy['NetworkSettings']['Networks'][container + 'net']['IPAddress']
    script = r'''
const { Client } = require('pg');
const fs = require('fs');
const net = require('net');
const assert = require('assert/strict');
const url = new URL(process.env.DATABASE_URL);
url.searchParams.delete('sslmode');
const options = {connectionString: url.toString(), connectionTimeoutMillis: 5000,
  ssl: {ca: fs.readFileSync('/run/secrets/postgres-ca.pem'), rejectUnauthorized: true}};
async function refused(config, sql, states) {
  const client = new Client(config);
  let error;
  try { await client.connect(); if (sql) await client.query(sql); }
  catch (e) { error = e; }
  finally { await client.end(); }
  assert(error, 'required operation denial absent');
  if (states) assert(states.includes(error.code), 'wrong denial class');
}
(async () => {
  const client = new Client(options); await client.connect();
  assert.equal((await client.query('SELECT current_user AS u')).rows[0].u, 'planka');
  assert.equal((await client.query('SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()')).rows[0].ssl, true);
  const sessions = (await client.query('SELECT s.ssl FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid) WHERE a.usename=current_user AND pid<>pg_backend_pid()')).rows;
  assert(sessions.length > 0 && sessions.every(s => s.ssl === true), 'application sessions must use TLS');
  const flags = (await client.query("SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user")).rows[0];
  assert(Object.values(flags).every(v => v === false));
  assert.equal((await client.query("SELECT rolcanlogin FROM pg_roles WHERE rolname='planka_migrate'")).rows[0].rolcanlogin, false);
  assert.equal((await client.query("SELECT has_schema_privilege(current_user,'public','CREATE') AS allowed")).rows[0].allowed, false);
  await client.end();
  for (const database of ['postgres', 'template1']) {
    const other = new URL(url); other.pathname = '/' + database;
    await refused({...options, connectionString: other.toString()}, null, ['42501']);
  }
  await refused(options, 'CREATE TABLE public.p0v3_denied_table (id int)', ['42501']);
  await refused(options, 'CREATE ROLE p0v3_denied_role', ['42501']);
  await refused({...options, ssl: false}, null, ['28000']);
  const socket = net.connect({host: ADDRESS, port: 8080});
  await new Promise((resolve, reject) => {
    socket.setTimeout(3000, () => { socket.destroy(); resolve(); });
    socket.once('error', e => { if (['EHOSTUNREACH','ENETUNREACH','ETIMEDOUT'].includes(e.code)) resolve(); else reject(e); });
    socket.once('connect', () => { socket.destroy(); reject(new Error('unexpected cross-network connection')); });
  });
  console.log(JSON.stringify({tlsVerifiedConnection: true, runtimeRoleNotPrivileged: true,
    migrationPrincipalRetired: true, foreignDatabaseDenials: true, schemaAndRoleMutationDenied: true,
    plaintextDatabaseDenied: true, unrelatedNetworkDenied: true}));
})().catch(() => { console.error('Canonical provider checks failed; no credential output'); process.exitCode=1; });
'''.replace('ADDRESS', json.dumps(address))
    result = subprocess.run(pod + ['exec', '-i', container + 'planka', 'node'], input=script,
                            capture_output=True, text=True, env=environment, timeout=90)
    assert result.returncode == 0, 'Canonical provider denial/readback checks failed'
    return json.loads(result.stdout)
