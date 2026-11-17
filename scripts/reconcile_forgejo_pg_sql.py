#!/usr/bin/python3
"""Bounded, no-replay reconciliation of the original r2 SQL component attempt.

Original migration returned success and wrote its stdout; a host-side table-format
assertion failed. Observe its original CID and exact SQL state, stop that same
container once, and retain a sidecar. Never fabricate attempt.result.json.
"""
if not __debug__:
    raise SystemExit('Optimized Python refused')
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-pg-sql-r2-01')
STORE = Path('/mnt/media/p0-v3/runtime-stores/canonical-v2')
PREFIX = ['sudo', '-n', '/usr/bin/podman', '--remote=false',
          '--module=' + str(STORE / 'containers.conf'), '--root=' + str(STORE / 'graph'),
          '--runroot=/run/p0-v3-canonical-v2/store',
          '--network-config-dir=' + str(STORE / 'networks')]


def persist(name, value):
    path = ROOT / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(value); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(parent)
    finally: os.close(parent)


def observe(arguments, timeout=20):
    r = subprocess.run(PREFIX + arguments, capture_output=True, timeout=timeout,
                       env={'PATH': '/usr/bin:/bin', 'HOME': '/home/gerald', 'LANG': 'C'})
    assert r.returncode == 0 and len(r.stdout) <= 4096 and len(r.stderr) <= 4096, 'original observation uncertain'
    return r.stdout.decode()


def main():
    assert not (ROOT / 'attempt.result.json').exists()
    assert not (ROOT / 'reconcile.intent.json').exists(), 'Original reconciliation already attempted; do not replay stop'
    original = (ROOT / 'attempt.intent.json').read_bytes()
    intent = json.loads(original)
    assert intent['container'] == 'p0v3-component-forgejo-pg-sql-r2-01' and intent['replay'] is False
    cid = (ROOT / 'start.stdout').read_text().strip()
    assert re.fullmatch(r'[a-f0-9]{64}', cid)
    migration = (ROOT / 'migration.stdout').read_bytes()
    assert migration.endswith(b'CREATE TABLE\nINSERT 0 1\n') and b'forgejo_migrate | f' in migration
    assert (ROOT / 'migration.stderr').read_bytes() == b'' and (ROOT / 'init.stderr').read_bytes() == b''
    inspection = observe(['inspect', '--format', '{{.Id}} {{.Image}} {{.State.Status}} {{.HostConfig.NetworkMode}} {{index .Config.Labels "io.p0v3.component-attempt"}}', cid]).strip().split()
    assert inspection == [cid, intent['imageId'], 'running', 'none', 'forgejo-pg-sql-r2-01']
    sql = "SELECT current_user, has_database_privilege('forgejo_migrate','forgejo','CREATE'), has_schema_privilege('forgejo_migrate','public','CREATE'), (SELECT value FROM public.p0v3_migration_check WHERE id=1)"
    readback = observe(['exec', cid, 'psql', '-X', '-U', 'postgres', '-d', 'forgejo', '-At', '-c', sql]).strip()
    assert readback == 'postgres|f|t|original', 'Native role/table readback differs; stop without success claim'
    stopIntent = {'schemaVersion': 1, 'originalIntentSha256': hashlib.sha256(original).hexdigest(),
                  'originalMigrationStdoutSha256': hashlib.sha256(migration).hexdigest(),
                  'originalCid': cid, 'readback': readback, 'stopOnly': True}
    persist('reconcile.intent.json', (json.dumps(stopIntent, sort_keys=True, separators=(',', ':')) + '\n').encode())
    stopped = subprocess.run(PREFIX + ['stop', '--time=15', cid], capture_output=True, timeout=40,
                             env={'PATH': '/usr/bin:/bin', 'HOME': '/home/gerald', 'LANG': 'C'})
    persist('reconcile.stop.stdout', stopped.stdout); persist('reconcile.stop.stderr', stopped.stderr)
    assert stopped.returncode == 0 and stopped.stdout.decode().strip() == cid and not stopped.stderr, 'Original stop uncertain; no replay'
    terminal = observe(['inspect', '--format', '{{.Id}} {{.Image}} {{.State.Status}} {{.HostConfig.NetworkMode}}', cid]).strip().split()
    assert terminal == [cid, intent['imageId'], 'exited', 'none']
    record = {**stopIntent, 'terminal': terminal, 'originalResultExists': False,
              'migrationNativeReadback': True, 'componentCompleted': False, 'appMigrated': False,
              'tlsVerified': False, 'releaseQualified': False}
    persist('attempt.reconciliation-v1.json', (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode())
    print('Original r2 SQL component reconciled and stopped, not replayed; original result remains absent')


if __name__ == '__main__':
    main()
