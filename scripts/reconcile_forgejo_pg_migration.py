#!/usr/bin/python3
"""Stop/reconcile the original r1 Forgejo migration pilot; no migration retry."""
if not __debug__:
    raise SystemExit('Optimized Python refused')
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-pg-migration-r1')
STORE = Path('/mnt/media/p0-v3/runtime-stores/canonical-v2')
PREFIX = ['sudo', '-n', '/usr/bin/podman', '--remote=false',
    '--module=' + str(STORE / 'containers.conf'), '--root=' + str(STORE / 'graph'),
    '--runroot=/run/p0-v3-canonical-v2/store',
    '--network-config-dir=' + str(STORE / 'networks')]

def persist(name, data):
    target = ROOT / name
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    parent = os.open(ROOT, os.O_DIRECTORY | os.O_RDONLY)
    try: os.fsync(parent)
    finally: os.close(parent)

def native(args):
    r = subprocess.run(PREFIX + args, capture_output=True, timeout=35,
                       env={'PATH': '/usr/bin:/bin', 'HOME': '/home/gerald', 'LANG': 'C'})
    assert r.returncode == 0 and len(r.stdout) <= 4096 and not r.stderr, 'Original native readback uncertain'
    return r.stdout.decode().strip()

def main():
    assert not (ROOT / 'attempt.result.json').exists() and not (ROOT / 'reconcile.intent.json').exists(), 'Original already terminal or stop uncertain'
    original = (ROOT / 'attempt.intent.json').read_bytes()
    intent = json.loads(original)
    assert intent['network'] == 'p0v3-component-forgejo-pg-migration-r1' and not intent['production']
    failure = (ROOT / 'forgejo-migrate.stdout').read_bytes()
    assert b'invalid base64 decoded length: 48, expects: 32' in failure and b'read-only file system' in failure
    failed = json.loads((ROOT / 'forgejo-migrate.result.json').read_bytes())
    assert failed['exitCode'] != 0 and failed['stdoutSha256'] == hashlib.sha256(failure).hexdigest()
    tls = (ROOT / 'tls-client.stdout').read_bytes()
    assert tls == b'forgejo_migrate|t\n' and json.loads((ROOT / 'tls-client.result.json').read_bytes())['exitCode'] == 0
    pgid = (ROOT / 'postgres-start.stdout').read_text().strip()
    assert re.fullmatch(r'[a-f0-9]{64}', pgid)
    expected = [pgid, '7cd945ac49388b3a008caee3fa77599bfc7901dbdda9ff6746562af82c49793c',
                'running', 'forgejo-pg-migration-r1']
    fmt = '{{.Id}} {{.Image}} {{.State.Status}} {{index .Config.Labels "io.p0v3.component-attempt"}}'
    assert native(['inspect', '--format', fmt, pgid]).split() == expected
    sql = "SELECT has_schema_privilege('forgejo_migrate','public','CREATE'), has_database_privilege('forgejo_migrate','forgejo','CREATE')"
    roles = native(['exec', pgid, 'psql', '-X', '-At', '-U', 'postgres', '-d', 'forgejo', '-c', sql])
    assert roles == 't|f', 'Original migration authority changed'
    stop = {'schemaVersion': 1, 'originalIntentSha256': hashlib.sha256(original).hexdigest(),
            'originalFailedMigrationSha256': hashlib.sha256(failure).hexdigest(), 'originalCid': pgid,
            'nativeTlsReadbackSha256': hashlib.sha256(tls).hexdigest(), 'roles': roles,
            'stopOnly': True, 'migrationReplayed': False}
    persist('reconcile.intent.json', (json.dumps(stop, sort_keys=True, separators=(',', ':')) + '\n').encode())
    command = subprocess.run(PREFIX + ['stop', '--time=15', pgid], capture_output=True, timeout=45,
                             env={'PATH': '/usr/bin:/bin', 'HOME': '/home/gerald', 'LANG': 'C'})
    persist('reconcile.stop.stdout', command.stdout or b'\n')
    persist('reconcile.stop.stderr', command.stderr or b'\n')
    assert command.returncode == 0 and command.stdout.decode().strip() == pgid and not command.stderr, 'Stop uncertain; never replay'
    assert native(['inspect', '--format', fmt, pgid]).split() == expected[:2] + ['exited'] + expected[3:]
    persist('attempt.reconciliation-v1.json', (json.dumps({**stop, 'postgresStopped': True,
        'originalResultExists': False, 'appSchemaMigrated': False, 'ownerAccountVerified': False,
        'releaseQualified': False}, sort_keys=True, separators=(',', ':')) + '\n').encode())
    print('Original r1 app migration failure reconciled; original SQL and Forgejo invocation were not replayed')

if __name__ == '__main__':
    main()
