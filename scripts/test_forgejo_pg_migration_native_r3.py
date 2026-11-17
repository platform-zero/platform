#!/usr/bin/python3
"""One fresh isolated Forgejo r2 PostgreSQL/TLS migration component attempt.

Not a generation, installed Quadlet, site deployment, application workflow, Kopia
capture or release pass. Each original external effect gets CREATE_NEW/fsynced
intent and durable stdout/stderr/result; a missing result forbids retry. Own private
network and containers are retained stopped; never remove/replace existing resources.
"""
if not __debug__:
    raise SystemExit('Optimized Python refused')
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import time
import yaml

ROOT = Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-pg-migration-r3')
SOURCE = Path(__file__).resolve().parents[1]
FRAGMENT = SOURCE / 'src/main/resources/fragments/v2/forgejo/r4/fragment.yaml'
TEMPLATE = SOURCE / 'src/main/resources/fragments/v2/forgejo/r4/app.ini.template'
INVENTORY = SOURCE / 'release/forgejo-pg-v2-development-inventory.json'
STORE = Path('/mnt/media/p0-v3/runtime-stores/canonical-v2')
NET = 'p0v3-component-forgejo-pg-migration-r3'
DATABASE = NET + '-postgres'
MIGRATION = NET + '-forgejo-migrate'
PREFIX = ['sudo', '-n', '/usr/bin/podman', '--remote=false',
          '--module=' + str(STORE / 'containers.conf'), '--root=' + str(STORE / 'graph'),
          '--runroot=/run/p0-v3-canonical-v2/store',
          '--network-config-dir=' + str(STORE / 'networks')]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data); out.flush(); os.fsync(out.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(parent)
    finally: os.close(parent)
    return digest(data)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def command(args, data=None, timeout=90):
    result = subprocess.run(PREFIX + args, input=data, capture_output=True, timeout=timeout,
                            env={'PATH': '/usr/bin:/bin', 'HOME': '/home/gerald', 'LANG': 'C'})
    assert len(result.stdout) <= 500000 and len(result.stderr) <= 500000, 'native output exceeds bound'
    return result


def effect(tag, args, data=None, timeout=90):
    assert re.fullmatch(r'[a-z][a-z0-9-]{2,40}', tag)
    intent = canonical({'step': tag, 'args': args, 'inputSha256': digest(data) if data else None,
                        'scope': 'isolated-native-component-only'})
    save(ROOT / (tag + '.intent.json'), intent)
    try:
        result = command(args, data, timeout)
    except Exception:
        raise RuntimeError(tag + ' effect uncertain; retain original intent, never retry') from None
    out = save(ROOT / (tag + '.stdout'), result.stdout or b'\n')
    err = save(ROOT / (tag + '.stderr'), result.stderr or b'\n')
    save(ROOT / (tag + '.result.json'), canonical({'intentSha256': digest(intent),
        'stdoutSha256': out, 'stderrSha256': err, 'exitCode': result.returncode}))
    assert result.returncode == 0, tag + ' failed; do not retry an uncertain native effect'
    return result.stdout.decode().strip()


def main():
    assert os.getuid() in range(1, 65535) and not ROOT.exists(), 'Original pilot exists; reconcile, do not replay'
    fragment = FRAGMENT.read_bytes(); template = TEMPLATE.read_bytes(); inventory = INVENTORY.read_bytes()
    parsed = yaml.safe_load(fragment)
    assert parsed['id'] == 'forgejo-postgres' and parsed['revision'] == 4
    processes = {p['id']: p for p in parsed['processes']}
    assert set(processes) == {'forgejo-db-init', 'forgejo-migrate', 'forgejo-owner-init',
                              'forgejo-db-finalize', 'forgejo'}
    images = {i['product']: i for i in json.loads(inventory)['images']}
    assert images['postgres-timescale']['imageId'] == '7cd945ac49388b3a008caee3fa77599bfc7901dbdda9ff6746562af82c49793c'
    assert images['forgejo']['imageId'] == 'b5ae2a0d5d9abdf9a4ac005f65d8971068789d4f5e19a3b8b541e26e8d8a3c0f'
    assert yaml.safe_load(fragment)['processes'][0]['command'][1].startswith('psql -X -v ON_ERROR_STOP=1')
    prior = Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-pg-migration-r2/attempt.reconciliation-v1.json')
    priorBytes = prior.read_bytes()
    assert json.loads(priorBytes)['postgresStopped'] and not json.loads(priorBytes)['originalResultExists']
    assert not json.loads(priorBytes)['appSchemaMigrated']
    available = int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))) // 1024
    assert available - 2048 >= 16384 and os.statvfs(STORE).f_bavail * os.statvfs(STORE).f_frsize // 1048576 - 2048 >= 10240
    assert stat.S_IMODE(STORE.stat().st_mode) & 0o002 == 0
    ROOT.mkdir(mode=0o700)
    save(ROOT / 'attempt.intent.json', canonical({'schemaVersion': 1, 'network': NET,
        'postgres': DATABASE, 'migration': MIGRATION, 'fragmentSha256': digest(fragment),
        'templateSha256': digest(template), 'inventorySha256': digest(inventory),
        'priorFailedPilotReconciliationSha256': digest(priorBytes), 'production': False, 'replay': False}))
    tls = ROOT / 'tls'; tls.mkdir(mode=0o700)
    cert = tls / 'server.crt'; key = tls / 'server.key'
    generated = subprocess.run(['/usr/bin/openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', str(key), '-out', str(cert), '-days', '2', '-subj', '/CN=postgres',
        '-addext', 'subjectAltName=DNS:postgres', '-addext', 'basicConstraints=critical,CA:TRUE'],
        capture_output=True, timeout=30)
    assert generated.returncode == 0 and len(cert.read_bytes()) < 8192
    os.chmod(cert, 0o644)
    # Root-only chown is scoped to the two new dev TLS files. Host parent stays owned by us.
    changed = subprocess.run(['sudo', '-n', '/usr/bin/chown', '999:999', str(key)], capture_output=True, timeout=15)
    assert changed.returncode == 0
    os.chmod(tls, 0o755)
    admin, migration, serving, secret, internal, jwtBytes = [secrets.token_hex(32) for _ in range(6)]
    jwt = base64.urlsafe_b64encode(bytes.fromhex(jwtBytes)).decode().rstrip('=')
    assert len(base64.urlsafe_b64decode(jwt + '=')) == 32 and len(jwt) == 43
    save(ROOT / 'pg.env', ('POSTGRES_PASSWORD=' + admin + '\n').encode())
    save(ROOT / 'roles.env', ('FORGEJO_MIGRATION_PASSWORD=' + migration + '\nFORGEJO_RUNTIME_PASSWORD=' + serving + '\n').encode())
    original = template.decode()
    for keyName, value in {'DATABASE_PRINCIPAL': 'forgejo_migrate', 'DATABASE_PASSWORD': migration,
                           'SECRET_KEY': secret, 'INTERNAL_TOKEN': internal, 'JWT_SECRET': jwt}.items():
        original = original.replace('{{' + keyName + '}}', value)
    assert '{{' not in original and 'SSL_MODE = verify-full' in original and 'HOST = postgres:5432' in original
    save(ROOT / 'app.ini', original.encode())
    data = ROOT / 'data'; data.mkdir(mode=0o700)
    env = ('HOME=/data\nUSER=git\nPGHOST=postgres\nPGPORT=5432\nPGDATABASE=forgejo\nPGUSER=forgejo_migrate\n' +
           'PGPASSWORD=' + migration + '\nPGSSLMODE=verify-full\nPGSSLROOTCERT=/tls/server.crt\n')
    save(ROOT / 'forgejo.env', env.encode())
    effect('network-create', ['network', 'create', '--internal', NET])
    pgid = effect('postgres-start', ['run', '-d', '--name', DATABASE, '--network=' + NET + ':alias=postgres',
        '--pull=never', '--memory=512m', '--pids-limit=128', '--rm=false',
        '--label=io.p0v3.component-attempt=forgejo-pg-migration-r3',
        '--tmpfs=/var/lib/postgresql/data:rw,nosuid,nodev,size=512m',
        '--volume=' + str(tls) + ':/tls:ro', '--env-file=' + str(ROOT / 'pg.env'),
        images['postgres-timescale']['imageId'], 'postgres', '-c', 'ssl=on',
        '-c', 'ssl_cert_file=/tls/server.crt', '-c', 'ssl_key_file=/tls/server.key',
        '-c', 'listen_addresses=*'], timeout=120)
    assert re.fullmatch(r'[a-f0-9]{64}', pgid), 'original PostgreSQL CID uncertain'
    ready = False
    for _ in range(60):
        probe = command(['exec', pgid, 'pg_isready', '-U', 'postgres'], timeout=10)
        if probe.returncode == 0:
            ready = True; break
        time.sleep(1)
    assert ready, 'original PostgreSQL readiness uncertain; do not restart'
    init = processes['forgejo-db-init']['command'][1]
    assert 'CREATE DATABASE forgejo OWNER postgres;' in init
    originalSql = ('set -eu\nexport PGUSER=postgres PGHOST=/var/run/postgresql\n' +
                   'FORGEJO_MIGRATION_PASSWORD=' + migration + '\nFORGEJO_RUNTIME_PASSWORD=' + serving + '\n' + init)
    effect('database-init', ['exec', '-i', pgid, 'sh', '-s'], originalSql.encode())
    # A separate pinned client proves both DNS hostname and TLS verification before app migration.
    tlsSql = ('set -eu\nexport PGPASSWORD=' + migration + '\n' +
              'psql -X -At -h postgres -U forgejo_migrate -d forgejo "sslmode=verify-full" ' +
              "-c 'SELECT current_user, (SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())'\n")
    # libpq's sslmode must be supplied through PGSSLMODE, never as a bare psql argument.
    tlsSql = tlsSql.replace(' "sslmode=verify-full" ', ' ').replace('export PGPASSWORD=', 'export PGSSLMODE=verify-full PGSSLROOTCERT=/tls/server.crt PGPASSWORD=')
    verified = effect('tls-client', ['run', '--rm=false', '--name', NET + '-tls-client', '--network=' + NET,
        '--pull=never', '--memory=128m', '--user=999:999', '--volume=' + str(tls) + ':/tls:ro',
        '-i', '--entrypoint=/bin/sh', images['postgres-timescale']['imageId'], '-s'], tlsSql.encode())
    assert verified == 'forgejo_migrate|t', 'native TLS readback wrong; no app migration authorized'
    migrated = effect('forgejo-migrate', ['run', '--rm=false', '--name', MIGRATION,
        '--network=' + NET, '--pull=never', '--memory=1024m', '--pids-limit=256',
        '--read-only', '--tmpfs=/tmp:rw,nosuid,nodev,size=128m', '--user=1000:1000',
        '--volume=' + str(data) + ':/data', '--volume=' + str(ROOT / 'app.ini') + ':/etc/forgejo/app.ini:ro',
        '--volume=' + str(tls) + ':/tls:ro', '--env-file=' + str(ROOT / 'forgejo.env'),
        '--entrypoint=/usr/local/bin/forgejo', images['forgejo']['imageId'],
        '--work-path', '/data', '--config', '/etc/forgejo/app.ini', 'migrate'], timeout=180)
    assert len(migrated) <= 400000
    # The actual Forgejo schema must exist before finalize retires the migration principal.
    schemaSql = "SELECT current_user, (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='user')"
    observed = effect('schema-readback', ['exec', pgid, 'psql', '-X', '-At', '-U', 'postgres',
        '-d', 'forgejo', '-c', schemaSql])
    assert observed == 'postgres|1', 'actual Forgejo user table missing; do not finalize'
    finalize = processes['forgejo-db-finalize']['command'][1]
    effect('database-finalize', ['exec', '-i', pgid, 'sh', '-s'],
        ('set -eu\nexport PGUSER=postgres PGHOST=/var/run/postgresql\n' + finalize).encode())
    effect('postgres-stop', ['stop', '--time=15', pgid], timeout=45)
    result = {'schemaVersion': 1, 'originalIntentSha256': digest((ROOT / 'attempt.intent.json').read_bytes()),
              'postgresCid': pgid, 'tlsDnsVerified': True, 'forgejoSchemaMigrated': True,
              'migrationAuthorityRetired': True, 'postgresStopped': True, 'networkInternal': True,
              'appWebVerified': False, 'ownerAccountVerified': False, 'kopiaRecovered': False,
              'installedUnitAudited': False, 'releaseQualified': False}
    save(ROOT / 'attempt.result.json', canonical(result))
    print('Isolated Forgejo SQL/TLS migration passed; no serving app, owner custody, Kopia or release claim')


if __name__ == '__main__':
    main()
