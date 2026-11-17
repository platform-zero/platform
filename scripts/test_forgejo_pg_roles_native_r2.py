#!/usr/bin/python3
"""One-shot, non-release r2 SQL role test against the pinned Timescale image.

No generation, site, production volume or public port is touched. The sole new
container is network-none, tmpfs-backed and retained stopped for inspectable evidence.
An existing intent/result refuses another attempt; never infer a missing result from
an exited command or replace/renumber an uncertain container.
"""
if not __debug__:
    raise SystemExit('Optimized Python refused')
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import subprocess
import time
import yaml

ROOT = Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-pg-sql-r2-02')
SOURCE = Path(__file__).resolve().parents[1]
FRAGMENT = SOURCE / 'src/main/resources/fragments/v2/forgejo/r2/fragment.yaml'
INVENTORY = SOURCE / 'release/forgejo-pg-v2-development-inventory.json'
NAME = 'p0v3-component-forgejo-pg-sql-r2-02'
STORE = Path('/mnt/media/p0-v3/runtime-stores/canonical-v2')
PREFIX = ['sudo', '-n', '/usr/bin/podman', '--remote=false',
          '--module=' + str(STORE / 'containers.conf'), '--root=' + str(STORE / 'graph'),
          '--runroot=/run/p0-v3-canonical-v2/store',
          '--network-config-dir=' + str(STORE / 'networks')]


def save(name, data):
    target = ROOT / name
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data); out.flush(); os.fsync(out.fileno())
    parent = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(parent)
    finally: os.close(parent)
    return hashlib.sha256(data).hexdigest()


def command(args, script=None, timeout=60):
    response = subprocess.run(PREFIX + args, input=script, capture_output=True, timeout=timeout,
                              env={'PATH': '/usr/bin:/bin', 'HOME': '/home/gerald', 'LANG': 'C'})
    assert len(response.stdout) <= 500000 and len(response.stderr) <= 500000, 'oversized native reply'
    return response


def main():
    assert os.getuid() != 0 and not ROOT.exists(), 'Original SQL component attempt exists; reconcile, do not replay'
    fragment = FRAGMENT.read_bytes(); inventory = INVENTORY.read_bytes()
    parsed = yaml.safe_load(fragment)
    assert parsed['id'] == 'forgejo-postgres' and parsed['revision'] == 2
    processes = {p['id']: p for p in parsed['processes']}
    assert set(processes) == {'forgejo-db-init', 'forgejo-migrate', 'forgejo-owner-init',
                              'forgejo-db-finalize', 'forgejo'}
    images = json.loads(inventory)['images']
    image = next(i for i in images if i['product'] == 'postgres-timescale')
    assert image['imageId'] == '7cd945ac49388b3a008caee3fa77599bfc7901dbdda9ff6746562af82c49793c'
    assert (stat.S_IMODE(STORE.stat().st_mode) & 0o002) == 0
    priorPath = Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-pg-sql-r2-01/attempt.reconciliation-v1.json')
    priorBytes = priorPath.read_bytes()
    prior = json.loads(priorBytes)
    assert prior['terminal'][2] == 'exited' and prior['originalResultExists'] is False
    assert not ROOT.exists()
    ROOT.mkdir(mode=0o700)
    intent = {'schemaVersion': 1, 'scriptRevision': 2,
              'priorTerminalReconciliationSha256': hashlib.sha256(priorBytes).hexdigest(),
              'scope': 'isolated-component-not-release', 'container': NAME,
              'imageId': image['imageId'], 'fragmentSha256': hashlib.sha256(fragment).hexdigest(),
              'inventorySha256': hashlib.sha256(inventory).hexdigest(), 'network': 'none',
              'database': 'tmpfs-no-production-volume', 'replay': False}
    save('attempt.intent.json', (json.dumps(intent, sort_keys=True, separators=(',', ':')) + '\n').encode())
    password = secrets.token_hex(32); migration = secrets.token_hex(32); serving = secrets.token_hex(32)
    # Disposable development-only credentials, protected for original-role readback after a lost ACK.
    save('role-test.env', ('FORGEJO_MIGRATION_PASSWORD=' + migration + '\nFORGEJO_RUNTIME_PASSWORD=' + serving + '\n').encode())
    # POSTGRES_PASSWORD is a test-only disposable password; never an application grant.
    envfile = ROOT / 'postgres-test.env'
    save(envfile.name, ('POSTGRES_PASSWORD=' + password + '\n').encode())
    cid = command(['run', '--detach', '--name', NAME, '--network=none', '--pull=never',
                   '--memory=512m', '--pids-limit=128', '--rm=false',
                   '--label=io.p0v3.component-attempt=forgejo-pg-sql-r2-02',
                   '--tmpfs=/var/lib/postgresql/data:rw,nosuid,nodev,size=512m',
                   '--env-file=' + str(envfile), image['imageId']], timeout=120)
    save('start.stdout', cid.stdout); save('start.stderr', cid.stderr)
    assert cid.returncode == 0 and len(cid.stdout.strip()) == 64 and all(c in b'0123456789abcdef' for c in cid.stdout.strip()), 'container start uncertain'
    actual = cid.stdout.strip().decode()
    ready = False
    for _ in range(50):
        check = command(['exec', actual, 'pg_isready', '-U', 'postgres'], timeout=10)
        if check.returncode == 0:
            ready = True; break
        time.sleep(1)
    assert ready, 'native PostgreSQL never became ready; original attempt retained'
    init = processes['forgejo-db-init']['command'][1]
    finalize = processes['forgejo-db-finalize']['command'][1]
    assert init.startswith('psql -X -v ON_ERROR_STOP=1') and finalize.startswith('psql -X -d forgejo')
    prefix = 'set -eu\nexport PGUSER=postgres PGHOST=/var/run/postgresql\n'
    init_script = (prefix + 'FORGEJO_MIGRATION_PASSWORD=' + migration + '\nFORGEJO_RUNTIME_PASSWORD=' + serving + '\n' + init)
    step = command(['exec', '-i', actual, 'sh', '-s'], init_script.encode(), 90)
    save('init.stdout', step.stdout); save('init.stderr', step.stderr)
    assert step.returncode == 0, 'r2 original initialization failed; do not rerun this SQL'
    # Test migration CREATE only on its own public schema, with no database CREATE.
    sql = """SELECT current_user, has_database_privilege(current_user,'forgejo','CREATE'),
        has_schema_privilege(current_user,'public','CREATE');
        CREATE TABLE public.p0v3_migration_check (id integer PRIMARY KEY, value text NOT NULL);
        INSERT INTO public.p0v3_migration_check VALUES (1, 'original');
    """
    migrate = command(['exec', '-i', actual, 'sh', '-s'],
        ('set -eu\nexport PGPASSWORD=' + migration +
         "\npsql -X -At -h 127.0.0.1 -U forgejo_migrate -d forgejo -v ON_ERROR_STOP=1 <<'SQL'\n" +
         sql + "\nSQL\n").encode(), 45)
    save('migration.stdout', migrate.stdout); save('migration.stderr', migrate.stderr)
    assert migrate.returncode == 0 and b'forgejo_migrate|f|t' in migrate.stdout, 'migration privileges differ'
    finish = command(['exec', '-i', actual, 'sh', '-s'], (prefix + finalize).encode(), 60)
    save('finalize.stdout', finish.stdout); save('finalize.stderr', finish.stderr)
    assert finish.returncode == 0, 'r2 finalize uncertain; do not replay'
    # Runtime principal cannot create schema/extension, but can write and read migrated data.
    readback = """set -eu
export PGPASSWORD=SERVING
psql -X -At -h 127.0.0.1 -U forgejo -d forgejo -v ON_ERROR_STOP=1 <<'SQL'
SELECT current_user, has_schema_privilege(current_user,'public','CREATE');
UPDATE public.p0v3_migration_check SET value='verified' WHERE id=1;
SELECT value FROM public.p0v3_migration_check WHERE id=1;
SQL
""".replace('SERVING', serving)
    observed = command(['exec', '-i', actual, 'sh', '-s'], readback.encode(), 45)
    save('runtime.stdout', observed.stdout); save('runtime.stderr', observed.stderr)
    assert observed.returncode == 0 and b'forgejo|f' in observed.stdout and b'verified' in observed.stdout, 'runtime privilege/readback failed'
    denial = command(['exec', '-i', actual, 'sh', '-s'],
        ('set -eu\nexport PGPASSWORD=' + serving + "\npsql -X -h 127.0.0.1 -U forgejo -d forgejo -v ON_ERROR_STOP=1 <<'SQL'\nCREATE EXTENSION timescaledb;\nSQL\n").encode(), 45)
    save('denial.stdout', denial.stdout); save('denial.stderr', denial.stderr)
    assert denial.returncode != 0 and b'permission denied' in denial.stderr.lower(), 'serving role installed extension or failed for unrelated reason'
    stopped = command(['stop', '--time=15', actual], timeout=40)
    save('stop.stdout', stopped.stdout); save('stop.stderr', stopped.stderr)
    assert stopped.returncode == 0, 'original component container stop uncertain'
    result = {'schemaVersion': 1, 'intentSha256': hashlib.sha256((ROOT / 'attempt.intent.json').read_bytes()).hexdigest(),
              'containerId': actual, 'roleMigration': True, 'runtimeCRUD': True,
              'extensionPermissionDenied': True, 'networkNone': True, 'stopped': True,
              'forgejoAppMigrated': False, 'tlsVerified': False, 'kopiaRecovered': False,
              'releaseQualified': False}
    save('attempt.result.json', (json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n').encode())
    print('Isolated r2 SQL component succeeded; Forgejo, TLS, Kopia and release remain unproven')


if __name__ == '__main__':
    main()
