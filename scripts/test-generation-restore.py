#!/usr/bin/env python3
"""Fresh foundation/SQL-cache encrypted restore engineering proof. Never restarts the source."""
if not __debug__:
    raise SystemExit('Optimized execution refused before effects')
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import tarfile
import time
import uuid

BASE = Path('/mnt/media/p0-v3')
PLATFORM = Path(__file__).resolve().parents[1]
CLI = PLATFORM / 'build/install/p0-v3-platform/bin/p0-v3-platform'
POD = ['sudo', '-n', 'podman', '--remote=false', '--root=' + str(BASE / 'release-runtime/graph'),
       '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=' + str(BASE / 'release-runtime/network-config')]


def validate_rows(rows):
    assert isinstance(rows, list) and len(rows) <= 8
    assert all(isinstance(row, dict) and set(row) == {'id', 'value'} and
               isinstance(row['id'], str) and re.fullmatch(r'(post-|chain-before-|chain-after-)[a-f0-9]{12}', row['id']) and
               (row['value'] is None or (isinstance(row['value'], str) and re.fullmatch(r'chain-value-[a-f0-9]{12}', row['value']))) for row in rows)
    assert len({row['id'] for row in rows}) == len(rows)
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--generation', required=True)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--capture', required=True)
    parser.add_argument('--applications', action='store_true', help='Restore the exact foundation/SQL-cache/Forgejo/Planka cohort')
    parser.add_argument('--canonical-core', action='store_true')
    parser.add_argument('--kopia', action='store_true', help='Restore the canonical cohort from its native encrypted Kopia snapshot')
    parser.add_argument('--isolated-store', action='store_true', help='Explicitly restore into the initialized canonical-v2 file-lock store')
    parser.add_argument('--rebackup', action='store_true', help='After historical verification, run an installed backup timer on this fresh private restore and retain a new point')
    parser.add_argument('--recovered-source', action='store_true', help='Read the immediate source oracle from its retained restore/rebackup receipt, not a fabricated clean-install receipt')
    args = parser.parse_args()
    assert not (args.rebackup or args.recovered_source or args.isolated_store) or args.kopia
    global POD
    if args.isolated_store:
        POD = ['sudo', '-n', 'podman', '--remote=false',
               '--module=/mnt/media/p0-v3/runtime-stores/canonical-v2/containers.conf',
               '--root=/mnt/media/p0-v3/runtime-stores/canonical-v2/graph',
               '--runroot=/run/p0-v3-canonical-v2/store',
               '--network-config-dir=/mnt/media/p0-v3/runtime-stores/canonical-v2/networks']
    if args.kopia:
        args.canonical_core = True
    if args.canonical_core:
        args.applications = True
    assert re.fullmatch(r'q-[a-f0-9]{12}', args.generation)
    assert re.fullmatch(r'[a-f0-9]{64}', args.bundle)
    assert re.fullmatch(r'cap-[a-f0-9]{12}', args.capture)
    os.umask(0o077)
    parent = None
    oracle_generation = args.generation
    if args.recovered_source:
        parent = json.loads((BASE / 'image-acquisition-receipts' / ('p0v3-generation-restore-' + args.generation[2:]) / 'receipt.json').read_text())
        assert parent['passed'] and parent['target'] == args.generation and parent['bundleSha256'] == args.bundle
        assert parent['rebackup']['capture'] == args.capture and not parent['restoreInheritsSiteAuthority']
        oracle_generation = parent['oracleSourceGeneration']
        assert re.fullmatch(r'q-[a-f0-9]{12}', oracle_generation)
    oracle_bytes = (BASE / 'image-acquisition-receipts' / ('p0v3-generation-' + oracle_generation[2:]) / 'receipt.json').read_bytes()
    oracle_hash = hashlib.sha256(oracle_bytes).hexdigest()
    source_receipt = json.loads(oracle_bytes)
    assert source_receipt['passed'] and source_receipt['generation'] == oracle_generation
    if parent:
        assert oracle_hash == parent['oracleSourceReceiptSha256']
        snapshot_rows = validate_rows(parent['rebackup']['rows'])
        assert {'id': 'chain-before-' + args.generation[2:], 'value': 'chain-value-' + args.generation[2:]} in snapshot_rows
        assert {'id': 'chain-after-' + args.generation[2:], 'value': None} in snapshot_rows
        if source_receipt.get('postSnapshotRow'):
            assert {'id': source_receipt['postSnapshotRow'], 'value': None} in snapshot_rows
    else:
        assert source_receipt['bundleSha256'] == args.bundle
        snapshot_rows = []
        if source_receipt.get('routineBackupCapture'):
            assert args.kopia and source_receipt['routineBackupCapture'] == args.capture
            snapshot_rows = validate_rows([{'id': source_receipt['postSnapshotRow'], 'value': None}])
    source_group = BASE / 'release-generations' / args.generation
    source_bundle_bytes = (source_group / 'bundle.json').read_bytes()
    assert hashlib.sha256(source_bundle_bytes).hexdigest() == args.bundle
    source_ownership = json.loads(source_bundle_bytes).get('ownership')
    assert bool(source_receipt.get('canonicalCore', False)) == args.canonical_core
    foundation_kind = 'canonical-core' if args.canonical_core else 'foundation'
    kinds = ('canonical-core', 'sql-cache', 'forgejo') if args.canonical_core else (('foundation', 'sql-cache', 'forgejo', 'planka') if args.applications else ('foundation', 'sql-cache'))
    assert {p['spec']['name'] for p in json.loads(source_bundle_bytes)['members']} == {args.generation + '-' + k for k in kinds}
    original = source_receipt['foundationReceipt']
    sql_nonce = source_receipt['sql-cacheReceipt'].removeprefix('p0v3-sql-cache-')
    assert re.fullmatch(r'p0v3-runtime-check-[a-f0-9]{12}', original) and re.fullmatch(r'[a-f0-9]{12}', sql_nonce)
    nonce = uuid.uuid4().hex[:12]
    target = 'q-' + nonce
    out = BASE / 'image-acquisition-receipts' / ('p0v3-generation-restore-' + nonce)
    out.mkdir(mode=0o700)
    for name in ('home', 'tmp'):
        (out / name).mkdir(mode=0o700)
    env = {'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64', 'PATH': '/usr/bin:/bin', 'HOME': str(out / 'home'),
           'TMPDIR': str(out / 'tmp'), 'LANG': 'C.UTF-8'}
    receipt = {'id': out.name, 'target': target, 'source': args.generation, 'capsule': args.capture, 'passed': False,
               'fullStackQualification': False, 'fullStackCycles': 0, 'sourceStarted': False, 'sourceUnfenced': False,
               'initializerReplay': False, 'publicActivation': False, 'bootEnrollment': False,
               'oracleSourceGeneration': oracle_generation, 'oracleSourceReceiptSha256': oracle_hash,
               'sourceWasRecoveredGeneration': args.recovered_source, 'isolatedStore': args.isolated_store}

    def digest(path):
        with path.open('rb') as stream:
            return hashlib.file_digest(stream, 'sha256').hexdigest()

    def record(name, data):
        with (out / name).open('x') as stream:
            json.dump(data, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())

    def run(label, argv, data=None, expected=0):
        record(label + '.intent.json', {'argvSha256': hashlib.sha256(json.dumps([str(x) for x in argv]).encode()).hexdigest(),
                                      'stdinSha256': hashlib.sha256((data or '').encode()).hexdigest(), 'target': target})
        result = subprocess.run([str(x) for x in argv], input=data, text=True, capture_output=True, env=env, timeout=1200)
        (out / (label + '.stdout')).write_text(result.stdout)
        (out / (label + '.stderr')).write_text(result.stderr)
        record(label + '.result.json', {'exitCode': result.returncode})
        assert result.returncode == expected, label + ' failed; retain private evidence and do not replay mutations'
        return result.stdout.strip()

    def census(label):
        value = json.loads(run(label, ['python3', PLATFORM / 'scripts/inspect-private-fleet.py']))
        result = json.loads((BASE / 'image-acquisition-receipts' / value['id'] / 'receipt.json').read_text())
        assert result['passed']
        record(label + '.json', result)
        return result

    def definitions():
        files = [p for p in CLI.parents[1].rglob('*') if p.is_file()]
        files += [PLATFORM / 'scripts' / name for name in ('test-generation-restore.py', 'application_restore_readback.py',
                  'canonical_provider_readback.py', 'generation_schedule_probe.py', 'install-generation-backup-schedule.py',
                  'install-private-boot-units.py', 'inspect-private-fleet.py', 'probe_receipt.py')]
        return {str(p.relative_to(PLATFORM)): digest(p) for p in sorted(files)}

    def source_metadata():
        paths = [source_group / 'bundle.json']
        if source_ownership is not None:
            paths.append(source_group / 'ownership.intent.json')
        for suffix in kinds:
            name = args.generation + '-' + suffix
            paths += [BASE / 'runtime-deployments' / (name + '.json')]
            paths += list((BASE / 'runtime-deployments' / name).iterdir())
        if args.kopia:
            paths += [p for p in (source_group / 'kopia-store').rglob('*') if p.is_file()]
        return {str(p.relative_to(BASE)): digest(p) for p in paths}

    manifests = {kind: BASE / 'runtime-deployments' / (target + '-' + kind + '.json') for kind in kinds}
    container = lambda kind, role: 'p0v3-live-' + target + '-' + (foundation_kind if kind == 'foundation' else kind) + '-' + role
    def runtime(label, kind, action, *extra):
        return run(label, [CLI, 'runtime', action, manifests[kind], *extra])

    def pg(label, statement):
        return run(label, POD + ['exec', '-i', container('foundation', 'postgres'), 'psql', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-tA'], statement)

    def maria(label, statement, password=True):
        cmd = ('MYSQL_PWD="$MARIADB_ROOT_PASSWORD" ' if password else '') + 'mariadb --socket=/tmp/mysql.sock -u root --batch --skip-column-names'
        return run(label, POD + ['exec', '-i', container('sql-cache', 'mariadb'), '/bin/sh', '-ec', cmd], statement, expected=0 if password else 1)

    def readback(label, historical_message):
        for index, row in enumerate(snapshot_rows):
            if row['value'] is None:
                assert pg(label + '-excluded-' + str(index), "SELECT COUNT(*) FROM p0v3_acceptance.runtime_checks WHERE id='" + row['id'] + "';") == '0'
            else:
                assert pg(label + '-preserved-' + str(index), "SELECT value FROM p0v3_acceptance.runtime_checks WHERE id='" + row['id'] + "';") == row['value']
        if snapshot_rows:
            receipt['postSnapshotDatabaseWriteExcluded'] = True
            receipt['snapshotRowsVerified'] = snapshot_rows
        marker = pg(label + '-pg', "SELECT value FROM p0v3_acceptance.runtime_checks WHERE id='" + original + "';")
        assert re.fullmatch(r'[a-f0-9]{32}', marker)
        value = run(label + '-valkey', POD + ['exec', container('foundation', 'valkey'), '/bin/sh', '-ec',
            'export REDISCLI_AUTH="$(sed -n \'s/^requirepass //p\' /etc/valkey/valkey.conf)"; valkey-cli GET ' + original])
        assert marker == value == historical_message['message']
        rows = run(label + '-ntfy', POD + ['exec', container('foundation', 'ntfy'), 'wget', '-q', '-O', '-',
            'http://127.0.0.1:8080/' + original + '/json?poll=1&since=all'])
        messages = [json.loads(line) for line in rows.splitlines() if line]
        assert any(m.get('id') == historical_message['mid'] and m.get('message') == marker and
                   m.get('time') == historical_message['time'] and m.get('expires') == historical_message['expires'] for m in messages)
        table = 'p0v3_acceptance.probe_' + sql_nonce
        assert maria(label + '-maria', 'SELECT value FROM ' + table + ' WHERE id=1;') == 'committed-' + sql_nonce
        assert maria(label + '-rollback', 'SELECT COUNT(*) FROM ' + table + ';') == '1'
        maria(label + '-password-denied', 'SELECT 1;', False)
        assert maria(label + '-roles', "SELECT COUNT(*) FROM mysql.global_priv WHERE User='' OR (User='root' AND Host<>'localhost');") == '0'

    before = None
    unchanged = None
    target_hash = None
    failure = None
    try:
        before = census('fleet-before')
        unchanged = source_metadata()
        record('source-before.json', unchanged)
        original_definitions = definitions()
        record('implementation.json', original_definitions)
        imported = json.loads(run('import', [CLI, 'release', ('generation-kopia-restore-canonical-core-v2' if args.isolated_store else 'generation-kopia-restore-canonical-core') if args.kopia else ('generation-restore-canonical-core' if args.canonical_core else ('generation-restore-applications' if args.applications else 'generation-restore-foundation')), PLATFORM / 'release/downloaded-candidate-inventory.json',
                                           args.generation, args.bundle, args.capture, target]).splitlines()[0])
        assert imported['passed'] and imported['action'] == 'restore-import'
        target_hash = imported['bundleSha256']
        run('clean-stage-denied', [CLI, 'release', 'generation-stage', target, target_hash], expected=1)
        generation_root = BASE / 'release-generations' / target
        recovered_bundle = json.loads((generation_root / 'recovered/source/bundle.json').read_text())
        target_bundle = json.loads((generation_root / 'bundle.json').read_text())
        assert recovered_bundle.get('ownership') == source_ownership
        assert target_bundle.get('ownership') is None
        if args.kopia:
            snapshot = target_bundle['recoverySourceKopia']
            assert snapshot['id'] == args.capture and snapshot['generation'] == args.generation and snapshot['bundleSha256'] == args.bundle
            assert target_bundle.get('recoverySourceArchiveSha256') is None
            receipt['kopiaSnapshotId'] = snapshot['snapshotId']
            receipt['kopiaRootObjectId'] = snapshot['rootObjectId']
            receipt['nativeKopiaRestore'] = True
        receipt['sourceOwnershipPreservedInAuthenticatedRecovery'] = source_ownership is not None
        receipt['restoreInheritsSiteAuthority'] = False
        ntfy_tar = generation_root / 'recovered' / (args.generation + '-' + foundation_kind) / 'volumes/ntfy.tar'
        with tarfile.open(ntfy_tar, 'r:') as archive:
            member = next(m for m in archive.getmembers() if m.name.removeprefix('./') == 'cache.db')
            assert member.isfile() and member.size < 1048576
            db = sqlite3.connect(':memory:')
            db.deserialize(archive.extractfile(member).read())
            db.row_factory = sqlite3.Row
            rows = db.execute('SELECT mid,message,time,expires FROM messages WHERE topic=?', (original,)).fetchall()
            assert len(rows) == 1
            historical = dict(rows[0]); db.close()
        assert historical['expires'] > time.time(), 'Historical message already expired; do not reset its clock or claim replay'
        for kind in manifests:
            spec = json.loads(manifests[kind].read_text())
            assert all(not p.get('oneShot', False) for p in spec['processes'])
            assert not (manifests[kind].parent / spec['name'] / 'runtime.jobs').exists()
            runtime('release-fresh-' + kind, kind, 'maintenance-leave', imported['fences'][spec['name']])
            states = json.loads(runtime('start-' + kind, kind, 'apply-private').splitlines()[0])
            assert all(s['state'] == 'running' for s in states)
        readback('before-restart', historical)
        if args.applications:
            from application_restore_readback import verify_applications
            receipt['applicationsBeforeRestart'] = verify_applications(BASE, source_receipt, target, out, 'before', run, POD, env)
        # Memcached is deliberately ephemeral: prove native set/get only on this new isolated target.
        network = 'p0v3-live-' + target + '-sql-cache-net'
        def cache(label, write):
            address = run(label + '-address', POD + ['inspect', '--format', '{{(index .NetworkSettings.Networks "' + network + '").IPAddress}}', container('sql-cache', 'memcached')])
            assert ipaddress.ip_address(address).is_private
            request = (b'set restore-fixture 0 0 7\r\nfixture\r\n' if write else b'') + b'get restore-fixture\r\nquit\r\n'
            record(label + '.intent.json', {'target': target, 'write': write})
            with socket.create_connection((address, 11211), timeout=5) as client:
                client.sendall(request)
                output = b''
                while True:
                    part = client.recv(4096)
                    if not part: break
                    output += part
                    assert len(output) < 65536
            assert output == (b'STORED\r\nVALUE restore-fixture 0 7\r\nfixture\r\nEND\r\n' if write else b'END\r\n')
            record(label + '.result.json', {'passed': True})
        cache('cache-initially-empty', False)
        cache('cache-write', True)
        for kind in manifests:
            runtime('stop-' + kind, kind, 'stop-private')
            runtime('restart-' + kind, kind, 'apply-private')
        readback('after-restart', historical)
        if args.applications:
            receipt['applicationsAfterRestart'] = verify_applications(BASE, source_receipt, target, out, 'after', run, POD, env)
        cache('cache-restart-empty', False)
        if args.canonical_core:
            from canonical_provider_readback import verify_provider
            receipt['providerReadback'] = verify_provider(target + '-canonical-core', POD, env)
        if args.rebackup:
            earlier = {'id': 'chain-before-' + nonce, 'value': 'chain-value-' + nonce}
            later = {'id': 'chain-after-' + nonce, 'value': None}
            next_rows = validate_rows(snapshot_rows + [earlier, later])
            pg('chain-before-write', "INSERT INTO p0v3_acceptance.runtime_checks VALUES ('" + earlier['id'] + "','" + earlier['value'] + "'); CHECKPOINT;")
            import_markers = {str(p): digest(p) for kind in kinds for p in
                              (manifests[kind].parent / (target + '-' + kind)).glob('runtime.import.*')}
            assert len(import_markers) == 2 * len(kinds)
            from generation_schedule_probe import exercise
            def scheduled_run(label, argv, expected_code=0):
                return run('rebackup-' + label, argv, expected=expected_code)
            def scheduled_record(path, value):
                assert path.parent == out
                record('rebackup-' + path.name, value)
            renewed, scheduled = exercise(PLATFORM, target, target_hash, PLATFORM / 'release/downloaded-candidate-inventory.json', out,
                                          scheduled_run, scheduled_record)
            assert renewed['passed'] and renewed['sourceResumed'] and renewed['snapshot']['generation'] == target
            assert renewed['snapshot']['bundleSha256'] == target_hash
            assert all(not (manifests[kind].parent / (target + '-' + kind) / 'runtime.jobs').exists() for kind in kinds)
            assert import_markers == {str(p): digest(p) for kind in kinds for p in
                                      (manifests[kind].parent / (target + '-' + kind)).glob('runtime.import.*')}
            assert pg('chain-before-survived-resume', "SELECT value FROM p0v3_acceptance.runtime_checks WHERE id='" + earlier['id'] + "';") == earlier['value']
            readback('after-rebackup', historical)
            receipt['applicationsAfterRebackup'] = verify_applications(BASE, source_receipt, target, out, 'rebackup', run, POD, env)
            pg('chain-after-write', "INSERT INTO p0v3_acceptance.runtime_checks VALUES ('" + later['id'] + "','after-rebackup'); CHECKPOINT;")
            assert pg('chain-after-present', "SELECT value FROM p0v3_acceptance.runtime_checks WHERE id='" + later['id'] + "';") == 'after-rebackup'
            receipt['rebackup'] = {'capture': renewed['snapshot']['id'], 'snapshotId': renewed['snapshot']['snapshotId'], 'rows': next_rows,
                                  'sourceResumed': True, 'initializerLedgerAbsent': True, 'originalImportMarkersUnchanged': True,
                                  'scheduled': scheduled, 'siteAuthorityGranted': False}
            run('clean-stage-still-denied', [CLI, 'release', 'generation-stage', target, target_hash], expected=1)
        assert unchanged == source_metadata()
        assert original_definitions == definitions()
        receipt.update(implementationUnchanged=True, nativeHistoricalPostgresValkeyNtfyReadback=True, ntfyIdTimeExpiryPreserved=True,
                       nativeMariaDbCommittedAndRolledBackState=True, authenticationDeniedWithoutPassword=True,
                       nativeMemcachedEphemeralLifecycle=True, restoredRestartReadback=True, sourceMetadataUnchanged=True,
                       bundleSha256=target_hash, nativeComponentRestoreVerified=True, logicalProducts=7 if args.applications else 5)
    except BaseException as error:
        failure = error
        receipt['failureType'] = type(error).__name__
    finally:
        try:
            bundle_file = BASE / 'release-generations' / target / 'bundle.json'
            if bundle_file.exists():
                target_hash = target_hash or digest(bundle_file)
                prior = bundle_file.parent / 'isolate.intent.json'
                if prior.exists():
                    # The controller already attempted failure isolation. Preserve it and link a stop-only reconciliation.
                    command = [CLI, 'release', 'generation-reconcile-isolation', target, target_hash,
                               'r-' + uuid.uuid4().hex[:12], digest(prior)]
                else:
                    command = [CLI, 'release', 'generation-isolate', target, target_hash]
                isolated = json.loads(run('retire', command).splitlines()[0])
                assert isolated['passed']
                receipt['retainedTargetFences'] = isolated['fences']
            after = census('fleet-after')
            if unchanged is not None:
                observed = source_metadata()
                record('source-after.json', observed)
                assert observed == unchanged
                receipt['sourceMetadataUnchanged'] = True
            if before:
                assert before['deployments'] == after['deployments']
                assert all(after['retainedFenceHashes'].get(name) == value for name, value in before['retainedFenceHashes'].items())
                receipt['protectedFleetAndPriorFencesUnchanged'] = True
            receipt['passed'] = failure is None and receipt.get('nativeComponentRestoreVerified', False)
        except BaseException as error:
            failure = failure or error
            receipt['cleanupFailureType'] = type(error).__name__
        record('receipt.json', receipt)
        print(json.dumps(receipt, indent=2))
    if failure:
        raise SystemExit('Restore failed; retained imports and action intents must not be replayed')


if __name__ == '__main__':
    main()
