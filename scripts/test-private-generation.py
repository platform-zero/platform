#!/usr/bin/env python3
"""Fresh five-service (optionally seven logical products) controller exercise; NOT full-stack qualification.
Never accepts an existing generation/name and never resumes or repeats its workflow writes.
"""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid

PLATFORM = Path(__file__).resolve().parents[1]
CLI = PLATFORM / 'build/install/p0-v3-platform/bin/p0-v3-platform'
RECEIPTS = Path('/mnt/media/p0-v3/image-acquisition-receipts')
RUNTIMES = Path('/mnt/media/p0-v3/runtime-deployments')
GENERATIONS = Path('/mnt/media/p0-v3/release-generations')
PODMAN = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph',
          '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']


def digest(data):
    return hashlib.sha256(data).hexdigest()


def write(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--inventory', type=Path, default=PLATFORM / 'release/downloaded-candidate-inventory.json')
    parser.add_argument('--simulate-interrupted-isolation', action='store_true',
                        help='Inject only an isolation intent in this fresh generation, then reconcile it; no process kill')
    parser.add_argument('--ownership-bound', action='store_true', help='Validate and seal site ownership before fresh credential preparation')
    parser.add_argument('--applications', action='store_true', help='Include fresh Forgejo and Planka; not central database wiring or full-release recovery')
    parser.add_argument('--canonical-core', action='store_true', help='Seven products with one shared PostgreSQL and scoped Planka runtime credentials')
    parser.add_argument('--routine-backup', action='store_true', help='Run controller-owned quiesce/Kopia/resume and a post-snapshot synthetic write')
    parser.add_argument('--backup-kill', action='store_true', help='Kill only this fresh backup controller after quiescence, then reconcile stop-only')
    parser.add_argument('--scheduled-backup', action='store_true', help='Install and observe a pinned daily timer, deduplication and a scoped inventory-failure alert')
    args = parser.parse_args()
    assert not ((args.routine_backup or args.scheduled_backup) and args.backup_kill)
    if args.scheduled_backup:
        args.routine_backup = True
    if args.routine_backup or args.backup_kill:
        args.canonical_core = True
    if args.canonical_core:
        args.applications = True
        args.ownership_bound = True
    os.umask(0o077)
    nonce = uuid.uuid4().hex[:12]
    generation = 'q-' + nonce
    out = RECEIPTS / ('p0v3-generation-' + nonce)
    out.mkdir(mode=0o700)
    (out / 'home').mkdir(mode=0o700)
    (out / 'tmp').mkdir(mode=0o700)
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(out / 'home'), 'TMPDIR': str(out / 'tmp'),
           'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64', 'LANG': 'C.UTF-8'}
    receipt = {'id': out.name, 'generation': generation, 'passed': False,
               'scope': 'fresh-private-seven-product-generation' if args.applications else 'fresh-private-five-service-generation', 'fullStackQualification': False,
               'encryptedRestore': False, 'publicActivation': False, 'bootEnrollment': False, 'canonicalCore': args.canonical_core}
    bundle_hash = None
    before = None
    failure = None

    def run(label, argv, expected_code=0):
        write(out / (label + '.intent.json'), {'argvSha256': digest(json.dumps([str(x) for x in argv]).encode()),
              'generation': generation, 'mayHaveEffects': True, 'replayPermitted': False})
        result = subprocess.run([str(x) for x in argv], capture_output=True, timeout=1200, env=env)
        # These particular tools emit only paths, IDs, digests or sanitized receipts, not credentials.
        with (out / (label + '.stdout')).open('xb') as stream:
            stream.write(result.stdout)
        with (out / (label + '.stderr')).open('xb') as stream:
            stream.write(result.stderr)
        write(out / (label + '.result.json'), {'exitCode': result.returncode,
              'stdoutSha256': digest(result.stdout), 'stderrSha256': digest(result.stderr)})
        assert result.returncode == expected_code, 'Generation exercise phase failed: ' + label
        return result.stdout.decode()

    def census(label):
        summary = json.loads(run(label, ['python3', PLATFORM / 'scripts/inspect-private-fleet.py']))
        assert summary['passed'] and summary['id'].startswith('p0v3-fleet-')
        value = json.loads((RECEIPTS / summary['id'] / 'receipt.json').read_text())
        write(out / (label + '.json'), value)
        return value

    def definitions():
        files = [file for file in CLI.parents[1].rglob('*') if file.is_file()]
        files += [PLATFORM / 'scripts' / name for name in
                  ('test-private-generation.py', 'test-persistent-foundation.py', 'test-persistent-sql-cache.py',
                   'test-persistent-forgejo.py', 'test-persistent-planka.py',
                   'inspect-private-fleet.py', 'probe_receipt.py', 'canonical_provider_readback.py', 'application_restore_readback.py',
                   'routine_backup_fault.py', 'test-import-interruption.py', 'generation_schedule_probe.py',
                   'install-generation-backup-schedule.py', 'install-private-boot-units.py')]
        return {str(file.relative_to(PLATFORM)): digest(file.read_bytes()) for file in sorted(files)}

    try:
        before = census('fleet-before')
        original_definitions = definitions()
        descriptor = {'scope': receipt['scope'], 'inventorySha256': digest(args.inventory.read_bytes()),
                      'implementationFiles': original_definitions,
                      'testConfiguration': {'simulateInterruptedIsolation': args.simulate_interrupted_isolation, 'ownershipBound': args.ownership_bound, 'applications': args.applications, 'canonicalCore': args.canonical_core, 'routineBackup': args.routine_backup, 'backupKill': args.backup_kill, 'scheduledBackup': args.scheduled_backup}}
        write(out / 'candidate.json', descriptor)
        candidate = digest((out / 'candidate.json').read_bytes())
        foundation_kind = 'canonical-core' if args.canonical_core else 'foundation'
        foundation, sql_cache = generation + '-' + foundation_kind, generation + '-sql-cache'
        request = {'schemaVersion': 1, 'id': generation, 'candidateSha256': candidate,
                   'inventorySha256': descriptor['inventorySha256'],
                   'selections': [{'recipe': 'sql-cache', 'dependencies': [foundation_kind]}, {'recipe': foundation_kind}],
                   'diskReservationMiB': 8192}
        if args.applications:
            request['selections'] += [{'recipe': 'forgejo', 'dependencies': [foundation_kind]}]
            if not args.canonical_core:
                request['selections'] += [{'recipe': 'planka', 'dependencies': ['foundation']}]
        names = [generation + '-' + selection['recipe'] for selection in request['selections']]
        expected_daemons = 7 if args.canonical_core else (8 if args.applications else 5)
        write(out / 'request.json', request)
        assembly = json.loads(run('assembly-plan', [CLI, 'release', 'generation-assembly-plan', args.inventory, out / 'request.json']))
        assert {m['recipe'] for m in assembly['members']} == {s['recipe'] for s in request['selections']}
        assert not assembly['globalIntegrationValidated'] and not assembly['fullStackQualification']
        assert {'worklane', 'mastodon-rss-publisher', 'caddy'} <= set(assembly['missingCapabilities'])
        prepare_command = [CLI, 'release', 'generation-prepare', args.inventory, out / 'request.json']
        if args.ownership_bound:
            graph = json.loads(run('ownership-inventory', [CLI, 'release', 'site-ownership-inventory', args.inventory, out / 'request.json']))
            owners = {p['process']: p['compiledProduct'] for p in graph['processes']}
            assert all(owners.values()) and all(i['compiledProduct'] for i in graph['inputs'])
            ownership = {'schemaVersion': 1, 'site': 'owned-foundation-' + nonce, 'assemblySha256': graph['assemblySha256'],
                         'processes': [{'process': p, 'product': owner} for p, owner in owners.items()],
                         'state': [{'volume': s['volume'], 'product': owners[s['writers'][0]], 'recoveryGroup': 'foundation-sql-cohort'} for s in graph['state']],
                         'inputs': [{'input': i['input'], 'product': i['compiledProduct'], 'credential': True, 'consumers': i['consumers']} for i in graph['inputs']],
                         'routes': [{'host': 'ntfy.v3.example.org', 'product': 'ntfy', 'process': foundation + '/ntfy', 'port': 8080}]}
            write(out / 'ownership.json', ownership)
            write(out / 'synthetic-hosts.json', ['ntfy.v3.example.org'])
            write(out / 'invalid-ownership.json', dict(ownership, processes=ownership['processes'][:-1]))
            run('invalid-ownership-denied', [CLI, 'release', 'generation-prepare-owned', args.inventory, out / 'request.json',
                                            out / 'invalid-ownership.json', out / 'synthetic-hosts.json'], expected_code=1)
            assert not (GENERATIONS / generation).exists()
            assert all(not (RUNTIMES / name).exists() and not (RUNTIMES / (name + '.json')).exists() for name in names)
            prepare_command = [CLI, 'release', 'generation-prepare-owned', args.inventory, out / 'request.json',
                               out / 'ownership.json', out / 'synthetic-hosts.json']
        sealed = run('prepare', prepare_command).splitlines()[0].split()
        receipt['typedAssemblyPrepared'] = True
        assert sealed[0] == generation and len(sealed) == 2
        bundle_hash = sealed[1]
        receipt['bundleSha256'] = bundle_hash
        if args.ownership_bound:
            source_bundle = json.loads((GENERATIONS / generation / 'bundle.json').read_text())
            binding = source_bundle['ownership']
            assert binding['contract'] == ownership and set(binding['approvedHosts']) == {'ntfy.v3.example.org'}
            assert source_bundle['assemblySha256'] == ownership['assemblySha256']
            assert json.loads((GENERATIONS / generation / 'ownership.intent.json').read_text()) == binding
            policy_hash = digest((GENERATIONS / generation / 'ownership.intent.json').read_bytes())
            run('owned-preparation-replay-denied', prepare_command, expected_code=1)
            assert digest((GENERATIONS / generation / 'ownership.intent.json').read_bytes()) == policy_hash
            receipt.update(ownershipBoundPreparation=True, invalidOwnershipDeniedBeforeCredentials=True, ownedPreparationReplayDenied=True)
        audit = json.loads(run('pristine-audit', [CLI, 'release', 'generation-audit', generation, bundle_hash]).splitlines()[0])
        assert all(member['existingResources'] == 0 and member['maintenanceId'] is None for member in audit['members'])
        staged = json.loads(run('stage', [CLI, 'release', 'generation-stage', generation, bundle_hash]).splitlines()[0])
        assert staged['passed']
        ledgers = {name: digest((RUNTIMES / name / 'runtime.jobs').read_bytes()) for name in names}
        containers = ['p0v3-live-' + name + '-' + p['id'] for name in names
                      for p in json.loads((RUNTIMES / (name + '.json')).read_text())['processes']]
        ids = run('ids-before', PODMAN + ['container', 'inspect', '--format', '{{.Id}}'] + containers)
        journeys = [('foundation', 'test-persistent-foundation.py', foundation), ('sql-cache', 'test-persistent-sql-cache.py', sql_cache)]
        if args.applications:
            journeys += [('forgejo', 'test-persistent-forgejo.py', generation + '-forgejo'), ('planka', 'test-persistent-planka.py', foundation if args.canonical_core else generation + '-planka')]
        for label, script, name in journeys:
            extra = ['--canonical-core'] if args.canonical_core and label in ('foundation', 'planka') else []
            native = json.loads(run('native-' + label, ['python3', PLATFORM / 'scripts' / script, '--name', name] + extra))
            assert native['passed']
            receipt[label + 'Receipt'] = native['id']
        if args.canonical_core:
            from canonical_provider_readback import verify_provider
            receipt['providerReadback'] = verify_provider(foundation, PODMAN, env)
            write(out / 'provider-readback.json', receipt['providerReadback'])
        if args.routine_backup:
            if args.scheduled_backup:
                from generation_schedule_probe import exercise
                backup, receipt['scheduledBackup'] = exercise(PLATFORM, generation, bundle_hash, args.inventory, out, run, write)
                capture_id = backup['access']['operation']
            else:
                capture_id = 'cap-' + uuid.uuid4().hex[:12]
                backup = json.loads(run('routine-backup', [CLI, 'release', 'generation-kopia-backup', args.inventory,
                                                          generation, bundle_hash, capture_id]).splitlines()[0])
            assert backup['passed'] and backup['sourceResumed'] and backup['access'] == {'generation': generation, 'operation': capture_id, 'bundleSha256': bundle_hash}
            assert backup['snapshot']['id'] == capture_id
            assert all(not (RUNTIMES / name / 'runtime.backup').exists() and not (RUNTIMES / name / 'runtime.maintenance').exists() for name in names)
            from application_restore_readback import verify_applications
            # The same historical oracle is used here as on isolated restored targets; no fixture creation.
            def readback_run(label, command):
                return run(label, command).strip()
            receipt['sourceAfterBackup'] = verify_applications(RUNTIMES.parent, receipt, generation, out, 'source-after-backup', readback_run, PODMAN, env)
            row = 'post-' + nonce
            sql = "INSERT INTO p0v3_acceptance.runtime_checks VALUES ('" + row + "','after-kopia-snapshot'); CHECKPOINT;"
            run('post-snapshot-write', PODMAN + ['exec', 'p0v3-live-' + foundation + '-postgres', 'psql', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', '-c', sql])
            observed = run('post-snapshot-readback', PODMAN + ['exec', 'p0v3-live-' + foundation + '-postgres', 'psql', '-U', 'postgres', '-tAc',
                           "SELECT value FROM p0v3_acceptance.runtime_checks WHERE id='" + row + "'"]).strip()
            assert observed == 'after-kopia-snapshot'
            receipt.update(routineBackupCapture=capture_id, routineBackupSnapshotId=backup['snapshot']['snapshotId'],
                           routineBackupSourceResumed=True, routineBackupLeasesReleased=True, postSnapshotRow=row)
        if args.backup_kill:
            from routine_backup_fault import exercise
            receipt['backupInterruption'] = exercise(generation, bundle_hash, out, CLI, args.inventory, PODMAN, env, run, write)
        assert ids == run('ids-after', PODMAN + ['container', 'inspect', '--format', '{{.Id}}'] + containers)
        assert ledgers == {name: digest((RUNTIMES / name / 'runtime.jobs').read_bytes()) for name in names}
        running = json.loads(run('running-audit', [CLI, 'release', 'generation-audit', generation, bundle_hash]).splitlines()[0])
        assert sum(p['state'] == 'running' for m in running['members'] for p in m['statuses']) == (0 if args.backup_kill else expected_daemons)
        assert original_definitions == definitions()
        receipt.update(nativeWorkflowsPassed=True, fiveDaemonsObserved=expected_daemons == 5, observedRunningDaemons=0 if args.backup_kill else expected_daemons,
                       logicalProducts=7 if args.applications else 5, initializerLedgersUnchanged=True,
                       containerIdentitiesPreserved=True, implementationUnchanged=True)
    except BaseException as error:
        failure = error
        receipt['failureType'] = type(error).__name__
    finally:
        try:
            if bundle_hash:
                root = GENERATIONS / generation
                outcome_path = root / 'isolate.result.json'
                if args.simulate_interrupted_isolation and failure is None:
                    # Scoped fault simulation, not an actual crash or whole-release interruption test.
                    # lockf uses the same POSIX record-lock domain as Java FileChannel.lock.
                    with (GENERATIONS / 'generation.lock').open('r+b') as lock:
                        fcntl.lockf(lock, fcntl.LOCK_EX)
                        write(root / 'isolate.intent.json', {'action': 'isolate', 'bundleSha256': bundle_hash,
                                                           'priorIntentSha256': None})
                    original = (root / 'isolate.intent.json').read_bytes()
                    prior_hash = digest(original)
                    write(out / 'simulated-boundary.json', {'scope': generation, 'processKilled': False,
                          'boundary': 'isolation-intent-before-first-effect', 'intentSha256': prior_hash})
                    run('isolate-replay-denied', [CLI, 'release', 'generation-isolate', generation, bundle_hash], expected_code=1)
                    reconciliation = 'r-' + uuid.uuid4().hex[:12]
                    run('reconcile-isolation', [CLI, 'release', 'generation-reconcile-isolation', generation,
                                               bundle_hash, reconciliation, prior_hash])
                    assert original == (root / 'isolate.intent.json').read_bytes()
                    assert not (root / 'isolate.result.json').exists()
                    outcome_path = root / ('isolate-reconcile-' + reconciliation + '.result.json')
                    receipt.update(simulatedIsolationBoundaryReconciled=True, originalPendingIntentUnchanged=True,
                                   actualProcessInterruptionTest=False)
                elif not (root / 'isolate.intent.json').exists():
                    run('isolate', [CLI, 'release', 'generation-isolate', generation, bundle_hash])
                outcome = json.loads(outcome_path.read_text())
                assert outcome['passed'] and outcome['bundleSha256'] == bundle_hash
                stopped = json.loads(run('stopped-audit', [CLI, 'release', 'generation-audit', generation, bundle_hash]).splitlines()[0])
                assert all(m['maintenanceId'] == outcome['fences'][m['name']] and
                           all(p['state'] in ('exited', 'completed', 'absent') for p in m['statuses']) for m in stopped['members'])
                receipt['retainedStoppedFences'] = outcome['fences']
            after = census('fleet-after')
            if before:
                assert before['deployments'] == after['deployments'], 'Protected fleet identities/start times changed'
                assert all(after['retainedFenceHashes'].get(k) == v for k, v in before['retainedFenceHashes'].items())
                receipt.update(protectedFleetUnchanged=True, retainedOriginalFencesUnchanged=True)
            receipt['passed'] = failure is None and receipt.get('nativeWorkflowsPassed', False) and bool(bundle_hash)
        except BaseException as error:
            receipt['cleanupFailureType'] = type(error).__name__
            failure = failure or error
        write(out / 'receipt.json', receipt)
    print(json.dumps(receipt, indent=2))
    if failure:
        raise SystemExit('Generation exercise failed; preserve all intents and reconcile the fresh namespace')


if __name__ == '__main__':
    main()
