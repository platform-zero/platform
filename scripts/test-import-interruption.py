#!/usr/bin/env python3
"""Inject scoped process loss or candidate-input corruption into a fresh import; never mutate or start the source."""
if not __debug__:
    raise SystemExit('Optimized execution refused before effects')
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import uuid

BASE = Path('/mnt/media/p0-v3')
PLATFORM = Path(__file__).resolve().parents[1]
CLI = PLATFORM / 'build/install/p0-v3-platform/bin/p0-v3-platform'


def process_state(pid):
    try:
        fields = Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()
        return {'pid': pid, 'state': fields[0], 'startTicks': fields[19]}
    except FileNotFoundError:
        return None


def descendants(pid):
    found = {}
    todo = [pid]
    while todo:
        parent = todo.pop()
        try:
            children = Path('/proc', str(parent), 'task', str(parent), 'children').read_text().split()
        except FileNotFoundError:
            continue
        for value in children:
            child = int(value)
            if child not in found:
                state = process_state(child)
                if state:
                    found[child] = state
                    todo.append(child)
            assert len(found) <= 32, 'Unexpected controller descendant population; do not signal other processes'
    return list(found.values())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--generation', required=True)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--capture', required=True)
    parser.add_argument('--fault', choices=('kill', 'tamper'), default='kill')
    parser.add_argument('--applications', action='store_true', help='Exercise four-member application restore isolation')
    parser.add_argument('--canonical-core', action='store_true')
    parser.add_argument('--kopia', action='store_true')
    parser.add_argument('--isolated-store', action='store_true')
    args = parser.parse_args()
    assert not args.isolated_store or args.kopia
    if args.kopia:
        args.canonical_core = True
    foundation_kind = 'canonical-core' if args.canonical_core else 'foundation'
    kinds = ('canonical-core', 'sql-cache', 'forgejo') if args.canonical_core else (('foundation', 'sql-cache', 'forgejo', 'planka') if args.applications else ('foundation', 'sql-cache'))
    assert re.fullmatch(r'q-[a-f0-9]{12}', args.generation)
    assert re.fullmatch(r'[a-f0-9]{64}', args.bundle)
    assert re.fullmatch(r'cap-[a-f0-9]{12}', args.capture)
    os.umask(0o077)
    nonce = uuid.uuid4().hex[:12]
    target = 'q-' + nonce
    out = BASE / 'image-acquisition-receipts' / ('p0v3-import-interruption-' + nonce)
    out.mkdir(mode=0o700)
    for name in ('home', 'tmp'):
        (out / name).mkdir(mode=0o700)
    env = {'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64', 'PATH': '/usr/bin:/bin', 'HOME': str(out / 'home'),
           'TMPDIR': str(out / 'tmp'), 'LANG': 'C.UTF-8'}
    control = BASE / 'release-generations' / target
    member = target + '-' + foundation_kind
    runtime = BASE / 'runtime-deployments' / member
    receipt = {'id': out.name, 'source': args.generation, 'target': target, 'passed': False, 'fault': args.fault,
               'actualControllerProcessKill': False, 'hostPowerLossTest': False, 'functionalRestoreVerified': False,
               'sourceStarted': False, 'sourceUnfenced': False, 'fullStackCycles': 0, 'isolatedStore': args.isolated_store}

    def digest(path):
        with path.open('rb') as stream:
            return hashlib.file_digest(stream, 'sha256').hexdigest()

    def record(name, value):
        with (out / name).open('x') as stream:
            json.dump(value, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())

    def run(label, argv, expected=0):
        record(label + '.intent.json', {'argvSha256': hashlib.sha256(json.dumps([str(x) for x in argv]).encode()).hexdigest(), 'target': target})
        result = subprocess.run([str(x) for x in argv], capture_output=True, timeout=600, env=env)
        (out / (label + '.stdout')).write_bytes(result.stdout)
        (out / (label + '.stderr')).write_bytes(result.stderr)
        record(label + '.result.json', {'exitCode': result.returncode})
        assert result.returncode == expected, label + ' failed; retain all pending intents'
        return result.stdout.decode()

    def census(label):
        output = json.loads(run(label, ['python3', PLATFORM / 'scripts/inspect-private-fleet.py']))
        value = json.loads((BASE / 'image-acquisition-receipts' / output['id'] / 'receipt.json').read_text())
        assert value['passed']
        record(label + '.json', value)
        return value

    def source_metadata():
        source_root = BASE / 'release-generations' / args.generation
        paths = [source_root / 'bundle.json']
        if (source_root / 'ownership.intent.json').exists():
            paths.append(source_root / 'ownership.intent.json')
        for kind in kinds:
            name = args.generation + '-' + kind
            paths += [BASE / 'runtime-deployments' / (name + '.json')]
            paths += list((BASE / 'runtime-deployments' / name).iterdir())
        if args.kopia:
            paths += [p for p in (source_root / 'kopia-store').rglob('*') if p.is_file()]
        return {str(p.relative_to(BASE)): digest(p) for p in paths}

    command = [CLI, 'release', ('generation-kopia-restore-canonical-core-v2' if args.isolated_store else 'generation-kopia-restore-canonical-core') if args.kopia else ('generation-restore-canonical-core' if args.canonical_core else ('generation-restore-applications' if args.applications else 'generation-restore-foundation')), PLATFORM / 'release/downloaded-candidate-inventory.json',
               args.generation, args.bundle, args.capture, target]
    process = None
    before = None
    original = None
    failure = None
    stopped = False
    settled = False
    try:
        before = census('fleet-before')
        original = source_metadata()
        record('source-before.json', original)
        record('implementation.json', {str(p.relative_to(CLI.parents[1])): digest(p) for p in CLI.parents[1].rglob('*') if p.is_file()})
        record('runner.json', {'path': str(Path(__file__).resolve()), 'sha256': digest(Path(__file__).resolve())})
        record('import.intent.json', {'target': target, 'source': args.generation, 'capsule': args.capture,
                                    'boundary': 'first imported volume re-export, before member completion'})
        with (out / 'import.stdout').open('xb') as stdout, (out / 'import.stderr').open('xb') as stderr:
            process = subprocess.Popen([str(x) for x in command], stdout=stdout, stderr=stderr, env=env)
            launched = process_state(process.pid)
            record('controller.json', launched)
            deadline = time.monotonic() + 600
            boundary = control / ('verify-' + member) / 'postgres.tar'
            while not boundary.exists():
                assert process.poll() is None, 'Controller exited before the intended boundary'
                assert time.monotonic() < deadline, 'Import boundary timed out'
                time.sleep(0.005)
            assert process.poll() is None and process_state(process.pid)['startTicks'] == launched['startTicks']
            record('stop-controller.intent.json', {'pid': process.pid, 'startTicks': launched['startTicks'], 'signal': 'SIGSTOP'})
            process.send_signal(signal.SIGSTOP)
            stopped = True
            deadline = time.monotonic() + 10
            while process_state(process.pid)['state'] not in ('T', 't'):
                assert time.monotonic() < deadline
                time.sleep(0.01)
            assert (runtime / 'runtime.import.intent').exists()
            assert not (runtime / 'runtime.import.complete').exists(), 'Boundary missed; do not relabel a completed import as interrupted'
            assert not (control / 'stage.result.json').exists()
            pending = {str(p.relative_to(BASE)): digest(p) for p in (control / 'stage.intent.json', runtime / 'runtime.import.intent')}
            record('pending-intents.json', pending)
            record('descendants-at-stop.json', descendants(process.pid))
            # Do not kill rootful children. Let the bounded in-flight command settle while the JVM cannot issue another command.
            deadline = time.monotonic() + 180
            while True:
                children = descendants(process.pid)
                if all(child['state'] == 'Z' for child in children):
                    settled = True
                    break
                assert time.monotonic() < deadline, 'Observed native child has not settled; isolation is not yet conclusive'
                time.sleep(0.05)
            record('descendants-before-kill.json', children)
            if args.fault == 'kill':
                record('kill-controller.intent.json', {'pid': process.pid, 'startTicks': launched['startTicks'], 'signal': 'SIGKILL'})
                process.kill()
                assert process.wait(timeout=30) == -signal.SIGKILL
                receipt['actualControllerProcessKill'] = True
            else:
                # Change only this candidate's future input, never the source capsule or original deployment.
                assert not (boundary.parent / 'valkey.tar').exists(), 'Missed early boundary; do not tamper with a potentially consumed later input'
                scratch = control / 'recovered' / (args.generation + '-' + foundation_kind) / 'volumes/ntfy.tar'
                expected_manifest = json.loads((control / 'recovered/manifest.json').read_text())
                declaration = next(f for f in expected_manifest['files'] if f['name'] == args.generation + '-' + foundation_kind + '/volumes/ntfy.tar')
                assert digest(scratch) == declaration['sha256']
                record('tamper.intent.json', {'target': str(scratch.relative_to(BASE)), 'beforeSha256': digest(scratch), 'sourceMutation': False})
                with scratch.open('ab') as stream:
                    stream.write(b'\x00'); stream.flush(); os.fsync(stream.fileno())
                record('tamper.result.json', {'afterSha256': digest(scratch)})
                assert digest(scratch) != declaration['sha256']
                record('continue-controller.intent.json', {'pid': process.pid, 'startTicks': launched['startTicks'], 'signal': 'SIGCONT'})
                process.send_signal(signal.SIGCONT)
                stopped = False
                assert process.wait(timeout=600) == 1
                failed = json.loads((control / 'stage.result.json').read_text())
                isolation = json.loads((control / 'isolate.result.json').read_text())
                assert not failed['passed'] and failed['action'] == 'restore-import'
                assert isolation['passed'] and set(isolation['fences']) == {target + '-' + kind for kind in kinds}
                record('controller-isolation.json', isolation)
                receipt['controllerOwnedFailureIsolationVerified'] = True
                receipt['controlledScratchTamperRejected'] = True
                receipt['originalIsolationSha256'] = digest(control / 'isolate.result.json')
            stopped = False
        receipt['observedNativeChildrenSettledAtBoundary'] = settled
        assert not (runtime / 'runtime.import.complete').exists()
        if args.fault == 'kill':
            assert not (control / 'stage.result.json').exists()
        run('startup-denied', [CLI, 'runtime', 'apply-private', BASE / 'runtime-deployments' / (member + '.json')], expected=1)
        fence_file = runtime / 'runtime.maintenance'
        if fence_file.exists():
            fence = json.loads(fence_file.read_text())
            run('release-denied', [CLI, 'runtime', 'maintenance-leave', BASE / 'runtime-deployments' / (member + '.json'), fence['id']], expected=1)
        run('import-replay-denied', command, expected=1)
        bundle_hash = digest(control / 'bundle.json')
        run('clean-stage-denied', [CLI, 'release', 'generation-stage', target, bundle_hash], expected=1)
        assert all(digest(BASE / path) == value for path, value in pending.items())
        receipt.update(pendingIntentsUnchanged=True, importReplayDenied=True, startupDenied=True, cleanStageDenied=True,
                       bundleSha256=bundle_hash, incompleteImportCompletionAbsent=True, cohortMembers=len(kinds))
    except BaseException as error:
        failure = error
        receipt['failureType'] = type(error).__name__
    finally:
        try:
            if process is not None and process.poll() is None:
                # Signal only the child we launched. Never signal a host-wide process group or rootful descendants.
                process.kill()
                process.wait(timeout=30)
                receipt['emergencyControllerTermination'] = True
            if not settled and (stopped or receipt.get('emergencyControllerTermination')):
                raise RuntimeError('Native descendants were not proven settled; retain pending scope without claiming safe reconciliation')
            if (control / 'bundle.json').exists():
                bundle_hash = digest(control / 'bundle.json')
                prior = control / 'isolate.intent.json'
                isolation = [CLI, 'release', 'generation-isolate', target, bundle_hash] if not prior.exists() else [
                    CLI, 'release', 'generation-reconcile-isolation', target, bundle_hash, 'r-' + uuid.uuid4().hex[:12], digest(prior)]
                result = json.loads(run('isolate', isolation).splitlines()[0])
                assert result['passed']
                audit = json.loads(run('audit-after-isolation', [CLI, 'release', 'generation-audit', target, bundle_hash]).splitlines()[0])
                assert all(all(s['state'] == 'absent' for s in m['statuses']) for m in audit['members'])
                receipt['retainedTargetFences'] = result['fences']
                receipt['noTargetDaemonEverCreated'] = True
                if args.fault == 'kill':
                    assert not (control / 'stage.result.json').exists(), 'Unknown import result must remain unknown'
                elif receipt.get('controllerOwnedFailureIsolationVerified'):
                    assert digest(control / 'isolate.result.json') == receipt['originalIsolationSha256']
                    assert not json.loads((control / 'stage.result.json').read_text())['passed']
            after = census('fleet-after')
            if before:
                assert before['deployments'] == after['deployments']
                assert all(after['retainedFenceHashes'].get(k) == v for k, v in before['retainedFenceHashes'].items())
                receipt['protectedFleetAndPriorFencesUnchanged'] = True
            if original is not None:
                observed = source_metadata()
                record('source-after.json', observed)
                assert observed == original
                receipt['sourceMetadataUnchanged'] = True
            receipt['passed'] = failure is None and (receipt.get('actualControllerProcessKill', False) or receipt.get('controlledScratchTamperRejected', False))
        except BaseException as error:
            failure = failure or error
            receipt['cleanupFailureType'] = type(error).__name__
        record('receipt.json', receipt)
        print(json.dumps(receipt, indent=2))
    if failure:
        raise SystemExit('Interruption proof failed; preserve unknown outcomes and do not replay or start the target')


if __name__ == '__main__':
    main()
