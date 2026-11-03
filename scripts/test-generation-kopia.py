#!/usr/bin/env python3
"""Native Kopia capture of an already stopped canonical cohort. Never starts/unfences a source."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

BASE = Path('/mnt/media/p0-v3')
PLATFORM = Path(__file__).resolve().parents[1]
CLI = PLATFORM / 'build/install/p0-v3-platform/bin/p0-v3-platform'
POD = ['sudo', '-n', 'podman', '--remote=false', '--root=' + str(BASE / 'release-runtime/graph'),
       '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=' + str(BASE / 'release-runtime/network-config')]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--generation', required=True)
    parser.add_argument('--bundle', required=True)
    args = parser.parse_args()
    assert re.fullmatch(r'q-[a-f0-9]{12}', args.generation)
    assert re.fullmatch(r'[a-f0-9]{64}', args.bundle)
    os.umask(0o077)
    nonce = uuid.uuid4().hex[:12]
    capture = 'cap-' + nonce
    out = BASE / 'image-acquisition-receipts' / ('p0v3-kopia-capture-' + nonce)
    out.mkdir(mode=0o700)
    for name in ('home', 'tmp'): (out / name).mkdir(mode=0o700)
    env = {'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64', 'PATH': '/usr/bin:/bin', 'HOME': str(out / 'home'), 'TMPDIR': str(out / 'tmp'), 'LANG': 'C.UTF-8'}
    receipt = {'id': out.name, 'generation': args.generation, 'bundleSha256': args.bundle, 'captureId': capture,
               'passed': False, 'sourceStarted': False, 'sourceUnfenced': False, 'functionalRestoreVerified': False,
               'fullStackQualification': False, 'publicActivation': False, 'scheduledBackup': False}
    def digest(path):
        with path.open('rb') as f: return hashlib.file_digest(f, 'sha256').hexdigest()
    def record(name, value):
        with (out / name).open('x') as f:
            json.dump(value, f, indent=2); f.flush(); os.fsync(f.fileno())
    def run(label, command, expected=0):
        record(label + '.intent.json', {'argvSha256': hashlib.sha256(json.dumps([str(x) for x in command]).encode()).hexdigest(), 'replayPermitted': False})
        r = subprocess.run([str(x) for x in command], capture_output=True, env=env, timeout=1200)
        (out / (label + '.stdout')).write_bytes(r.stdout); (out / (label + '.stderr')).write_bytes(r.stderr)
        record(label + '.result.json', {'exitCode': r.returncode})
        assert r.returncode == expected, label + ' failed; preserve repository, custody and pending intents'
        return r.stdout.decode()
    def census(label):
        result = json.loads(run(label, ['python3', PLATFORM / 'scripts/inspect-private-fleet.py']))
        value = json.loads((BASE / 'image-acquisition-receipts' / result['id'] / 'receipt.json').read_text())
        assert value['passed']; record(label + '.json', value); return value
    source_root = BASE / 'release-generations' / args.generation
    assert digest(source_root / 'bundle.json') == args.bundle
    bundle = json.loads((source_root / 'bundle.json').read_text())
    assert {p['spec']['name'] for p in bundle['members']} == {args.generation + '-' + k for k in ('canonical-core', 'sql-cache', 'forgejo')}
    def metadata():
        paths = [source_root / 'bundle.json', source_root / 'ownership.intent.json']
        for pin in bundle['members']:
            name = pin['spec']['name']; paths += [BASE / 'runtime-deployments' / (name + '.json')]
            paths += list((BASE / 'runtime-deployments' / name).iterdir())
        return {str(p.relative_to(BASE)): digest(p) for p in paths}
    before = None
    original = None
    failure = None
    try:
        before = census('fleet-before'); original = metadata(); record('source-before.json', original)
        record('implementation.json', {str(p.relative_to(CLI.parents[1])): digest(p) for p in CLI.parents[1].rglob('*') if p.is_file()})
        record('runner.json', {'sha256': digest(Path(__file__).resolve())})
        store_root = source_root / 'kopia-store'
        custody_file = BASE / 'kopia-custody' / (args.generation + '.env')
        retained = {str(p): digest(p) for p in [store_root / 'repository.binding.json', store_root / 'initialize.scope.json', store_root / 'initialize.intent.json', store_root / 'initialize.result.json', custody_file]} if store_root.exists() else None
        command = [CLI, 'release', 'generation-kopia-capture', PLATFORM / 'release/downloaded-candidate-inventory.json', args.generation, args.bundle, capture]
        result = json.loads(run('capture', command).splitlines()[0]); assert result['passed']
        snapshot = result['snapshot']; assert snapshot['id'] == capture and snapshot['generation'] == args.generation and snapshot['bundleSha256'] == args.bundle
        root = source_root / 'kopia-captures' / capture
        assert not (root / 'payload').exists() and not (root / 'state.cap').exists() and not list(root.glob('*.tar'))
        assert not (source_root / 'kopia-store/snapshot.pending.json').exists()
        assert json.loads((root / 'snapshot.complete.json').read_text()) == snapshot
        run('capture-replay-denied', command, 1)
        wrong = out / 'wrong.env'; wrong.write_text('KOPIA_PASSWORD=wrong-' + nonce + '\n')
        repository = source_root / 'kopia-store/repository'
        # Independent native client: no original source or original custody/configuration mount.
        denied = POD + ['run', '--rm', '--name=p0v3-kopia-denial-' + nonce, '--pull=never', '--network=none', '--read-only', '--cap-drop=all',
            '--security-opt=no-new-privileges', '--security-opt=apparmor=p0v3-private-v1', '--user=' + str(os.getuid()) + ':' + str(os.getgid()),
            '--memory=1024m', '--pids-limit=128', '--image-volume=ignore', '--tmpfs=/tmp:rw,nosuid,nodev,size=128m',
            '--env=HOME=/tmp', '--env=KOPIA_CACHE_DIRECTORY=/tmp/cache', '--env-file=' + str(wrong), '--volume=' + str(repository) + ':/repository:ro',
            snapshot['image'], '--config-file=/tmp/repository.config', '--disable-file-logging', 'repository', 'connect', 'filesystem', '--path=/repository', '--readonly', '--no-check-for-updates']
        run('wrong-password-denied', denied, 1)
        assert b'invalid repository password' in (out / 'wrong-password-denied.stderr').read_bytes().lower()
        assert original == metadata()
        if retained is not None:
            assert retained == {path: digest(Path(path)) for path in retained}
            receipt['existingRepositoryAndCustodyReusedWithoutInitialization'] = True
        receipt.update(nativeKopiaSnapshot=True, snapshotId=snapshot['snapshotId'], rootObjectId=snapshot['rootObjectId'],
            plaintextBytes=snapshot['plaintextBytes'], files=snapshot['files'], plaintextStagingRemoved=True,
            wrongRepositoryPasswordDenied=True, captureReplayDenied=True, sourceMetadataUnchanged=True)
    except BaseException as error:
        failure = error; receipt['failureType'] = type(error).__name__
    finally:
        try:
            after = census('fleet-after')
            if before:
                assert before['deployments'] == after['deployments'] and before['retainedFenceHashes'] == after['retainedFenceHashes']
                receipt['protectedFleetAndAllFencesUnchanged'] = True
            if original is not None: assert original == metadata()
            receipt['passed'] = failure is None and receipt.get('nativeKopiaSnapshot', False)
        except BaseException as error:
            failure = failure or error; receipt['finalCheckFailureType'] = type(error).__name__
        record('receipt.json', receipt)
    print(json.dumps(receipt, indent=2))
    if failure: raise SystemExit('Kopia capture failed; retain all evidence and uncertain operations')


if __name__ == '__main__': main()
