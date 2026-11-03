#!/usr/bin/env python3
"""Read-only capacity observation plus a fresh restore request that MUST be rejected before namespace allocation.
Run only against an already observed zero-free-lock dedicated store; never fills a store or removes retained objects.
"""
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
POD = ['sudo', '-n', 'podman', '--remote=false', '--root=' + str(BASE / 'release-runtime/graph'),
       '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=' + str(BASE / 'release-runtime/network-config')]
CLI = PLATFORM / 'build/install/p0-v3-platform/bin/p0-v3-platform'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source'); parser.add_argument('bundle'); parser.add_argument('capture')
    args = parser.parse_args()
    assert re.fullmatch(r'q-[a-f0-9]{12}', args.source) and re.fullmatch(r'[a-f0-9]{64}', args.bundle)
    assert re.fullmatch(r'cap-[a-f0-9]{12}', args.capture)
    os.umask(0o077)
    env = {**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'}
    target = 'q-' + uuid.uuid4().hex[:12]
    out = BASE / 'image-acquisition-receipts' / ('p0v3-lock-admission-' + target[2:]); out.mkdir(mode=0o700)
    def record(name, value):
        with (out / name).open('x') as stream:
            json.dump(value, stream, indent=2); stream.flush(); os.fsync(stream.fileno())
    def observation():
        info = json.loads(subprocess.check_output(POD + ['info', '--format', 'json']))
        assert info['store']['graphRoot'] == str(BASE / 'release-runtime/graph')
        assert info['store']['runRoot'] == '/run/p0-v3-release-runtime/store'
        return {'freeLocks': info['host']['freeLocks'],
                'containers': subprocess.check_output(POD + ['ps', '-aq'], text=True).split(),
                'volumes': subprocess.check_output(POD + ['volume', 'ls', '-q'], text=True).split()}
    before = observation(); assert before['freeLocks'] == 0, 'This probe never manufactures exhaustion'
    record('before.json', before)
    receipt = {'id': out.name, 'source': args.source, 'target': target, 'passed': False,
               'scope': 'lock-capacity-refusal-only', 'fullStackQualification': False}
    target_root = BASE / 'release-generations' / target
    command = [str(x) for x in [CLI, 'release', 'generation-kopia-restore-canonical-core',
               PLATFORM / 'release/downloaded-candidate-inventory.json', args.source, args.bundle, args.capture, target]]
    record('request.intent.json', {'target': target, 'argvSha256': hashlib.sha256(json.dumps(command).encode()).hexdigest()})
    try:
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=1200)
        (out / 'request.stdout').write_text(result.stdout); (out / 'request.stderr').write_text(result.stderr)
        assert result.returncode == 1 and 'InsufficientRuntimeLocks' in result.stderr
        assert not target_root.exists()
        assert not list((BASE / 'runtime-deployments').glob(target + '*'))
        after = observation(); record('after.json', after)
        assert before == after
        receipt.update(passed=True, typedCapacityDenial=True, targetNamespaceNotCreated=True, runtimeObjectsUnchanged=True,
                       observedFreeLocks=0, retainedContainers=len(before['containers']), retainedVolumes=len(before['volumes']))
    finally:
        if (target_root / 'bundle.json').exists():
            # Unexpected external capacity changes must not leave a newly accepted target without a retirement attempt.
            digest = hashlib.sha256((target_root / 'bundle.json').read_bytes()).hexdigest()
            prior = target_root / 'isolate.intent.json'
            command = [str(CLI), 'release', 'generation-isolate', target, digest]
            if prior.exists():
                command = [str(CLI), 'release', 'generation-reconcile-isolation', target, digest,
                           'r-' + uuid.uuid4().hex[:12], hashlib.sha256(prior.read_bytes()).hexdigest()]
            result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=1200)
            (out / 'unexpected-target-retirement.stdout').write_text(result.stdout)
            (out / 'unexpected-target-retirement.stderr').write_text(result.stderr)
            assert result.returncode == 0
        record('receipt.json', receipt)
        print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
