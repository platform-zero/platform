#!/usr/bin/env python3
"""Check durable initialization and identity state across the real private runtime lifecycle.
Does not enroll the real owner's TOTP or publish any endpoint.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

P = ['sudo', '-n', 'podman', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store',
     '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
CLI = Path(__file__).resolve().parents[1] / 'build/install/p0-v3-platform/bin/p0-v3-platform'


def command(args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=180,
                            env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
    if result.returncode:
        raise RuntimeError('Private identity lifecycle command failed; inspect owned resources')
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='identity-r2')
    name = parser.parse_args().name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    base = Path('/mnt/media/p0-v3/runtime-deployments')
    manifest = base / (name + '.json')
    spec = json.loads(manifest.read_text())
    assert spec['name'] == name
    init = next(p for p in spec['processes'] if p['id'] == 'identity-db-init')
    assert init['oneShot']
    container = lambda role: 'p0v3-live-' + name + '-' + role
    runtime = lambda action: json.loads(command([str(CLI), 'runtime', action, str(manifest)]).splitlines()[0])
    query = lambda: command(P + ['exec', container('postgres'), 'psql', '-U', 'postgres', '-d', 'keycloak', '-tAc',
        "SELECT u.id || ':' || a.required_action FROM user_entity u JOIN user_required_action a ON a.user_id=u.id WHERE u.username='owner' ORDER BY a.required_action"])
    run_id = 'p0v3-persistent-identity-' + uuid.uuid4().hex[:12]
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / run_id
    directory.mkdir(mode=0o700)
    receipt = {'id': run_id, 'scope': 'persistent-private-identity-not-full-stack', 'passed': False, 'deployment': name}
    try:
        runtime('apply-private')
        before = query()
        assert {line.split(':')[1] for line in before.splitlines()} == {'UPDATE_PASSWORD', 'CONFIGURE_TOTP'}
        journal = json.loads((base / name / 'runtime.jobs').read_text())
        assert 'identity-db-init' in journal['completed']
        job = container('identity-db-init')
        exists = subprocess.run(P + ['container', 'exists', job], capture_output=True, timeout=20).returncode
        assert exists in (0, 1)
        if exists == 0:
            obj = json.loads(command(P + ['container', 'inspect', job]))[0]
            labels = obj['Config']['Labels']
            assert labels['io.p0v3.private-deployment'] == name
            assert labels['io.p0v3.runtime-fingerprint'] == journal['fingerprint']
            assert obj['Image'] == init['imageId'] and obj['State']['Status'] == 'exited' and obj['State']['ExitCode'] == 0
            command(P + ['rm', job])  # Completed helper only, never a daemon or volume.
        runtime('stop-private')
        statuses = runtime('apply-private')
        assert next(p for p in statuses if p['id'] == 'identity-db-init')['state'] == 'completed'
        assert before == query()
        assert subprocess.run(P + ['container', 'exists', job], capture_output=True, timeout=20).returncode == 1
        receipt.update(passed=True, completedJobNotReplayed=True, ownerIdentityPreserved=True,
                       mandatoryPasswordAndTotpPreserved=True, cleanStopRestartVerified=True,
                       browserJourney=False, encryptedRestoreTest=False)
        print(json.dumps(receipt, indent=2))
    finally:
        fd = os.open(directory / 'receipt.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as out:
            json.dump(receipt, out, indent=2)
            out.flush()
            os.fsync(out.fileno())


if __name__ == '__main__':
    main()
