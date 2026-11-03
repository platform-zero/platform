#!/usr/bin/env python3
"""Durable maintenance/boot refusal on a new disposable private SFU; never changes existing units."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/media/p0-v3/runtime-deployments')
CLI = ROOT / 'platform/build/install/p0-v3-platform/bin/p0-v3-platform'
ENV = {**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'}
OLD = Path('/mnt/media/p0-v3/runtime-supervision/releases/60aee905f1ae5bfad60f9a70f7e6c0d08c0da23c1fb008e364c389d3e60ba3d6/bin/p0-v3-platform')


def main():
    nonce = uuid.uuid4().hex[:12]; name = 'fence-' + nonce
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-maintenance-' + nonce)
    directory.mkdir(mode=0o700)
    manifest = BASE / (name + '.json'); unit = 'p0v3-private-' + name + '.service'
    assert not manifest.exists() and not (BASE / name).exists() and not (Path('/etc/systemd/system') / unit).exists()
    receipt = {'id': directory.name, 'deployment': name, 'passed': False, 'fullStackAcceptance': False,
               'scope': 'private-controller-maintenance-not-global-write-freeze', 'hostRebootTest': False}
    enrolled = False

    def run(args, succeeds=True):
        result = subprocess.run(list(map(str, args)), capture_output=True, env=ENV, timeout=1200)
        if succeeds:
            assert result.returncode == 0, 'Maintenance probe operation failed; diagnostic deployment retained'
        else:
            assert result.returncode != 0, 'Fenced startup unexpectedly succeeded'
        return result.stdout

    def runtime(action, *args, succeeds=True): return run([CLI, 'runtime', action, manifest, *args], succeeds)
    def states(): return json.loads(runtime('status-private').splitlines()[0])
    def stopped(): assert all(p['state'] != 'running' for p in states())

    try:
        run([CLI, 'runtime', 'prepare-livekit', ROOT / 'platform/release/downloaded-candidate-inventory.json', name])
        runtime('apply-private')
        run(['python3', ROOT / 'platform/scripts/install-private-boot-units.py', '--activate', name]); enrolled = True
        content = manifest.read_bytes(); manifest_hash = hashlib.sha256(content).hexdigest()
        receipt['phase'] = 'persist-before-quiescence'
        fence = json.loads(runtime('maintenance-enter', 'backup', 'livekit'))
        stopped()
        assert json.loads(runtime('maintenance-status')) == fence
        assert json.loads(runtime('maintenance-enter', 'backup', 'livekit')) == fence
        assert json.loads(runtime('maintenance-status')) == fence
        receipt['phase'] = 'ordinary-and-pinned-boot-refusal'
        runtime('apply-private', succeeds=False); runtime('provision-private', succeeds=False)
        run(['sudo', '-n', 'systemctl', 'restart', unit], succeeds=False); stopped()
        # Previous pinned controllers must fail closed on the unknown control record, not ignore it.
        assert OLD.is_file()
        run([OLD, 'runtime', 'boot-apply', name, manifest_hash], succeeds=False); stopped()
        receipt['phase'] = 'bounded-staging'
        runtime('stage-private', 'rtc', succeeds=False)
        runtime('stage-private', 'livekit')
        assert {p['id'] for p in states() if p['state'] == 'running'} == {'livekit'}
        runtime('apply-private', succeeds=False)
        runtime('maintenance-leave', fence['id'], succeeds=False)
        runtime('stop-private'); stopped()
        runtime('maintenance-leave', str(uuid.uuid4()), succeeds=False)
        assert json.loads(runtime('maintenance-status')) == fence
        receipt['phase'] = 'explicit-release-and-restart'
        runtime('maintenance-leave', fence['id'])
        assert json.loads(runtime('maintenance-status')) is None
        stopped()  # Release itself never starts applications.
        run(['sudo', '-n', 'systemctl', 'restart', unit])
        assert all(p['state'] == 'running' for p in states())
        assert manifest.read_bytes() == content
        receipt.update(passed=True, phase='complete', durableFenceSurvivedControllerInvocations=True,
                       ordinaryApplyDenied=True, newAndOldPinnedBootDenied=True, explicitDependencyStagingOnly=True,
                       runningStagePreventsRelease=True, staleGenerationDenied=True, explicitReleaseVerified=True,
                       immutableManifestUnchanged=True)
    finally:
        if enrolled:
            try: run(['sudo', '-n', 'systemctl', 'disable', '--now', unit])
            except Exception: receipt.update(passed=False, unitQuarantineFailed=True)
        if manifest.exists():
            try: runtime('stop-private'); stopped()
            except Exception: receipt.update(passed=False, runtimeQuarantineFailed=True)
        with os.fdopen(os.open(directory / 'receipt.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'w') as out:
            json.dump(receipt, out, indent=2); out.flush(); os.fsync(out.fileno())
    assert receipt['passed']; print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    if not __debug__: raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
