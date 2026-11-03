"""Scoped native backup-controller interruption. Never kills a process group or resumes an uncertain source."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import signal
import subprocess
import time
import uuid


def exercise(generation, bundle, out, cli, inventory, pod, env, run, write):
    assert re.fullmatch(r'q-[a-f0-9]{12}', generation) and re.fullmatch(r'[a-f0-9]{64}', bundle)
    # Reuse the already tested read-only /proc identity and descendant observers, not its main program.
    definition = importlib.util.spec_from_file_location('p0v3_import_fault_observers', Path(__file__).with_name('test-import-interruption.py'))
    observers = importlib.util.module_from_spec(definition)
    definition.loader.exec_module(observers)
    capture = 'cap-' + uuid.uuid4().hex[:12]
    base = Path('/mnt/media/p0-v3')
    root = base / 'release-generations' / generation / 'backups' / capture
    command = [str(x) for x in [cli, 'release', 'generation-kopia-backup', inventory, generation, bundle, capture]]
    write(out / 'backup-fault-launch.intent.json', {'generation': generation, 'capture': capture, 'argvSha256': hashlib.sha256(json.dumps(command).encode()).hexdigest()})
    process = None
    paused = False
    killed = False
    try:
        with (out / 'backup-fault.stdout').open('xb') as stdout, (out / 'backup-fault.stderr').open('xb') as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, env=env)
            original = observers.process_state(process.pid)
            write(out / 'backup-fault-controller.json', original)
            deadline = time.monotonic() + 600
            while not (root / 'quiesced.json').exists():
                assert process.poll() is None, 'Backup exited before the intended boundary'
                assert time.monotonic() < deadline
                time.sleep(0.005)
            assert process.poll() is None and observers.process_state(process.pid)['startTicks'] == original['startTicks']
            write(out / 'backup-fault-stop.intent.json', {'pid': process.pid, 'startTicks': original['startTicks'], 'signal': 'SIGSTOP'})
            process.send_signal(signal.SIGSTOP); paused = True
            deadline = time.monotonic() + 10
            while observers.process_state(process.pid)['state'] not in ('T', 't'):
                assert time.monotonic() < deadline; time.sleep(0.01)
            assert not list(root.glob('resume-*.intent.json')) and not (root / 'result.json').exists(), 'Missed boundary; do not mislabel a completed backup'
            intent = (root / 'intent.json').read_bytes()
            assert json.loads(intent) == {'generation': generation, 'operation': capture, 'bundleSha256': bundle}
            deadline = time.monotonic() + 180
            while True:
                children = observers.descendants(process.pid)
                if all(c['state'] == 'Z' for c in children): break
                assert time.monotonic() < deadline, 'Native child not settled; no unsafe process-group killing'
                time.sleep(0.05)
            write(out / 'backup-fault-settled-children.json', children)
            write(out / 'backup-fault-kill.intent.json', {'pid': process.pid, 'startTicks': original['startTicks'], 'signal': 'SIGKILL'})
            process.kill(); assert process.wait(timeout=30) == -signal.SIGKILL
            paused = False; killed = True
        assert not (root / 'result.json').exists()
        names = [generation + '-' + k for k in ('canonical-core', 'forgejo', 'sql-cache')]
        for name in names:
            manifest = base / 'runtime-deployments' / (name + '.json')
            assert (manifest.parent / name / 'runtime.backup').exists()
            run('backup-boot-denied-' + name, [cli, 'runtime', 'boot-apply', name, hashlib.sha256(manifest.read_bytes()).hexdigest()], expected_code=1)
        other = 'cap-' + uuid.uuid4().hex[:12]
        run('backup-new-id-denied', [cli, 'release', 'generation-kopia-backup', inventory, generation, bundle, other], expected_code=1)
        assert not (root.parent / other).exists()
        result = json.loads(run('backup-stop-reconciliation', [cli, 'release', 'generation-backup-reconcile', generation, bundle, capture,
                              'r-' + uuid.uuid4().hex[:12], hashlib.sha256(intent).hexdigest()]).splitlines()[0])
        assert result['passed'] and set(result['fences']) == set(names)
        assert (root / 'intent.json').read_bytes() == intent and not (root / 'result.json').exists()
        assert all((base / 'runtime-deployments' / name / 'runtime.backup').exists() for name in names)
        for name in names:
            run('backup-retained-lease-denied-' + name, [cli, 'runtime', 'apply-private', base / 'runtime-deployments' / (name + '.json')], expected_code=1)
        return {'capture': capture, 'actualControllerKill': True, 'hostPowerLossTest': False, 'sourceResumed': False,
                'bootStartupDenied': True, 'newOperationIdDenied': True, 'stopOnlyReconciled': True,
                'originalIntentUnchanged': True, 'originalOutcomeStillUnknown': True, 'leasesRetained': True}
    finally:
        if process is not None and process.poll() is None:
            # A missed boundary is not a kill proof. Let this exact controller finish its already authorized operation.
            if paused: process.send_signal(signal.SIGCONT)
            process.wait(timeout=1200)
        if killed:
            # No restart, snapshot submission or fence removal is attempted by this cleanup.
            assert process.returncode == -signal.SIGKILL
