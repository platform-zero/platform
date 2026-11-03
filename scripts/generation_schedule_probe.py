"""Native client for a fresh generation's installed daily timer. No production orchestration logic."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import hashlib
import json
import os
from pathlib import Path
import re
import time


def exercise(platform, generation, bundle, inventory, out, run, write):
    assert re.fullmatch(r'q-[a-f0-9]{12}', generation) and re.fullmatch(r'[a-f0-9]{64}', bundle)
    root = Path('/mnt/media/p0-v3/release-generations') / generation / 'backup-schedule'
    name = 'p0v3-backup-' + generation
    installed = None
    try:
        installed = json.loads(run('schedule-install', ['python3', platform / 'scripts/install-generation-backup-schedule.py',
                                                       '--activate', inventory, generation, bundle]))
        assert installed['activated'] and installed['generation'] == generation and not installed['weeklyRestoreInstalled']
        binding = installed['bindingSha256']
        cli = Path('/mnt/media/p0-v3/runtime-supervision/releases') / installed['controllerTreeSha256'] / 'bin/p0-v3-platform'
        deadline = time.monotonic() + 600
        # No `systemctl start SERVICE`: the installed timer must perform the first invocation itself.
        while True:
            assert time.monotonic() < deadline, 'Installed timer did not complete within the test budget'
            assert not (root / 'failure.alert').exists(), 'Installed backup failed; preserve timer and controller evidence'
            records = list(root.glob('slots/*/result.json'))
            assert len(records) <= 1
            if records:
                try: result = json.loads(records[0].read_text())
                except json.JSONDecodeError: time.sleep(.05); continue
                break
            time.sleep(.1)
        assert result['failureType'] is None and result['slot']['bindingSha256'] == binding
        backup = result['backup']
        assert backup['passed'] and backup['sourceResumed']
        # Keep the timer referenced until invocation observations are captured: disabling it can
        # garbage-collect the inactive service and reset its historical timestamps to zero.
        # systemd job completion can follow the durable slot result by a few milliseconds.
        for i in range(100):
            state = run('schedule-completion-state-' + str(i), ['systemctl', 'show', name + '.service', '-p', 'ActiveState', '--value']).strip()
            if state == 'inactive': break
            assert state == 'activating'; time.sleep(.1)
        assert state == 'inactive'
        service_result = run('schedule-service-result', ['systemctl', 'show', name + '.service', '-p', 'Result', '--value']).strip()
        assert service_result == 'success'
        started = run('schedule-native-invocation', ['systemctl', 'show', name + '.service', '-p', 'ExecMainStartTimestampMonotonic', '--value']).strip()
        assert started.isdigit() and int(started) > 0
        run('schedule-disable-after-fire', ['sudo', '-n', 'systemctl', 'disable', '--now', name + '.timer'])
        before = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob('slots/*/*.json')}
        duplicate = json.loads(run('schedule-duplicate-tick', [cli, 'release', 'backup-schedule-tick', generation, binding]))
        assert duplicate['status'] == 'already-completed' and duplicate['slot'] == result['slot']
        assert before == {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob('slots/*/*.json')}
        # Explicit scoped integrity fault: only this schedule's private COPY of the inventory changes.
        # It is retained corrupted; neither the original inventory nor snapshot/source state is repaired or replayed.
        path = root / 'inventory.json'
        old = path.read_bytes(); bad = old + b'\n'
        write(out / 'schedule-inventory-fault.intent.json', {'scope': generation, 'beforeSha256': hashlib.sha256(old).hexdigest(),
                                                         'afterSha256': hashlib.sha256(bad).hexdigest(), 'sourceInventoryChanged': False})
        with path.open('wb') as stream:
            stream.write(bad); stream.flush()
            os.fsync(stream.fileno())
        run('schedule-bound-inventory-denied', ['sudo', '-n', 'systemctl', 'start', name + '.service'], expected_code=1)
        deadline = time.monotonic() + 30
        while not (root / 'failure.alert').exists():
            assert time.monotonic() < deadline; time.sleep(.1)
        assert (root / 'failure.alert').read_text() == binding
        assert before == {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.glob('slots/*/*.json')}
        run('schedule-alert-retry-denied', [cli, 'release', 'backup-schedule-tick', generation, binding], expected_code=1)
        return backup, {'installedTimerFired': True, 'dailyCalendarUtc': '03:00', 'pinnedControllerVerified': True,
                        'duplicateTickDidNotSnapshot': True, 'inventoryTamperDeniedBeforeNewAttempt': True,
                        'systemdOnFailureLocalAlert': True, 'failureAndCorruptInputRetained': True,
                        'weeklyRestoreInstalled': False, 'retentionDeletion': False, 'hostReboot': False}
    finally:
        # Suspension is irreversible and serialized with any running job. Never clear a failed slot or backup lease.
        # Handle an installer exit with unknown acknowledgement as well as its ordinary success response.
        timer = Path('/etc/systemd/system') / (name + '.timer')
        if timer.exists():
            intent = json.loads((root / 'install.intent.json').read_text())
            assert hashlib.sha256(timer.read_bytes()).hexdigest() == intent['units'][timer.name]
            binding = intent['bindingSha256']
            cli = Path('/mnt/media/p0-v3/runtime-supervision/releases') / intent['controllerTreeSha256'] / 'bin/p0-v3-platform'
            run('schedule-suspend', [cli, 'release', 'backup-schedule-suspend', generation, binding])
            run('schedule-disable-final', ['sudo', '-n', 'systemctl', 'disable', '--now', name + '.timer'])
            assert run('schedule-disabled', ['systemctl', 'is-enabled', name + '.timer'], expected_code=1).strip() == 'disabled'
            assert run('schedule-inactive', ['systemctl', 'is-active', name + '.timer'], expected_code=3).strip() == 'inactive'
            assert json.loads(run('schedule-suspended-tick', [cli, 'release', 'backup-schedule-tick', generation, binding]))['status'] == 'suspended'
