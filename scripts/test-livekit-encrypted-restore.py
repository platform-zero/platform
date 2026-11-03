#!/usr/bin/env python3
"""Encrypted recovery of SFU keys/configuration, not persistence of ephemeral calls or recordings."""
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import uuid
from matrix_recovery_safety import require_target_stopped, require_source_unchanged

SPEC = importlib.util.spec_from_file_location('rtc_probe', Path(__file__).with_name('test-private-livekit.py'))
RTC = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(RTC)
ROOT, BASE, CLI, P = RTC.ROOT, RTC.BASE, RTC.CLI, RTC.P
INVENTORY = ROOT / 'platform/release/downloaded-candidate-inventory.json'
JAVA = {**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'}


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    source, nonce = 'livekit', uuid.uuid4().hex[:12]
    target = 'rrestore-' + nonce
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-rtc-restore-' + nonce)
    directory.mkdir(mode=0o700)
    snapshot, export = directory / 'snapshot', directory / 'export'
    snapshot.mkdir(mode=0o700); export.mkdir(mode=0o700)
    source_bytes = (BASE / (source + '.json')).read_bytes(); spec = json.loads(source_bytes)
    assert not spec.get('volumes') and {p['id'] for p in spec['processes']} == {'livekit', 'rtc'}
    assert not (BASE / (target + '.json')).exists() and not (BASE / target).exists()
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    unit = 'p0v3-private-livekit.service'
    unit_path = Path('/etc/systemd/system') / unit
    assert not unit_path.is_symlink() and unit_path.stat().st_uid == 0
    assert re.search(r'^ExecStart=/mnt/media/p0-v3/runtime-supervision/releases/[a-f0-9]{64}/bin/p0-v3-platform runtime boot-apply livekit ' + source_hash + '$', unit_path.read_text(), re.M)
    repo, config = directory.name + '-repository', directory.name + '-config'
    kopia_image = next(i['pinnedImage'] for i in json.loads(INVENTORY.read_text())['images'] if i['product'] == 'kopia')
    RTC.write(directory / 'kopia.env', 'KOPIA_PASSWORD=' + secrets.token_hex(32) + '\n')
    receipt = {'id': directory.name, 'source': source, 'restore': target, 'passed': False,
               'scope': 'stateless-sfu-configuration-recovery', 'fullStackAcceptance': False, 'offHostBackup': False,
               'activeCallsBackedUp': False, 'sourceManifestSha256': source_hash, 'harnessSha256': digest(Path(__file__))}
    maintenance, lock = False, None

    def run(command):
        result = subprocess.run(command, capture_output=True, env=JAVA, timeout=1200)
        if result.returncode:
            RTC.write(directory / ('failure-' + uuid.uuid4().hex[:8] + '.log'), result.stderr.decode(errors='replace'))
            raise RuntimeError('Private RTC recovery failed; protected diagnostics retained')
        return result.stdout

    def system(*args): return run(['sudo', '-n', 'systemctl', *args, unit])
    def runtime(action, name): return json.loads(run([str(CLI), 'runtime', action, str(BASE / (name + '.json'))]).splitlines()[0])
    def inspect(name, process): return json.loads(run(P + ['inspect', 'p0v3-live-' + name + '-' + process]))[0]
    def api(name, method, room):
        data = inspect(name, 'rtc'); assert data['State']['Running']
        address = data['NetworkSettings']['Networks']['p0v3-live-' + name + '-net']['IPAddress']
        key, secret = re.search(r'^  "([^"]+)": "([^"]+)"$', (BASE / name / 'livekit.yaml').read_text(), re.M).groups()
        token = RTC.jwt(key, secret, 'recovery-fixture', {'roomCreate': True, 'roomList': True, 'roomAdmin': True, 'room': room})
        body = json.dumps({'name': room} if method == 'CreateRoom' else {'room': room} if method == 'DeleteRoom' else {'names': [room]}).encode()
        context = ssl.create_default_context(cafile=str(BASE / name / 'ca.pem'))
        with socket.create_connection((address, 8443), timeout=15) as raw, context.wrap_socket(raw, server_hostname='rtc') as tls:
            tls.sendall(('POST /twirp/livekit.RoomService/' + method + ' HTTP/1.1\r\nHost: rtc:8443\r\nContent-Type: application/json\r\nAuthorization: Bearer ' + token + '\r\nContent-Length: ' + str(len(body)) + '\r\nConnection: close\r\n\r\n').encode() + body)
            response = http.client.HTTPResponse(tls); response.begin(); assert response.status == 200
            return json.loads(response.read(1048576))

    def kopia(*args):
        return run(P + ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=all',
            '--security-opt=no-new-privileges', '--security-opt=apparmor=p0v3-private-v1', '--user=1000:1000',
            '--memory=1024m', '--pids-limit=256', '--image-volume=ignore', '--tmpfs=/tmp:rw,nosuid,nodev,size=128m',
            '--volume', repo + ':/repository:U', '--volume', config + ':/config:U', '--volume', str(snapshot) + ':/snapshot:ro',
            '--volume', str(export) + ':/restore:rw', '--env-file', str(directory / 'kopia.env'), '--env=HOME=/tmp',
            '--env=KOPIA_CACHE_DIRECTORY=/tmp/cache', kopia_image, '--config-file=/config/repository.config', '--disable-file-logging', *args])

    try:
        assert system('is-enabled').strip() == b'enabled' and system('is-active').strip() == b'active'
        runtime('apply-private', source)
        receipt['phase'] = 'freeze-and-capture-config'
        maintenance = True; system('disable', '--now')
        lock = (BASE / source / 'runtime.lock').open('r+b'); fcntl.lockf(lock, fcntl.LOCK_EX)
        frozen = {p['id']: inspect(source, p['id']) for p in spec['processes']}
        assert all(not d['State']['Running'] for d in frozen.values())
        inputs = {f['file'] for p in spec['processes'] for f in p.get('files', [])}
        RTC.write(snapshot / 'source-spec.json', source_bytes.decode())
        for name in inputs:
            path = BASE / source / name
            assert re.fullmatch(r'[a-z][a-z0-9.-]{0,79}', name) and not path.is_symlink() and path.stat().st_mode & 0o777 == 0o600
            RTC.write(snapshot / name, path.read_text())
        hashes = {p.name: digest(p) for p in snapshot.iterdir()}
        RTC.write(snapshot / 'manifest.json', json.dumps(hashes, sort_keys=True))
        receipt['archiveManifestSha256'] = digest(snapshot / 'manifest.json')
        for volume in (repo, config):
            assert subprocess.run(P + ['volume', 'exists', volume], capture_output=True).returncode == 1
            run(P + ['volume', 'create', '--label=io.p0v3.restore-probe=' + directory.name, volume])
        kopia('repository', 'create', 'filesystem', '--path=/repository', '--no-check-for-updates')
        snapshot_id = json.loads(kopia('snapshot', 'create', '--json', '/snapshot'))['rootEntry']['obj']
        receipt['snapshotId'] = snapshot_id
        kopia('snapshot', 'verify', '--verify-files-percent=100')
        kopia('snapshot', 'restore', '--no-overwrite-files', '--no-overwrite-directories', '--no-overwrite-symlinks', '--skip-owners', '--flush-files', snapshot_id, '/restore/recovered')
        for process, before in frozen.items():
            after = inspect(source, process)
            assert before['Id'] == after['Id'] and before['State']['StartedAt'] == after['State']['StartedAt'] and not after['State']['Running']
        assert digest(BASE / (source + '.json')) == source_hash
        for name in inputs: assert digest(BASE / source / name) == hashes[name]
        # Keep the source stopped AND fenced until the target has been stopped and read back.
        # A completed restore command is not permission to resume either side.
        recovered = export / 'recovered'
        assert digest(recovered / 'manifest.json') == receipt['archiveManifestSha256']
        assert {p.name for p in recovered.iterdir()} == set(hashes) | {'manifest.json'}
        for name, checksum in hashes.items():
            path = recovered / name
            assert path.is_file() and not path.is_symlink() and digest(path) == checksum
            path.chmod(0o600)
        recovered.chmod(0o700)
        run([str(CLI), 'runtime', 'prepare-livekit-restore', str(INVENTORY), str(recovered), target])
        receipt['phase'] = 'restored-media-journey'
        result = json.loads(run(['python3', str(ROOT / 'platform/scripts/test-private-livekit.py'), '--name', target]))
        assert result['passed'] and result['afterRestart']['syntheticVideoDecoded'] and result['afterRestart']['syntheticAudioReceived']
        assert result['afterRestart']['clientMediaE2eeVerified'] and result['afterRestart']['wrongMediaKeyDenied']
        receipt['restoredBrowserFixture'] = result['id']
        target_room = 'target-' + nonce
        assert api(target, 'CreateRoom', target_room)['name'] == target_room
        require_source_unchanged(frozen, {p: inspect(source, p) for p in frozen})
        assert digest(BASE / (source + '.json')) == source_hash
        for name in inputs: assert digest(BASE / source / name) == hashes[name]
        receipt['phase'] = 'target-isolation-before-source-resume'
        runtime('stop-private', target)
        receipt['isolatedTargetContainers'] = require_target_stopped(
            frozen, {p: inspect(target, p) for p in frozen}, target)
        receipt['targetIsolationVerifiedBeforeSourceResume'] = True
        lock.close(); lock = None
        # Only this successful readback path resumes the source. Failure/timeout never does.
        receipt['sourceResumeAttempted'] = True
        system('enable', '--now'); maintenance = False
        assert not api(source, 'ListRooms', target_room).get('rooms')
        receipt.update(passed=True, phase='complete', encryptedExportVerified=True, keysAndConfigurationPreserved=True,
                       restoredMediaVerified=True, restoredClientMediaE2eeVerified=True, sourceDoesNotContainTargetRoom=True)
    finally:
        if lock: lock.close()
        if maintenance:
            receipt.update(passed=False, sourceResumeWithheld=not receipt.get('sourceResumeAttempted', False),
                           explicitReconciliationRequired=True)
        if (BASE / (target + '.json')).exists():
            try:
                runtime('stop-private', target)
                require_target_stopped([p['id'] for p in spec['processes']],
                    {p['id']: inspect(target, p['id']) for p in spec['processes']}, target)
            except Exception: receipt.update(passed=False, restoreQuarantineFailed=True)
        RTC.write(directory / 'receipt.json', json.dumps(receipt, indent=2))
    assert receipt['passed'], 'Recovery cleanup failed; receipt retained'
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    if not __debug__: raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
