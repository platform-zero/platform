#!/usr/bin/env python3
"""Freeze persistent Forgejo, verify an encrypted Kopia snapshot, and functionally restore in isolation.
All restored application bytes AND credentials come from Kopia, never a plaintext source copy.
"""
import argparse
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import urllib.error
import urllib.request
import uuid

P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / 'platform/build/install/p0-v3-platform/bin/p0-v3-platform'
INVENTORY = ROOT / 'platform/release/downloaded-candidate-inventory.json'
BASE = Path('/mnt/media/p0-v3/runtime-deployments')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def private_write(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', default='forgejo-r2')
    parser.add_argument('--fixture', type=Path, required=True, help='Private passed persistent-Forgejo receipt directory')
    args = parser.parse_args()
    source = args.source
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', source)
    fixture = args.fixture
    assert fixture.is_absolute() and fixture.resolve() == fixture and fixture.stat().st_mode & 0o777 == 0o700
    previous = json.loads((fixture / 'receipt.json').read_text())
    assert previous['passed'] and previous['scope'] == 'persistent-private-forgejo-not-full-stack'
    credentials = json.loads((fixture / 'user.json').read_text())
    user = credentials['username']
    assert re.fullmatch(r'journey-[a-f0-9]{12}', user)
    auth = 'Basic ' + base64.b64encode((user + ':' + credentials['password']).encode()).decode()
    nonce = uuid.uuid4().hex[:12]
    prefix = 'p0v3-forgejo-restore-' + nonce
    target = 'frestore-' + nonce
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / prefix
    directory.mkdir(mode=0o700)
    recovered = directory / 'recovered'
    recovered.mkdir(mode=0o700)
    env = directory / 'kopia.env'
    private_write(env, ('KOPIA_PASSWORD=' + secrets.token_hex(32) + '\n').encode())
    images = json.loads(INVENTORY.read_text())['images']
    kopia_image = next(i['pinnedImage'] for i in images if i['product'] == 'kopia')
    forgejo_image = next(i['pinnedImage'] for i in images if i['product'] == 'forgejo')
    source_manifest = (BASE / (source + '.json')).read_bytes()
    source_spec = json.loads(source_manifest)
    assert source_spec['name'] == source
    assert next(p['image'] for p in source_spec['processes'] if p['id'] == 'forgejo') == forgejo_image
    repo, config, export = [prefix + '-' + v for v in ('repository', 'config', 'export')]
    receipt = {'id': prefix, 'scope': 'persistent-private-forgejo-encrypted-restore-not-full-stack', 'passed': False,
               'source': source, 'restore': target, 'offHostBackup': False, 'browserJourney': False,
               'sourceManifestSha256': hashlib.sha256(source_manifest).hexdigest()}
    source_stopped = False
    source_lock = None
    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))

    def pod(*arguments, timeout=180):
        result = subprocess.run(P + list(arguments), capture_output=True, timeout=timeout)
        if result.returncode:
            # Keep diagnostics private; helper output can contain recovered credentials.
            path = directory / ('failure-' + uuid.uuid4().hex[:8] + '.log')
            private_write(path, result.stderr)
            raise RuntimeError('Scoped Podman operation failed: ' + arguments[0])
        return result.stdout

    def runtime(action, name):
        result = subprocess.run([str(CLI), 'runtime', action, str(BASE / (name + '.json'))], capture_output=True, timeout=900,
            env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0, 'Scoped runtime lifecycle failed'
        return json.loads(result.stdout.splitlines()[0])

    def address(name):
        data = json.loads(pod('inspect', 'p0v3-live-' + name + '-forgejo'))[0]
        assert data['Config']['Labels']['io.p0v3.private-deployment'] == name
        assert not data['HostConfig']['PortBindings']
        networks = data['NetworkSettings']['Networks']
        assert set(networks) == {'p0v3-live-' + name + '-net'}
        ip = networks['p0v3-live-' + name + '-net']['IPAddress']
        assert ipaddress.ip_address(ip).is_private
        return ip

    def api(ip, path, payload=None, method=None):
        headers = {'Authorization': auth, 'Accept': 'application/json'}
        if payload is not None:
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request('http://' + ip + ':3000/api/v1' + path, headers=headers,
            data=None if payload is None else json.dumps(payload).encode(), method=method)
        try:
            with opener.open(request, timeout=20) as response:
                raw = response.read(2097153)
                assert len(raw) <= 2097152
                return json.loads(raw)
        except urllib.error.HTTPError as error:
            raise RuntimeError('Scoped Forgejo API returned ' + str(error.code)) from None

    def helper(image, mounts, command, entrypoint=None, extra=()):
        arguments = ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=all',
                     '--security-opt=no-new-privileges', '--security-opt=apparmor=p0v3-private-v1', '--user=1000:1000',
                     '--memory=1024m', '--pids-limit=256', '--image-volume=ignore', '--tmpfs=/tmp:rw,nosuid,nodev,size=128m']
        for mount in mounts:
            arguments += ['--volume', mount]
        if entrypoint:
            arguments += ['--entrypoint', entrypoint]
        return pod(*(arguments + list(extra) + [image] + command))

    def kopia(*command):
        return helper(kopia_image, [repo + ':/repository:U', config + ':/config:U', export + ':/restore:U',
            'p0v3-live-' + source + '-volume-forgejo:/snapshot/data:ro', str(BASE / source) + ':/snapshot/inputs:ro',
            str(BASE / (source + '.json')) + ':/snapshot/spec.json:ro'],
            ['--config-file=/config/repository.config', '--disable-file-logging', *command],
            extra=['--env-file', str(env), '--env=HOME=/tmp', '--env=KOPIA_CACHE_DIRECTORY=/tmp/cache'])

    path = '/repos/' + user + '/lifecycle/contents/README.md'
    issues_path = '/repos/' + user + '/lifecycle/issues?state=all'
    try:
        runtime('apply-private', source)
        source_ip = address(source)
        assert api(source_ip, '/user')['login'] == user
        baseline = api(source_ip, path)
        original = base64.b64decode(baseline['content'])
        issues = api(source_ip, issues_path)
        assert issues
        receipt['phase'] = 'freeze-and-encrypt'
        stopped = runtime('stop-private', source)
        source_stopped = True
        assert all(p['exitCode'] in (0, 143) for p in stopped)
        source_lock = (BASE / source / 'runtime.lock').open('r+b')
        fcntl.lockf(source_lock, fcntl.LOCK_EX)
        frozen = json.loads(pod('inspect', 'p0v3-live-' + source + '-forgejo'))[0]
        assert not frozen['State']['Running']
        for volume in (repo, config, export):
            assert subprocess.run(P + ['volume', 'exists', volume], capture_output=True).returncode == 1
            pod('volume', 'create', '--label=io.p0v3.restore-probe=' + prefix, volume)
        kopia('repository', 'create', 'filesystem', '--path=/repository', '--no-check-for-updates')
        snapshot = json.loads(kopia('snapshot', 'create', '--json', '/snapshot'))
        snapshot_id = snapshot['rootEntry']['obj']
        receipt['snapshotId'] = snapshot_id
        kopia('snapshot', 'verify', '--verify-files-percent=100')
        kopia('snapshot', 'restore', '--no-overwrite-files', '--no-overwrite-directories', '--no-overwrite-symlinks',
              '--skip-owners', '--flush-files', snapshot_id, '/restore/export')
        after = json.loads(pod('inspect', 'p0v3-live-' + source + '-forgejo'))[0]
        assert not after['State']['Running'] and after['State']['StartedAt'] == frozen['State']['StartedAt'] and after['Id'] == frozen['Id']
        source_lock.close()
        source_lock = None
        receipt['phase'] = 'source-mutation'
        runtime('apply-private', source)
        source_stopped = False
        source_ip = address(source)
        source_content = original + ('\nSource-only after snapshot ' + nonce + '\n').encode()
        api(source_ip, path, {'sha': baseline['sha'], 'content': base64.b64encode(source_content).decode(),
                             'message': 'Source isolation fixture'}, method='PUT')
        receipt['phase'] = 'recover-inputs-and-data'
        recovered_manifest = helper(forgejo_image, [export + ':/export:ro'],
            ['-ec', 'head -c 1048577 /export/export/spec.json'], '/bin/sh')
        assert recovered_manifest == source_manifest
        private_write(recovered / 'source-spec.json', recovered_manifest)
        for file in ('app.ini', 'forgejo.env'):
            data = helper(forgejo_image, [export + ':/export:ro'], ['-ec', 'head -c 1048577 /export/export/inputs/' + file], '/bin/sh')
            assert 0 < len(data) <= 1048576
            private_write(recovered / file, data)
        result = subprocess.run([str(CLI), 'runtime', 'prepare-forgejo-restore', str(INVENTORY), str(recovered), target],
            capture_output=True, timeout=30, env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0
        assert all(p['state'] == 'absent' for p in runtime('provision-private', target))
        target_volume = 'p0v3-live-' + target + '-volume-forgejo'
        helper(forgejo_image, [export + ':/export:ro', target_volume + ':/target:U'], ['-ec',
            'test -z "$(ls -A /target)"; touch /target/.restore-in-progress; '
            'cp -a /export/export/data/. /target/; rm /target/.restore-in-progress; '
            'if ! diff -r /export/export/data /target; then touch /target/.restore-in-progress; exit 1; fi'], '/bin/sh')
        receipt['phase'] = 'isolated-functional-readback'
        runtime('apply-private', target)
        restored_ip = address(target)
        assert restored_ip != source_ip
        pod('exec', 'p0v3-live-' + target + '-forgejo', '/bin/sh', '-ec', '! nc -z -w 2 ' + source_ip + ' 3000')
        assert api(restored_ip, '/user')['login'] == user
        restored = api(restored_ip, path)
        assert base64.b64decode(restored['content']) == original
        assert [(i['number'], i['title']) for i in api(restored_ip, issues_path)] == [(i['number'], i['title']) for i in issues]
        restored_content = original + ('\nRestored-only isolated write ' + nonce + '\n').encode()
        api(restored_ip, path, {'sha': restored['sha'], 'content': base64.b64encode(restored_content).decode(),
                              'message': 'Isolated restored write'}, method='PUT')
        assert base64.b64decode(api(restored_ip, path)['content']) == restored_content
        assert base64.b64decode(api(source_ip, path)['content']) == source_content
        receipt.update(passed=True, phase='complete', encryptedSnapshotVerified=True, credentialsRecoveredFromKopia=True,
            repositoryAndIssuesRestored=True, regularUserLoginRestored=True, sourceMutationExcluded=True,
            restoredWritesIsolated=True, sourceTcpBlockedFromRestore=True)
    finally:
        if source_lock is not None:
            source_lock.close()
        if source_stopped:
            try:
                runtime('apply-private', source)
            except Exception:
                receipt['sourceResumeFailed'] = True
                receipt['passed'] = False
        # Also quarantine a partially started restore if its apply failed.
        if (BASE / (target + '.json')).exists():
            try:
                runtime('stop-private', target)
            except Exception:
                receipt['restoreStopFailed'] = True
                receipt['passed'] = False
        private_write(directory / 'receipt.json', json.dumps(receipt, indent=2).encode())
    print(json.dumps(receipt, indent=2))
    assert receipt['passed'], 'Restore cleanup or source resume failed'


if __name__ == '__main__':
    main()
