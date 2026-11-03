#!/usr/bin/env python3
"""Coordinated private financial dump/files/keys encryption and isolated native-browser recovery."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import uuid
from financial_restore_archive import inventory as tar_inventory

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/media/p0-v3/runtime-deployments')
CLI = ROOT / 'platform/build/install/p0-v3-platform/bin/p0-v3-platform'
INVENTORY = ROOT / 'platform/release/downloaded-candidate-inventory.json'
P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
JAVA = {**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'}


def write(path, data):
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


def digest(path):
    assert path.is_file() and not path.is_symlink()
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', default='firefly-r2')
    args = parser.parse_args()
    source = args.source
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', source)
    nonce = uuid.uuid4().hex[:12]
    prefix, target = 'p0v3-finance-restore-' + nonce, 'ffrestore-' + nonce
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / prefix
    directory.mkdir(mode=0o700)
    snapshot, export = directory / 'snapshot', directory / 'export'
    snapshot.mkdir(mode=0o700)
    export.mkdir(mode=0o700)
    (snapshot / 'inputs').mkdir(mode=0o700)
    source_bytes = (BASE / (source + '.json')).read_bytes()
    spec = json.loads(source_bytes)
    assert spec['name'] == source
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    images = json.loads(INVENTORY.read_text())['images']
    image = next(i['pinnedImage'] for i in images if i['product'] == 'firefly-iii')
    kopia_image = next(i['pinnedImage'] for i in images if i['product'] == 'kopia')
    assert next(p['image'] for p in spec['processes'] if p['id'] == 'php') == image
    inputs = sorted({p['environmentFile'] for p in spec['processes'] if p.get('environmentFile')} |
                    {f['file'] for p in spec['processes'] for f in p.get('files', [])})
    unit = 'p0v3-private-' + source + '.service'
    unit_path = Path('/etc/systemd/system') / unit
    assert unit_path.is_file() and not unit_path.is_symlink() and unit_path.stat().st_uid == 0
    assert re.search(r'^ExecStart=/mnt/media/p0-v3/runtime-supervision/releases/[a-f0-9]{64}/bin/p0-v3-platform runtime boot-apply '
                     + re.escape(source) + ' ' + source_hash + '$', unit_path.read_text(), re.M)
    repo, config = prefix + '-repository', prefix + '-config'
    write(directory / 'kopia.env', ('KOPIA_PASSWORD=' + secrets.token_hex(32) + '\n').encode())
    receipt = {'id': prefix, 'scope': 'private-financial-encrypted-restore-not-full-stack', 'source': source,
        'restore': target, 'passed': False, 'fullStackAcceptance': False, 'offHostBackup': False, 'sourceManifestSha256': source_hash}
    maintenance, lock, fence = False, None, None

    def run(command, stdin=None, stdout=None, timeout=900):
        result = subprocess.run(command, stdin=stdin, stdout=stdout or subprocess.PIPE, stderr=subprocess.PIPE, env=JAVA, timeout=timeout)
        if result.returncode:
            write(directory / ('failure-' + uuid.uuid4().hex[:8] + '.log'), result.stderr)
            raise RuntimeError('Scoped financial recovery operation failed; private diagnostics retained')
        return result.stdout

    def runtime(action, name, *extra):
        return json.loads(run([str(CLI), 'runtime', action, str(BASE / (name + '.json')), *extra]).splitlines()[0])

    def system(*arguments):
        return run(['sudo', '-n', 'systemctl', *arguments, unit])

    def release_fence():
        nonlocal fence
        if fence is None:
            assert json.loads(run([str(CLI), 'runtime', 'maintenance-status', str(BASE / (source + '.json'))])) is None, 'Uncertain maintenance identity; retaining fence'
            return
        runtime('stop-private', source)
        run([str(CLI), 'runtime', 'maintenance-leave', str(BASE / (source + '.json')), fence['id']])
        fence = None

    def browser(name, fixture=None):
        command = ['python3', str(ROOT / 'platform/scripts/test-private-firefly-browser.py'), '--name', name]
        if fixture:
            command += ['--verify-fixture', str(fixture)]
        result = json.loads(run(command))
        assert result['passed'] and result['financialJourney']
        return result

    def inspect(name, process):
        return json.loads(run(P + ['inspect', 'p0v3-live-' + name + '-' + process]))[0]

    def volume_helper(name, volume, readonly, command, stdin=None, stdout=None):
        mount = 'p0v3-live-' + name + '-volume-' + volume + ':/data:' + ('ro' if readonly else 'U')
        return run(P + ['run', '--rm', '-i', '--pull=never', '--network=none', '--read-only', '--cap-drop=all',
            '--security-opt=no-new-privileges', '--security-opt=apparmor=p0v3-private-v1', '--user=33:33',
            '--memory=512m', '--pids-limit=128', '--image-volume=ignore', '--tmpfs=/tmp:rw,nosuid,nodev,size=64m',
            '--volume', mount, '--entrypoint=/bin/sh', image, '-ec', command], stdin, stdout)

    def archive_volume(name, volume, path):
        with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb') as out:
            volume_helper(name, volume, True, 'tar -cf - -C /data .', stdout=out)
            out.flush(); os.fsync(out.fileno())
        return tar_inventory(path)

    def kopia(*command):
        return run(P + ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=all',
            '--security-opt=no-new-privileges', '--security-opt=apparmor=p0v3-private-v1', '--user=1000:1000',
            '--memory=1024m', '--pids-limit=256', '--image-volume=ignore', '--tmpfs=/tmp:rw,nosuid,nodev,size=128m',
            '--volume', repo + ':/repository:U', '--volume', config + ':/config:U', '--volume', str(snapshot) + ':/snapshot:ro',
            '--volume', str(export) + ':/restore:rw', '--env-file', str(directory / 'kopia.env'), '--env=HOME=/tmp',
            '--env=KOPIA_CACHE_DIRECTORY=/tmp/cache', kopia_image, '--config-file=/config/repository.config',
            '--disable-file-logging', *command])

    def count_account(name, fixture_nonce):
        assert re.fullmatch(r'[a-f0-9]{12}', fixture_nonce)
        return int(run(P + ['exec', 'p0v3-live-' + name + '-postgres', 'psql', '-X', '-U', 'postgres', '-d', 'firefly', '-At',
            '-c', "SELECT count(*) FROM accounts WHERE name='Fixture wallet " + fixture_nonce + "'"]).strip())

    try:
        receipt['phase'] = 'source-financial-fixture'
        assert system('is-enabled').strip() == b'enabled' and system('is-active').strip() == b'active'
        original = browser(source)
        fixture = directory.parent / original['id']
        receipt['sourceFixture'] = original['id']
        jobs = digest(BASE / source / 'runtime.jobs')
        receipt['phase'] = 'disable-boot-and-freeze'
        maintenance = True
        system('disable', '--now')
        assert json.loads(run([str(CLI), 'runtime', 'maintenance-status', str(BASE / (source + '.json'))])) is None
        fence = json.loads(run([str(CLI), 'runtime', 'maintenance-enter', str(BASE / (source + '.json')), 'backup', 'postgres']))
        blocked = subprocess.run([str(CLI), 'runtime', 'apply-private', str(BASE / (source + '.json'))], capture_output=True, env=JAVA, timeout=120)
        assert blocked.returncode != 0
        receipt['durableSourceFenceVerified'] = True
        staged = runtime('stage-private', source, 'postgres')
        assert {p['id'] for p in staged if p['state'] == 'running'} == {'postgres'}
        lock = (BASE / source / 'runtime.lock').open('r+b')
        fcntl.lockf(lock, fcntl.LOCK_EX)
        frozen = {p['id']: inspect(source, p['id']) for p in spec['processes']}
        assert {p for p, data in frozen.items() if data['State']['Running']} == {'postgres'}
        write(snapshot / 'inputs/source-spec.json', source_bytes)
        for file in inputs:
            assert re.fullmatch(r'[a-z][a-z0-9.-]{0,79}', file)
            path = BASE / source / file
            assert not path.is_symlink() and path.stat().st_mode & 0o777 == 0o600
            write(snapshot / 'inputs' / file, path.read_bytes())
        write(snapshot / 'fixture.json', json.dumps(original).encode())
        with os.fdopen(os.open(snapshot / 'postgres.dump', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb') as out:
            run(P + ['exec', 'p0v3-live-' + source + '-postgres', 'pg_dump', '-U', 'postgres', '-d', 'firefly',
                     '--format=custom', '--no-owner', '--no-privileges'], stdout=out)
            out.flush(); os.fsync(out.fileno())
        trees = {volume: archive_volume(source, volume, snapshot / (volume + '.tar')) for volume in ('storage', 'cache')}
        hashes = {str(p.relative_to(snapshot)): digest(p) for p in snapshot.rglob('*') if p.is_file()}
        write(snapshot / 'manifest.json', json.dumps(hashes, sort_keys=True).encode())
        receipt['archiveManifestSha256'] = digest(snapshot / 'manifest.json')
        receipt['phase'] = 'encrypt-and-export'
        for volume in (repo, config):
            assert subprocess.run(P + ['volume', 'exists', volume], capture_output=True).returncode == 1
            run(P + ['volume', 'create', '--label=io.p0v3.restore-probe=' + prefix, volume])
        kopia('repository', 'create', 'filesystem', '--path=/repository', '--no-check-for-updates')
        snapshot_id = json.loads(kopia('snapshot', 'create', '--json', '/snapshot'))['rootEntry']['obj']
        receipt['snapshotId'] = snapshot_id
        kopia('snapshot', 'verify', '--verify-files-percent=100')
        kopia('snapshot', 'restore', '--no-overwrite-files', '--no-overwrite-directories', '--no-overwrite-symlinks',
              '--skip-owners', '--flush-files', snapshot_id, '/restore/recovered')
        for process, before in frozen.items():
            after = inspect(source, process)
            assert before['Id'] == after['Id'] and before['State']['StartedAt'] == after['State']['StartedAt']
            assert before['State']['Running'] == after['State']['Running']
        assert digest(BASE / source / 'runtime.jobs') == jobs and digest(BASE / (source + '.json')) == source_hash
        lock.close(); lock = None
        release_fence()
        system('enable', '--now'); maintenance = False
        source_only = browser(source)
        receipt['sourceAfterSnapshotFixture'] = source_only['id']
        recovered = export / 'recovered'
        assert digest(recovered / 'manifest.json') == receipt['archiveManifestSha256']
        assert json.loads((recovered / 'manifest.json').read_text()) == hashes
        assert {str(p.relative_to(recovered)) for p in recovered.rglob('*') if p.is_file()} == set(hashes) | {'manifest.json'}
        for file, expected in hashes.items():
            assert digest(recovered / file) == expected
        recovered_fixture = directory / 'recovered-fixture'
        recovered_fixture.mkdir(mode=0o700)
        write(recovered_fixture / 'receipt.json', (recovered / 'fixture.json').read_bytes())
        receipt['phase'] = 'restore-empty-target'
        assert not (BASE / (target + '.json')).exists()
        run([str(CLI), 'runtime', 'prepare-firefly-restore', str(INVENTORY), str(recovered / 'inputs'), target])
        assert all(p['state'] == 'absent' for p in runtime('provision-private', target))
        staged = runtime('stage-private', target, 'firefly-db-init')
        assert {p['id'] for p in staged if p['state'] == 'running'} == {'postgres'}
        with (recovered / 'postgres.dump').open('rb') as dump:
            run(P + ['exec', '-i', 'p0v3-live-' + target + '-postgres', 'pg_restore', '-U', 'postgres', '-d', 'firefly',
                     '--role=firefly', '--no-owner', '--no-privileges', '--exit-on-error'], stdin=dump)
        for volume in ('storage', 'cache'):
            assert tar_inventory(recovered / (volume + '.tar')) == trees[volume]
            with (recovered / (volume + '.tar')).open('rb') as data:
                volume_helper(target, volume, False,
                    'test -z "$(ls -A /data)"; touch /data/.restore-in-progress; tar --no-same-owner -xpf - -C /data', stdin=data)
            check_path = directory / ('restored-' + volume + '.tar')
            # Keep the incomplete marker until content/mode verification succeeds.
            actual = archive_volume(target, volume, check_path)
            assert '.restore-in-progress' in actual
            del actual['.restore-in-progress']
            assert actual == trees[volume]
            volume_helper(target, volume, False, "printf '%s\\n' '" + source_hash + "' > /data/.p0v3-restore-complete; sync; rm /data/.restore-in-progress; sync")
        runtime('apply-private', target)
        source_web = inspect(source, 'firefly')['NetworkSettings']['Networks']['p0v3-live-' + source + '-net']['IPAddress']
        assert re.fullmatch(r'[0-9.]+', source_web)
        run(P + ['exec', 'p0v3-live-' + target + '-php', 'php', '-r',
                 '$s=@fsockopen("' + source_web + '",8080,$e,$m,2); if($s){fclose($s);exit(1);}'])
        receipt['phase'] = 'native-restored-financial-workflows'
        readback = browser(target, recovered_fixture)
        assert count_account(target, source_only['fixtureNonce']) == 0
        restored_only = browser(target)
        assert count_account(source, restored_only['fixtureNonce']) == 0
        assert count_account(target, restored_only['fixtureNonce']) == 1
        assert count_account(source, source_only['fixtureNonce']) == 1
        browser(source, fixture)
        receipt.update(passed=True, phase='complete', encryptedSnapshotVerified=True, recoveredInputsAndKeys=True,
            migrationsNotReplayed=True, restoredFinancialReadback=True, nativeRestoredFinancialWrites=True,
            sourceMutationExcluded=True, restoredWritesIsolated=True, sourceTcpBlockedFromRestore=True,
            restoredReadbackReceipt=readback['id'], restoredWriteReceipt=restored_only['id'])
    finally:
        if lock is not None:
            lock.close()
        if maintenance:
            try:
                release_fence()
                system('enable', '--now')
            except Exception:
                receipt.update(passed=False, sourceResumeFailed=True)
        if (BASE / (target + '.json')).exists():
            try:
                runtime('stop-private', target)
            except Exception:
                receipt.update(passed=False, quarantineFailed=True)
        write(directory / 'receipt.json', json.dumps(receipt, indent=2).encode())
    assert receipt['passed']
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    if not __debug__:
        raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
