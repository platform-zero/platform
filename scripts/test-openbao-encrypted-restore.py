#!/usr/bin/env python3
"""Quiesced Raft/audit/config/shares recovery on a separate network; no production custody claim."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import uuid
from financial_restore_archive import inventory as tar_inventory

SPEC = importlib.util.spec_from_file_location('bao_probe', Path(__file__).with_name('test-private-openbao.py'))
B = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(B)
ROOT, BASE, CLI, P = B.ROOT, B.BASE, B.CLI, B.P
INVENTORY = ROOT / 'platform/release/downloaded-candidate-inventory.json'
JAVA = {**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'}


def raw_write(path, data):
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb') as out:
        out.write(data); out.flush(); os.fsync(out.fileno())


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--fixture', required=True, type=Path); args = parser.parse_args()
    fixture = args.fixture
    assert fixture.is_absolute() and fixture.resolve() == fixture and fixture.stat().st_mode & 0o777 == 0o700
    assert not (fixture / 'recovery.json').is_symlink() and (fixture / 'recovery.json').stat().st_mode & 0o777 == 0o600
    old = json.loads((fixture / 'receipt.json').read_text()); source = old['deployment']; assert old['passed']
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', source)
    state = json.loads((fixture / 'recovery.json').read_text()); record = json.loads((fixture / 'fixture.json').read_text())
    source_bytes = (BASE / (source + '.json')).read_bytes(); spec = json.loads(source_bytes); source_hash = hashlib.sha256(source_bytes).hexdigest()
    assert source_hash == state['sourceManifestSha256'] and len(spec['processes']) == 1 and spec['processes'][0]['id'] == 'bao'
    nonce = uuid.uuid4().hex[:12]; target = 'brestore-' + nonce
    directory = fixture.parent / ('p0v3-bao-restore-' + nonce); directory.mkdir(mode=0o700)
    snapshot, export = directory / 'snapshot', directory / 'export'; snapshot.mkdir(mode=0o700); export.mkdir(mode=0o700)
    (snapshot / 'inputs').mkdir(mode=0o700)
    assert not (BASE / (target + '.json')).exists() and not (BASE / target).exists()
    unit = 'p0v3-private-' + source + '.service'; unit_path = Path('/etc/systemd/system') / unit
    assert not unit_path.is_symlink() and unit_path.stat().st_uid == 0
    assert re.search(r'^ExecStart=/mnt/media/p0-v3/runtime-supervision/releases/[a-f0-9]{64}/bin/p0-v3-platform runtime boot-apply ' + re.escape(source) + ' ' + source_hash + '$', unit_path.read_text(), re.M)
    images = json.loads(INVENTORY.read_text())['images']; kopia_image = next(i['pinnedImage'] for i in images if i['product'] == 'kopia')
    image = spec['processes'][0]['image']; repo, config = directory.name + '-repository', directory.name + '-config'
    raw_write(directory / 'kopia.env', ('KOPIA_PASSWORD=' + secrets.token_hex(32) + '\n').encode())
    receipt = {'id': directory.name, 'source': source, 'restore': target, 'passed': False, 'fullStackAcceptance': False,
               'scope': 'private-raft-secrets-recovery', 'productionKeyCustody': False, 'offHostBackup': False, 'sourceManifestSha256': source_hash}
    maintenance, lock, fence = False, None, None

    def run(command, stdin=None, stdout=None):
        result = subprocess.run(command, stdin=stdin, stdout=stdout or subprocess.PIPE, stderr=subprocess.PIPE, env=JAVA, timeout=1200)
        if result.returncode:
            raw_write(directory / ('failure-' + uuid.uuid4().hex[:8] + '.log'), result.stderr)
            raise RuntimeError('Scoped OpenBao recovery failed; private diagnostics retained')
        return result.stdout

    def system(*args): return run(['sudo', '-n', 'systemctl', *args, unit])
    def release_fence():
        nonlocal fence
        if fence is None:
            assert json.loads(run([str(CLI), 'runtime', 'maintenance-status', str(BASE / (source + '.json'))])) is None, 'Uncertain maintenance identity; retaining fence'
            return
        B.runtime('stop-private', source)
        run([str(CLI), 'runtime', 'maintenance-leave', str(BASE / (source + '.json')), fence['id']])
        fence = None

    def inspect(name): return json.loads(run(P + ['inspect', 'p0v3-live-' + name + '-bao']))[0]
    def volume(name, readonly, command, stdin=None, stdout=None):
        return run(P + ['run', '--rm', '-i', '--pull=never', '--network=none', '--read-only', '--cap-drop=all',
            '--security-opt=no-new-privileges', '--security-opt=apparmor=p0v3-private-v1', '--user=1000:1000', '--memory=512m',
            '--pids-limit=128', '--image-volume=ignore', '--tmpfs=/tmp:rw,nosuid,nodev,size=64m',
            '--volume', 'p0v3-live-' + name + '-volume-data:/data:' + ('ro' if readonly else 'U'), '--entrypoint=/bin/sh', image, '-ec', command], stdin, stdout)

    def archive(name, path):
        with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'wb') as out:
            volume(name, True, 'tar -cf - -C /data .', stdout=out); out.flush(); os.fsync(out.fileno())
        return tar_inventory(path)

    def kopia(*args):
        return run(P + ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=all',
            '--security-opt=no-new-privileges', '--security-opt=apparmor=p0v3-private-v1', '--user=1000:1000', '--memory=1024m',
            '--pids-limit=256', '--image-volume=ignore', '--tmpfs=/tmp:rw,nosuid,nodev,size=128m',
            '--volume', repo + ':/repository:U', '--volume', config + ':/config:U', '--volume', str(snapshot) + ':/snapshot:ro',
            '--volume', str(export) + ':/restore:rw', '--env-file', str(directory / 'kopia.env'), '--env=HOME=/tmp', '--env=KOPIA_CACHE_DIRECTORY=/tmp/cache',
            kopia_image, '--config-file=/config/repository.config', '--disable-file-logging', *args])

    try:
        assert system('is-enabled').strip() == b'enabled' and system('is-active').strip() == b'active'
        B.runtime('apply-private', source); source_bao = B.Bao(source); source_bao.unseal(state)
        assert source_bao.request('GET', 'keykeeper/data/' + record['item'], token=state['root_token'])['data']['data']['value'] == record['value']
        receipt['phase'] = 'freeze-and-encrypt'
        maintenance = True; system('disable', '--now')
        assert json.loads(run([str(CLI), 'runtime', 'maintenance-status', str(BASE / (source + '.json'))])) is None
        fence = json.loads(run([str(CLI), 'runtime', 'maintenance-enter', str(BASE / (source + '.json')), 'backup']))
        blocked = subprocess.run([str(CLI), 'runtime', 'apply-private', str(BASE / (source + '.json'))], capture_output=True, env=JAVA, timeout=120)
        assert blocked.returncode != 0
        receipt['durableSourceFenceVerified'] = True
        lock = (BASE / source / 'runtime.lock').open('r+b'); fcntl.lockf(lock, fcntl.LOCK_EX)
        frozen = inspect(source); assert not frozen['State']['Running']
        inputs = {spec['processes'][0]['environmentFile']} | {f['file'] for f in spec['processes'][0]['files']}
        raw_write(snapshot / 'inputs/source-spec.json', source_bytes)
        for name in inputs:
            path = BASE / source / name
            assert re.fullmatch(r'[a-z][a-z0-9.-]{0,79}', name) and not path.is_symlink() and path.stat().st_mode & 0o777 == 0o600
            raw_write(snapshot / 'inputs' / name, path.read_bytes())
        raw_write(snapshot / 'recovery.json', (fixture / 'recovery.json').read_bytes())
        raw_write(snapshot / 'fixture.json', (fixture / 'fixture.json').read_bytes())
        tree = archive(source, snapshot / 'backend.tar')
        assert 'audit.log' in tree and any('raft' in name for name in tree)
        backend = (snapshot / 'backend.tar').read_bytes()
        assert record['value'].encode() not in backend and state['root_token'].encode() not in backend
        assert all(key.encode() not in backend for key in state['keys_base64'])
        hashes = {str(p.relative_to(snapshot)): digest(p) for p in snapshot.rglob('*') if p.is_file()}
        B.private_write(snapshot / 'manifest.json', hashes); receipt['archiveManifestSha256'] = digest(snapshot / 'manifest.json')
        for name in (repo, config):
            assert subprocess.run(P + ['volume', 'exists', name], capture_output=True).returncode == 1
            run(P + ['volume', 'create', '--label=io.p0v3.restore-probe=' + directory.name, name])
        kopia('repository', 'create', 'filesystem', '--path=/repository', '--no-check-for-updates')
        snapshot_id = json.loads(kopia('snapshot', 'create', '--json', '/snapshot'))['rootEntry']['obj']; receipt['snapshotId'] = snapshot_id
        kopia('snapshot', 'verify', '--verify-files-percent=100')
        kopia('snapshot', 'restore', '--no-overwrite-files', '--no-overwrite-directories', '--no-overwrite-symlinks', '--skip-owners', '--flush-files', snapshot_id, '/restore/recovered')
        after = inspect(source)
        assert frozen['Id'] == after['Id'] and frozen['State']['StartedAt'] == after['State']['StartedAt'] and not after['State']['Running']
        assert digest(BASE / (source + '.json')) == source_hash
        for name in inputs: assert digest(BASE / source / name) == hashes['inputs/' + name]
        lock.close(); lock = None; release_fence(); system('enable', '--now'); maintenance = False
        source_bao.refresh(); source_bao.unseal(state)
        source_only = str(uuid.uuid4())
        source_bao.request('POST', 'keykeeper/data/' + source_only, {'options': {'cas': 0}, 'data': {'value': 'after-snapshot'}}, state['root_token'])
        recovered = export / 'recovered'
        assert digest(recovered / 'manifest.json') == receipt['archiveManifestSha256']
        assert {str(p.relative_to(recovered)) for p in recovered.rglob('*') if p.is_file()} == set(hashes) | {'manifest.json'}
        assert all(not p.is_symlink() for p in recovered.rglob('*'))
        for name, checksum in hashes.items(): assert digest(recovered / name) == checksum
        assert tar_inventory(recovered / 'backend.tar') == tree
        recovered_state = json.loads((recovered / 'recovery.json').read_text())
        assert recovered_state == state
        run([str(CLI), 'runtime', 'prepare-single-user-restore', str(INVENTORY), str(recovered / 'inputs'), target])
        B.runtime('provision-private', target)
        with (recovered / 'backend.tar').open('rb') as data:
            volume(target, False, 'test -z "$(ls -A /data)"; touch /data/.restore-in-progress; tar -xf - -C /data; sync', stdin=data)
        restored_tree = archive(target, directory / 'verified-target.tar'); assert restored_tree.pop('.restore-in-progress')['directory'] is False
        assert restored_tree == tree
        volume(target, False, 'rm /data/.restore-in-progress; printf "%s\\n" ' + source_hash + ' > /data/.p0v3-restore-complete; sync')
        receipt['phase'] = 'isolated-threshold-and-secret-recovery'
        B.runtime('apply-private', target); restored = B.Bao(target)
        assert restored.request('GET', 'sys/seal-status')['sealed']; restored.unseal(recovered_state)
        result = restored.request('GET', 'keykeeper/data/' + record['item'], token=recovered_state['root_token'])['data']
        assert result['metadata']['version'] == 2 and result['data']['value'] == record['value']
        restored.request('GET', 'keykeeper/data/' + source_only, token=recovered_state['root_token'], expected=(404,))
        new_id = str(uuid.uuid4())
        restored.request('POST', 'keykeeper/data/' + new_id, {'options': {'cas': 0}, 'data': {'value': 'restore-only'}}, recovered_state['root_token'])
        source_bao.request('GET', 'keykeeper/data/' + new_id, token=state['root_token'], expected=(404,))
        B.runtime('stop-private', target); B.runtime('apply-private', target); restored.refresh(); restored.unseal(recovered_state)
        assert restored.request('GET', 'keykeeper/data/' + new_id, token=recovered_state['root_token'])['data']['data']['value'] == 'restore-only'
        data = inspect(target)
        code = 'import socket; s=socket.socket(); s.settimeout(3); assert s.connect_ex((' + repr(source_bao.address) + ',8200)) != 0'
        run(['sudo', '-n', 'nsenter', '--target=' + str(data['State']['Pid']), '--net', '--setuid=' + str(os.getuid()), '--setgid=' + str(os.getgid()), '/usr/bin/python3', '-c', code])
        receipt.update(passed=True, phase='complete', encryptedExportVerified=True, raftAndAuditTreeVerified=True,
                       restoredThresholdUnseal=True, versionedSecretRecovered=True, plaintextAbsentFromBackendArchive=True,
                       postSnapshotWriteExcluded=True, divergentWritesIsolated=True, sourceTcpBlockedFromRestore=True, restoredRestartVerified=True)
    finally:
        if lock: lock.close()
        if maintenance:
            try: release_fence(); system('enable', '--now'); source_bao.refresh(); source_bao.unseal(state)
            except Exception: receipt.update(passed=False, sourceResumeFailed=True)
        if (BASE / (target + '.json')).exists():
            try: assert all(p['state'] != 'running' for p in B.runtime('stop-private', target))
            except Exception: receipt.update(passed=False, restoredQuarantineFailed=True)
        B.private_write(directory / 'receipt.json', receipt)
    assert receipt['passed']; print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    if not __debug__: raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
