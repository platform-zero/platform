#!/usr/bin/env python3
"""Real, private Caddy -> ntfy roundtrip and stopped-cache isolated restore.
Uses already acquired digest images, generated unique v3 names and no published ports.
Retains named volumes and private receipt. This is component evidence, never full-stack acceptance.
"""
import json
import os
import secrets
import subprocess
import time
import uuid
from pathlib import Path

STORE = '/mnt/media/p0-v3/release-runtime'
P = ['sudo', '-n', 'podman', '--root=' + STORE + '/graph',
     '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=' + STORE + '/network-config']
RECEIPTS = Path('/mnt/media/p0-v3/image-acquisition-receipts')

def run(*args, timeout=60):
    result = subprocess.run(P + list(args), capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Private component command failed: ' + result.stderr[-3000:])
    return result.stdout.strip()

def image(name):
    d = json.loads((RECEIPTS / (name + '.json')).read_text())
    ref = d['pinnedImage']
    actual = json.loads(run('image', 'inspect', ref))[0]
    if actual['Id'] != d['imageId']:
        raise RuntimeError('Candidate image identity mismatch')
    return ref

def main():
    token = uuid.uuid4().hex[:12]
    prefix = 'p0v3-ingress-' + token
    network = prefix + '-net'
    source, restored, proxy, restore_proxy = [prefix + suffix for suffix in ('-ntfy', '-restore', '-caddy', '-caddy-restore')]
    source_volume, restore_volume = prefix + '-data', prefix + '-restored-data'
    caddy, ntfy, kopia_image = image('caddy'), image('ntfy'), image('kopia')
    backup_volume, backup_config = prefix + '-backup', prefix + '-backup-config'
    password_file = RECEIPTS / (prefix + '-kopia.env')
    fd = os.open(password_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as secret:
        secret.write('KOPIA_PASSWORD=' + secrets.token_urlsafe(48) + '\n')
        secret.flush()
        os.fsync(secret.fileno())
    containers = []
    receipt = {'scope': 'real-private-caddy-ntfy-kopia-component-test-not-full-stack', 'id': prefix,
               'sourceVolume': source_volume, 'restoredVolume': restore_volume,
               'encryptedBackupVolume': backup_volume, 'backupConfigVolume': backup_config,
               'recoveryKeyFile': str(password_file), 'passed': False}
    try:
        run('network', 'create', '--internal', network)
        run('volume', 'create', source_volume)
        run('volume', 'create', restore_volume)
        run('volume', 'create', backup_volume)
        run('volume', 'create', backup_config)
        def kopia(*args):
            return run('run', '--rm', '--pull=never', '--network=none', '--read-only',
                       '--cap-drop=all', '--security-opt=no-new-privileges', '--user=65532:65532',
                       '--tmpfs=/tmp:rw,nosuid,nodev,size=64m', '--env-file', str(password_file),
                       '--env=HOME=/tmp', '--env=KOPIA_CACHE_DIRECTORY=/tmp/cache',
                       '--volume', backup_volume + ':/repository:U', '--volume', backup_config + ':/config:U',
                       '--volume', source_volume + ':/source:ro', '--volume', restore_volume + ':/restore:U',
                       kopia_image, '--config-file=/config/repository.config', '--disable-file-logging', *args,
                       timeout=120)
        def start_ntfy(name, volume, cache_path='/data/cache.db'):
            run('run', '-d', '--name', name, '--pull=never', '--network', network,
                '--read-only', '--cap-drop=all', '--security-opt=no-new-privileges', '--user=65532:65532',
                '--volume', volume + ':/data:U', ntfy, 'serve', '--listen-http=:8080',
                '--cache-file=' + cache_path, '--cache-duration=24h')
            containers.append(name)
        def start_proxy(name, backend):
            run('run', '-d', '--name', name, '--pull=never', '--network', network,
                '--read-only', '--cap-drop=all', '--cap-add=NET_BIND_SERVICE',
                '--security-opt=no-new-privileges', '--user=65532:65532',
                caddy, 'caddy', 'reverse-proxy', '--from', 'http://:8080', '--to', 'http://' + backend + ':8080')
            containers.append(name)
        def read(name):
            return run('exec', name, 'wget', '-qO-', 'http://127.0.0.1:8080/fixture/json?poll=1&since=all', timeout=10)
        def ready(name):
            for _ in range(40):
                try:
                    run('exec', name, 'wget', '-qO-', 'http://127.0.0.1:8080/v1/health', timeout=5)
                    return
                except (subprocess.SubprocessError, RuntimeError):
                    time.sleep(1)
            raise RuntimeError('Private readiness timed out')
        def post(name, message):
            return json.loads(run('exec', name, 'wget', '-qO-', '--post-data=' + message,
                                  'http://127.0.0.1:8080/fixture'))
        start_ntfy(source, source_volume)
        start_proxy(proxy, source)
        ready(proxy)
        original = post(proxy, 'p0v3-before-snapshot-' + token)
        assert original['id'] in read(proxy)
        run('stop', source)
        # Closed SQLite files go through encrypted Kopia, then into a fresh separate volume.
        kopia('repository', 'create', 'filesystem', '--path=/repository', '--no-check-for-updates')
        snapshot = json.loads(kopia('snapshot', 'create', '--json', '/source'))
        snapshot_id = snapshot['rootEntry']['obj']
        receipt['snapshotId'] = snapshot_id
        kopia('snapshot', 'verify', '--verify-files-percent=100')
        run('run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=all',
            '--volume', restore_volume + ':/restore:ro', '--entrypoint', '/bin/sh', caddy,
            '-ec', 'test -z "$(ls -A /restore)"')
        kopia('snapshot', 'restore', '--no-overwrite-files', '--no-overwrite-directories',
              '--no-overwrite-symlinks', '--skip-owners', '--flush-files', snapshot_id, '/restore/data')
        run('start', source)
        ready(proxy)
        start_ntfy(restored, restore_volume, '/data/data/cache.db')
        start_proxy(restore_proxy, restored)
        ready(restore_proxy)
        assert original['id'] in read(restore_proxy)
        restored_post = post(restore_proxy, 'p0v3-only-in-restored-' + token)
        assert restored_post['id'] in read(restore_proxy)
        assert restored_post['id'] not in read(proxy)
        receipt.update(passed=True, originalMessageId=original['id'], restoredMessageId=restored_post['id'])
        print(json.dumps(receipt, indent=2))
    finally:
        for name in reversed(containers):
            subprocess.run(P + ['rm', '-f', name], capture_output=True, timeout=40)
        subprocess.run(P + ['network', 'rm', network], capture_output=True, timeout=40)
        (RECEIPTS / (prefix + '.json')).write_text(json.dumps(receipt, indent=2) + '\n')

if __name__ == '__main__':
    main()
