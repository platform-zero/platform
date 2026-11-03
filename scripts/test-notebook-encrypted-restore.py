#!/usr/bin/env python3
"""Exercise reusable single-user recovery with encrypted notebook data, recovered credentials and a real kernel."""
import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
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
    parser.add_argument('--source', default='notebook-r2')
    parser.add_argument('--fixture', type=Path, required=True)
    args = parser.parse_args()
    source = args.source
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', source)
    assert args.fixture.is_absolute() and args.fixture.resolve() == args.fixture and args.fixture.stat().st_mode & 0o777 == 0o700
    previous = json.loads((args.fixture / 'receipt.json').read_text())
    assert previous['passed'] and previous['scope'] == 'persistent-private-notebook-not-full-stack'
    assert re.fullmatch(r'p0v3-notebook-[a-f0-9]{12}', previous['id'])
    notebook = 'p0v3-' + previous['id'][-12:] + '.ipynb'
    nonce = uuid.uuid4().hex[:12]
    prefix, target = 'p0v3-notebook-restore-' + nonce, 'nrestore-' + nonce
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / prefix
    directory.mkdir(mode=0o700)
    recovered = directory / 'recovered'
    recovered.mkdir(mode=0o700)
    env = directory / 'kopia.env'
    private_write(env, ('KOPIA_PASSWORD=' + secrets.token_hex(32) + '\n').encode())
    images = json.loads(INVENTORY.read_text())['images']
    kopia_image = next(i['pinnedImage'] for i in images if i['product'] == 'kopia')
    image = next(i['pinnedImage'] for i in images if i['product'] == 'jupyter-notebook')
    source_manifest = (BASE / (source + '.json')).read_bytes()
    source_hash = hashlib.sha256(source_manifest).hexdigest()
    spec = json.loads(source_manifest)
    assert spec['name'] == source and next(p['image'] for p in spec['processes'] if p['id'] == 'notebook') == image
    assert spec['volumes'] == [{'id': 'home', 'userId': 1000}]
    inputs = sorted({p['environmentFile'] for p in spec['processes'] if p.get('environmentFile')} |
                    {f['file'] for p in spec['processes'] for f in p.get('files', [])})
    input_hashes = {f: hashlib.sha256((BASE / source / f).read_bytes()).hexdigest() for f in inputs}
    source_token = dict(line.split('=', 1) for line in (BASE / source / 'notebook.env').read_text().splitlines())['P0V3_NOTEBOOK_TOKEN']
    repo, config, export = [prefix + '-' + v for v in ('repository', 'config', 'export')]
    receipt = {'id': prefix, 'scope': 'private-notebook-encrypted-restore-not-full-stack', 'passed': False,
               'source': source, 'restore': target, 'offHostBackup': False, 'browserJourney': False,
               'sourceManifestSha256': source_hash}
    source_stopped, source_lock = False, None
    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))

    def pod(*arguments):
        result = subprocess.run(P + list(arguments), capture_output=True, timeout=240)
        if result.returncode:
            private_write(directory / ('failure-' + uuid.uuid4().hex[:8] + '.log'), result.stderr)
            raise RuntimeError('Scoped restore Podman operation failed: ' + arguments[0])
        return result.stdout

    def runtime(action, deployment):
        result = subprocess.run([str(CLI), 'runtime', action, str(BASE / (deployment + '.json'))], capture_output=True, timeout=900,
            env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0, 'Scoped restore runtime lifecycle failed'
        return json.loads(result.stdout.splitlines()[0])

    def address(deployment):
        data = json.loads(pod('inspect', 'p0v3-live-' + deployment + '-notebook'))[0]
        assert data['Config']['Labels']['io.p0v3.private-deployment'] == deployment and not data['HostConfig']['PortBindings']
        assert set(data['NetworkSettings']['Networks']) == {'p0v3-live-' + deployment + '-net'}
        ip = data['NetworkSettings']['Networks']['p0v3-live-' + deployment + '-net']['IPAddress']
        assert ipaddress.ip_address(ip).is_private
        return ip

    def api(ip, token, path, content=None, absent=False):
        headers = {'Authorization': 'token ' + token, 'Content-Type': 'application/json'}
        request = urllib.request.Request('http://' + ip + ':8888/api/contents/' + path, headers=headers,
            data=None if content is None else json.dumps(content).encode(), method='GET' if content is None else 'PUT')
        try:
            with opener.open(request, timeout=30) as response:
                assert not absent, 'Post-snapshot artifact leaked across restore boundary'
                raw = response.read(2097153)
                assert len(raw) <= 2097152
                return json.loads(raw)
        except urllib.error.HTTPError as error:
            if absent and error.code == 404:
                return None
            raise RuntimeError('Private notebook restore API returned ' + str(error.code)) from None

    def helper(selected_image, mounts, command, entrypoint=None, extra=()):
        arguments = ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=all',
            '--security-opt=no-new-privileges', '--security-opt=apparmor=p0v3-private-v1', '--user=1000:1000',
            '--memory=1024m', '--pids-limit=256', '--image-volume=ignore', '--tmpfs=/tmp:rw,nosuid,nodev,size=128m']
        for mount in mounts:
            arguments += ['--volume', mount]
        if entrypoint:
            arguments += ['--entrypoint', entrypoint]
        return pod(*(arguments + list(extra) + [selected_image] + command))

    def kopia(*command):
        return helper(kopia_image, [repo + ':/repository:U', config + ':/config:U', export + ':/restore:U',
            'p0v3-live-' + source + '-volume-home:/snapshot/data:ro', str(BASE / source) + ':/snapshot/inputs:ro',
            str(BASE / (source + '.json')) + ':/snapshot/spec.json:ro'],
            ['--config-file=/config/repository.config', '--disable-file-logging', *command],
            extra=['--env-file', str(env), '--env=HOME=/tmp', '--env=KOPIA_CACHE_DIRECTORY=/tmp/cache'])

    try:
        runtime('apply-private', source)
        source_ip = address(source)
        baseline = api(source_ip, source_token, notebook)['content']
        assert baseline['cells'][0]['outputs'][0]['text'] == '55\n'
        receipt['phase'] = 'freeze-and-encrypt'
        stopped = runtime('stop-private', source)
        source_stopped = True
        assert all(p['exitCode'] in (0, 143) for p in stopped)
        source_lock = (BASE / source / 'runtime.lock').open('r+b')
        fcntl.lockf(source_lock, fcntl.LOCK_EX)
        frozen = json.loads(pod('inspect', 'p0v3-live-' + source + '-notebook'))[0]
        assert not frozen['State']['Running']
        for volume in (repo, config, export):
            assert subprocess.run(P + ['volume', 'exists', volume], capture_output=True).returncode == 1
            pod('volume', 'create', '--label=io.p0v3.restore-probe=' + prefix, volume)
        kopia('repository', 'create', 'filesystem', '--path=/repository', '--no-check-for-updates')
        snapshot_id = json.loads(kopia('snapshot', 'create', '--json', '/snapshot'))['rootEntry']['obj']
        receipt['snapshotId'] = snapshot_id
        kopia('snapshot', 'verify', '--verify-files-percent=100')
        kopia('snapshot', 'restore', '--no-overwrite-files', '--no-overwrite-directories', '--no-overwrite-symlinks',
              '--skip-owners', '--flush-files', snapshot_id, '/restore/export')
        after = json.loads(pod('inspect', 'p0v3-live-' + source + '-notebook'))[0]
        assert not after['State']['Running'] and after['Id'] == frozen['Id'] and after['State']['StartedAt'] == frozen['State']['StartedAt']
        source_lock.close()
        source_lock = None
        runtime('apply-private', source)
        source_stopped = False
        source_ip = address(source)
        source_only = 'source-only-' + nonce + '.txt'
        api(source_ip, source_token, source_only, {'type': 'file', 'format': 'text', 'content': 'source only ' + nonce})
        receipt['phase'] = 'recover-exported-inputs'
        exported_spec = helper(image, [export + ':/export:ro'], ['-ec', 'head -c 1048577 /export/export/spec.json'], '/bin/sh')
        assert exported_spec == source_manifest
        private_write(recovered / 'source-spec.json', exported_spec)
        for file in inputs:
            assert re.fullmatch(r'[a-z][a-z0-9.-]{0,79}', file)
            content = helper(image, [export + ':/export:ro'], ['-ec', 'head -c 1048577 /export/export/inputs/' + file], '/bin/sh')
            assert hashlib.sha256(content).hexdigest() == input_hashes[file]
            private_write(recovered / file, content)
        restored_token = dict(line.split('=', 1) for line in (recovered / 'notebook.env').read_text().splitlines())['P0V3_NOTEBOOK_TOKEN']
        result = subprocess.run([str(CLI), 'runtime', 'prepare-single-user-restore', str(INVENTORY), str(recovered), target], capture_output=True,
            timeout=30, env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0
        assert all(p['state'] == 'absent' for p in runtime('provision-private', target))
        helper(image, [export + ':/export:ro', 'p0v3-live-' + target + '-volume-home:/target:U'], ['-ec',
            'test -z "$(ls -A /target)"; touch /target/.restore-in-progress; cp -a /export/export/data/. /target/; '
            'rm /target/.restore-in-progress; if ! diff -r /export/export/data /target; then touch /target/.restore-in-progress; exit 1; fi; '
            "printf '%s\\n' '" + source_hash + "' > /target/.p0v3-restore-complete; sync"], '/bin/sh')
        receipt['phase'] = 'isolated-execution'
        runtime('apply-private', target)
        restored_ip = address(target)
        assert restored_ip != source_ip
        pod('exec', 'p0v3-live-' + target + '-notebook', '/opt/conda/bin/python', '-c',
            'import socket; s=socket.socket(); s.settimeout(2); assert s.connect_ex(("' + source_ip + '",8888)) != 0; s.close()')
        assert api(restored_ip, restored_token, notebook)['content'] == baseline
        api(restored_ip, restored_token, source_only, absent=True)
        jars = list(Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1/com.google.code.gson/gson/2.12.1').glob('*/*.jar'))
        assert len(jars) == 1
        restored_file = 'p0v3-' + nonce + '.ipynb'
        with tempfile.TemporaryDirectory(prefix='nr-', dir='/mnt/media/p0-v3/cache') as scratch:
            execution = subprocess.run(['/usr/lib/jvm/java-21-openjdk-amd64/bin/java', '-Djava.io.tmpdir=' + scratch, '--class-path', str(jars[0]),
                str(ROOT / 'acceptance/scripts/NotebookKernelProbe.java')], input=json.dumps({'address': restored_ip, 'token': restored_token,
                'file': restored_file, 'mode': 'execute'}), capture_output=True, text=True, timeout=240)
            private_write(directory / 'restored-kernel.log', execution.stderr.replace(restored_token, '[redacted]').encode())
            assert execution.returncode == 0
        assert api(restored_ip, restored_token, restored_file)['content']['cells'][0]['outputs'][0]['text'] == '55\n'
        api(source_ip, source_token, restored_file, absent=True)
        assert api(source_ip, source_token, notebook)['content'] == baseline
        receipt.update(passed=True, phase='complete', encryptedSnapshotVerified=True, inputManifestAndCredentialsRecovered=True,
            savedNotebookRestored=True, realRestoredKernelExecuted=True, sourceMutationExcluded=True,
            restoredWritesIsolated=True, sourceTcpBlockedFromRestore=True)
    finally:
        if source_lock is not None:
            source_lock.close()
        if source_stopped:
            try:
                runtime('apply-private', source)
            except Exception:
                receipt.update(passed=False, sourceResumeFailed=True)
        if (BASE / (target + '.json')).exists():
            try:
                runtime('stop-private', target)
            except Exception:
                receipt.update(passed=False, restoredQuarantineFailed=True)
        private_write(directory / 'receipt.json', json.dumps(receipt, indent=2).encode())
    assert receipt['passed']
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
