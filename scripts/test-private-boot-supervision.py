#!/usr/bin/env python3
"""Exercise actual systemd stop/start, retained jobs and notebook state. Never reboot the shared host."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/media/p0-v3/runtime-deployments')
P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
NAMES = ['foundation-r3', 'identity-r2', 'observability', 'forgejo-r2', 'planka-r3', 'sql-cache',
         'jellyfin-r4', 'donetick', 'homeassistant-r2', 'notebook-r2', 'qbittorrent', 'matrix-r2', 'opensearch-r2', 'firefly-r2', 'bookstack-r3', 'knowledge-identity-r4', 'livekit', 'openbao-r4', 'mastodon-r4', 'matrix-identity-r4', 'searxng-r2', 'erpnext-r7', 'crowdsec-r4', 'seafile-r4', 'files-office-r7', 'keykeeper-identity-r4', 'node-metrics-r2', 'backup', 'huly-r10', 'jupyterhub-r8', 'sogo-r2']


def call(args, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=900, **kwargs)
    assert result.returncode == 0, 'Scoped supervision test command failed; state retained'
    return result.stdout


def write(path, content):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(content)
        out.flush()
        os.fsync(out.fileno())


def inventory():
    result = {}
    for name in NAMES:
        spec = json.loads((BASE / (name + '.json')).read_text())
        assert spec['name'] == name
        for process in spec['processes']:
            if process.get('oneShot', False):
                continue
            container = 'p0v3-live-' + name + '-' + process['id']
            data = json.loads(call(P + ['inspect', container]))[0]
            assert data['Config']['Labels']['io.p0v3.private-deployment'] == name and data['State']['Running']
            assert not data['HostConfig']['PortBindings']
            result[container] = {'id': data['Id'], 'started': data['State']['StartedAt']}
    return result


def initializer_states():
    result = {}
    for name in NAMES:
        spec = json.loads((BASE / (name + '.json')).read_text())
        for process in spec['processes']:
            if not process.get('oneShot', False):
                continue
            container = 'p0v3-live-' + name + '-' + process['id']
            exists = subprocess.run(P + ['container', 'exists', container], capture_output=True, timeout=30)
            assert exists.returncode in (0, 1)
            if exists.returncode == 1:
                result[container] = None
            else:
                data = json.loads(call(P + ['inspect', container]))[0]
                assert data['Config']['Labels']['io.p0v3.private-deployment'] == name
                assert data['State']['Status'] == 'exited' and data['State']['ExitCode'] == 0
                result[container] = (data['Id'], data['State']['StartedAt'])
    return result


def job_hashes():
    result = {}
    for name in NAMES:
        spec = json.loads((BASE / (name + '.json')).read_text())
        path = BASE / name / 'runtime.jobs'
        if any(p.get('oneShot', False) for p in spec['processes']):
            result[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        else:
            assert not path.exists(), 'Unexpected initialization journal'
            result[name] = None
    return result


def main():
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-boot-' + uuid.uuid4().hex[:12])
    directory.mkdir(mode=0o700)
    receipt = {'id': directory.name, 'passed': False, 'scope': 'private-systemd-lifecycle-not-full-stack',
        'hostRebootTest': False, 'fullStackAcceptance': False}
    token = dict(line.split('=', 1) for line in (BASE / 'notebook-r2/notebook.env').read_text().splitlines())['P0V3_NOTEBOOK_TOKEN']
    filename = 'p0v3-' + directory.name.rsplit('-', 1)[1] + '.ipynb'

    def kernel(mode):
        data = json.loads(call(P + ['inspect', 'p0v3-live-notebook-r2-notebook']))[0]
        assert set(data['NetworkSettings']['Networks']) == {'p0v3-live-notebook-r2-net'}
        address = data['NetworkSettings']['Networks']['p0v3-live-notebook-r2-net']['IPAddress']
        assert ipaddress.ip_address(address).is_private
        jars = list(Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1/com.google.code.gson/gson/2.12.1').glob('*/*.jar'))
        assert len(jars) == 1
        with tempfile.TemporaryDirectory(prefix='bk-', dir='/mnt/media/p0-v3/cache') as scratch:
            result = subprocess.run(['/usr/lib/jvm/java-21-openjdk-amd64/bin/java', '-Djava.io.tmpdir=' + scratch,
                '--class-path', str(jars[0]), str(ROOT / 'acceptance/scripts/NotebookKernelProbe.java')],
                input=json.dumps({'address': address, 'token': token, 'file': filename, 'mode': mode}),
                text=True, capture_output=True, timeout=240)
            write(directory / (mode + '.log'), result.stderr.replace(token, '[redacted]'))
            assert result.returncode == 0, 'Native notebook probe failed; private diagnostics retained'
            return json.loads(result.stdout)

    try:
        receipt['phase'] = 'idempotent-enrollment'
        before = inventory()
        controllers = set()
        units = ['p0v3-private-' + n + '.service' for n in NAMES]
        for name, unit in zip(NAMES, units):
            path = Path('/etc/systemd/system') / unit
            info = path.lstat()
            assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o644
            content = path.read_bytes()
            match = re.search(rb'^ExecStart=(/mnt/media/p0-v3/runtime-supervision/releases/([a-f0-9]{64})/bin/p0-v3-platform) runtime boot-apply ', content, re.M)
            assert match, 'Unit lacks a pinned controller'
            controller, digest = (v.decode() for v in match.groups())
            expected = call([controller, 'runtime', 'boot-unit', name, digest, str(os.getuid())],
                env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
            assert content == expected, 'Installed unit or manifest drifted'
            controllers.add(digest)
        call(['sudo', '-n', 'systemctl', 'enable', '--now', *units])
        assert inventory() == before, 'Repeated unit enrollment restarted or replaced a daemon'
        jobs = job_hashes()
        initializers = initializer_states()
        receipt['phase'] = 'real-kernel-write'
        kernel('execute')
        receipt['phase'] = 'systemd-restart'
        call(['sudo', '-n', 'systemctl', 'restart', *units])
        after = inventory()
        assert set(before) == set(after)
        assert all(before[n]['id'] == after[n]['id'] and before[n]['started'] != after[n]['started'] for n in before)
        assert jobs == job_hashes()
        assert initializers == initializer_states(), 'Completed initializer reran or was recreated'
        for unit in units:
            assert call(['systemctl', 'is-enabled', unit]).strip() == b'enabled'
            assert call(['systemctl', 'is-active', unit]).strip() == b'active'
        receipt['phase'] = 'functional-readback'
        kernel('verify')
        sealed = subprocess.run(P + ['exec', 'p0v3-live-openbao-r4-bao', '/usr/bin/bao', 'status', '-format=json'], capture_output=True, timeout=30)
        assert sealed.returncode == 2 and json.loads(sealed.stdout)['sealed']
        receipt['manualUnsealRequired'] = ['openbao-r4']
        receipt.update(passed=True, phase='complete', controllerTreeSha256s=sorted(controllers),
            units=units, restartedDaemons=len(after), containerIdentitiesPreserved=True, initializationJournalsUnchanged=True, completedInitializersNotReplayed=True,
            repeatedEnrollmentIdempotent=True, actualKernelWriteAndReadback=True, imageUpdates=False)
    finally:
        write(directory / 'receipt.json', json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    if not __debug__: raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
