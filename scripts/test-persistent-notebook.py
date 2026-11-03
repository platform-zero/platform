#!/usr/bin/env python3
"""Execute a real kernel over WebSocket, save actual output, restart and verify the saved notebook."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / 'platform/build/install/p0-v3-platform/bin/p0-v3-platform'


def private_write(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='notebook-r2')
    name = parser.parse_args().name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    base = Path('/mnt/media/p0-v3/runtime-deployments')
    manifest = base / (name + '.json')
    spec = json.loads(manifest.read_text())
    assert spec['name'] == name and {p['id'] for p in spec['processes']} == {'notebook-init', 'notebook'}
    values = dict(line.split('=', 1) for line in (base / name / 'notebook.env').read_text().splitlines())
    token = values['P0V3_NOTEBOOK_TOKEN']
    nonce = uuid.uuid4().hex[:12]
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-notebook-' + nonce)
    directory.mkdir(mode=0o700)
    receipt = {'id': directory.name, 'scope': 'persistent-private-notebook-not-full-stack', 'passed': False}

    def runtime(action):
        result = subprocess.run([str(CLI), 'runtime', action, str(manifest)], capture_output=True, text=True, timeout=900,
            env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0, 'Owned notebook lifecycle failed'
        return json.loads(result.stdout.splitlines()[0])

    def probe(mode):
        data = json.loads(subprocess.check_output(P + ['inspect', 'p0v3-live-' + name + '-notebook'], stderr=subprocess.DEVNULL))[0]
        assert data['Config']['Labels']['io.p0v3.private-deployment'] == name
        assert set(data['NetworkSettings']['Networks']) == {'p0v3-live-' + name + '-net'}
        address = data['NetworkSettings']['Networks']['p0v3-live-' + name + '-net']['IPAddress']
        assert ipaddress.ip_address(address).is_private
        jars = list(Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1/com.google.code.gson/gson/2.12.1').glob('*/*.jar'))
        assert len(jars) == 1
        with tempfile.TemporaryDirectory(prefix='nk-', dir='/mnt/media/p0-v3/cache') as scratch:
            process = subprocess.run(['/usr/lib/jvm/java-21-openjdk-amd64/bin/java', '-Djava.io.tmpdir=' + scratch,
                '--class-path', str(jars[0]), str(ROOT / 'acceptance/scripts/NotebookKernelProbe.java')],
                input=json.dumps({'address': address, 'token': token, 'file': 'p0v3-' + nonce + '.ipynb', 'mode': mode}),
                text=True, capture_output=True, timeout=240)
            private_write(directory / (mode + '.log'), process.stderr.replace(token, '[redacted]'))
            assert process.returncode == 0, 'Actual kernel/readback probe failed; private diagnostic retained'
            return json.loads(process.stdout)

    try:
        runtime('apply-private')
        receipt['phase'] = 'kernel-execution'
        receipt.update(probe('execute'))
        receipt['phase'] = 'restart'
        stopped = runtime('stop-private')
        assert all(p['exitCode'] in (0, 143) for p in stopped)
        runtime('apply-private')
        receipt.update(probe('verify'))
        logs = subprocess.run(P + ['logs', 'p0v3-live-' + name + '-notebook'], capture_output=True, text=True, timeout=20)
        assert token not in logs.stdout + logs.stderr, 'Configured notebook token appeared in daemon logs'
        receipt.update(passed=True, phase='complete', realKernelWebSocketExecution=True, savedNotebookPersisted=True,
                       cleanStopRestartVerified=True, configuredTokenAbsentFromLogs=True, browserJourney=False,
                       encryptedRestoreTest=False, multiUserHubIsolation=False)
        print(json.dumps(receipt, indent=2))
    finally:
        private_write(directory / 'receipt.json', json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
