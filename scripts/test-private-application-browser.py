#!/usr/bin/env python3
"""Run real Chromium in the audited application's network namespace, dropping to the invoking UID/GID."""
import argparse
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
BASE = Path('/mnt/media/p0-v3/runtime-deployments')


def private_write(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('application', choices=('forgejo', 'planka'))
    parser.add_argument('--deployment', required=True)
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--stop-after', action='store_true', help='Quarantine a restored instance after the browser journey')
    args = parser.parse_args()
    name = args.deployment
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    fixture = json.loads((args.fixture / 'receipt.json').read_text())
    assert fixture['passed'] and fixture['scope'] == 'persistent-private-' + args.application + '-not-full-stack'
    run_id = 'p0v3-browser-' + uuid.uuid4().hex[:12]
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / run_id
    directory.mkdir(mode=0o700)
    receipt = {'id': run_id, 'scope': 'private-application-browser-not-full-stack', 'application': args.application,
               'deployment': name, 'fixture': fixture['id'], 'passed': False}

    def runtime(action):
        result = subprocess.run([str(CLI), 'runtime', action, str(BASE / (name + '.json'))], capture_output=True, text=True,
                                timeout=900, env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0, 'Owned runtime lifecycle failed'

    try:
        runtime('apply-private')
        data = json.loads(subprocess.check_output(P + ['inspect', 'p0v3-live-' + name + '-' + args.application], stderr=subprocess.DEVNULL))[0]
        assert data['Config']['Labels']['io.p0v3.private-deployment'] == name and data['State']['Running']
        networks = data['NetworkSettings']['Networks']
        assert set(networks) == {'p0v3-live-' + name + '-net'} and not data['HostConfig']['PortBindings']
        inputs = {'application': args.application, 'address': networks['p0v3-live-' + name + '-net']['IPAddress'],
                  'directory': str(directory), 'fixtureId': fixture['id']}
        if args.application == 'forgejo':
            inputs.update(json.loads((args.fixture / 'user.json').read_text()))
        else:
            values = dict(line.split('=', 1) for line in (BASE / name / 'planka.env').read_text().splitlines())
            inputs.update(username=values['DEFAULT_ADMIN_EMAIL'], password=values['DEFAULT_ADMIN_PASSWORD'], cardId=fixture['cardId'])
        cache = Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1')
        jars = [jar for artifact in ('driver', 'driver-bundle', 'playwright')
                for jar in sorted((cache / ('com.microsoft.playwright/' + artifact + '/1.55.0')).glob('*/*.jar'))]
        jars += sorted((cache / 'com.google.code.gson/gson/2.12.1').glob('*/*.jar'))
        assert len(jars) == 4
        with tempfile.TemporaryDirectory(prefix='ab-', dir='/mnt/media/p0-v3/cache') as scratch:
            command = ['sudo', '-n', 'nsenter', '--target=' + str(data['State']['Pid']), '--net',
                       '--setuid=' + str(os.getuid()), '--setgid=' + str(os.getgid()),
                       '/usr/bin/env', 'HOME=' + scratch, 'TMPDIR=' + scratch,
                       '/usr/lib/jvm/java-21-openjdk-amd64/bin/java', '-Djava.io.tmpdir=' + scratch,
                       '--class-path', ':'.join(map(str, jars)), str(ROOT / 'acceptance/scripts/PrivateApplicationBrowserProbe.java')]
            result = subprocess.run(command, input=json.dumps(inputs), capture_output=True, text=True, timeout=180)
            private_write(directory / 'chromium.log', result.stderr)
            assert result.returncode == 0, 'Real Chromium journey failed; private diagnostic retained'
            receipt.update(json.loads(result.stdout), passed=True)
    finally:
        if args.stop_after:
            try:
                runtime('stop-private')
            except Exception:
                receipt.update(passed=False, stopFailed=True)
        private_write(directory / 'receipt.json', json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))
    assert receipt['passed']


if __name__ == '__main__':
    main()
