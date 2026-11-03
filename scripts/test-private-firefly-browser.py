#!/usr/bin/env python3
"""Native private Firefly browser journey with synthetic finances, then fresh-login readback after restart."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/media/p0-v3/runtime-deployments')
CLI = ROOT / 'platform/build/install/p0-v3-platform/bin/p0-v3-platform'
P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']


def write(path, text):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(text)
        out.flush()
        os.fsync(out.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='firefly-r2')
    parser.add_argument('--verify-fixture', type=Path)
    args = parser.parse_args()
    name = args.name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    spec = json.loads((BASE / (name + '.json')).read_text())
    assert spec['name'] == name and {p['id'] for p in spec['processes']} == {
        'postgres-init', 'postgres', 'firefly-db-init', 'firefly-files-init', 'firefly-migrate', 'php', 'firefly'}
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-firefly-browser-' + uuid.uuid4().hex[:12])
    directory.mkdir(mode=0o700)
    receipt = {'id': directory.name, 'scope': 'private-firefly-browser-not-full-stack', 'deployment': name, 'passed': False,
        'encryptedRestoreTest': False, 'publicHttpsTest': False, 'fullStackAcceptance': False}
    values = dict(line.split('=', 1) for line in (BASE / name / 'firefly.env').read_text().splitlines())
    inputs = {'directory': str(directory), 'password': values['P0V3_FIXTURE_PASSWORD'], 'nonce': uuid.uuid4().hex[:12]}
    fixture = None
    if args.verify_fixture:
        assert args.verify_fixture.is_absolute() and args.verify_fixture.resolve() == args.verify_fixture
        assert args.verify_fixture.stat().st_mode & 0o777 == 0o700
        fixture = json.loads((args.verify_fixture / 'receipt.json').read_text())
        assert fixture['passed'] and fixture['financialJourney'] and re.fullmatch(r'[a-f0-9]{12}', fixture['fixtureNonce'])
        inputs.update(nonce=fixture['fixtureNonce'], accountUrl=fixture['accountUrl'], transactionUrl=fixture['transactionUrl'])
    receipt['fixtureNonce'] = inputs['nonce']
    cache = Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1')
    jars = [jar for artifact in ('driver', 'driver-bundle', 'playwright')
        for jar in sorted((cache / ('com.microsoft.playwright/' + artifact + '/1.55.0')).glob('*/*.jar'))]
    jars += sorted((cache / 'com.google.code.gson/gson/2.12.1').glob('*/*.jar'))
    assert len(jars) == 4

    def runtime(action):
        result = subprocess.run([str(CLI), 'runtime', action, str(BASE / (name + '.json'))], capture_output=True,
            timeout=900, env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0, 'Private financial lifecycle failed; state retained'
        return json.loads(result.stdout.splitlines()[0])

    def browser(mode):
        data = json.loads(subprocess.check_output(P + ['inspect', 'p0v3-live-' + name + '-firefly'], stderr=subprocess.DEVNULL))[0]
        assert data['Config']['Labels']['io.p0v3.private-deployment'] == name and data['State']['Running']
        assert set(data['NetworkSettings']['Networks']) == {'p0v3-live-' + name + '-net'} and not data['HostConfig']['PortBindings']
        address = data['NetworkSettings']['Networks']['p0v3-live-' + name + '-net']['IPAddress']
        assert ipaddress.ip_address(address).is_private
        inputs.update(address=address, mode=mode)
        with tempfile.TemporaryDirectory(prefix='fb-', dir='/mnt/media/p0-v3/cache') as scratch:
            result = subprocess.run(['sudo', '-n', 'nsenter', '--target=' + str(data['State']['Pid']), '--net',
                '--setuid=' + str(os.getuid()), '--setgid=' + str(os.getgid()), '/usr/bin/env', 'HOME=' + scratch, 'TMPDIR=' + scratch,
                '/usr/lib/jvm/java-21-openjdk-amd64/bin/java', '-Djava.io.tmpdir=' + scratch, '--class-path', ':'.join(map(str, jars)),
                str(ROOT / 'acceptance/scripts/FireflyBrowserProbe.java')], input=json.dumps(inputs), text=True,
                capture_output=True, timeout=300)
            write(directory / (mode + '.log'), result.stderr.replace(inputs['password'], '[redacted]'))
            assert result.returncode == 0, 'Native Firefly journey failed; private diagnostic retained'
            journey = json.loads(result.stdout)
            assert journey.get('financialJourney') is True and journey.get('fullStackAcceptance') is False
            return journey

    try:
        receipt['phase'] = 'native-browser-create'
        runtime('apply-private')
        if fixture is None:
            receipt.update(browser('create'))
            inputs.update(accountUrl=receipt['accountUrl'], transactionUrl=receipt['transactionUrl'])
            jobs = hashlib.sha256((BASE / name / 'runtime.jobs').read_bytes()).hexdigest()
            receipt['phase'] = 'restart'
            assert all(p['exitCode'] in (0, 143) for p in runtime('stop-private'))
            runtime('apply-private')
            assert hashlib.sha256((BASE / name / 'runtime.jobs').read_bytes()).hexdigest() == jobs
            receipt.update(cleanRestartVerified=True, initializationJournalUnchanged=True, freshLoginAfterRestart=True)
        else:
            receipt.update(sourceFixture=fixture['id'], accountUrl=inputs['accountUrl'], transactionUrl=inputs['transactionUrl'],
                cleanRestartVerified=False, freshLoginAfterRestart=False)
        receipt['phase'] = 'fresh-browser-readback'
        receipt.update(browser('verify'))
        receipt.update(passed=True, phase='complete')
    finally:
        write(directory / 'receipt.json', json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    if not __debug__:
        raise SystemExit('Optimized Python disables safety assertions; refusing effects')
    main()
