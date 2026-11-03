#!/usr/bin/env python3
"""Audited, protected Huly browser diagnostics. This does not produce an acceptance pass."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/media/p0-v3/runtime-deployments')
CLI = ROOT / 'platform/build/install/p0-v3-platform/bin/p0-v3-platform'
P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph', '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='huly-r10')
    parser.add_argument('--mode', choices=['inspect', 'login', 'workspace-form', 'create-workspace', 'verify-workspace', 'resume-workspace-form', 'inspect-projects', 'inspect-issue-form', 'create-issue', 'verify-issue'], default='inspect')
    args = parser.parse_args()
    assert re.fullmatch('[a-z][a-z0-9-]{0,39}', args.name)
    os.umask(0o077)
    manifest, inputs = BASE / (args.name + '.json'), BASE / args.name
    env = dict(os.environ, JAVA_HOME='/usr/lib/jvm/java-21-openjdk-amd64')
    subprocess.run([str(CLI), 'runtime', 'status-private', str(manifest)], env=env, capture_output=True, check=True, timeout=120)
    deployment = json.loads(subprocess.check_output(P + ['inspect', 'p0v3-live-' + args.name + '-huly']))[0]
    assert deployment['State']['Running'] and not deployment['HostConfig']['PortBindings']
    assert deployment['Config']['Labels']['io.p0v3.private-deployment'] == args.name
    networks = deployment['NetworkSettings']['Networks']
    assert set(networks) == {'p0v3-live-' + args.name + '-net'}
    address = networks['p0v3-live-' + args.name + '-net']['IPAddress']
    assert ipaddress.ip_address(address).is_private
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-huly-browser-' + uuid.uuid4().hex[:12])
    directory.mkdir(mode=0o700)
    receipt = {'id': directory.name, 'deployment': args.name, 'passed': False, 'diagnosticOnly': True, 'fullStackAcceptance': False, 'manifestSha256': hashlib.sha256(manifest.read_bytes()).hexdigest()}
    try:
        try:
            with socket.create_connection((address, 8443), timeout=10) as raw, ssl.create_default_context().wrap_socket(raw, server_hostname='huly'):
                pass
        except ssl.SSLCertVerificationError:
            receipt['defaultTrustDenied'] = True
        else:
            raise AssertionError('Private CA unexpectedly trusted globally')
        context = ssl.create_default_context(cafile=str(inputs / 'ca.pem'))
        for origin, expected in [('https://huly:8443', 200), ('https://foreign.invalid', 403)]:
            with socket.create_connection((address, 8443), timeout=15) as raw, context.wrap_socket(raw, server_hostname='huly') as transport:
                assert transport.getpeercert(binary_form=True) == ssl.PEM_cert_to_DER_cert((inputs / 'web.pem').read_text())
                connection = http.client.HTTPConnection('huly', 8443, timeout=15)
                connection.sock = transport
                connection.request('GET', '/', headers={'Origin': origin})
                response = connection.getresponse()
                assert response.status == expected
                content = response.read(4 * 1024 * 1024 + 1)
                assert len(content) <= 4 * 1024 * 1024
        receipt['verifiedTlsAndForeignOriginDenial'] = True
        public = subprocess.check_output(['openssl', 'x509', '-in', str(inputs / 'web.pem'), '-pubkey', '-noout'])
        der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=public, capture_output=True, check=True).stdout
        values = {'address': address, 'pin': base64.b64encode(hashlib.sha256(der).digest()).decode(), 'directory': str(directory), 'mode': args.mode}
        if args.mode != 'inspect':
            owner = json.loads((inputs / 'bootstrap-users.json').read_text())[0]
            values.update(email=owner['email'], password=owner['password'])
            if args.mode in ('create-issue', 'verify-issue'):
                outsider = json.loads((inputs / 'bootstrap-users.json').read_text())[2]
                values.update(outsiderEmail=outsider['email'], outsiderPassword=outsider['password'])
        workflow = args.mode in ('create-workspace', 'verify-workspace', 'resume-workspace-form', 'inspect-projects', 'inspect-issue-form', 'create-issue', 'verify-issue')
        if workflow:
            state_root = Path('/mnt/media/p0-v3/huly-probe-state')
            if not state_root.exists():
                state_root.mkdir(mode=0o700)
            assert state_root.resolve() == state_root and state_root.stat().st_uid == os.getuid() and state_root.stat().st_mode & 0o777 == 0o700
            intent = state_root / (receipt['manifestSha256'] + '.workspace.intent')
            if args.mode == 'create-workspace':
                state = {'manifestSha256': receipt['manifestSha256'], 'workspaceName': 'Private Huly ' + uuid.uuid4().hex[:12], 'phase': 'creation-intent', 'diagnosticDirectory': str(directory)}
                with intent.open('x') as stream:
                    stream.write(json.dumps(state)); stream.flush(); os.fsync(stream.fileno())
                fd = os.open(state_root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            assert not intent.is_symlink() and intent.stat().st_uid == os.getuid() and intent.stat().st_mode & 0o777 == 0o600 and intent.stat().st_size <= 8192
            assert json.loads(intent.read_text())['manifestSha256'] == receipt['manifestSha256']
            values.update(intent=str(intent), manifestSha256=receipt['manifestSha256'])
            receipt['workspaceIntent'] = str(intent)
        cache = Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1')
        jars = [jar for artifact in ('driver', 'driver-bundle', 'playwright') for jar in (cache / ('com.microsoft.playwright/' + artifact + '/1.55.0')).glob('*/*.jar')] + list((cache / 'com.google.code.gson/gson/2.12.1').glob('*/*.jar'))
        assert len(jars) == 4
        with tempfile.TemporaryDirectory(prefix='huly-', dir='/mnt/media/p0-v3/cache') as scratch:
            result = subprocess.run(['sudo', '-n', 'nsenter', '--target=' + str(deployment['State']['Pid']), '--net', '--setuid=' + str(os.getuid()), '--setgid=' + str(os.getgid()), '/usr/bin/env', 'HOME=' + scratch, 'TMPDIR=' + scratch, '/usr/lib/jvm/java-21-openjdk-amd64/bin/java', '-Djava.io.tmpdir=' + scratch, '--class-path', ':'.join(map(str, jars)), str(ROOT / ('acceptance/scripts/HulyWorkspaceProbe.java' if workflow else 'acceptance/scripts/HulyBrowserProbe.java'))], input=json.dumps(values).encode(), capture_output=True, timeout=600 if workflow else 240)
            (directory / 'browser.log').write_bytes(result.stderr)
            assert result.returncode == 0, 'Native Huly browser diagnostic failed; state retained'
            receipt.update(json.loads(result.stdout))
            if (directory / 'issue-proof.json').exists():
                receipt.update(json.loads((directory / 'issue-proof.json').read_text()))
    finally:
        (directory / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps(receipt))


if __name__ == '__main__':
    main()
