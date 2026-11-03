#!/usr/bin/env python3
"""Native isolated-origin Hub diagnostic; no notebook creation or independent acceptance claim."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import base64
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import uuid

spec = importlib.util.spec_from_file_location('private_browser_constants', Path(__file__).with_name('inspect-private-huly.py'))
H = importlib.util.module_from_spec(spec); spec.loader.exec_module(H)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--name', default='jupyterhub-r8'); parser.add_argument('--user', choices=['alice', 'bob'], default='alice'); parser.add_argument('--mode', choices=['login', 'create', 'resume', 'verify'], default='login'); args = parser.parse_args()
    assert re.fullmatch('[a-z][a-z0-9-]{0,39}', args.name)
    os.umask(0o077)
    manifest, inputs = H.BASE / (args.name + '.json'), H.BASE / args.name
    subprocess.run([str(H.CLI), 'runtime', 'status-private', str(manifest)], env=dict(os.environ, JAVA_HOME='/usr/lib/jvm/java-21-openjdk-amd64'), capture_output=True, check=True, timeout=120)
    data = json.loads(subprocess.check_output(H.P + ['inspect', 'p0v3-live-' + args.name + '-hub']))[0]
    assert data['State']['Running'] and not data['HostConfig']['PortBindings']
    assert data['Config']['Labels']['io.p0v3.private-deployment'] == args.name
    assert set(data['NetworkSettings']['Networks']) == {'p0v3-live-' + args.name + '-net'}
    address = data['NetworkSettings']['Networks']['p0v3-live-' + args.name + '-net']['IPAddress']
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-hub-browser-' + uuid.uuid4().hex[:12]); directory.mkdir(mode=0o700)
    receipt = {'id': directory.name, 'deployment': args.name, 'user': args.user, 'passed': False, 'diagnosticOnly': True, 'fullStackAcceptance': False, 'manifestSha256': hashlib.sha256(manifest.read_bytes()).hexdigest()}
    (directory / 'receipt.json').write_text(json.dumps(receipt))
    try:
        context = ssl.create_default_context(cafile=str(inputs / 'trust.pem'))
        for host in ['hub', 'alice.hub', 'bob.hub']:
            with socket.create_connection((address, 8443), timeout=10) as raw, context.wrap_socket(raw, server_hostname=host) as transport:
                assert transport.getpeercert(binary_form=True) == ssl.PEM_cert_to_DER_cert((inputs / 'hub-web.pem').read_text())
        try:
            with socket.create_connection((address, 8443), timeout=10) as raw, ssl.create_default_context().wrap_socket(raw, server_hostname='hub'):
                pass
        except ssl.SSLCertVerificationError:
            receipt['defaultTrustDenied'] = True
        else:
            raise AssertionError('Private CA unexpectedly trusted globally')
        receipt['allThreeHostnamesAndLeafVerified'] = True
        for host, request_host, path, origin, expected in [
            ('hub', 'hub:8443', '/user/alice/', 'https://hub:8443', 403),
            ('hub', 'foreign.invalid', '/', 'https://hub:8443', 421),
            ('hub', 'hub:8443', '/hub/login', 'https://foreign.invalid', 403),
            ('alice.hub', 'alice.hub:8443', '/user/alice/lab', 'https://bob.hub:8443', 403),
            ('bob.hub', 'bob.hub:8443', '/user/bob/lab', 'https://alice.hub:8443', 403),
        ]:
            with socket.create_connection((address, 8443), timeout=10) as raw, context.wrap_socket(raw, server_hostname=host) as transport:
                client = http.client.HTTPConnection(host, 8443, timeout=10); client.sock = transport
                client.request('GET', path, headers={'Host': request_host, 'Origin': origin})
                response = client.getresponse(); assert response.status == expected
                assert len(response.read(65537)) <= 65536
        receipt['foreignOriginHostAndLoginOriginNotebookDenied'] = True
        public = subprocess.check_output(['openssl', 'x509', '-in', str(inputs / 'hub-web.pem'), '-pubkey', '-noout'])
        der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=public, capture_output=True, check=True).stdout
        values = {'address': address, 'pin': base64.b64encode(hashlib.sha256(der).digest()).decode(), 'directory': str(directory), 'user': args.user, 'password': json.loads((inputs / 'hub-settings.json').read_text())['passwords'][args.user]}
        if args.mode != 'login':
            state_root = Path('/mnt/media/p0-v3/hub-probe-state'); state_root.mkdir(mode=0o700, exist_ok=True)
            assert state_root.resolve() == state_root and state_root.stat().st_uid == os.getuid() and state_root.stat().st_mode & 0o777 == 0o700
            intent = state_root / (receipt['manifestSha256'] + '.' + args.user + '.intent')
            if args.mode == 'create':
                state = {'manifestSha256': receipt['manifestSha256'], 'user': args.user, 'file': 'p0v3-' + uuid.uuid4().hex[:12] + '.ipynb', 'diagnosticDirectory': str(directory)}
                with intent.open('x') as stream:
                    stream.write(json.dumps(state)); stream.flush(); os.fsync(stream.fileno())
                fd = os.open(state_root, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            assert not intent.is_symlink() and intent.stat().st_uid == os.getuid() and intent.stat().st_mode & 0o777 == 0o600
            state = json.loads(intent.read_text()); assert state['manifestSha256'] == receipt['manifestSha256'] and state['user'] == args.user
            if args.mode == 'resume':
                reconciliation = Path(str(intent) + '.reconciliation')
                assert reconciliation.resolve() == reconciliation and reconciliation.stat().st_uid == os.getuid() and reconciliation.stat().st_mode & 0o777 == 0o600
                proof = json.loads(reconciliation.read_text())
                assert proof['intentSha256'] == hashlib.sha256(intent.read_bytes()).hexdigest() and proof['manifestSha256'] == receipt['manifestSha256']
                assert proof['user'] == args.user and proof['file'] == state['file'] and proof['nativeFileStatus'] == 404 and proof['nativeSessions'] == 0
                assert Path(str(intent) + '.started').is_file() and not Path(str(intent) + '.resume-started').exists()
            values.update(file=state['file'], mode=args.mode, intent=str(intent))
            receipt['intent'] = str(intent)
            other = 'bob' if args.user == 'alice' else 'alice'
            other_intent = state_root / (receipt['manifestSha256'] + '.' + other + '.intent')
            if other_intent.exists():
                other_state = json.loads(other_intent.read_text())
                assert other_state['manifestSha256'] == receipt['manifestSha256'] and other_state['user'] == other
                values['otherFile'] = other_state['file']
        cache = Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1')
        jars = [jar for artifact in ('driver', 'driver-bundle', 'playwright') for jar in (cache / ('com.microsoft.playwright/' + artifact + '/1.55.0')).glob('*/*.jar')] + list((cache / 'com.google.code.gson/gson/2.12.1').glob('*/*.jar'))
        assert len(jars) == 4
        with tempfile.TemporaryDirectory(prefix='hub-', dir='/mnt/media/p0-v3/cache') as scratch:
            result = subprocess.run(['sudo', '-n', 'nsenter', '--target=' + str(data['State']['Pid']), '--net', '--setuid=' + str(os.getuid()), '--setgid=' + str(os.getgid()), '/usr/bin/env', 'HOME=' + scratch, 'TMPDIR=' + scratch, '/usr/lib/jvm/java-21-openjdk-amd64/bin/java', '-Djava.io.tmpdir=' + scratch, '--class-path', ':'.join(map(str, jars)), str(H.ROOT / 'acceptance/scripts/HubBrowserProbe.java')], input=json.dumps(values).encode(), capture_output=True, timeout=350)
            (directory / 'browser.log').write_bytes(result.stderr)
            assert result.returncode == 0, 'Native Hub diagnostic failed; protected evidence retained'
            receipt.update(json.loads(result.stdout))
            if (directory / 'notebook-proof.json').exists():
                receipt.update(json.loads((directory / 'notebook-proof.json').read_text()))
    finally:
        (directory / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps(receipt))


if __name__ == '__main__':
    main()
