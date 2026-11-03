#!/usr/bin/env python3
"""Validate private Matrix TLS, then run real Element journeys inside the audited Caddy network namespace."""
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
import urllib.parse

P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / 'platform/build/install/p0-v3-platform/bin/p0-v3-platform'
BASE = Path('/mnt/media/p0-v3/runtime-deployments')


def private_write(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='matrix-r2')
    parser.add_argument('--fixture', type=Path, help='Fresh passed Matrix fixture whose users have not yet enrolled browser crypto devices; omitted creates one')
    args = parser.parse_args()
    name = args.name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    if args.fixture is None:
        fresh = subprocess.run(['python3', str(ROOT / 'platform/scripts/test-persistent-synapse.py'), '--name', name],
            capture_output=True, text=True, timeout=900)
        assert fresh.returncode == 0, 'Fresh native Matrix fixture failed'
        fixture_id = json.loads(fresh.stdout)['id']
        assert re.fullmatch(r'p0v3-synapse-[a-f0-9]{12}', fixture_id)
        args.fixture = Path('/mnt/media/p0-v3/image-acquisition-receipts') / fixture_id
    assert args.fixture.is_absolute() and args.fixture.resolve() == args.fixture and args.fixture.stat().st_mode & 0o777 == 0o700
    fixture = json.loads((args.fixture / 'receipt.json').read_text())
    assert fixture['passed'] and fixture['scope'] == 'persistent-private-synapse-not-full-stack'
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-matrix-browser-' + uuid.uuid4().hex[:12])
    directory.mkdir(mode=0o700)
    receipt = {'id': directory.name, 'scope': 'private-matrix-browser-not-full-stack', 'passed': False, 'deployment': name, 'fixture': fixture['id']}
    try:
        result = subprocess.run([str(CLI), 'runtime', 'apply-private', str(BASE / (name + '.json'))], capture_output=True, timeout=900,
            env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0
        data = json.loads(subprocess.check_output(P + ['inspect', 'p0v3-live-' + name + '-caddy'], stderr=subprocess.DEVNULL))[0]
        assert data['Config']['Labels']['io.p0v3.private-deployment'] == name and data['State']['Running']
        assert set(data['NetworkSettings']['Networks']) == {'p0v3-live-' + name + '-net'} and not data['HostConfig']['PortBindings']
        address = data['NetworkSettings']['Networks']['p0v3-live-' + name + '-net']['IPAddress']
        assert ipaddress.ip_address(address).is_private
        ca = subprocess.check_output(P + ['exec', 'p0v3-live-' + name + '-caddy', 'head', '-c', '65537',
            '/data/caddy/pki/authorities/local/root.crt'], stderr=subprocess.DEVNULL).decode()
        assert len(ca) <= 65536 and ca.startswith('-----BEGIN CERTIFICATE-----')
        private_write(directory / 'ca.pem', ca)
        tls = ssl.create_default_context(cadata=ca)
        with tls.wrap_socket(socket.create_connection((address, 8443), timeout=10), server_hostname='element') as connection:
            certificate = connection.getpeercert(binary_form=True)
            receipt['leafCertificateSha256'] = hashlib.sha256(certificate).hexdigest()
            public_key = subprocess.run(['/usr/bin/openssl', 'x509', '-inform', 'DER', '-pubkey', '-noout'], input=certificate, capture_output=True, check=True).stdout
            spki = subprocess.run(['/usr/bin/openssl', 'pkey', '-pubin', '-outform', 'DER'], input=public_key, capture_output=True, check=True).stdout
            certificate_pin = base64.b64encode(hashlib.sha256(spki).digest()).decode()
            client = http.client.HTTPConnection('element', 8443, timeout=15)
            client.sock = connection
            client.request('GET', '/config.json')
            response = client.getresponse()
            assert response.status == 200
            config = json.loads(response.read(65536))
            assert config['default_server_config']['m.homeserver']['base_url'] == 'https://element:8443'
            client.request('GET', '/_matrix/client/versions')
            response = client.getresponse()
            assert response.status == 200 and json.loads(response.read(65536))['versions']
            client.close()
        receipt['privateCaAndHostnameVerified'] = True
        inputs = {'address': address, 'directory': str(directory), 'fixtureId': fixture['id'], 'roomId': fixture['roomId'],
                  'certificatePin': certificate_pin, 'mediaSha256': fixture['mediaSha256'],
                  'encryptedRoomId': fixture['encryptedRoomId'], 'browserNonce': uuid.uuid4().hex}
        inputs.update(json.loads((args.fixture / 'users.json').read_text()))
        cache = Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1')
        jars = [jar for artifact in ('driver', 'driver-bundle', 'playwright')
                for jar in sorted((cache / ('com.microsoft.playwright/' + artifact + '/1.55.0')).glob('*/*.jar'))]
        jars += sorted((cache / 'com.google.code.gson/gson/2.12.1').glob('*/*.jar'))
        assert len(jars) == 4
        with tempfile.TemporaryDirectory(prefix='mb-', dir='/mnt/media/p0-v3/cache') as scratch:
            command = ['sudo', '-n', 'nsenter', '--target=' + str(data['State']['Pid']), '--net',
                '--setuid=' + str(os.getuid()), '--setgid=' + str(os.getgid()), '/usr/bin/env', 'HOME=' + scratch, 'TMPDIR=' + scratch,
                '/usr/lib/jvm/java-21-openjdk-amd64/bin/java', '-Djava.io.tmpdir=' + scratch, '--class-path', ':'.join(map(str, jars)),
                str(ROOT / 'acceptance/scripts/MatrixBrowserProbe.java')]
            result = subprocess.run(command, input=json.dumps(inputs), capture_output=True, text=True, timeout=300)
            private_write(directory / 'chromium.log', result.stderr)
            assert result.returncode == 0, 'Real Element journey failed; private diagnostic retained'
            journey = json.loads(result.stdout)
            assert all(journey.get(field) is True for field in ('nativeRecoveryKeySetup', 'encryptedSessionBackupConfirmed',
                'originalCryptoDevicesClosed', 'freshDeviceDecryptionVerified', 'encryptedKeyRecoveryTest'))
            assert journey.get('fullStackAcceptance') is False
            receipt.update(journey)
        with tls.wrap_socket(socket.create_connection((address, 8443), timeout=10), server_hostname='element') as connection:
            client = http.client.HTTPConnection('element', 8443, timeout=30)
            client.sock = connection
            user = inputs['bob']
            client.request('POST', '/_matrix/client/v3/login', body=json.dumps({'type': 'm.login.password',
                'identifier': {'type': 'm.id.user', 'user': user['username']}, 'password': user['password']}),
                headers={'Content-Type': 'application/json'})
            response = client.getresponse()
            assert response.status == 200
            login = json.loads(response.read(65536))
            assert login['user_id'] == '@' + user['username'] + ':matrix.private.invalid'
            path = '/_matrix/client/v3/rooms/' + urllib.parse.quote(fixture['encryptedRoomId'], safe='') + '/messages?dir=b&limit=10'
            client.request('GET', path, headers={'Authorization': 'Bearer ' + login['access_token']})
            response = client.getresponse()
            assert response.status == 200
            raw = response.read(2097153)
            assert len(raw) <= 2097152
            events = json.loads(raw)['chunk']
            encrypted = [e for e in events if e['type'] == 'm.room.encrypted']
            assert encrypted and all(e['content']['algorithm'] == 'm.megolm.v1.aes-sha2' and e['content'].get('ciphertext') for e in encrypted)
            assert ('Private encrypted delivery ' + inputs['browserNonce']).encode() not in raw
            assert not any(e['type'] == 'm.room.message' for e in events)
            client.close()
        receipt.update(passed=True, endToEndEncryptionTest=True, serverStoredCiphertextOnly=True)
    finally:
        private_write(directory / 'receipt.json', json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
