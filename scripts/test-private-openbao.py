#!/usr/bin/env python3
"""Native TLS/Raft/Shamir/KV-v2 authorization and restart; fixture custody, not production unseal."""
import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/media/p0-v3/runtime-deployments')
CLI = ROOT / 'platform/build/install/p0-v3-platform/bin/p0-v3-platform'
P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']


def private_write(path, value):
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'w') as out:
        out.write(json.dumps(value)); out.flush(); os.fsync(out.fileno())
    fd = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


class Bao:
    def __init__(self, name):
        assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
        self.name = name
        self.context = ssl.create_default_context(cafile=str(BASE / name / 'ca.pem'))
        self.refresh()

    def refresh(self):
        data = json.loads(subprocess.check_output(P + ['inspect', 'p0v3-live-' + self.name + '-bao']))[0]
        assert data['Config']['Labels']['io.p0v3.private-deployment'] == self.name and data['State']['Running']
        assert not data['HostConfig']['PortBindings'] and set(data['NetworkSettings']['Networks']) == {'p0v3-live-' + self.name + '-net'}
        self.address = data['NetworkSettings']['Networks']['p0v3-live-' + self.name + '-net']['IPAddress']
        assert ipaddress.ip_address(self.address).is_private

    def request(self, method, path, body=None, token=None, expected=(200, 204)):
        payload = b'' if body is None else json.dumps(body).encode()
        headers = 'Host: bao:8200\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(payload)) + '\r\nConnection: close\r\n'
        if token: headers += 'X-Vault-Token: ' + token + '\r\n'
        with socket.create_connection((self.address, 8200), timeout=15) as raw, self.context.wrap_socket(raw, server_hostname='bao') as tls:
            assert tls.getpeercert(binary_form=True) == ssl.PEM_cert_to_DER_cert((BASE / self.name / 'web.pem').read_text())
            tls.sendall((method + ' /v1/' + path + ' HTTP/1.1\r\n' + headers + '\r\n').encode() + payload)
            response = http.client.HTTPResponse(tls); response.begin()
            content = response.read(1048577)
            assert len(content) <= 1048576 and response.status in expected, 'Unexpected private OpenBao response status ' + str(response.status)
            return json.loads(content) if content else {}

    def unseal(self, state):
        status = self.request('GET', 'sys/seal-status')
        if not status['sealed']: return
        self.request('POST', 'sys/unseal', {'reset': True})
        for index, key in enumerate(state['keys_base64'][:3]):
            status = self.request('POST', 'sys/unseal', {'key': key})
            assert status['sealed'] == (index < 2)
        for _ in range(60):
            status = self.request('GET', 'sys/health', expected=(200, 429, 503))
            if not status['sealed'] and not status.get('standby', False): return
            time.sleep(0.5)
        raise RuntimeError('OpenBao did not become operational after unseal')


def runtime(action, name):
    result = subprocess.run([str(CLI), 'runtime', action, str(BASE / (name + '.json'))], capture_output=True, timeout=1200,
                            env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
    assert result.returncode == 0, 'Private OpenBao lifecycle failed; state retained'
    return json.loads(result.stdout.splitlines()[0])


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--name', default='openbao-r4'); parser.add_argument('--fixture', type=Path)
    args = parser.parse_args(); name = args.name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-bao-' + uuid.uuid4().hex[:12]); directory.mkdir(mode=0o700)
    receipt = {'id': directory.name, 'deployment': name, 'passed': False, 'scope': 'private-secrets-backend-not-keykeeper-integration',
               'fullStackAcceptance': False, 'productionKeyCustody': False, 'automaticUnseal': False}
    try:
        runtime('apply-private', name); bao = Bao(name)
        source_hash = hashlib.sha256((BASE / (name + '.json')).read_bytes()).hexdigest()
        initialized = bao.request('GET', 'sys/init')['initialized']
        if args.fixture:
            assert initialized and args.fixture.is_absolute() and args.fixture.resolve() == args.fixture and args.fixture.stat().st_mode & 0o777 == 0o700
            path = args.fixture / 'recovery.json'
            assert not path.is_symlink() and path.stat().st_mode & 0o777 == 0o600
            state = json.loads(path.read_text()); assert state['sourceManifestSha256'] == source_hash
            private_write(directory / 'recovery.json', state)
        else:
            assert not initialized, 'Already initialized: supply protected prior fixture; never reset or reinitialize'
            private_write(directory / 'initialization-intent.json', {'sourceManifestSha256': source_hash})
            state = bao.request('POST', 'sys/init', {'secret_shares': 5, 'secret_threshold': 3})
            assert len(state['keys_base64']) == 5 and state['root_token']
            state['sourceManifestSha256'] = source_hash
            private_write(directory / 'recovery.json', state)
        root = state['root_token']; bao.unseal(state)
        audit = bao.request('GET', 'sys/audit', token=root)['data']['private/']
        assert audit['type'] == 'file' and audit['options']['file_path'] == '/bao/data/audit.log' and audit['options']['log_raw'] == 'false'
        mounts = bao.request('GET', 'sys/mounts', token=root)['data']
        if 'keykeeper/' not in mounts:
            bao.request('POST', 'sys/mounts/keykeeper', {'type': 'kv', 'options': {'version': '2'}}, root)
        else:
            assert mounts['keykeeper/']['type'] == 'kv' and mounts['keykeeper/']['options']['version'] == '2'
        for attempt in range(30):
            configured = bao.request('POST', 'keykeeper/config', {'cas_required': True, 'max_versions': 5}, root, expected=(200, 204, 400))
            if not configured.get('errors'): break
            assert all('upgrad' in error.lower() and 'version' in error.lower() for error in configured['errors']), 'Unexpected KV configuration rejection'
            time.sleep(0.5)
        else: raise RuntimeError('KV-v2 upgrade readiness budget exhausted')
        receipt['phase'] = 'native-kv-and-policy'
        nonce = uuid.uuid4().hex[:12]; item = str(uuid.uuid4()); value = secrets.token_hex(32)
        policy = 'fixture-' + nonce
        bao.request('PUT', 'sys/policies/acl/' + policy, {'policy': 'path "keykeeper/data/' + item + '" { capabilities = ["read"] }'}, root)
        reader = bao.request('POST', 'auth/token/create', {'policies': [policy], 'no_default_policy': True, 'ttl': '1h', 'renewable': False}, root)['auth']['client_token']
        path = 'keykeeper/data/' + item
        bao.request('GET', path, expected=(403,))
        bao.request('POST', path, {'options': {'cas': 0}, 'data': {'value': value}}, root)
        assert bao.request('GET', path, token=reader)['data']['data']['value'] == value
        bao.request('POST', path, {'options': {'cas': 0}, 'data': {'value': 'stale'}}, root, expected=(400,))
        bao.request('POST', path, {'options': {'cas': 1}, 'data': {'value': 'forbidden'}}, reader, expected=(403,))
        bao.request('GET', 'sys/mounts', token=reader, expected=(403,))
        bao.request('POST', 'sys/seal', token=reader, expected=(403,))
        bao.request('POST', path, {'options': {'cas': 1}, 'data': {'value': value, 'revision': 'two'}}, root)
        private_write(directory / 'fixture.json', {'item': item, 'value': value})
        receipt['phase'] = 'restart-sealed-and-threshold-recovery'
        assert all(p['exitCode'] == 0 for p in runtime('stop-private', name))
        runtime('apply-private', name); bao.refresh()
        assert bao.request('GET', 'sys/seal-status')['sealed']
        bao.request('GET', path, token=root, expected=(503,))
        bao.unseal(state)
        recovered = bao.request('GET', path, token=reader)['data']
        assert recovered['metadata']['version'] == 2 and recovered['data'] == {'value': value, 'revision': 'two'}
        bao.request('POST', 'auth/token/revoke', {'token': reader}, root)
        bao.request('GET', path, token=reader, expected=(403,))
        bao.request('DELETE', 'sys/policies/acl/' + policy, token=root)
        bao.request('POST', 'sys/seal', token=root)
        assert bao.request('GET', 'sys/seal-status')['sealed']
        bao.unseal(state)
        assert bao.request('GET', path, token=root)['data']['data']['value'] == value
        receipt.update(passed=True, phase='complete', nativeTlsVerified=True, thresholdUnsealVerified=True, casConflictRejected=True,
                       anonymousAndScopedAccessDenied=True, revokedTokenDenied=True, restartStartsSealed=True,
                       versionedSecretPersisted=True, explicitSealVerified=True, finalOperationalUnsealed=True)
    finally:
        private_write(directory / 'receipt.json', receipt)
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    if not __debug__: raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
