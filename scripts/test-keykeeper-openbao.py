#!/usr/bin/env python3
"""Actual Keykeeper store/authorization on private OpenBao; no fabricated OIDC/HTTP-service claim."""
import argparse
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import secrets
import subprocess
import time
import uuid

SPEC = importlib.util.spec_from_file_location('bao_probe', Path(__file__).with_name('test-private-openbao.py'))
B = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(B)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--fixture', required=True, type=Path); args = parser.parse_args()
    fixture = args.fixture
    assert fixture.is_absolute() and fixture.resolve() == fixture and fixture.stat().st_mode & 0o777 == 0o700
    recovery = fixture / 'recovery.json'; assert not recovery.is_symlink() and recovery.stat().st_mode & 0o777 == 0o600
    previous = json.loads((fixture / 'receipt.json').read_text()); name = previous['deployment']
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    state = json.loads(recovery.read_text()); assert state['sourceManifestSha256'] == hashlib.sha256((B.BASE / (name + '.json')).read_bytes()).hexdigest()
    directory = fixture.parent / ('p0v3-keykeeper-bao-' + uuid.uuid4().hex[:12]); directory.mkdir(mode=0o700)
    receipt = {'id': directory.name, 'deployment': name, 'passed': False, 'fullStackAcceptance': False, 'identityAuthenticationTest': False,
               'scope': 'native-keykeeper-store-on-private-bao-not-deployed-keykeeper'}
    bao = B.Bao(name); bao.unseal(state); root = state['root_token']
    mount = 'fixture-' + uuid.uuid4().hex[:12]
    try:
        bao.request('POST', 'sys/mounts/' + mount, {'type': 'kv', 'options': {'version': '2'}}, root)
        for _ in range(30):
            result = bao.request('POST', mount + '/config', {'cas_required': True}, root, expected=(200, 204, 400))
            if not result.get('errors'): break
            assert all('upgrad' in e.lower() and 'version' in e.lower() for e in result['errors'])
            time.sleep(0.5)
        else: raise RuntimeError('KV-v2 mount readiness exhausted')
        policy = 'path "' + mount + '/data/*" { capabilities = ["create", "read", "update"] }\npath "' + mount + '/metadata/*" { capabilities = ["read", "list"] }\npath "' + mount + '/metadata" { capabilities = ["list"] }'
        bao.request('PUT', 'sys/policies/acl/' + mount, {'policy': policy}, root)
        token = bao.request('POST', 'auth/token/create', {'policies': [mount], 'no_default_policy': True, 'ttl': '1h', 'renewable': False}, root)['auth']['client_token']
        bao.request('GET', 'sys/mounts', token=token, expected=(403,))
        truststore = directory / 'trust.p12'
        result = subprocess.run(['/usr/lib/jvm/java-21-openjdk-amd64/bin/keytool', '-importcert', '-noprompt', '-alias', 'bao',
            '-file', str(B.BASE / name / 'ca.pem'), '-keystore', str(truststore), '-storepass', 'changeit'], capture_output=True)
        assert result.returncode == 0
        truststore.chmod(0o600)
        jars = list((B.ROOT / 'keykeeper/build/install/p0-v3-keykeeper/lib').glob('*.jar'))
        jars += list(Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1/com.google.code.gson/gson/2.12.1').glob('*/*.jar'))
        assert len(jars) >= 5
        inputs = {'mount': mount, 'token': token, 'value': secrets.token_hex(32)}
        hosts = directory / 'hosts'
        B.private_write(directory / 'fixture.json', inputs)

        def native(label, trusted=True):
            hosts.write_text(bao.address + ' bao\n127.0.0.1 localhost\n'); hosts.chmod(0o600)
            trust_args = ['-Djavax.net.ssl.trustStore=' + str(truststore), '-Djavax.net.ssl.trustStorePassword=changeit'] if trusted else []
            result = subprocess.run(['/usr/lib/jvm/java-21-openjdk-amd64/bin/java', '-Djdk.net.hosts.file=' + str(hosts), *trust_args,
                '--class-path', ':'.join(map(str, jars)), str(B.ROOT / 'acceptance/scripts/KeykeeperBaoProbe.java')],
                input=json.dumps(inputs), capture_output=True, text=True, timeout=120)
            safe = result.stderr.replace(token, '[redacted]').replace(inputs['value'], '[redacted]')
            B.private_write(directory / (label + '.log.json'), {'stderr': safe})
            if not trusted:
                assert result.returncode != 0, 'Untrusted private CA was accepted'
                return None
            assert result.returncode == 0, 'Native Keykeeper adapter failed; protected diagnostics retained'
            return json.loads(result.stdout)

        native('untrusted-ca', trusted=False)
        created = native('create'); assert created['passed']; inputs['item'] = created['item']
        B.runtime('stop-private', name); B.runtime('apply-private', name); bao.refresh()
        assert bao.request('GET', 'sys/seal-status')['sealed']; bao.unseal(state)
        assert native('readback')['passed']
        bao.request('POST', 'auth/token/revoke', {'token': token}, root)
        bao.request('GET', mount + '/data/' + inputs['item'], token=token, expected=(403,))
        receipt.update(passed=True, item=inputs['item'], nativeStoreRoundtrip=True, humanAgentGrantsVerified=True,
                       editAndShareDenialVerified=True, revocationVerified=True, casConflictRejected=True,
                       restartReadback=True, perProcessTlsTrustOnly=True, untrustedCaDenied=True, scopedBackendTokenRevoked=True)
    finally:
        B.private_write(directory / 'receipt.json', receipt)
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    if not __debug__: raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
