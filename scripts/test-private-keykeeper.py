#!/usr/bin/env python3
"""Private native Keykeeper OIDC/OpenBao journey; never a full-stack acceptance receipt."""
if not __debug__:
    raise SystemExit('Optimized Python disables safety checks; refusing effects')
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
import uuid
from keykeeper_probe_client import Client

spec = importlib.util.spec_from_file_location('bao_probe', Path(__file__).with_name('test-private-openbao.py'))
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='keykeeper-identity-r4')
    parser.add_argument('--fixture', type=Path)
    parser.add_argument('--bootstrap-only', action='store_true')
    parser.add_argument('--supervised', action='store_true')
    args = parser.parse_args(); name = args.name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    source = B.BASE / name
    source_hash = hashlib.sha256((B.BASE / (name + '.json')).read_bytes()).hexdigest()
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-keykeeper-id-' + uuid.uuid4().hex[:12]); directory.mkdir(mode=0o700)
    receipt = {'id': directory.name, 'deployment': name, 'manifestSha256': source_hash, 'fixture': args.fixture.name if args.fixture else None, 'passed': False, 'fullStackAcceptance': False, 'productionCustody': False, 'publicHttpsTest': False, 'realOwnerOnboarding': False, 'coordinatedRecovery': False}
    def run(action, label=None):
        result = subprocess.run([str(B.CLI), 'runtime', action, str(B.BASE / (name + '.json'))], capture_output=True, timeout=1200,
                                env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        B.private_write(directory / ((label or action) + '.json'), {'stdout': result.stdout.decode(), 'stderr': result.stderr.decode()})
        assert result.returncode == 0, 'Runtime operation failed; protected diagnostics retained'
    env = dict(line.split('=', 1) for line in (source / 'keeper.env').read_text().splitlines())
    realm = json.loads((source / 'realm.json').read_text())
    try:
        bao = B.Bao(name)
        if args.fixture:
            assert args.fixture.is_absolute() and args.fixture.resolve() == args.fixture and args.fixture.stat().st_mode & 0o777 == 0o700
            recovery = args.fixture / 'recovery.json'
            assert not recovery.is_symlink() and recovery.stat().st_mode & 0o777 == 0o600
            state = json.loads(recovery.read_text()); assert state['sourceManifestSha256'] == source_hash
            B.private_write(directory / 'recovery.json', state)
        else:
            assert not bao.request('GET', 'sys/init')['initialized'], 'Existing initialized state requires its protected fixture'
            B.private_write(directory / 'initialize-intent.json', {'sourceManifestSha256': source_hash})
            state = bao.request('POST', 'sys/init', {'secret_shares': 5, 'secret_threshold': 3})
            state['sourceManifestSha256'] = source_hash
            B.private_write(directory / 'recovery.json', state)
        bao.unseal(state); root = state['root_token']
        if not args.fixture:
            bao.request('POST', 'sys/mounts/keykeeper', {'type': 'kv', 'options': {'version': '2'}}, root)
            # Only bounded reads while the newly mounted KV-v2 backend becomes ready.
            for _ in range(60):
                status = bao.request('GET', 'keykeeper/config', token=root, expected=(200, 400))
                if 'errors' not in status: break
                time.sleep(.5)
            else: raise RuntimeError('KV readiness exhausted')
            bao.request('POST', 'keykeeper/config', {'cas_required': True}, root)
            policy = 'path "keykeeper/data/*" { capabilities = ["create", "read", "update"] }\npath "keykeeper/metadata/*" { capabilities = ["read", "list"] }\npath "keykeeper/metadata" { capabilities = ["list"] }'
            bao.request('PUT', 'sys/policies/acl/keykeeper', {'policy': policy}, root)
            issued = bao.request('POST', 'auth/token/create', {'id': env['KEYKEEPER_BAO_TOKEN'], 'policies': ['keykeeper'], 'no_default_policy': True, 'ttl': '768h', 'renewable': False, 'no_parent': True}, root)
            assert issued['auth']['client_token'] == env['KEYKEEPER_BAO_TOKEN']
            B.private_write(directory / 'bootstrap-complete.json', {'serviceTokenLeaseSeconds': issued['auth']['lease_duration'], 'sourceManifestSha256': source_hash})
        else:
            marker = args.fixture / 'bootstrap-complete.json'
            assert marker.is_file() and not marker.is_symlink() and marker.stat().st_mode & 0o777 == 0o600, 'Incomplete provisioning requires explicit reconciliation; no bootstrap replay'
            completed = json.loads(marker.read_text())
            assert completed['sourceManifestSha256'] == source_hash and type(completed['serviceTokenLeaseSeconds']) is int and completed['serviceTokenLeaseSeconds'] > 0
            B.private_write(directory / 'bootstrap-complete.json', completed)
        bao.request('GET', 'sys/mounts', token=env['KEYKEEPER_BAO_TOKEN'], expected=(403,))
        run('apply-private')
        keeper = Client(B.P, B.BASE, name, 'keeper', 8443, 'keeper-')
        identity = Client(B.P, B.BASE, name, 'identity', 8443, 'identity-')
        keeper.request('GET', '/api/items', expected=(403,))
        token_path = '/realms/p0v3/protocol/openid-connect/token'
        def machine(client):
            config = next(c for c in realm['clients'] if c['clientId'] == client)
            return identity.request('POST', token_path, {'grant_type': 'client_credentials', 'client_id': client, 'client_secret': config['secret']}, form=True)['access_token']
        token = machine('keykeeper-agent')
        assert isinstance(keeper.request('GET', '/api/items', token=token), list)
        keeper.request('GET', '/api/items', token='invalid-token', expected=(403,))
        keeper.request('GET', '/api/items', token=machine('keykeeper-rogue'), expected=(403,))
        identity.request('POST', token_path, {'grant_type': 'password', 'client_id': 'keykeeper-human', 'username': 'owner', 'password': 'invalid'}, expected=(400,), form=True)
        receipt.update(phase='bootstrap-complete', nativeAgentOidcVerified=True, wrongClientDenied=True, passwordGrantDenied=True, backendAdminDenied=True)
        if not args.bootstrap_only:
            receipt['phase'] = 'native-browser'
            if args.fixture and (args.fixture / 'state.json').exists():
                old_state = args.fixture / 'state.json'
                assert not old_state.is_symlink() and old_state.stat().st_mode & 0o777 == 0o600
                browser_state = json.loads(old_state.read_text())
                assert browser_state['sourceManifestSha256'] == source_hash and 'pendingWrite' not in browser_state
            else:
                browser_state = {'sourceManifestSha256': source_hash, 'agentSubject': env['KEYKEEPER_OIDC_AGENT_SUBJECTS'], 'users': {}, 'value': 'Synthetic initial value ' + uuid.uuid4().hex, 'editedValue': 'Synthetic edited value ' + uuid.uuid4().hex}
                for who in ('owner', 'outsider'):
                    user = next(u for u in realm['users'] if u['username'] == who)
                    browser_state['users'][who] = {'subject': user['id'], 'initialPassword': user['credentials'][0]['value'], 'password': secrets.token_hex(32), 'changed': False, 'totpSecret': ''}
            receipt['createdRecordThisRun'] = 'item' not in browser_state
            B.private_write(directory / 'state.json', browser_state)
            pins = []
            for file in ('keeper-web.pem', 'identity-web.pem'):
                pub = subprocess.check_output(['openssl', 'x509', '-in', str(source / file), '-pubkey', '-noout'])
                der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'der'], input=pub, capture_output=True, check=True).stdout
                pins.append(base64.b64encode(hashlib.sha256(der).digest()).decode())
            cache = Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1')
            jars = [j for a in ('driver', 'driver-bundle', 'playwright') for j in (cache / ('com.microsoft.playwright/' + a + '/1.55.0')).glob('*/*.jar')] + list((cache / 'com.google.code.gson/gson/2.12.1').glob('*/*.jar'))
            assert len(jars) == 4
            def browser(mode):
                keeper.refresh(); identity.refresh()
                cfg = {'directory': str(directory), 'mode': mode, 'keeperAddress': keeper.address, 'identityAddress': identity.address, 'pins': ','.join(pins)}
                with tempfile.TemporaryDirectory(prefix='ki-', dir='/mnt/media/p0-v3/cache') as scratch:
                    result = subprocess.run(['sudo', '-n', 'nsenter', '--target=' + str(keeper.info['State']['Pid']), '--net', '--setuid=' + str(os.getuid()), '--setgid=' + str(os.getgid()), '/usr/bin/env', 'HOME=' + scratch, 'TMPDIR=' + scratch, '/usr/lib/jvm/java-21-openjdk-amd64/bin/java', '-Djava.io.tmpdir=' + scratch, '--class-path', ':'.join(map(str, jars)), str(B.ROOT / 'acceptance/scripts/KeykeeperIdentityBrowserProbe.java')], input=json.dumps(cfg), capture_output=True, text=True, timeout=420)
                current = json.loads((directory / 'state.json').read_text())
                safe = result.stderr
                for user in current['users'].values():
                    for key in ('initialPassword', 'password', 'totpSecret'):
                        if user.get(key): safe = safe.replace(user[key], '[redacted]')
                B.private_write(directory / (mode + '-browser-log.json'), {'stderr': safe})
                assert result.returncode == 0, 'Native Keykeeper browser failed; protected diagnostics retained'
                assert json.loads(result.stdout)['passed']
                return current
            if 'item' in browser_state:
                keeper.request('GET', '/api/items/' + browser_state['item'], token=machine('keykeeper-agent'), expected=(403,))
            browser_state = browser('grant'); item = browser_state['item']; token = machine('keykeeper-agent')
            assert keeper.request('GET', '/api/items/' + item, token=token)['value'] == browser_state['value']
            keeper.request('PUT', '/api/items/' + item, {'value': 'denied-agent-edit'}, token, expected=(403,))
            keeper.request('POST', '/api/items/' + item + '/share', {'recipient': {'issuer': env['KEYKEEPER_OIDC_ISSUER'], 'subject': browser_state['users']['outsider']['subject'], 'kind': 'HUMAN'}, 'rights': ['READ']}, token, expected=(403,))
            # Real shipped CLI, in the application namespace. Bearer enters private stdin, not argv.
            cli = subprocess.run(B.P + ['exec', '-i', 'p0v3-live-' + name + '-keeper', '/bin/sh', '-ec', 'IFS= read -r KEYKEEPER_ACCESS_TOKEN; export KEYKEEPER_ACCESS_TOKEN; exec /opt/keykeeper/bin/p0-v3-keykeeper cli --oidc read ' + item], input=token + '\n', capture_output=True, text=True, timeout=30)
            assert cli.returncode == 0 and cli.stdout.rstrip('\n') == browser_state['value']
            browser('revoke'); keeper.request('GET', '/api/items/' + item, token=machine('keykeeper-agent'), expected=(403,))
            with socket.create_connection((keeper.address, 8443), timeout=10) as raw:
                try:
                    with ssl.create_default_context().wrap_socket(raw, server_hostname='keeper'):
                        raise AssertionError('System trust accepted private certificate')
                except ssl.SSLCertVerificationError: pass
            processes = [p['id'] for p in json.loads((B.BASE / (name + '.json')).read_text())['processes'] if not p.get('oneShot', False)]
            def running():
                return {p: json.loads(subprocess.check_output(B.P + ['inspect', 'p0v3-live-' + name + '-' + p]))[0] for p in processes}
            before = running(); journal = hashlib.sha256((source / 'runtime.jobs').read_bytes()).hexdigest()
            receipt['phase'] = 'restart'
            if args.supervised:
                unit = 'p0v3-private-' + name + '.service'
                subprocess.run(['systemctl', 'is-enabled', '--quiet', unit], check=True)
                subprocess.run(['sudo', '-n', 'systemctl', 'restart', unit], check=True, timeout=600)
                subprocess.run(['systemctl', 'is-active', '--quiet', unit], check=True)
            else:
                run('stop-private'); run('apply-private', 'restart-apply')
            keeper.refresh(); identity.refresh(); bao.refresh()
            assert bao.request('GET', 'sys/seal-status')['sealed']
            keeper.request('GET', '/api/items', token=machine('keykeeper-agent'), expected=(503,))
            bao.unseal(state)  # Explicit test-operator action, never a boot hook or daemon.
            browser('verify')
            keeper.request('GET', '/api/items/' + item, token=machine('keykeeper-agent'), expected=(403,))
            record = bao.request('GET', 'keykeeper/data/' + item, token=env['KEYKEEPER_BAO_TOKEN'])['data']['data']['record']
            assert record['metadata']['owner'] == {'issuer': env['KEYKEEPER_OIDC_ISSUER'], 'subject': browser_state['users']['owner']['subject'], 'kind': 'HUMAN'}
            assert record['value'] == browser_state['value'] and record['metadata']['grants'] == []
            sql = "SELECT u.username,u.id,(SELECT count(*) FROM credential c WHERE c.user_id=u.id AND c.type='otp'),(SELECT count(*) FROM user_required_action a WHERE a.user_id=u.id) FROM user_entity u JOIN realm r ON r.id=u.realm_id WHERE r.name='p0v3' AND u.username IN ('owner','outsider') ORDER BY u.username"
            database_password = dict(line.split('=', 1) for line in (source / 'keycloak.env').read_text().splitlines())['KC_DB_PASSWORD']
            rows = subprocess.run(B.P + ['exec', '-i', 'p0v3-live-' + name + '-postgres', '/bin/sh', '-ec', 'IFS= read -r PGPASSWORD; export PGPASSWORD; exec psql -X -h 127.0.0.1 -U keycloak -d keycloak -At -v ON_ERROR_STOP=1 -c "$1"', 'sh', sql], input=database_password + '\n', capture_output=True, text=True, check=True).stdout.splitlines()
            assert rows == [who + '|' + browser_state['users'][who]['subject'] + '|1|0' for who in ('outsider', 'owner')]
            after = running()
            assert all(before[p]['Id'] == after[p]['Id'] and before[p]['State']['StartedAt'] != after[p]['State']['StartedAt'] and after[p]['State']['Running'] for p in processes)
            assert hashlib.sha256((source / 'runtime.jobs').read_bytes()).hexdigest() == journal
            receipt.update(passed=True, phase='complete', nativeHumanOidc=True, passwordChangeAndTotp=True, passwordOnlyDenied=True, nativeBrowserEditShareRevoke=True, nativeAgentCli=True, agentReadOnlyAndRevocationVerified=True, outsiderDenied=True, csrfDenied=True, privateTlsVerified=True, initializerJournalUnchanged=True, sameContainerRestart=True, supervised=args.supervised, sealedBackendUnavailableVerified=True, actualDatabaseIdentityAndOtpVerified=True, automaticUnseal=False, item=item)
    except BaseException:
        receipt['passed'] = False
        raise
    finally:
        B.private_write(directory / 'receipt.json', receipt)
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
