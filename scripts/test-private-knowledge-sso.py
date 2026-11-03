#!/usr/bin/env python3
"""Native confidential OIDC/PKCE, private verified TLS, required actions and wiki authorization."""
import argparse
import base64
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
import tempfile
import uuid
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/media/p0-v3/runtime-deployments')
CLI = ROOT / 'platform/build/install/p0-v3-platform/bin/p0-v3-platform'
P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']


def write(path, data):
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'w') as out:
        out.write(data); out.flush(); os.fsync(out.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='knowledge-identity-r4')
    parser.add_argument('--fixture', type=Path, help='Reuse protected synthetic credential state, never reset a provisioned identity')
    args = parser.parse_args(); name = args.name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-knowledge-sso-' + uuid.uuid4().hex[:12])
    directory.mkdir(mode=0o700)
    realm = json.loads((BASE / name / 'realm.json').read_text())
    owner = next(u for u in realm['users'] if u['username'] == 'owner')
    outsider = next(u for u in realm['users'] if u['username'] == 'outsider')
    state = {'initialPassword': owner['credentials'][0]['value'], 'password': secrets.token_hex(32),
             'changed': False, 'enrolled': False, 'totpSecret': ''}
    if args.fixture:
        assert args.fixture.is_absolute() and args.fixture.resolve() == args.fixture and args.fixture.stat().st_mode & 0o777 == 0o700
        path = args.fixture / 'state.json'
        assert not path.is_symlink() and path.stat().st_mode & 0o777 == 0o600
        previous = json.loads((args.fixture / 'receipt.json').read_text())
        assert previous['deployment'] == name
        state = json.loads(path.read_text())
    write(directory / 'state.json', json.dumps(state))
    receipt = {'id': directory.name, 'scope': 'private-native-oidc-wiki-not-full-stack', 'deployment': name,
        'passed': False, 'fullStackAcceptance': False, 'publicHttpsTest': False, 'encryptedRestoreTest': False,
        'startedWithEnrolledIdentity': state['enrolled']}
    nonce = uuid.uuid4().hex[:12]
    local_values = dict(line.split('=', 1) for line in (BASE / name / 'admin.env').read_text().splitlines())
    inputs = {'directory': str(directory), 'nonce': nonce, 'outsiderPassword': outsider['credentials'][0]['value'],
              'localPassword': local_values['P0V3_FIXTURE_PASSWORD']}
    cache = Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1')
    jars = [jar for artifact in ('driver', 'driver-bundle', 'playwright')
        for jar in sorted((cache / ('com.microsoft.playwright/' + artifact + '/1.55.0')).glob('*/*.jar'))]
    jars += sorted((cache / 'com.google.code.gson/gson/2.12.1').glob('*/*.jar'))
    assert len(jars) == 4

    def runtime(action):
        result = subprocess.run([str(CLI), 'runtime', action, str(BASE / (name + '.json'))], capture_output=True, timeout=1200,
            env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0, 'Private SSO runtime operation failed; state retained'
        return json.loads(result.stdout.splitlines()[0])

    def audit():
        data = json.loads(subprocess.check_output(P + ['inspect', 'p0v3-live-' + name + '-knowledge'], stderr=subprocess.DEVNULL))[0]
        assert data['Config']['Labels']['io.p0v3.private-deployment'] == name and data['State']['Running']
        assert not data['HostConfig']['PortBindings'] and set(data['NetworkSettings']['Networks']) == {'p0v3-live-' + name + '-net'}
        address = data['NetworkSettings']['Networks']['p0v3-live-' + name + '-net']['IPAddress']
        assert ipaddress.ip_address(address).is_private
        return data, address

    def verify_tls(address):
        context = ssl.create_default_context(cafile=str(BASE / name / 'ca.pem'))
        with socket.create_connection((address, 8443), timeout=15) as raw, context.wrap_socket(raw, server_hostname='knowledge') as tls:
            expected = ssl.PEM_cert_to_DER_cert((BASE / name / 'web.pem').read_text())
            assert tls.getpeercert(binary_form=True) == expected
            tls.sendall(b'GET /identity/realms/p0v3/.well-known/openid-configuration HTTP/1.1\r\nHost: knowledge:8443\r\nConnection: close\r\n\r\n')
            response = http.client.HTTPResponse(tls); response.begin(); assert response.status == 200
            discovery = json.loads(response.read(1048576))
            assert discovery['issuer'] == 'https://knowledge:8443/identity/realms/p0v3'
        try:
            with socket.create_connection((address, 8443), timeout=15) as raw, ssl.create_default_context().wrap_socket(raw, server_hostname='knowledge'):
                raise AssertionError('Unexpected shared trust of private fixture CA')
        except ssl.SSLCertVerificationError:
            receipt['untrustedCaDenied'] = True
        for bad_redirect in (False, True):
            query = {'client_id': 'bookstack', 'response_type': 'code', 'scope': 'openid', 'state': 'private-negative-fixture',
                     'redirect_uri': 'https://unapproved.invalid/callback' if bad_redirect else 'https://knowledge:8443/oidc/callback'}
            if bad_redirect:
                query.update(code_challenge='a' * 43, code_challenge_method='S256')
            path = '/identity/realms/p0v3/protocol/openid-connect/auth?' + urllib.parse.urlencode(query)
            with socket.create_connection((address, 8443), timeout=15) as raw, context.wrap_socket(raw, server_hostname='knowledge') as tls:
                tls.sendall(('GET ' + path + ' HTTP/1.1\r\nHost: knowledge:8443\r\nConnection: close\r\n\r\n').encode())
                response = http.client.HTTPResponse(tls); response.begin()
                if not bad_redirect and response.status == 302:
                    location = urllib.parse.urlsplit(response.getheader('Location'))
                    parameters = urllib.parse.parse_qs(location.query)
                    assert (location.scheme, location.netloc, location.path) == ('https', 'knowledge:8443', '/oidc/callback')
                    assert parameters.get('error') == ['invalid_request'] and 'code' not in parameters
                else:
                    assert response.status == 400, 'Authorization request was not rejected'
                response.read(1048576)
        receipt.update(missingPkceRejected=True, unapprovedRedirectRejected=True)
        public = subprocess.check_output(['openssl', 'x509', '-in', str(BASE / name / 'web.pem'), '-pubkey', '-noout'])
        der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=public, capture_output=True, check=True).stdout
        inputs['spki'] = base64.b64encode(hashlib.sha256(der).digest()).decode()
        receipt['certificateSha256'] = hashlib.sha256(expected).hexdigest()

    def browser(mode):
        data, address = audit(); verify_tls(address); inputs.update(address=address, mode=mode)
        with tempfile.TemporaryDirectory(prefix='ks-', dir='/mnt/media/p0-v3/cache') as scratch:
            result = subprocess.run(['sudo', '-n', 'nsenter', '--target=' + str(data['State']['Pid']), '--net',
                '--setuid=' + str(os.getuid()), '--setgid=' + str(os.getgid()), '/usr/bin/env', 'HOME=' + scratch, 'TMPDIR=' + scratch,
                '/usr/lib/jvm/java-21-openjdk-amd64/bin/java', '-Djava.io.tmpdir=' + scratch, '--class-path', ':'.join(map(str, jars)),
                str(ROOT / 'acceptance/scripts/KnowledgeSsoBrowserProbe.java')], input=json.dumps(inputs), capture_output=True, text=True, timeout=420)
            safe = result.stderr
            recovery = json.loads((directory / 'state.json').read_text())
            for value in [*recovery.values(), inputs['outsiderPassword'], inputs['localPassword']]:
                if isinstance(value, str) and value: safe = safe.replace(value, '[redacted]')
            write(directory / (mode + '.log'), safe)
            assert result.returncode == 0, 'Native SSO journey failed; protected recovery state retained'
            result = json.loads(result.stdout)
            assert result['nativeOidcJourney'] and not result['fullStackAcceptance']
            return result

    def database_checks():
        sql = "SELECT external_auth_id FROM users WHERE email='fixture@localhost.invalid'; SELECT count(*) FROM users WHERE email='outsider@localhost.invalid';"
        command = 'MYSQL_PWD="$MARIADB_ROOT_PASSWORD" mariadb --socket=/tmp/mysql.sock -u root bookstack -Nse ' + "\"" + sql + "\""
        result = subprocess.run(P + ['exec', 'p0v3-live-' + name + '-mariadb', '/bin/sh', '-ec', command], capture_output=True, text=True, check=True)
        assert result.stdout.splitlines() == [owner['id'], '0']
        sql = "SELECT count(*) FROM user_required_action WHERE user_id='" + owner['id'] + "'; SELECT count(*) FROM credential WHERE user_id='" + owner['id'] + "' AND type='otp';"
        result = subprocess.run(P + ['exec', 'p0v3-live-' + name + '-postgres', 'psql', '-X', '-U', 'postgres', '-d', 'keycloak', '-At', '-c', sql], capture_output=True, text=True, check=True)
        assert result.stdout.splitlines() == ['0', '1']

    try:
        receipt['phase'] = 'onboarding-and-authoring'
        runtime('apply-private')
        receipt.update(browser('create')); database_checks(); inputs['pageUrl'] = receipt['pageUrl']
        jobs = hashlib.sha256((BASE / name / 'runtime.jobs').read_bytes()).hexdigest()
        receipt['phase'] = 'restart-and-sso-readback'
        assert all(p['exitCode'] in (0, 143) for p in runtime('stop-private'))
        runtime('apply-private')
        assert hashlib.sha256((BASE / name / 'runtime.jobs').read_bytes()).hexdigest() == jobs
        receipt.update(browser('verify')); database_checks()
        receipt.update(passed=True, phase='complete', verifiedCaAndHostname=True, exactSubjectBinding=True,
            unprovisionedSubjectNotCreated=True, requiredActionsClearedAndOtpStored=True, cleanRestartVerified=True,
            initializationJournalUnchanged=True)
    finally:
        write(directory / 'receipt.json', json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    if not __debug__:
        raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
