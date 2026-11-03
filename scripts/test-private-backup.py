#!/usr/bin/env python3
"""Native private Kopia HTTPS API snapshot + networkless read-only repository restore."""
if not __debug__:
    raise SystemExit('Optimized Python disables safety checks; refusing effects')
import argparse
import base64
import hashlib
import http.client
from http.cookies import SimpleCookie
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import time
import uuid
import urllib.parse
from probe_receipt import private_receipt

spec = importlib.util.spec_from_file_location('backup_helpers', Path(__file__).with_name('test-private-openbao.py'))
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)


def write_intent(state, filename, payload):
    assert re.fullmatch(r'backup-(file|upload)-[a-f0-9]{64}\.intent', filename)
    encoded = json.dumps(payload, sort_keys=True).encode(); assert len(encoded) <= 8192
    assert state.is_absolute() and state.resolve() == state
    state.mkdir(mode=0o700, exist_ok=True)
    assert state.stat().st_mode & 0o777 == 0o700
    path = state / filename
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
        stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(state, os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)
    return path


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--supervised', action='store_true'); parser.add_argument('--create-snapshot', action='store_true', help='One explicit, durably journalled snapshot upload; never retried'); args = parser.parse_args()
    name = 'backup'; root = B.BASE / name; manifest = B.BASE / (name + '.json')
    deployment = json.loads(manifest.read_text()); assert deployment['name'] == name
    assert {p['id'] for p in deployment['processes']} == {'repository-init', 'backup'}
    image = deployment['processes'][0]['image']
    assert image == 'docker.io/kopia/kopia@sha256:83d8bc7bce313dd8b2c17771b5f3f804e18e79ad7d7cc6bc994ff5872374794d'
    nonce = uuid.uuid4().hex[:12]; directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-backup-' + nonce); directory.mkdir(mode=0o700)
    environment = dict(line.split('=', 1) for line in (root / 'server.env').read_text().splitlines())
    expected = (root / 'fixture.txt').read_bytes(); assert expected.startswith(b'Platform Zero synthetic backup fixture.')
    receipt = {'id': directory.name, 'deployment': name, 'passed': False, 'fullStackAcceptance': False, 'offHostBackup': False, 'manifestSha256': hashlib.sha256(manifest.read_bytes()).hexdigest()}
    def run(command, ok=True):
        result = subprocess.run(command, capture_output=True, timeout=600, env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        if ok and result.returncode:
            B.private_write(directory / ('failure-' + uuid.uuid4().hex[:8] + '.json'), {'stderr': result.stderr.decode(errors='replace')})
            raise RuntimeError('Native backup operation failed; protected diagnostics retained')
        return result.stdout if ok else result
    def runtime(action): return run([str(B.CLI), 'runtime', action, str(manifest)])
    def inspect():
        data = json.loads(run(B.P + ['inspect', 'p0v3-live-backup-backup']))[0]
        assert data['State']['Running'] and not data['HostConfig']['PortBindings'] and data['Config']['Labels']['io.p0v3.private-deployment'] == name
        assert set(data['NetworkSettings']['Networks']) == {'p0v3-live-backup-net'}
        return data
    def request(path, method='GET', body=None, auth='admin', csrf=True, expected_status=200, context=None, hostname='backup'):
        assert path.startswith('/') and '\r' not in path and '\n' not in path
        data = inspect(); address = data['NetworkSettings']['Networks']['p0v3-live-backup-net']['IPAddress']
        with socket.create_connection((address, 51515), timeout=15) as raw, (context or ctx).wrap_socket(raw, server_hostname=hostname) as tls:
            assert tls.getpeercert(binary_form=True) == leaf
            headers = {'Host': 'backup:51515', 'Connection': 'close', 'Content-Type': 'application/json'}
            if auth is not None:
                if auth == 'admin': user, password = environment['KOPIA_SERVER_USERNAME'], environment['KOPIA_SERVER_PASSWORD']
                elif auth == 'control': user, password = environment['KOPIA_SERVER_CONTROL_USER'], environment['KOPIA_SERVER_CONTROL_PASSWORD']
                else: user, password = 'invalid', 'invalid'
                headers['Authorization'] = 'Basic ' + base64.b64encode((user + ':' + password).encode()).decode()
            if csrf and token:
                headers['X-Kopia-CSRF-Token'] = token; headers['Cookie'] = cookie
            encoded = json.dumps(body).encode() if body is not None else b''; headers['Content-Length'] = str(len(encoded))
            tls.sendall((method + ' ' + path + ' HTTP/1.1\r\n' + ''.join(k + ': ' + v + '\r\n' for k, v in headers.items()) + '\r\n').encode() + encoded)
            with http.client.HTTPResponse(tls) as response:
                response.begin(); content = response.read(1048577); assert len(content) <= 1048576
                assert response.status == expected_status, 'Unexpected native backup status ' + str(response.status)
                return content, response.getheaders()
    def api(path, **kw): return json.loads(request(path, **kw)[0])
    def session():
        nonlocal token, cookie
        content, headers = request('/', csrf=False)
        match = re.search(rb'<meta name="kopia-csrf-token" content="([a-f0-9]{64})"', content); assert match
        cookies = SimpleCookie()
        for key, value in headers:
            if key.lower() == 'set-cookie': cookies.load(value)
        assert 'Kopia-Session-Cookie' in cookies
        token = match.group(1).decode(); cookie = 'Kopia-Session-Cookie=' + cookies['Kopia-Session-Cookie'].value
    ctx = ssl.create_default_context(cafile=str(root / 'ca.pem')); leaf = ssl.PEM_cert_to_DER_cert((root / 'web.pem').read_text()); token = None; cookie = None
    with private_receipt(receipt, lambda value: B.private_write(directory / 'receipt.json', value)):
        runtime('apply-private'); before = inspect(); jobs = hashlib.sha256((root / 'runtime.jobs').read_bytes()).hexdigest()
        receipt['phase'] = 'native-authentication'
        request('/', auth=None, csrf=False, expected_status=401); request('/', auth='invalid', csrf=False, expected_status=401)
        for context, hostname in ((ssl.create_default_context(), 'backup'), (ctx, 'wrong-backup')):
            try: request('/', context=context, hostname=hostname, csrf=False)
            except ssl.SSLError: pass
            else: raise AssertionError('Untrusted TLS endpoint accepted')
        session()
        request('/api/v1/sources', csrf=False, expected_status=401)
        request('/api/v1/sources', method='POST', body={'path': '/source/absent-' + nonce, 'policy': {}, 'createSnapshot': False}, csrf=False, expected_status=401)
        request('/api/v1/sources', auth='control', expected_status=403)
        status = api('/api/v1/repo/status'); B.private_write(directory / 'repository-status.json', status)
        sources = api('/api/v1/sources')['sources']
        assert all(s['source']['path'] in ('/source', '/source/fixture.txt') for s in sources), 'Unexpected source; no automatic replacement'
        receipt['phase'] = 'native-snapshot'
        if not any(s['source']['path'] == '/source/fixture.txt' for s in sources):
            # Persist a deployment-level intent before a potentially ambiguous non-idempotent write.
            write_intent(Path('/mnt/media/p0-v3/backup-probe-state'), 'backup-file-' + receipt['manifestSha256'] + '.intent',
                         {'path': '/source/fixture.txt', 'receipt': directory.name})
            created = api('/api/v1/sources', method='POST', body={'path': '/source/fixture.txt', 'createSnapshot': True, 'policy': {}})
            assert created['snapshotted']; receipt['createdSnapshotThisRun'] = True
        else: receipt['createdSnapshotThisRun'] = False
        sources = api('/api/v1/sources')['sources']
        selected = [s['source'] for s in sources if s['source']['path'] == '/source/fixture.txt']; assert len(selected) == 1
        snapshot_url = '/api/v1/snapshots?' + urllib.parse.urlencode({**selected[0], 'all': '1'})
        previous_ids = {item['id'] for item in api(snapshot_url)['snapshots']}
        if args.create_snapshot:
            intent = write_intent(Path('/mnt/media/p0-v3/backup-probe-state'), 'backup-upload-' + receipt['manifestSha256'] + '.intent',
                                  {'receipt': directory.name, 'source': selected[0], 'previousSnapshotIds': sorted(previous_ids)})
            response = api('/api/v1/sources/upload?' + urllib.parse.urlencode(selected[0]), method='POST')
            assert len(response['sources']) == 1
        for _ in range(90):
            snapshots = api(snapshot_url)['snapshots']
            if snapshots and all(not item.get('incomplete') for item in snapshots) and (not args.create_snapshot or any(item['id'] not in previous_ids for item in snapshots)): break
            time.sleep(1)
        else: raise AssertionError('Native snapshot observation exhausted; no resubmission')
        assert len(snapshots) >= 1
        if args.create_snapshot:
            fresh = [item for item in snapshots if item['id'] not in previous_ids]; assert len(fresh) == 1
            snapshot = fresh[0]; receipt['createdSnapshotThisRun'] = True
            B.private_write(directory / 'observed-upload.json', {'snapshotId': snapshot['id'], 'intentSha256': hashlib.sha256(intent.read_bytes()).hexdigest()})
        else: snapshot = max(snapshots, key=lambda item: item['startTime'])
        object_id = snapshot['rootID']; assert re.fullmatch('[a-z0-9]{20,100}', object_id)
        receipt['snapshotId'] = snapshot['id']; receipt['rootObjectId'] = object_id
        receipt['phase'] = 'isolated-native-restore'
        output = directory.name + '-export'
        assert run(B.P + ['volume', 'exists', output], ok=False).returncode == 1
        run(B.P + ['volume', 'create', '--label=io.p0v3.restore-probe=' + directory.name, output])
        common = B.P + ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=all', '--security-opt=no-new-privileges', '--security-opt=apparmor=p0v3-private-v1', '--user=1000:1000', '--memory=1024m', '--pids-limit=128', '--image-volume=ignore', '--tmpfs=/tmp:rw,nosuid,nodev,size=128m', '--env=HOME=/tmp', '--env=KOPIA_CACHE_DIRECTORY=/tmp/cache', '--volume', 'p0v3-live-backup-volume-repository:/repository:ro', '--volume', output + ':/restore:U']
        # Wrong-password client has neither server configuration nor any source-file mount.
        wrong = directory / 'wrong.env'; wrong.write_text('KOPIA_PASSWORD=wrong-' + nonce + '\n'); wrong.chmod(0o600)
        denied = run(common + ['--env-file', str(wrong), image, '--config-file=/tmp/repo.config', '--disable-file-logging', 'repository', 'connect', 'filesystem', '--path=/repository', '--readonly', '--no-check-for-updates'], ok=False)
        B.private_write(directory / 'wrong-password-denial.json', {'status': denied.returncode, 'stderr': denied.stderr.decode(errors='replace')})
        assert denied.returncode != 0 and b'invalid repository password' in denied.stderr.lower()
        command = 'set -eu; export HOME=/tmp KOPIA_CONFIG_PATH=/tmp/repo.config KOPIA_CACHE_DIRECTORY=/tmp/cache; kopia --disable-file-logging repository connect filesystem --path=/repository --readonly --no-check-for-updates; kopia --disable-file-logging snapshot verify --verify-files-percent=100; kopia --disable-file-logging snapshot restore --no-overwrite-files --no-overwrite-directories --no-overwrite-symlinks --skip-owners --flush-files ' + object_id + ' /restore/recovered'
        run(common + ['--env-file', str(root / 'repository.env'), '--entrypoint=/bin/sh', image, '-ec', command])
        restored = run(common + ['--entrypoint=/bin/sh', image, '-ec', 'test -f /restore/recovered; test ! -L /restore/recovered; cat /restore/recovered'])
        assert restored == expected
        receipt['restoredSha256'] = hashlib.sha256(restored).hexdigest()
        receipt['phase'] = 'restart-persistence'
        if args.supervised:
            unit = 'p0v3-private-backup.service'; run(['systemctl', 'is-enabled', '--quiet', unit]); run(['sudo', '-n', 'systemctl', 'restart', unit]); run(['systemctl', 'is-active', '--quiet', unit])
        else: runtime('stop-private'); runtime('apply-private')
        session(); after = inspect()
        assert before['Id'] == after['Id'] and before['State']['StartedAt'] != after['State']['StartedAt']
        assert hashlib.sha256((root / 'runtime.jobs').read_bytes()).hexdigest() == jobs
        assert api(snapshot_url)['snapshots'] == snapshots
        request('/api/v1/sources', auth=None, expected_status=401)
        receipt.update(passed=True, phase='complete', nativeTlsAndAuthentication=True, missingCsrfDenied=True, controlUserDeniedUi=True, nativeApiSnapshot=True, isolatedNetworklessRestore=True, wrongRepositoryPasswordDenied=True, plaintextRestoredBytesVerified=True, persistentSnapshotAfterRestart=True, initializerJournalUnchanged=True, supervised=args.supervised)
    print(json.dumps(receipt))


if __name__ == '__main__': main()
