#!/usr/bin/env python3
"""Native Huly issue/description, tenant denial, indexing, TLS and actual restart persistence.
Requires the previously acknowledged synthetic workspace and issue. Never creates or replays them.
"""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
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
import uuid
from probe_receipt import private_receipt

_spec = importlib.util.spec_from_file_location('huly_diagnostics', Path(__file__).with_name('inspect-private-huly.py'))
H = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(H)


def write(path, value):
    payload = value if isinstance(value, bytes) else (json.dumps(value, indent=2) + '\n').encode()
    with path.open('wb') as stream:
        os.chmod(path, 0o600); stream.write(payload); stream.flush(); os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--name', default='huly-r10'); parser.add_argument('--supervised', action='store_true'); args = parser.parse_args()
    assert re.fullmatch('[a-z][a-z0-9-]{0,39}', args.name)
    os.umask(0o077)
    manifest, inputs = H.BASE / (args.name + '.json'), H.BASE / args.name
    fingerprint = hashlib.sha256(manifest.read_bytes()).hexdigest(); spec = json.loads(manifest.read_text())
    roles = [p['id'] for p in spec['processes'] if not p.get('oneShot', False)]
    assert set(roles) == {'cockroach', 'elastic', 'objects', 'redpanda', 'stats', 'account', 'workspace', 'transactor', 'collaborator', 'rekoni', 'fulltext', 'front', 'kvs', 'huly'}
    assert {p['id'] for p in spec['processes'] if p.get('oneShot', False)} == {'database-init', 'elastic-config-init', 'elastic-users', 'account-bootstrap'}
    assert {v['id'] for v in spec['volumes']} == {'cockroach', 'elastic', 'elastic-config', 'objects', 'redpanda', 'workspace-logs'}
    assert all(p['userId'] == 1000 and not p.get('capabilities') and p['apparmorProfile'] == 'p0v3-private-v1' for p in spec['processes'])
    intent = Path('/mnt/media/p0-v3/huly-probe-state') / (fingerprint + '.workspace.intent')
    for file in (intent, Path(str(intent) + '.issue.intent'), Path(str(intent) + '.issue.intent.permalink')):
        assert file.resolve() == file and file.stat().st_uid == os.getuid() and file.stat().st_mode & 0o777 == 0o600 and file.stat().st_size <= 8192
    workspace = json.loads(intent.read_text()); issue = json.loads(Path(str(intent) + '.issue.intent').read_text())
    assert workspace['manifestSha256'] == issue['manifestSha256'] == fingerprint and workspace['workspace'] == issue['workspace']
    assert workspace['phase'] == 'creation-acknowledged'
    nonce = issue['title'].removeprefix('Private issue '); assert re.fullmatch('[a-f0-9]{12}', nonce)
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-huly-' + uuid.uuid4().hex[:12]); directory.mkdir(mode=0o700)
    receipt = {'id': directory.name, 'deployment': args.name, 'manifestSha256': fingerprint, 'passed': False, 'fullStackAcceptance': False,
               'scope': 'Private native Huly issue/description, outsider denial, indexing and restart', 'createdIssueThisRun': False,
               'realOwnerOnboarding': False, 'encryptedRecovery': False, 'publicHttpsTest': False, 'phase': 'audit'}
    write(directory / 'receipt.json', receipt)
    env = dict(os.environ, JAVA_HOME='/usr/lib/jvm/java-21-openjdk-amd64')
    unit = 'p0v3-private-' + args.name + '.service'

    def runtime(action):
        result = subprocess.run([str(H.CLI), 'runtime', action, str(manifest)], env=env, capture_output=True, timeout=1200)
        write(directory / (action + '-' + uuid.uuid4().hex[:8] + '.log'), result.stdout + result.stderr)
        assert result.returncode == 0, 'Lifecycle failed; protected diagnostics retained'

    def inspect(role):
        data = json.loads(subprocess.run(H.P + ['inspect', 'p0v3-live-' + args.name + '-' + role], capture_output=True, check=True, timeout=20).stdout)[0]
        assert data['State']['Running'] and not data['HostConfig']['PortBindings']
        assert set(data['NetworkSettings']['Networks']) == {'p0v3-live-' + args.name + '-net'}
        assert data['Config']['Labels']['io.p0v3.private-deployment'] == args.name
        return data

    def snapshot(label, values):
        write(directory / (label + '-containers.json'), {role: {'id': data['Id'], 'startedAt': data['State']['StartedAt'], 'image': data['Image'], 'ports': data['HostConfig']['PortBindings']} for role, data in values.items()})

    def frozen_inputs():
        names = {p['environmentFile'] for p in spec['processes'] if p.get('environmentFile')} | {f['file'] for p in spec['processes'] for f in p.get('files', [])} | {'runtime.jobs', 'runtime.owner'}
        return {name: hashlib.sha256((inputs / name).read_bytes()).hexdigest() for name in sorted(names)}

    def browser(label):
        result = subprocess.run(['python3', str(Path(__file__).with_name('inspect-private-huly.py')), '--name', args.name, '--mode', 'verify-issue'], capture_output=True, timeout=650)
        write(directory / (label + '-browser.log'), result.stdout + result.stderr)
        assert result.returncode == 0, 'Native issue verification failed; no creation replay permitted'
        evidence = json.loads(result.stdout)
        assert evidence['manifestSha256'] == fingerprint and evidence['nativeIssueAndDescription'] and evidence['outsiderWorkspaceDenied'] and evidence['createdIssueThisRun'] is False
        receipt[label + 'BrowserEvidence'] = evidence['id']

    def index():
        credentials = json.loads((inputs / 'search-bootstrap.json').read_text())
        config = 'silent\nshow-error\ncacert="/configuration/es-ca.pem"\nuser="huly:' + credentials['application'] + '"\nurl="https://elastic:9200/huly*/_search?size=20&q=' + nonce + '"\n'
        result = subprocess.run(H.P + ['exec', '-i', 'p0v3-live-' + args.name + '-elastic', 'curl', '--config', '-'], input=config.encode(), capture_output=True, timeout=30)
        assert result.returncode == 0
        data = json.loads(result.stdout); hits = data['hits']['hits']
        assert any(issue['title'] in json.dumps(hit['_source']) and issue['description'] in json.dumps(hit['_source']) for hit in hits)
        receipt['nativeFulltextIndexedIssueAndDescription'] = True

    def transport():
        result = subprocess.run(H.P + ['exec', '-i', 'p0v3-live-' + args.name + '-kvs', '/usr/local/bin/node', '-e', Path(__file__).with_name('huly-kvs-transport-probe.cjs').read_text()],
                                input=json.dumps({'wrongCa': (inputs / 'ca.pem').read_text()}).encode(), capture_output=True, timeout=70)
        write(directory / ('kvs-transport-' + uuid.uuid4().hex[:8] + '.log'), result.stdout + result.stderr)
        assert result.returncode == 0
        proof = json.loads(result.stdout)
        assert all(proof[key] for key in ('verifiedRemoteTls', 'wrongCaDenied', 'wrongHostnameDenied', 'plaintextDatabaseDenied'))
        probe = H.P + ['exec', 'p0v3-live-' + args.name + '-cockroach', 'curl', '-sS', '--connect-timeout', '3']
        status = subprocess.run(probe + ['http://kvs:8094/status'], capture_output=True, timeout=10)
        blocked = subprocess.run(probe + ['http://kvs:26257/'], capture_output=True, timeout=10)
        assert status.returncode == 0 and status.stdout == b'ok' and blocked.returncode == 7
        receipt['kvsTlsBridge'] = proof | {'inaccessibleFromPeer': True}
        ingress = inspect('huly'); address = ingress['NetworkSettings']['Networks']['p0v3-live-' + args.name + '-net']['IPAddress']
        context = ssl.create_default_context(cafile=str(inputs / 'ca.pem'))
        for host, path, expected in [('foreign.invalid', '/', 421), ('huly:8443', '/_collaborator', 404), ('huly:8443', '/_unavailable/gmail', 503)]:
            with socket.create_connection((address, 8443), timeout=10) as raw, context.wrap_socket(raw, server_hostname='huly') as stream:
                assert stream.getpeercert(binary_form=True) == ssl.PEM_cert_to_DER_cert((inputs / 'web.pem').read_text())
                connection = http.client.HTTPConnection('huly', 8443, timeout=10); connection.sock = stream
                connection.request('GET', path, headers={'Host': host, 'Origin': 'https://huly:8443'})
                response = connection.getresponse(); assert response.status == expected
                assert len(response.read(65537)) <= 65536
        receipt['strictSniHostAndNativeCollaborationRoute'] = True

    with private_receipt(receipt, lambda value: write(directory / 'receipt.json', value)):
        runtime('status-private')
        before = {role: inspect(role) for role in roles}; hashes = frozen_inputs()
        snapshot('before', before); write(directory / 'frozen-input-hashes.json', hashes)
        receipt['phase'] = 'before-restart'; browser('beforeRestart'); index(); transport()
        receipt['phase'] = 'restart'
        if args.supervised:
            subprocess.run(['systemctl', 'is-enabled', unit], capture_output=True, check=True, timeout=20)
            subprocess.run(['sudo', '-n', 'systemctl', 'stop', unit], capture_output=True, check=True, timeout=300)
            subprocess.run(['sudo', '-n', 'systemctl', 'start', unit], capture_output=True, check=True, timeout=1200)
            subprocess.run(['systemctl', 'is-active', unit], capture_output=True, check=True, timeout=20)
        else:
            runtime('stop-private'); runtime('apply-private')
        after = {role: inspect(role) for role in roles}; snapshot('after', after)
        assert all(before[role]['Id'] == after[role]['Id'] and before[role]['State']['StartedAt'] != after[role]['State']['StartedAt'] for role in roles)
        assert hashes == frozen_inputs() and fingerprint == hashlib.sha256(manifest.read_bytes()).hexdigest()
        receipt['phase'] = 'after-restart'; browser('afterRestart'); index(); transport(); runtime('status-private')
        receipt.update(passed=True, phase='complete', daemonsRestarted=len(roles), immutableInputsAndInitializerJournalUnchanged=True, supervisedRestart=args.supervised)
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
