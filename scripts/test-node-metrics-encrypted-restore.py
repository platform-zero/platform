#!/usr/bin/env python3
"""Stopped, fenced exporter textfiles + Prometheus TSDB + exact PKI/configuration recovery.
Synthetic private data only. Does not claim off-host storage or full-stack acceptance.
"""
if not __debug__:
    raise SystemExit('Optimized Python disables safety checks; refusing effects')
import argparse
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import socket
import ssl
import subprocess
import time
import urllib.parse
import uuid
from financial_restore_archive import inventory
from probe_receipt import private_receipt

spec = importlib.util.spec_from_file_location('metrics_helpers', Path(__file__).with_name('test-private-openbao.py'))
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)
ENV = {**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'}
MAX_ARCHIVE = 1024 ** 3


def digest(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def private(path, data):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())


def fixture_identity(path, manifest_hash):
    assert path.resolve() == path and path.stat().st_mode & 0o777 == 0o700
    assert not list(path.glob('*invalidat*'))
    receipt = json.loads((path / 'receipt.json').read_text())
    assert receipt['passed'] and receipt['phase'] == 'complete' and receipt['deployment'] == 'node-metrics-r2'
    assert receipt['manifestSha256'] == manifest_hash and receipt['nativeTsdbHistorySurvivedRestart']
    ids = set()
    for intent in path.glob('probe-*-intent.json'):
        data = json.loads(intent.read_text()); match = re.fullmatch(r'probe-([a-f0-9]{32})\.prom', data['file'])
        assert match; ids.add(match.group(1))
    assert len(ids) == 1
    return receipt, ids.pop()


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--fixture', required=True, type=Path); args = parser.parse_args()
    source = 'node-metrics-r2'; source_path = B.BASE / (source + '.json'); source_hash = digest(source_path)
    fixture, prior_id = fixture_identity(args.fixture, source_hash)
    source_spec = json.loads(source_path.read_text())
    assert source_spec['volumes'] == [{'id': 'prometheus', 'userId': 65534}, {'id': 'metrics', 'userId': 65534}]
    assert {p['id'] for p in source_spec['processes']} == {'metrics-init', 'node', 'prometheus'}
    image = next(p['image'] for p in source_spec['processes'] if p['id'] == 'node')
    assert image == 'localhost/p0v3-node-exporter@sha256:daf70dc167702888cd9d949edab429eda1d3abb92a81d788f8bb427711b28a96'
    candidate = B.ROOT / 'platform/release/downloaded-candidate-inventory.json'
    kopia_image = next(i['pinnedImage'] for i in json.loads(candidate.read_text())['images'] if i['product'] == 'kopia')
    nonce = uuid.uuid4().hex[:12]; target = 'nmrestore-' + nonce
    assert not (B.BASE / (target + '.json')).exists() and not (B.BASE / target).exists()
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-metrics-restore-' + nonce)
    directory.mkdir(mode=0o700); snapshot = directory / 'snapshot'; export = directory / 'export'
    snapshot.mkdir(mode=0o700); export.mkdir(mode=0o700)
    private(directory / 'kopia.env', ('KOPIA_PASSWORD=' + secrets.token_hex(32) + '\n').encode())
    unit = 'p0v3-private-' + source + '.service'; unit_path = Path('/etc/systemd/system') / unit
    assert not unit_path.is_symlink() and unit_path.stat().st_uid == 0
    assert re.search(r'^ExecStart=/mnt/media/p0-v3/runtime-supervision/releases/[a-f0-9]{64}/bin/p0-v3-platform runtime boot-apply ' + source + ' ' + source_hash + '$', unit_path.read_text(), re.M)
    repo, config = directory.name + '-repository', directory.name + '-config'
    receipt = {'id': directory.name, 'source': source, 'restore': target, 'passed': False, 'fullStackAcceptance': False, 'offHostBackup': False, 'hostMonitoring': False, 'sourceManifestSha256': source_hash}
    lock = None; fence = None; target_fence = None; maintenance = False
    def run(command, data=None, ok=True, stdin=None):
        result = subprocess.run(command, input=data, stdin=stdin, capture_output=True, env=ENV, timeout=1200)
        if ok and result.returncode:
            private(directory / ('failure-' + uuid.uuid4().hex[:8] + '.log'), result.stderr)
            raise RuntimeError('Metrics recovery operation failed; protected diagnostics retained')
        return result.stdout if ok else result
    def runtime(action, name):
        return json.loads(run([str(B.CLI), 'runtime', action, str(B.BASE / (name + '.json'))]).splitlines()[0])
    def system(*args): return run(['sudo', '-n', 'systemctl', *args, unit])
    def inspect(name, role):
        return json.loads(run(B.P + ['inspect', 'p0v3-live-' + name + '-' + role]))[0]
    def address(name, role):
        data = inspect(name, role); network = 'p0v3-live-' + name + '-net'
        assert data['State']['Running'] and not data['HostConfig']['PortBindings']
        assert data['Config']['Labels']['io.p0v3.private-deployment'] == name and set(data['NetworkSettings']['Networks']) == {network}
        return data['NetworkSettings']['Networks'][network]['IPAddress']
    def query(name, expression, at=None):
        params = {'query': expression}
        if at is not None: params['time'] = str(at)
        connection = http.client.HTTPConnection(address(name, 'prometheus'), 9090, timeout=15)
        try:
            connection.request('GET', '/api/v1/query?' + urllib.parse.urlencode(params)); response = connection.getresponse(); body = response.read(1048577)
            assert response.status == 200 and len(body) <= 1048576
            result = json.loads(body); assert result['status'] == 'success'; return result['data']['result']
        finally: connection.close()
    def value(name, expression, expected, at=None):
        for _ in range(60):
            result = query(name, expression, at)
            if len(result) == 1 and float(result[0]['value'][1]) == expected: return
            time.sleep(1)
        raise AssertionError('Native restored metric observation exhausted')
    def metrics(name):
        root = B.BASE / name; context = ssl.create_default_context(cafile=str(root / 'ca.pem'))
        context.load_cert_chain(str(root / 'admin.pem'), str(root / 'admin-key.pem'))
        with socket.create_connection((address(name, 'node'), 9100), timeout=15) as raw, context.wrap_socket(raw, server_hostname='node') as tls:
            assert tls.getpeercert(binary_form=True) == ssl.PEM_cert_to_DER_cert((root / 'node.pem').read_text())
            tls.sendall(b'GET /metrics HTTP/1.1\r\nHost: node:9100\r\nConnection: close\r\n\r\n')
            with http.client.HTTPResponse(tls) as response:
                response.begin(); body = response.read(1048577); assert response.status == 200 and len(body) <= 1048576
                return body.decode()
    def write_metric(name, side, number):
        assert side in ('before', 'source', 'target') and number == 1
        filename = 'recovery-' + nonce + '-' + side + '.prom'
        expression = 'p0v3_recovery_probe{run="' + nonce + '",side="' + side + '"}'
        payload = (expression + ' 1\n').encode()
        private(directory / (name + '-' + side + '-intent.json'), json.dumps({'file': filename, 'sha256': hashlib.sha256(payload).hexdigest()}).encode())
        command = 'set -eu; umask 077; test ! -e "$1"; test ! -L "$1"; test ! -e "$1.tmp"; test ! -L "$1.tmp"; cat > "$1.tmp"; sync; mv "$1.tmp" "$1"; sync'
        run(B.P + ['exec', '-i', 'p0v3-live-' + name + '-node', '/bin/sh', '-c', command, 'sh', '/synthetic/' + filename], payload)
        value(name, expression, 1); assert expression + ' 1' in metrics(name)
        return expression
    def volume_args(name, volume, readonly):
        assert volume in ('metrics', 'prometheus')
        return B.P + ['run', '--rm', '--interactive', '--pull=never', '--network=none', '--read-only', '--cap-drop=all', '--security-opt=no-new-privileges', '--security-opt=apparmor=p0v3-private-v1', '--user=65534:65534', '--memory=256m', '--pids-limit=64', '--image-volume=ignore', '--volume', 'p0v3-live-' + name + '-volume-' + volume + ':/state:' + ('ro' if readonly else 'rw'), '--entrypoint=/bin/sh', image, '-ec']
    def volume(name, vol, readonly, command, data=None, ok=True, stdin=None):
        return run(volume_args(name, vol, readonly) + [command], data, ok, stdin)
    def capture(name, vol, path):
        # Bounded streaming, not an unbounded communicate()/in-memory tar buffer.
        with path.open('xb') as out, (directory / ('tar-' + uuid.uuid4().hex[:8] + '.log')).open('xb') as error:
            os.fchmod(out.fileno(), 0o600); os.fchmod(error.fileno(), 0o600)
            child = subprocess.Popen(volume_args(name, vol, True) + ['tar -cf - -C /state .'], stdout=subprocess.PIPE, stderr=error)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ); count = 0; deadline = time.monotonic() + 180
                    while True:
                        assert time.monotonic() < deadline, 'Archive capture timed out'
                        if not selector.select(1): continue
                        data = os.read(child.stdout.fileno(), 1048576)
                        if not data: break
                        count += len(data); assert count <= MAX_ARCHIVE, 'Archive capture budget exceeded'
                        out.write(data)
                assert child.wait(timeout=30) == 0
                out.flush(); os.fsync(out.fileno())
            finally:
                if child.poll() is None: child.kill(); child.wait()
                child.stdout.close()
        return inventory(path, max_bytes=MAX_ARCHIVE)
    def kopia(*args, password=None, configuration='/config/repository.config', ok=True):
        return run(B.P + ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=all', '--security-opt=no-new-privileges', '--security-opt=apparmor=p0v3-private-v1', '--user=1000:1000', '--memory=1024m', '--pids-limit=256', '--image-volume=ignore', '--tmpfs=/tmp:rw,nosuid,nodev,size=128m', '--volume', repo + ':/repository:U', '--volume', config + ':/config:U', '--volume', str(snapshot) + ':/snapshot:ro', '--volume', str(export) + ':/restore:rw', '--env-file', str(password or directory / 'kopia.env'), '--env=HOME=/tmp', '--env=KOPIA_CACHE_DIRECTORY=/tmp/cache', kopia_image, '--config-file=' + configuration, '--disable-file-logging', *args], ok=ok)
    def release_source():
        nonlocal fence
        if fence is None:
            assert runtime('maintenance-status', source) is None, 'Uncertain source fence; manual reconciliation required'
            return
        runtime('stop-private', source)
        run([str(B.CLI), 'runtime', 'maintenance-leave', str(source_path), fence['id']]); fence = None
    def guard_check(ok):
        # Invoke the exact generated guard with both volumes, without replaying a runtime initializer.
        target_spec = json.loads((B.BASE / (target + '.json')).read_text()); guard = target_spec['processes'][0]['command'][-1]
        command = B.P + ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=all', '--security-opt=no-new-privileges', '--security-opt=apparmor=p0v3-private-v1', '--user=65534:65534', '--memory=128m', '--pids-limit=64', '--image-volume=ignore']
        for vol in ('metrics', 'prometheus'): command += ['--volume', 'p0v3-live-' + target + '-volume-' + vol + ':/recovered/' + vol + ':ro']
        result = run(command + ['--entrypoint=/bin/sh', image, '-ec', guard], ok=False)
        assert (result.returncode == 0) == ok
    historical = 'p0v3_mutable_probe{run="' + prior_id + '"}'
    with private_receipt(receipt, lambda data: B.private_write(directory / 'receipt.json', data)):
        try:
            assert system('is-enabled').strip() == b'enabled' and system('is-active').strip() == b'active'
            runtime('apply-private', source)
            value(source, historical, 42, fixture['sampleTime'])
            value(source, 'node_textfile_scrape_error{job="private-node"}', 1, fixture['alertTime'])
            before_expr = write_metric(source, 'before', 1)
            jobs = digest(B.BASE / source / 'runtime.jobs'); receipt['phase'] = 'fenced-capture'
            maintenance = True; system('disable', '--now')
            assert runtime('maintenance-status', source) is None
            fence = json.loads(run([str(B.CLI), 'runtime', 'maintenance-enter', str(source_path), 'backup']))
            assert run([str(B.CLI), 'runtime', 'apply-private', str(source_path)], ok=False).returncode != 0
            lock = (B.BASE / source / 'runtime.lock').open('r+b'); fcntl.lockf(lock, fcntl.LOCK_EX)
            frozen = {p['id']: inspect(source, p['id']) for p in source_spec['processes']}; assert all(not item['State']['Running'] for item in frozen.values())
            inputs = {p['environmentFile'] for p in source_spec['processes'] if p.get('environmentFile')} | {f['file'] for p in source_spec['processes'] for f in p.get('files', [])}
            private(snapshot / 'source-spec.json', source_path.read_bytes())
            for file in inputs:
                path = B.BASE / source / file; assert not path.is_symlink() and path.stat().st_mode & 0o777 == 0o600
                private(snapshot / file, path.read_bytes())
            trees = {}
            for vol in ('metrics', 'prometheus'):
                trees[vol] = capture(source, vol, snapshot / (vol + '.tar'))
                assert '.p0v3-restore-complete' not in trees[vol] and '.restore-in-progress' not in trees[vol]
                private(snapshot / (vol + '-tree.json'), json.dumps(trees[vol], sort_keys=True).encode())
            hashes = {path.name: digest(path) for path in snapshot.iterdir()}
            private(snapshot / 'manifest.json', json.dumps(hashes, sort_keys=True).encode()); receipt['archiveManifestSha256'] = digest(snapshot / 'manifest.json')
            for name in (repo, config):
                assert run(B.P + ['volume', 'exists', name], ok=False).returncode == 1
                run(B.P + ['volume', 'create', '--label=io.p0v3.restore-probe=' + directory.name, name])
            kopia('repository', 'create', 'filesystem', '--path=/repository', '--no-check-for-updates')
            snapshot_id = json.loads(kopia('snapshot', 'create', '--json', '/snapshot'))['rootEntry']['obj']; receipt['snapshotId'] = snapshot_id
            kopia('snapshot', 'verify', '--verify-files-percent=100')
            private(directory / 'wrong.env', ('KOPIA_PASSWORD=wrong-' + nonce + '\n').encode())
            denied = kopia('repository', 'connect', 'filesystem', '--path=/repository', '--no-check-for-updates', password=directory / 'wrong.env', configuration='/tmp/wrong.config', ok=False)
            assert denied.returncode != 0 and b'invalid repository password' in denied.stderr.lower()
            kopia('snapshot', 'restore', '--no-overwrite-files', '--no-overwrite-directories', '--no-overwrite-symlinks', '--skip-owners', '--flush-files', snapshot_id, '/restore/recovered')
            for vol in trees: assert capture(source, vol, directory / (vol + '-stable.tar')) == trees[vol]
            for file in inputs: assert digest(B.BASE / source / file) == hashes[file]
            assert digest(source_path) == source_hash and digest(B.BASE / source / 'runtime.jobs') == jobs
            for role, before in frozen.items():
                after = inspect(source, role); assert before['Id'] == after['Id'] and before['State']['StartedAt'] == after['State']['StartedAt'] and not after['State']['Running']
            lock.close(); lock = None; release_source(); system('enable', '--now'); maintenance = False
            source_expr = write_metric(source, 'source', 1)
            recovered = export / 'recovered'; assert not recovered.is_symlink() and digest(recovered / 'manifest.json') == receipt['archiveManifestSha256']
            assert {path.name for path in recovered.iterdir()} == set(hashes) | {'manifest.json'}
            for file, checksum in hashes.items():
                path = recovered / file; assert not path.is_symlink() and path.is_file() and digest(path) == checksum; path.chmod(0o600)
            recovered.chmod(0o700)
            for vol in trees: assert inventory(recovered / (vol + '.tar'), max_bytes=MAX_ARCHIVE) == trees[vol]
            run([str(B.CLI), 'runtime', 'prepare-node-metrics-restore', str(candidate), str(recovered), target]); runtime('provision-private', target)
            target_path = B.BASE / (target + '.json')
            target_fence = json.loads(run([str(B.CLI), 'runtime', 'maintenance-enter', str(target_path), 'restore']))
            assert run([str(B.CLI), 'runtime', 'apply-private', str(target_path)], ok=False).returncode != 0
            receipt['phase'] = 'guarded-import'
            with (B.BASE / target / 'runtime.lock').open('r+b') as target_lock:
                fcntl.lockf(target_lock, fcntl.LOCK_EX); guard_check(False)
                for vol in trees:
                    volume(target, vol, False, 'test -z "$(ls -A /state)"; umask 077; touch /state/.restore-in-progress; sync')
                    with (recovered / (vol + '.tar')).open('rb') as stream: volume(target, vol, False, 'tar -xf - -C /state; sync', stdin=stream)
                    actual = capture(target, vol, directory / (vol + '-imported.tar')); actual.pop('.restore-in-progress')
                    assert actual == trees[vol]
                guard_check(False)
                for vol in trees:
                    volume(target, vol, False, 'rm /state/.restore-in-progress; ln -s nonexistent /state/.restore-in-progress')
                guard_check(False)
                for vol in trees:
                    volume(target, vol, False, "rm /state/.restore-in-progress; printf '%s\\n' wrong > /state/.p0v3-restore-complete; sync")
                guard_check(False)
                for vol in trees:
                    volume(target, vol, False, "rm /state/.p0v3-restore-complete; printf '%s\\n' " + source_hash + " > /state/foreign-marker; ln -s foreign-marker /state/.p0v3-restore-complete; sync")
                guard_check(False)
                for vol in trees:
                    volume(target, vol, False, "rm /state/.p0v3-restore-complete /state/foreign-marker; printf '%s\\n' " + source_hash + " > /state/.p0v3-restore-complete; sync")
                guard_check(True)
            run([str(B.CLI), 'runtime', 'maintenance-leave', str(target_path), target_fence['id']]); target_fence = None
            runtime('apply-private', target)
            receipt['phase'] = 'native-restored-history'
            value(target, before_expr, 1); value(target, historical, 42, fixture['sampleTime'])
            value(target, 'node_textfile_scrape_error{job="private-node"}', 1, fixture['alertTime'])
            assert before_expr + ' 1' in metrics(target) and source_expr not in metrics(target) and not query(target, source_expr)
            target_expr = write_metric(target, 'target', 1); assert target_expr not in metrics(source) and not query(source, target_expr)
            target_jobs = digest(B.BASE / target / 'runtime.jobs'); before = {role: inspect(target, role) for role in ('node', 'prometheus')}
            runtime('stop-private', target); runtime('apply-private', target)
            value(target, target_expr, 1); value(target, historical, 42, fixture['sampleTime']); assert not query(target, source_expr)
            for role, old in before.items():
                after = inspect(target, role); assert after['Id'] == old['Id'] and after['State']['StartedAt'] != old['State']['StartedAt']
            assert digest(B.BASE / target / 'runtime.jobs') == target_jobs and digest(B.BASE / source / 'runtime.jobs') == jobs
            for role, port in (('node', 9100), ('prometheus', 9090)):
                code = 'import socket; s=socket.socket(); s.settimeout(3); assert s.connect_ex((' + repr(address(source, role)) + ',' + str(port) + '))!=0'
                run(['sudo', '-n', 'nsenter', '--target=' + str(inspect(target, 'node')['State']['Pid']), '--net', '--setuid=' + str(os.getuid()), '--setgid=' + str(os.getgid()), '/usr/bin/python3', '-c', code])
            assert system('is-enabled').strip() == b'enabled' and system('is-active').strip() == b'active' and runtime('maintenance-status', source) is None
            receipt.update(passed=True, phase='complete', wrongPasswordDenied=True, encryptedExportVerified=True, sourceFenceAndStabilityVerified=True, restoredMutualTlsScrape=True, restoredTsdbHistoricalSamples=True, postSnapshotWriteExcluded=True, divergentWritesIsolated=True, incompleteForeignSymlinkMarkerDenied=True, restoredRestartVerified=True, initializerJournalsUnchanged=True, sourceTcpBlocked=True)
        finally:
            if lock: lock.close()
            cleanup_failed = False
            if maintenance:
                try: release_source(); system('enable', '--now')
                except Exception: cleanup_failed = True; receipt['sourceResumeFailed'] = True
            if (B.BASE / (target + '.json')).exists():
                try: assert all(p['state'] != 'running' for p in runtime('stop-private', target))
                except Exception: cleanup_failed = True; receipt['restoreQuarantineFailed'] = True
            if target_fence is not None: receipt['retainedRestoreFence'] = target_fence['id']
            if cleanup_failed: raise RuntimeError('Metrics recovery cleanup incomplete; manual reconciliation required')
    print(json.dumps(receipt))


if __name__ == '__main__': main()
