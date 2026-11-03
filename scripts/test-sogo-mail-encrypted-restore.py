#!/usr/bin/env python3
"""Fenced cold PG/mail/home/config capture, encrypted Kopia restore and isolated native journeys."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
from email import policy
from email.message import EmailMessage
import fcntl
import hashlib
import http.client
import imaplib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import smtplib
import socket
import ssl
import subprocess
import time
import uuid
import base64
from financial_restore_archive import inventory, extraction_command
from probe_receipt import private_receipt

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/media/p0-v3/runtime-deployments')
CLI = ROOT / 'platform/build/install/p0-v3-platform/bin/p0-v3-platform'
P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph', '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
ENV = dict(os.environ, JAVA_HOME='/usr/lib/jvm/java-21-openjdk-amd64')
LIMIT = 1024 ** 3


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def private(path, data):
    with path.open('xb') as stream:
        stream.write(data); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--fixture', required=True, type=Path); args = parser.parse_args(); os.umask(0o077)
    source = 'sogo-mail-r2'; source_path = BASE / (source + '.json'); source_hash = digest(source_path); spec = json.loads(source_path.read_text())
    assert args.fixture.resolve() == args.fixture and args.fixture.stat().st_mode & 0o777 == 0o700 and not list(args.fixture.glob('*invalidat*'))
    proof = json.loads((args.fixture / 'receipt.json').read_text()); assert proof['passed'] and proof['phase'] == 'complete' and proof['manifestSha256'] == source_hash and proof['nativeSogoSmtpDeliveryAndSentCopy'] and proof['nativeSogoCrossUserMailboxDenial']
    volumes = {v['id']: v['userId'] for v in spec['volumes']}; assert volumes == {'database': 999, 'home': 994, 'mail': 2000}
    helper = next(p['image'] for p in spec['processes'] if p['id'] == 'mail-init')
    candidate = ROOT / 'platform/release/downloaded-candidate-inventory.json'
    kopia_image = next(i['pinnedImage'] for i in json.loads(candidate.read_text())['images'] if i['product'] == 'kopia')
    nonce = uuid.uuid4().hex[:12]; target = 'smrestore-' + nonce; assert not (BASE / (target + '.json')).exists() and not (BASE / target).exists()
    out = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-sogo-mail-restore-' + nonce); out.mkdir(mode=0o700)
    snapshot = out / 'snapshot'; snapshot.mkdir(mode=0o700); export = out / 'export'; export.mkdir(mode=0o700)
    private(out / 'kopia.env', ('KOPIA_PASSWORD=' + secrets.token_hex(32) + '\n').encode())
    repo, config = out.name + '-repository', out.name + '-config'
    unit = 'p0v3-private-' + source + '.service'; unit_path = Path('/etc/systemd/system') / unit
    assert not unit_path.is_symlink() and unit_path.stat().st_uid == 0 and re.search(r'^ExecStart=/mnt/media/p0-v3/runtime-supervision/releases/[a-f0-9]{64}/bin/p0-v3-platform runtime boot-apply ' + source + ' ' + source_hash + '$', unit_path.read_text(), re.M)
    receipt = {'id': out.name, 'source': source, 'restore': target, 'sourceManifestSha256': source_hash, 'passed': False, 'fullStackAcceptance': False, 'offHostBackup': False, 'pendingDraftRecovery': False, 'phase': 'audit'}
    fence = target_fence = lock = None; maintenance = False; jobs = None
    def run(command, data=None, stdin=None, ok=True, timeout=1200):
        r = subprocess.run(command, input=data, stdin=stdin, capture_output=True, env=ENV, timeout=timeout)
        if ok and r.returncode:
            private(out / ('failure-' + uuid.uuid4().hex[:8] + '.log'), r.stdout + r.stderr)
            raise RuntimeError('Recovery operation failed; protected evidence retained')
        return r.stdout if ok else r
    def runtime(action, name):
        return json.loads(run([str(CLI), 'runtime', action, str(BASE / (name + '.json'))]).splitlines()[0])
    def system(*action):
        return run(['sudo', '-n', 'systemctl', *action, unit])
    def inspect(name, role):
        return json.loads(run(P + ['inspect', 'p0v3-live-' + name + '-' + role]))[0]
    def address(name, role):
        c = inspect(name, role); assert c['State']['Running'] and not c['HostConfig']['PortBindings']
        assert c['Config']['Labels']['io.p0v3.private-deployment'] == name and set(c['NetworkSettings']['Networks']) == {'p0v3-live-' + name + '-net'}
        return next(iter(c['NetworkSettings']['Networks'].values()))['IPAddress']
    def volume_args(name, vol, readonly):
        assert vol in volumes
        return P + ['run', '--rm', '-i', '--pull=never', '--network=none', '--read-only', '--cap-drop=all', '--security-opt=no-new-privileges', '--security-opt=apparmor=p0v3-private-v1', '--user=' + str(volumes[vol]) + ':' + str(volumes[vol]), '--memory=256m', '--pids-limit=64', '--image-volume=ignore', '--volume', 'p0v3-live-' + name + '-volume-' + vol + ':/state:' + ('ro' if readonly else 'rw'), '--entrypoint=/bin/sh', helper, '-ec']
    def volume(name, vol, command, readonly=False, stdin=None):
        return run(volume_args(name, vol, readonly) + [command], stdin=stdin)
    def capture(name, vol, path):
        with path.open('xb') as stream, (out / ('tar-' + uuid.uuid4().hex[:8] + '.log')).open('xb') as error:
            child = subprocess.Popen(volume_args(name, vol, True) + ['tar -cf - -C /state .'], stdout=subprocess.PIPE, stderr=error)
            try:
                with selectors.DefaultSelector() as poll:
                    poll.register(child.stdout, selectors.EVENT_READ); count = 0; deadline = time.monotonic() + 180
                    while True:
                        assert time.monotonic() < deadline
                        if not poll.select(1):
                            continue
                        data = os.read(child.stdout.fileno(), 1048576)
                        if not data:
                            break
                        count += len(data); assert count <= LIMIT; stream.write(data)
                assert child.wait(timeout=30) == 0; stream.flush(); os.fsync(stream.fileno())
            finally:
                if child.poll() is None:
                    child.kill(); child.wait()
                child.stdout.close()
        return inventory(path, max_bytes=LIMIT, expected_owner=(volumes[vol], volumes[vol]))
    def kopia(*args, password=None, configuration='/config/repository.config', ok=True):
        return run(P + ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=all', '--security-opt=no-new-privileges', '--security-opt=apparmor=p0v3-private-v1', '--user=1000:1000', '--memory=1024m', '--pids-limit=256', '--image-volume=ignore', '--tmpfs=/tmp:rw,nosuid,nodev,size=128m', '--volume', repo + ':/repository:U', '--volume', config + ':/config:U', '--volume', str(snapshot) + ':/snapshot:ro', '--volume', str(export) + ':/restore:rw', '--env-file', str(password or out / 'kopia.env'), '--env=HOME=/tmp', '--env=KOPIA_CACHE_DIRECTORY=/tmp/cache', kopia_image, '--config-file=' + configuration, '--disable-file-logging', *args], ok=ok)
    def marker_mail(name, side, create=False):
        host = address(name, 'mail'); ca = ssl.create_default_context(cafile=str(BASE / name / 'mail-ca.pem')); users = json.loads((BASE / name / 'users.json').read_text()); subject = 'Recovery ' + nonce + ' ' + side
        class SMTP(smtplib.SMTP_SSL):
            def _get_socket(self, host, port, timeout):
                return self.context.wrap_socket(socket.create_connection((address(name, 'mail'), port), timeout=timeout), server_hostname='mail')
        class IMAP(imaplib.IMAP4_SSL):
            def _create_socket(self, timeout):
                return ca.wrap_socket(socket.create_connection((host, self.port), timeout=timeout), server_hostname='mail')
        if create:
            msg = EmailMessage(policy=policy.SMTP); msg['From'] = 'alice@p0v3.example.org'; msg['To'] = 'bob@p0v3.example.org'; msg['Subject'] = subject; msg['Message-ID'] = '<' + nonce + '-' + side + '@p0v3.example.org>'; msg.set_content('Synthetic isolated recovery ' + side)
            body = msg.as_bytes(); private(out / (name + '-' + side + '-mail.intent'), hashlib.sha256(body).hexdigest().encode())
            with SMTP('mail', 2465, local_hostname='probe.example.org', context=ca, timeout=20) as c:
                c.login('alice@p0v3.example.org', users['alice']); assert c.sendmail('alice@p0v3.example.org', ['bob@p0v3.example.org'], body) == {}
            private(out / (name + '-' + side + '-mail.accepted'), b'accepted\n')
        for attempt in range(60 if create else 1):
            with IMAP('mail', 2993, ssl_context=ca, timeout=20) as c:
                assert c.login('bob@p0v3.example.org', users['bob'])[0] == 'OK' and c.select('INBOX', readonly=True)[0] == 'OK'
                status, data = c.uid('search', None, 'SUBJECT', '"' + subject + '"'); assert status == 'OK'
                ids = data[0].split(); assert len(ids) <= 1
                if ids:
                    status, parts = c.uid('fetch', ids[0], '(BODY.PEEK[])'); assert status == 'OK'
                    raw = next(x[1] for x in parts if isinstance(x, tuple)); assert ('Synthetic isolated recovery ' + side).encode() in raw
                    return {'uid': ids[0].decode(), 'uidValidity': c.response('UIDVALIDITY')[1][0].decode(), 'sha256': hashlib.sha256(raw).hexdigest()}
            if create:
                time.sleep(1)
        assert not create, 'Native marker delivery deadline; no resend authorized'
        return None
    def marker_calendar(name, side, create=False):
        host = address(name, 'groupware'); ca = ssl.create_default_context(cafile=str(BASE / name / 'ca.pem')); users = json.loads((BASE / name / 'users.json').read_text())
        path = '/SOGo/dav/alice/Calendar/personal/recovery-' + nonce + '-' + side + '.ics'
        def request(method, body=None):
            with socket.create_connection((host, 8443), timeout=20) as raw, ca.wrap_socket(raw, server_hostname='groupware') as tls:
                c = http.client.HTTPConnection('groupware', 8443, timeout=20); c.sock = tls
                c.request(method, path, body, {'Host': 'groupware:8443', 'Authorization': 'Basic ' + base64.b64encode(('alice:' + users['alice']).encode()).decode(), 'Content-Type': 'text/calendar', 'If-None-Match': '*' if method == 'PUT' else '"never-match"'})
                r = c.getresponse(); value = r.read(1048577); assert len(value) <= 1048576; return r.status, value
        if create:
            body = ('BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//P0v3//Synthetic recovery//EN\r\nBEGIN:VEVENT\r\nUID:' + nonce + '-' + side + '\r\nDTSTAMP:20261102T000000Z\r\nDTSTART:20261102T120000Z\r\nDTEND:20261102T123000Z\r\nSUMMARY:Recovery ' + nonce + ' ' + side + '\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n').encode()
            private(out / (name + '-' + side + '-calendar.intent'), hashlib.sha256(body).hexdigest().encode()); status, response = request('PUT', body); private(out / (name + '-' + side + '-calendar.outcome'), json.dumps({'status': status}).encode()); assert status == 201
        status, body = request('GET')
        if status == 404:
            assert not create; return None
        assert status == 200 and ('Recovery ' + nonce + ' ' + side).encode() in body
        return hashlib.sha256(body).hexdigest()
    def guard(role, expected):
        target_spec = json.loads((BASE / (target + '.json')).read_text()); process = next(p for p in target_spec['processes'] if p['id'] == role)
        command = P + ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=all', '--security-opt=no-new-privileges', '--security-opt=apparmor=p0v3-private-v1', '--user=' + str(process['userId']) + ':' + str(process.get('groupId', process['userId'])), '--memory=128m', '--pids-limit=64', '--image-volume=ignore']
        for mount in process['volumes']:
            command += ['--volume', 'p0v3-live-' + target + '-volume-' + mount['volume'] + ':' + mount['target'] + ':ro']
        if role == 'mail-init':
            command += ['--secret', 'source=p0v3-live-' + target + '-file-generation,type=mount,target=/run/secrets/generation,uid=2000,gid=2000,mode=0400']
        result = run(command + ['--entrypoint=/bin/sh', process['image'], *process['command']], ok=False)
        assert (result.returncode == 0) == expected
    def release_source():
        nonlocal fence
        assert fence is not None, 'Unknown source fence; explicit reconciliation required'
        runtime('stop-private', source)
        assert digest(source_path) == source_hash and digest(BASE / source / 'runtime.jobs') == jobs
        run([str(CLI), 'runtime', 'maintenance-leave', str(source_path), fence['id']]); fence = None
    with private_receipt(receipt, lambda r: (out / 'receipt.json').write_text(json.dumps(r, indent=2))):
        try:
            assert system('is-enabled').strip() == b'enabled' and system('is-active').strip() == b'active'
            runtime('status-private', source)
            before_mail = marker_mail(source, 'before', True); before_calendar = marker_calendar(source, 'before', True)
            jobs = digest(BASE / source / 'runtime.jobs'); receipt['phase'] = 'fenced-capture'; maintenance = True; system('disable', '--now')
            assert runtime('maintenance-status', source) is None
            fence = json.loads(run([str(CLI), 'runtime', 'maintenance-enter', str(source_path), 'backup']))
            assert run([str(CLI), 'runtime', 'apply-private', str(source_path)], ok=False).returncode != 0
            lock = (BASE / source / 'runtime.lock').open('r+b'); fcntl.lockf(lock, fcntl.LOCK_EX)
            frozen = {p['id']: inspect(source, p['id']) for p in spec['processes']}; assert all(not c['State']['Running'] for c in frozen.values())
            inputs = {p['environmentFile'] for p in spec['processes'] if p.get('environmentFile')} | {f['file'] for p in spec['processes'] for f in p.get('files', [])}
            private(snapshot / 'source-spec.json', source_path.read_bytes())
            for file in inputs:
                path = BASE / source / file; assert not path.is_symlink() and path.stat().st_mode & 0o777 == 0o600; private(snapshot / file, path.read_bytes())
            trees = {}
            for vol in volumes:
                trees[vol] = capture(source, vol, snapshot / (vol + '.tar')); extraction_command(trees[vol])  # Reject reserved marker collisions before any import.
                private(snapshot / (vol + '-tree.json'), json.dumps(trees[vol], sort_keys=True).encode())
            hashes = {p.name: digest(p) for p in snapshot.iterdir()}; private(snapshot / 'manifest.json', json.dumps(hashes, sort_keys=True).encode()); receipt['archiveManifestSha256'] = digest(snapshot / 'manifest.json')
            for name in (repo, config):
                assert run(P + ['volume', 'exists', name], ok=False).returncode == 1; run(P + ['volume', 'create', '--label=io.p0v3.restore-probe=' + out.name, name])
            kopia('repository', 'create', 'filesystem', '--path=/repository', '--no-check-for-updates')
            snapshot_id = json.loads(kopia('snapshot', 'create', '--json', '/snapshot'))['rootEntry']['obj']; receipt['snapshotId'] = snapshot_id
            kopia('snapshot', 'verify', '--verify-files-percent=100')
            private(out / 'wrong.env', ('KOPIA_PASSWORD=wrong-' + nonce + '\n').encode())
            denied = kopia('repository', 'connect', 'filesystem', '--path=/repository', '--no-check-for-updates', password=out / 'wrong.env', configuration='/tmp/wrong.config', ok=False)
            assert denied.returncode != 0 and b'invalid repository password' in denied.stderr.lower()
            kopia('snapshot', 'restore', '--no-overwrite-files', '--no-overwrite-directories', '--no-overwrite-symlinks', '--skip-owners', '--flush-files', snapshot_id, '/restore/recovered')
            for vol in volumes:
                assert capture(source, vol, out / (vol + '-stable.tar')) == trees[vol]
            for file in inputs:
                assert digest(BASE / source / file) == hashes[file]
            for role, old in frozen.items():
                current = inspect(source, role); assert current['Id'] == old['Id'] and current['State']['StartedAt'] == old['State']['StartedAt'] and not current['State']['Running']
            lock.close(); lock = None; release_source(); system('enable', '--now'); maintenance = False
            source_mail = marker_mail(source, 'source', True); source_calendar = marker_calendar(source, 'source', True)
            recovered = export / 'recovered'; assert not recovered.is_symlink() and digest(recovered / 'manifest.json') == receipt['archiveManifestSha256']
            assert {p.name for p in recovered.iterdir()} == set(hashes) | {'manifest.json'}
            for file, checksum in hashes.items():
                path = recovered / file; assert not path.is_symlink() and path.is_file() and digest(path) == checksum; path.chmod(0o600)
            recovered.chmod(0o700)
            for vol in volumes:
                assert inventory(recovered / (vol + '.tar'), max_bytes=LIMIT, expected_owner=(volumes[vol], volumes[vol])) == trees[vol]
            run([str(CLI), 'runtime', 'prepare-sogo-mail-restore', str(candidate), str(recovered), target]); runtime('provision-private', target)
            target_path = BASE / (target + '.json'); target_fence = json.loads(run([str(CLI), 'runtime', 'maintenance-enter', str(target_path), 'restore']))
            assert run([str(CLI), 'runtime', 'apply-private', str(target_path)], ok=False).returncode != 0
            receipt['phase'] = 'guarded-import'
            with (BASE / target / 'runtime.lock').open('r+b') as target_lock:
                fcntl.lockf(target_lock, fcntl.LOCK_EX)
                guards = {'database': 'database-init', 'mail': 'mail-init', 'home': 'home-restore-check'}
                for vol, role in guards.items():
                    guard(role, False)
                    volume(target, vol, 'test -z "$(ls -A /state)"; umask 077; touch /state/.restore-in-progress; sync')
                    with (recovered / (vol + '.tar')).open('rb') as stream:
                        volume(target, vol, extraction_command(trees[vol]), stdin=stream)
                    actual = capture(target, vol, out / (vol + '-imported.tar')); actual.pop('.restore-in-progress'); assert actual == trees[vol]
                    guard(role, False)
                    volume(target, vol, 'rm /state/.restore-in-progress; ln -s missing /state/.restore-in-progress'); guard(role, False)
                    volume(target, vol, "rm /state/.restore-in-progress; printf '%s\\n' wrong > /state/.p0v3-restore-complete; sync"); guard(role, False)
                    volume(target, vol, "rm /state/.p0v3-restore-complete; printf '%s\\n' " + source_hash + ' > /state/foreign-marker; ln -s foreign-marker /state/.p0v3-restore-complete'); guard(role, False)
                    volume(target, vol, "rm /state/.p0v3-restore-complete /state/foreign-marker; printf '%s\\n' " + source_hash + ' > /state/.p0v3-restore-complete; sync'); guard(role, True)
            run([str(CLI), 'runtime', 'maintenance-leave', str(target_path), target_fence['id']]); target_fence = None; runtime('apply-private', target)
            receipt['phase'] = 'functional-restore'
            assert marker_mail(target, 'before') == before_mail and marker_calendar(target, 'before') == before_calendar
            assert marker_mail(target, 'source') is None and marker_calendar(target, 'source') is None
            target_mail = marker_mail(target, 'target', True); target_calendar = marker_calendar(target, 'target', True)
            assert marker_mail(source, 'target') is None and marker_calendar(source, 'target') is None
            for script in ('test-private-mail.py', 'test-private-sogo-mail.py', 'test-private-sogo.py'):
                result = run(['python3', str(ROOT / 'platform/scripts' / script), '--name', target, '--restored-from', source]); private(out / (script + '.log'), result)
                result_proof = json.loads(result.splitlines()[-1]); assert result_proof['passed']; receipt[script] = result_proof['id']
            assert marker_mail(target, 'target') == target_mail and marker_calendar(target, 'target') == target_calendar
            assert marker_mail(source, 'source') == source_mail and marker_calendar(source, 'source') == source_calendar
            assert marker_mail(target, 'source') is None and marker_calendar(target, 'source') is None
            for role, port in (('mail', 2993), ('database', 5432), ('groupware', 8443)):
                code = 'import socket;s=socket.socket();s.settimeout(3);assert s.connect_ex((' + repr(address(source, role)) + ',' + str(port) + '))!=0'
                run(['sudo', '-n', 'nsenter', '--target=' + str(inspect(target, 'sogod')['State']['Pid']), '--net', '/usr/bin/setpriv', '--reuid=' + str(os.getuid()), '--regid=' + str(os.getgid()), '--clear-groups', '--no-new-privs', '/usr/bin/python3', '-c', code])
            assert digest(BASE / source / 'runtime.jobs') == jobs and system('is-enabled').strip() == b'enabled' and system('is-active').strip() == b'active'
            receipt.update(passed=True, phase='complete', coldThreeVolumeCapture=True, wrongPasswordDenied=True, encryptedExportVerified=True, sourceFenceAndStabilityVerified=True, incompleteForeignSymlinkMarkersDenied=True, nativeCalendarContactMailBrowserRestored=True, postSnapshotWritesExcluded=True, divergentMailAndCalendarWritesIsolated=True, sourceTcpBlocked=True, noProvisioningReplay=True)
        finally:
            if lock:
                lock.close()
            failed = False
            if maintenance:
                try:
                    release_source(); system('enable', '--now')
                except Exception:
                    failed = True; receipt['sourceResumeFailed'] = True
            if (BASE / (target + '.json')).exists():
                try:
                    assert all(p['state'] != 'running' for p in runtime('stop-private', target))
                except Exception:
                    failed = True; receipt['restoreQuarantineFailed'] = True
            if target_fence:
                receipt['retainedRestoreFence'] = target_fence['id']
            if failed:
                raise RuntimeError('Recovery cleanup incomplete; explicit reconciliation required')
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
