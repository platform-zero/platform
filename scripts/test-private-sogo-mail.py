#!/usr/bin/env python3
"""Verify existing SOGo->SMTP->IMAP fixtures and five-process persistence; never resend."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import email
from email import policy
import hashlib
import imaplib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import uuid
from probe_receipt import private_receipt
from restored_sogo_fixture import fixture_hash


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--name', default='sogo-mail-r2'); parser.add_argument('--supervised', action='store_true'); parser.add_argument('--restored-from'); args = parser.parse_args()
    assert re.fullmatch('[a-z][a-z0-9-]{0,39}', args.name); os.umask(0o077)
    root = Path(__file__).resolve().parents[2]; base = Path('/mnt/media/p0-v3/runtime-deployments'); inputs = base / args.name
    manifest = base / (args.name + '.json'); fingerprint = hashlib.sha256(manifest.read_bytes()).hexdigest(); spec = json.loads(manifest.read_text())
    processes = [p for p in spec['processes'] if not p.get('oneShot', False)]
    assert {p['id'] for p in processes} == {'database', 'cache', 'sogod', 'groupware', 'mail'}
    out = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-sogo-mail-' + uuid.uuid4().hex[:12]); out.mkdir(mode=0o700)
    receipt = {'id': out.name, 'deployment': args.name, 'manifestSha256': fingerprint, 'passed': False, 'fullStackAcceptance': False, 'publicDelivery': False, 'encryptedRecovery': False, 'browserComposeUi': False, 'phase': 'audit'}
    p = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph', '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
    cli = root / 'platform/build/install/p0-v3-platform/bin/p0-v3-platform'
    def runtime(action):
        result = subprocess.run([str(cli), 'runtime', action, str(manifest)], env=dict(os.environ, JAVA_HOME='/usr/lib/jvm/java-21-openjdk-amd64'), capture_output=True, timeout=600)
        (out / (action + '-' + uuid.uuid4().hex[:8] + '.log')).write_bytes(result.stdout + result.stderr); assert result.returncode == 0
    def containers():
        rows = {}
        for process in processes:
            c = json.loads(subprocess.check_output(p + ['inspect', 'p0v3-live-' + args.name + '-' + process['id']]))[0]
            assert c['State']['Running'] and c['HostConfig']['ReadonlyRootfs'] and not c['HostConfig']['PortBindings'] and not c['EffectiveCaps'] and not c['BoundingCaps']
            assert c['Config']['User'] == str(process['userId']) + ':' + str(process.get('groupId', process['userId']))
            assert 'no-new-privileges' in c['HostConfig']['SecurityOpt'] and c['Image'].removeprefix('sha256:') == process['imageId']
            rows[process['id']] = {'id': c['Id'], 'start': c['State']['StartedAt'], 'ip': next(iter(c['NetworkSettings']['Networks'].values()))['IPAddress']}
        return rows
    def hashes():
        names = {p['environmentFile'] for p in spec['processes'] if p.get('environmentFile')} | {f['file'] for p in spec['processes'] for f in p.get('files', [])} | {'runtime.owner', 'runtime.jobs'}
        return {name: hashlib.sha256((inputs / name).read_bytes()).hexdigest() for name in sorted(names)}
    with private_receipt(receipt, lambda r: (out / 'receipt.json').write_text(json.dumps(r, indent=2))):
        runtime('status-private'); before = containers(); frozen = hashes()
        oracle_hash = fixture_hash(base, args.name, args.restored_from)
        receipt['restoredFrom'] = args.restored_from
        fixture = Path('/mnt/media/p0-v3/mail-probe-state') / (oracle_hash + '.json')
        assert fixture.parent.resolve() == fixture.parent and fixture.parent.stat().st_uid == os.getuid() and fixture.parent.stat().st_mode & 0o777 == 0o700
        def read_state(suffix):
            file = Path(str(fixture) + suffix)
            assert not file.is_symlink() and file.stat().st_uid == os.getuid() and file.stat().st_mode & 0o777 == 0o600 and file.stat().st_size < 1048576
            return json.loads(file.read_text())
        saved = read_state(''); assert saved['manifestSha256'] == oracle_hash and re.fullmatch('[a-f0-9]{12}', saved['nonce']); nonce = saved['nonce']
        sent = read_state('.sogo.send.outcome'); assert sent['status'] == 200 and json.loads(sent['body'])['status'] == 'success'
        intent = read_state('.sogo.send.intent'); assert intent['manifestSha256'] == oracle_hash and intent['nonce'] == nonce
        expected = json.loads(intent['body']); assert expected['subject'] == 'Private SOGo mail ' + nonce and expected['to'] == ['bob@p0v3.example.org'] and expected['text'] == 'Synthetic SOGo SMTP body ' + nonce
        users = json.loads((inputs / 'users.json').read_text()); context = ssl.create_default_context(cafile=str(inputs / 'mail-ca.pem'))
        def verify_mail(label):
            address = containers()['mail']['ip']
            class IMAP(imaplib.IMAP4_SSL):
                def _create_socket(self, timeout):
                    return context.wrap_socket(socket.create_connection((address, self.port), timeout=timeout), server_hostname='mail')
            proofs = {}
            for user, folder in [('bob', 'INBOX'), ('alice', 'Sent'), ('outsider', 'INBOX')]:
                with IMAP('mail', 2993, ssl_context=context, timeout=20) as c:
                    assert c.login(user + '@p0v3.example.org', users[user])[0] == 'OK'
                    assert c.select(folder, readonly=True)[0] == 'OK'
                    status, data = c.uid('search', None, 'SUBJECT', '"Private SOGo mail ' + nonce + '"'); assert status == 'OK'
                    if user == 'outsider':
                        assert data == [b'']; continue
                    ids = data[0].split(); assert len(ids) == 1
                    status, data = c.uid('fetch', ids[0], '(BODY.PEEK[])'); assert status == 'OK'
                    raw = next(x[1] for x in data if isinstance(x, tuple)); message = email.message_from_bytes(raw, policy=policy.default)
                    assert message['Subject'] == expected['subject'] and 'alice@p0v3.example.org' in message['From'] and 'bob@p0v3.example.org' in message['To']
                    assert expected['text'] in message.get_body(preferencelist=('plain',)).get_content()
                    proofs[user] = {'uid': ids[0].decode(), 'uidValidity': c.response('UIDVALIDITY')[1][0].decode(), 'messageId': str(message['Message-ID']), 'sha256': hashlib.sha256(raw).hexdigest()}
            assert proofs['bob']['messageId'] == proofs['alice']['messageId']
            (out / (label + '-native-mail.json')).write_text(json.dumps(proofs, indent=2)); return proofs
        def browser(label, outgoing, uid=None, deny=None):
            command = ['python3', str(root / 'platform/scripts/inspect-private-sogo-mail.py'), '--name', args.name] + (['--outgoing'] if outgoing else [])
            if args.restored_from:
                command += ['--restored-from', args.restored_from]
            if uid:
                command += ['--message-uid', uid]
            if deny:
                command += ['--deny-user', deny]
            result = subprocess.run(command, capture_output=True, timeout=300); (out / (label + '-browser.log')).write_bytes(result.stdout + result.stderr)
            assert result.returncode == 0; proof = json.loads(result.stdout); assert proof['nativeSogoMailboxCrossUserDenied' if deny else 'nativeSogoImapBrowserReadback'] and proof['diagnosticOnly'] and not proof['createdMessagesThisRun']
            receipt[label + 'BrowserDiagnostic'] = proof['id']
        def tls(label):
            source = (root / 'platform/scripts/sogo_native_tls_probe.py').read_bytes(); address = containers()['mail']['ip']; image = next(p['image'] for p in processes if p['id'] == 'sogod')
            for port in ('2465', '2993'):
                for host, expected in [('mail', 'trusted'), (address, 'denied')]:
                    result = subprocess.run(p + ['exec', '-i', 'p0v3-live-' + args.name + '-sogod', '/usr/bin/python3', '-', host, port, expected], input=source, capture_output=True, timeout=40)
                    (out / (label + '-native-tls-' + port + '-' + expected + '.log')).write_bytes(result.stdout + result.stderr)
                    assert result.returncode == 0 and json.loads(result.stdout)['trusted'] == (expected == 'trusted')
                result = subprocess.run(p + ['run', '--rm', '--pull=never', '--image-volume=ignore', '--network=container:p0v3-live-' + args.name + '-sogod', '--read-only', '--user=994:994', '--cap-drop=all', '--security-opt=no-new-privileges', '--security-opt=apparmor=p0v3-private-v1', '--memory=256m', '--pids-limit=64', '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=32m,mode=1777', '--env=HOME=/tmp', '--env=LD_LIBRARY_PATH=/usr/local/lib/sogo:/usr/local/lib:/usr/lib', '--env=LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libssl.so.3', '--entrypoint=/usr/bin/python3', '-i', image, '-', 'mail', port, 'denied'], input=source, capture_output=True, timeout=45)
                (out / (label + '-native-untrusted-ca-' + port + '.log')).write_bytes(result.stdout + result.stderr)
                assert result.returncode == 0 and not json.loads(result.stdout)['trusted'] and b'certificate verify failed' in result.stderr.lower()
        receipt['phase'] = 'before-restart'; baseline = verify_mail('before'); tls('before'); browser('before-incoming', False); browser('before-outgoing', True, baseline['bob']['uid'])
        for user in ('alice', 'outsider'):
            browser('before-denied-' + user, False, baseline['bob']['uid'], user)
        receipt['phase'] = 'restart'
        if args.supervised:
            unit = 'p0v3-private-' + args.name + '.service'
            subprocess.run(['systemctl', 'is-enabled', unit], capture_output=True, check=True, timeout=20)
            subprocess.run(['sudo', '-n', 'systemctl', 'stop', unit], capture_output=True, check=True, timeout=300)
            subprocess.run(['sudo', '-n', 'systemctl', 'start', unit], capture_output=True, check=True, timeout=600)
        else:
            runtime('stop-private'); runtime('apply-private')
        after = containers(); assert all(before[r]['id'] == after[r]['id'] and before[r]['start'] != after[r]['start'] for r in before)
        assert frozen == hashes() and hashlib.sha256(manifest.read_bytes()).hexdigest() == fingerprint
        receipt['phase'] = 'after-restart'; assert baseline == verify_mail('after'); tls('after'); browser('after-incoming', False); browser('after-outgoing', True, baseline['bob']['uid'])
        for user in ('alice', 'outsider'):
            browser('after-denied-' + user, False, baseline['bob']['uid'], user)
        runtime('status-private')
        (out / 'containers.json').write_text(json.dumps({'before': before, 'after': after}, indent=2)); (out / 'inputs.json').write_text(json.dumps(frozen, indent=2))
        receipt.update(passed=True, phase='complete', nativeSogoSmtpDeliveryAndSentCopy=True, nativeBrowserIncomingAndOutgoingReadback=True, nativeSopeHostnameAndCaDenials=True, nativeSogoCrossUserMailboxDenial=True, unchangedUidValidityAndContent=True, immutableInputsAndInitializersUnchanged=True, daemonsRestarted=5, supervisedRestart=args.supervised, createdMessagesThisRun=False)
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
