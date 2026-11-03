#!/usr/bin/env python3
"""Read-only native browser diagnostic of the existing, manifest-bound mail fixture."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid
from probe_receipt import private_receipt
from sogo_mail_safety import redact_diagnostics
from restored_sogo_fixture import fixture_hash


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--name', default='sogo-mail-r2'); parser.add_argument('--send', action='store_true'); parser.add_argument('--resume-compose', action='store_true'); parser.add_argument('--outgoing', action='store_true'); parser.add_argument('--deny-user', choices=('alice', 'outsider')); parser.add_argument('--message-uid'); parser.add_argument('--restored-from'); args = parser.parse_args()
    assert re.fullmatch('[a-z][a-z0-9-]{0,39}', args.name); os.umask(0o077)
    root = Path(__file__).resolve().parents[2]; base = Path('/mnt/media/p0-v3/runtime-deployments'); inputs = base / args.name
    fingerprint = hashlib.sha256((base / (args.name + '.json')).read_bytes()).hexdigest()
    oracle_hash = fixture_hash(base, args.name, args.restored_from, mutating=args.send or args.resume_compose)
    fixture = Path('/mnt/media/p0-v3/mail-probe-state') / (oracle_hash + '.json')
    assert fixture.parent.resolve() == fixture.parent and fixture.parent.stat().st_uid == os.getuid() and fixture.parent.stat().st_mode & 0o777 == 0o700
    assert not fixture.is_symlink() and fixture.stat().st_uid == os.getuid() and fixture.stat().st_mode & 0o777 == 0o600
    value = json.loads(fixture.read_text()); assert value['manifestSha256'] == oracle_hash
    assert json.loads(Path(str(fixture) + '.send-outcome').read_text()) == {'accepted': True}
    out = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-sogo-mail-browser-' + uuid.uuid4().hex[:12]); out.mkdir(mode=0o700)
    receipt = {'id': out.name, 'passed': False, 'diagnosticOnly': True, 'manifestSha256': fingerprint, 'fullStackAcceptance': False, 'smtpViaSogo': False}
    with private_receipt(receipt, lambda r: (out / 'receipt.json').write_text(json.dumps(r, indent=2))):
        p = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph', '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
        container = json.loads(subprocess.check_output(p + ['inspect', 'p0v3-live-' + args.name + '-groupware']))[0]
        assert container['State']['Running'] and not container['HostConfig']['PortBindings']
        address = next(iter(container['NetworkSettings']['Networks'].values()))['IPAddress']
        public = subprocess.check_output(['openssl', 'x509', '-in', str(inputs / 'web.pem'), '-pubkey', '-noout'])
        der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=public, capture_output=True, check=True).stdout
        env = dict(line.split('=', 1) for line in (inputs / 'bootstrap.env').read_text().splitlines())
        values = {'address': address, 'nonce': value['nonce'], 'user': 'alice' if args.send else 'bob', 'password': env['ALICE_PASSWORD' if args.send else 'BOB_PASSWORD'], 'directory': str(out), 'pin': base64.b64encode(hashlib.sha256(der).digest()).decode(), 'send': args.send, 'statePrefix': str(fixture) + '.sogo', 'manifestSha256': fingerprint}
        assert not (args.send and (args.outgoing or args.deny_user or args.message_uid))
        if args.message_uid:
            assert re.fullmatch('[1-9][0-9]{0,9}', args.message_uid); values['messageUid'] = args.message_uid
        if args.deny_user:
            assert args.message_uid
            values.update(user=args.deny_user, password=env[args.deny_user.upper() + '_PASSWORD'])
        values['outgoing'] = args.outgoing
        if args.outgoing:
            accepted = json.loads(Path(str(fixture) + '.sogo.send.outcome').read_text())
            assert accepted['status'] == 200 and json.loads(accepted['body'])['status'] == 'success'
        if args.resume_compose:
            assert args.send
            reconciliation = Path(str(fixture) + '.sogo.compose-reconciliation.json')
            assert not reconciliation.is_symlink() and reconciliation.stat().st_uid == os.getuid() and reconciliation.stat().st_mode & 0o777 == 0o600
            record = json.loads(reconciliation.read_text())
            assert record['manifestSha256'] == fingerprint and record['authorization'] in ('one-resume-after-confirmed-dns-failure', 'one-resume-after-confirmed-preaction-timeout')
            assert record['intentSha256'] == hashlib.sha256(Path(str(fixture) + '.sogo.compose.intent').read_bytes()).hexdigest()
            diagnostic = Path('/mnt/media/p0-v3/image-acquisition-receipts') / record['diagnostic'] / 'browser.log'
            assert re.fullmatch('p0v3-sogo-mail-browser-[a-f0-9]{12}', record['diagnostic'])
            assert record['diagnosticSha256'] == hashlib.sha256(diagnostic.read_bytes()).hexdigest()
            text = diagnostic.read_text()
            if record['authorization'] == 'one-resume-after-confirmed-dns-failure':
                assert 'getaddrinfo EAI_AGAIN groupware' in text
            else:
                assert 'locator resolved to hidden' in text and 'Locator.waitFor' in text and 'SogoMailBrowserProbe.java:41' in text
            assert not Path(str(fixture) + '.sogo.compose.outcome').exists() and not Path(str(fixture) + '.sogo.send.intent').exists()
            values.update(resumeCompose=True, reconciliationSha256=hashlib.sha256(reconciliation.read_bytes()).hexdigest())
        cache = Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1')
        jars = [j for artifact in ('driver', 'driver-bundle', 'playwright') for j in (cache / ('com.microsoft.playwright/' + artifact + '/1.55.0')).glob('*/*.jar')] + list((cache / 'com.google.code.gson/gson/2.12.1').glob('*/*.jar')); assert len(jars) == 4
        with tempfile.TemporaryDirectory(prefix='sogo-mail-', dir='/mnt/media/p0-v3/cache') as scratch:
            result = subprocess.run(['sudo', '-n', 'nsenter', '--target=' + str(container['State']['Pid']), '--net', '/usr/bin/setpriv', '--reuid=' + str(os.getuid()), '--regid=' + str(os.getgid()), '--clear-groups', '--no-new-privs', '/usr/bin/env', 'HOME=' + scratch, 'TMPDIR=' + scratch, '/usr/lib/jvm/java-21-openjdk-amd64/bin/java', '-Djava.io.tmpdir=' + scratch, '--class-path', ':'.join(map(str, jars)), str(root / 'acceptance/scripts/SogoMailBrowserProbe.java')], input=json.dumps(values).encode(), capture_output=True, timeout=250)
            (out / 'browser.log').write_text(redact_diagnostics(result.stderr, [v for k, v in env.items() if 'PASSWORD' in k])); assert result.returncode == 0, 'Native browser failed; protected diagnostic retained'
        proof = json.loads(result.stdout)
        if args.send:
            assert proof['nativeSogoSmtpAccepted'] and proof['createdMessagesThisRun'] and not proof['browserComposeUi']
        elif args.deny_user:
            assert proof['nativeSogoMailboxCrossUserDenied'] and not proof['createdMessagesThisRun']
        else:
            assert proof['nativeSogoImapBrowserReadback'] and not proof['createdMessagesThisRun']
        receipt.update(proof); receipt['passed'] = False
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
