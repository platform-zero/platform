#!/usr/bin/env python3
"""Native private SMTP/IMAP delivery; explicit one-shot DATA intent and read-only repeats."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import base64
import email
from email.message import EmailMessage
from email import policy
import hashlib
import http.client
import imaplib
import json
import os
from pathlib import Path
import re
import smtplib
import socket
import ssl
import subprocess
import time
import uuid
from probe_receipt import private_receipt
from restored_sogo_fixture import fixture_hash
from mail_fixture_selection import select_fixture_uid

BASE = Path('/mnt/media/p0-v3/runtime-deployments')
ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / 'platform/build/install/p0-v3-platform/bin/p0-v3-platform'
P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph', '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
DOMAIN = 'p0v3.example.org'


def durable(path, value, exclusive=False):
    with path.open('xb' if exclusive else 'wb') as stream:
        stream.write(value if isinstance(value, bytes) else json.dumps(value, indent=2).encode()); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--name', default='mail-r9'); parser.add_argument('--create', action='store_true'); parser.add_argument('--supervised', action='store_true'); parser.add_argument('--restored-from'); args = parser.parse_args()
    assert re.fullmatch('[a-z][a-z0-9-]{0,39}', args.name); os.umask(0o077)
    manifest = BASE / (args.name + '.json'); inputs = BASE / args.name; fingerprint = hashlib.sha256(manifest.read_bytes()).hexdigest()
    spec = json.loads(manifest.read_text()); roles = {p['id'] for p in spec['processes']}
    oracle_hash = fixture_hash(BASE, args.name, args.restored_from, mutating=args.create)
    composite = roles == {'mail', 'mail-init', 'database-init', 'database', 'accounts-init', 'cache', 'sogod', 'groupware'} | ({'home-restore-check'} if args.restored_from else set())
    assert composite or roles == {'mail', 'mail-init'}
    out = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-mail-' + uuid.uuid4().hex[:12]); out.mkdir(mode=0o700)
    receipt = {'id': out.name, 'deployment': args.name, 'manifestSha256': fingerprint, 'passed': False, 'fullStackAcceptance': False, 'publicDelivery': False, 'realOwnerOnboarding': False, 'encryptedRecovery': False, 'sogoIntegration': False, 'restoredFrom': args.restored_from, 'phase': 'audit'}
    def runtime(action):
        r = subprocess.run([str(CLI), 'runtime', action, str(manifest)], env=dict(os.environ, JAVA_HOME='/usr/lib/jvm/java-21-openjdk-amd64'), capture_output=True, timeout=600)
        (out / (action + '-' + uuid.uuid4().hex[:8] + '.log')).write_bytes(r.stdout + r.stderr)
        assert r.returncode == 0, 'Runtime failed; protected logs retained'
    def container():
        s = json.loads(subprocess.run(P + ['inspect', 'p0v3-live-' + args.name + '-mail'], capture_output=True, check=True).stdout)[0]
        assert s['State']['Running'] and s['Config']['User'] == '2000:2000' and s['HostConfig']['ReadonlyRootfs'] and not s['HostConfig']['PortBindings'] and not s['EffectiveCaps'] and not s['BoundingCaps']
        assert 'no-new-privileges' in s['HostConfig']['SecurityOpt'] and set(s['NetworkSettings']['Networks']) == {'p0v3-live-' + args.name + '-net'}
        assert not any(v.startswith('STALWART_RECOVERY') for v in s['Config']['Env'])
        return {'id': s['Id'], 'start': s['State']['StartedAt'], 'ip': next(iter(s['NetworkSettings']['Networks'].values()))['IPAddress']}
    def hashes():
        names = {p['environmentFile'] for p in spec['processes'] if p.get('environmentFile')} | {f['file'] for p in spec['processes'] for f in p.get('files', [])} | {'runtime.owner', 'runtime.jobs'}
        return {n: hashlib.sha256((inputs / n).read_bytes()).hexdigest() for n in sorted(names)}
    with private_receipt(receipt, lambda r: durable(out / 'receipt.json', r)):
        runtime('status-private'); before = container(); frozen = hashes(); address = before['ip']; durable(out / 'before.json', before); durable(out / 'inputs.json', frozen)
        context = ssl.create_default_context(cafile=str(inputs / ('mail-ca.pem' if composite else 'ca.pem'))); users = json.loads((inputs / 'users.json').read_text())
        class SMTP(smtplib.SMTP_SSL):
            def _get_socket(self, host, port, timeout):
                return self.context.wrap_socket(socket.create_connection((address, port), timeout=timeout), server_hostname='mail')
        class IMAP(imaplib.IMAP4_SSL):
            def _create_socket(self, timeout):
                return self.ssl_context.wrap_socket(socket.create_connection((address, self.port), timeout=timeout), server_hostname='mail')
        def smtp():
            return SMTP('mail', 2465, local_hostname='probe.example.org', context=context, timeout=20)
        def mailbox(user):
            client = IMAP('mail', 2993, ssl_context=context, timeout=20)
            assert client.login(user + '@' + DOMAIN, users[user])[0] == 'OK'
            assert client.select('INBOX', readonly=True)[0] == 'OK'
            return client
        def api(credential, method, arguments):
            with socket.create_connection((address, 8443), timeout=15) as raw, context.wrap_socket(raw, server_hostname='mail') as transport:
                c = http.client.HTTPConnection('mail', 8443, timeout=15); c.sock = transport
                c.request('POST', '/jmap/', json.dumps({'using': ['urn:ietf:params:jmap:core', 'urn:stalwart:jmap'], 'methodCalls': [[method, arguments, 'p0']]}), {'Host': 'mail:8443', 'Authorization': 'Basic ' + base64.b64encode(credential.encode()).decode(), 'Content-Type': 'application/json'})
                r = c.getresponse(); body = r.read(1048577); assert len(body) <= 1048576
                return r.status, body
        def boundaries():
            for port in (2465, 2993, 8443):
                with socket.create_connection((address, port), timeout=10) as raw, context.wrap_socket(raw, server_hostname='mail') as transport:
                    assert transport.getpeercert(binary_form=True) == ssl.PEM_cert_to_DER_cert(next(s for s in json.loads((inputs / 'mail-seed.json').read_text()) if s['method'] == 'x:Certificate/set')['arguments']['create']['certificate']['certificate']['value'])
                try:
                    with socket.create_connection((address, port), timeout=10) as raw, ssl.create_default_context().wrap_socket(raw, server_hostname='mail'):
                        pass
                except ssl.SSLCertVerificationError:
                    pass
                else:
                    raise AssertionError('Private certificate unexpectedly trusted')
                try:
                    with socket.create_connection((address, port), timeout=10) as raw, context.wrap_socket(raw, server_hostname='wrong.example.org'):
                        pass
                except ssl.SSLCertVerificationError:
                    pass
                else:
                    raise AssertionError('Wrong TLS hostname accepted')
            with IMAP('mail', 2993, ssl_context=context, timeout=20) as c:
                try:
                    c.login('bob@' + DOMAIN, users['alice'])
                except imaplib.IMAP4.error:
                    pass
                else:
                    raise AssertionError('Alice credential impersonated Bob')
            with smtp() as c:
                c.ehlo(); assert c.mail('alice@' + DOMAIN)[0] >= 500
            with smtp() as c:
                c.login('alice@' + DOMAIN, users['alice']); assert c.mail('bob@' + DOMAIN)[0] >= 500
            with smtp() as c:
                c.login('alice@' + DOMAIN, users['alice']); assert c.mail('alice@' + DOMAIN)[0] == 250
                assert c.rcpt('nobody@example.net')[0] >= 500
            with smtp() as c:
                try:
                    c.login('alice@' + DOMAIN, 'incorrect-fixture-password')
                except smtplib.SMTPAuthenticationError:
                    pass
                else:
                    raise AssertionError('Wrong password accepted')
            recovery = next(x.split('=', 1)[1] for x in (inputs / ('mail-bootstrap.env' if composite else 'bootstrap.env')).read_text().splitlines() if x.startswith('STALWART_RECOVERY_ADMIN='))
            assert api(recovery, 'x:Account/get', {})[0] == 401
            status, body = api('alice@' + DOMAIN + ':' + users['alice'], 'x:Account/get', {})
            assert status == 200; response = json.loads(body)['methodResponses'][0]
            assert response[0] == 'error' and response[1]['type'] == 'forbidden'
            receipt['tlsUnauthorizedSenderRelayPasswordAndAdminDenials'] = True
        boundaries()
        state = Path('/mnt/media/p0-v3/mail-probe-state'); state.mkdir(mode=0o700, exist_ok=True)
        assert state.resolve() == state and state.stat().st_uid == os.getuid() and state.stat().st_mode & 0o777 == 0o700
        fixture = state / (oracle_hash + '.json')
        if args.create:
            nonce = uuid.uuid4().hex[:12]; message_id = '<p0v3-' + nonce + '@' + DOMAIN + '>'
            durable(fixture, {'manifestSha256': fingerprint, 'nonce': nonce, 'messageId': message_id}, True)
        assert not fixture.is_symlink() and fixture.stat().st_uid == os.getuid() and fixture.stat().st_mode & 0o777 == 0o600 and fixture.stat().st_size < 8192
        v = json.loads(fixture.read_text()); nonce = v['nonce']; message_id = v['messageId']
        assert v['manifestSha256'] == oracle_hash and re.fullmatch('[a-f0-9]{12}', nonce) and message_id == '<p0v3-' + nonce + '@' + DOMAIN + '>'
        # Search the native indexed subject; validate the exact Message-ID after fetch.
        search_id = '"Private mail ' + nonce + '"'
        attachment = (b'Private synthetic mail attachment\x00\xff\r\n' * 1024)
        if args.create:
            with mailbox('bob') as c:
                status, data = c.uid('search', None, 'HEADER', 'SUBJECT', search_id); assert status == 'OK' and data == [b'']
            msg = EmailMessage(policy=policy.SMTP); msg['From'] = 'alice@' + DOMAIN; msg['To'] = 'bob@' + DOMAIN; msg['Subject'] = 'Private mail ' + nonce; msg['Message-ID'] = message_id
            msg.set_content('Synthetic native SMTP body ' + nonce); msg.add_attachment(attachment, maintype='application', subtype='octet-stream', filename='synthetic.bin')
            encoded = msg.as_bytes(); durable(Path(str(fixture) + '.message'), encoded, True)
            durable(Path(str(fixture) + '.send-intent'), {'manifestSha256': fingerprint, 'messageId': message_id, 'sha256': hashlib.sha256(encoded).hexdigest()}, True)
            with smtp() as c:
                c.login('alice@' + DOMAIN, users['alice']); assert c.sendmail('alice@' + DOMAIN, ['bob@' + DOMAIN], encoded) == {}
            durable(Path(str(fixture) + '.send-outcome'), {'accepted': True}, True)
        for suffix in ('.message', '.send-intent', '.send-outcome'):
            entry = Path(str(fixture) + suffix)
            assert not entry.is_symlink() and entry.stat().st_uid == os.getuid() and entry.stat().st_mode & 0o777 == 0o600 and entry.stat().st_size < 1048576
        intent = json.loads(Path(str(fixture) + '.send-intent').read_text())
        assert intent == {'manifestSha256': oracle_hash, 'messageId': message_id, 'sha256': hashlib.sha256(Path(str(fixture) + '.message').read_bytes()).hexdigest()}
        assert json.loads(Path(str(fixture) + '.send-outcome').read_text()) == {'accepted': True}, 'Unreconciled SMTP submission'
        def verify(label):
            deadline = time.monotonic() + 60
            while True:
                with mailbox('bob') as c:
                    status, data = c.uid('search', None, 'HEADER', 'SUBJECT', search_id); assert status == 'OK'
                    ids = data[0].split(); assert len(ids) <= 32
                    candidates = []
                    for uid in ids:
                        status, headers = c.uid('fetch', uid, '(BODY.PEEK[HEADER.FIELDS (SUBJECT MESSAGE-ID)])'); assert status == 'OK'
                        candidates.append((uid, next(part[1] for part in headers if isinstance(part, tuple))))
                    selected = select_fixture_uid(candidates, 'Private mail ' + nonce, message_id)
                    if selected is not None:
                        validity = c.response('UIDVALIDITY')[1][0].decode()
                        status, content = c.uid('fetch', selected, '(BODY.PEEK[])'); assert status == 'OK'
                        raw = next(part[1] for part in content if isinstance(part, tuple)); parsed = email.message_from_bytes(raw, policy=policy.default)
                        assert parsed['Subject'] == 'Private mail ' + nonce and parsed['Message-ID'] == message_id
                        assert nonce in parsed.get_body(preferencelist=('plain',)).get_content()
                        assert list(parsed.iter_attachments())[0].get_payload(decode=True) == attachment
                        proof = {'uid': selected.decode(), 'uidValidity': validity, 'sha256': hashlib.sha256(raw).hexdigest()}; durable(out / (label + '-mail.json'), proof)
                        break
                if time.monotonic() >= deadline:
                    raise AssertionError('Native delivery deadline exceeded; no SMTP retry')
                time.sleep(1)
            for user in ('alice', 'outsider'):
                with mailbox(user) as c:
                    assert c.uid('search', None, 'HEADER', 'SUBJECT', search_id) == ('OK', [b''])
            return proof
        receipt['phase'] = 'before-restart'; saved = verify('before')
        receipt['phase'] = 'restart'
        if args.supervised:
            unit = 'p0v3-private-' + args.name + '.service'
            subprocess.run(['systemctl', 'is-enabled', unit], capture_output=True, check=True, timeout=20)
            subprocess.run(['sudo', '-n', 'systemctl', 'stop', unit], capture_output=True, check=True, timeout=300)
            subprocess.run(['sudo', '-n', 'systemctl', 'start', unit], capture_output=True, check=True, timeout=600)
        else:
            runtime('stop-private'); runtime('apply-private')
        after = container(); durable(out / 'after.json', after); address = after['ip']
        assert before['id'] == after['id'] and before['start'] != after['start'] and frozen == hashes() and hashlib.sha256(manifest.read_bytes()).hexdigest() == fingerprint
        receipt['phase'] = 'after-restart'; assert saved == verify('after'); boundaries(); runtime('status-private')
        logs = subprocess.run(P + ['logs', 'p0v3-live-' + args.name + '-mail'], capture_output=True, check=True, timeout=30)
        serving_log = logs.stdout + logs.stderr; durable(out / 'native-serving.log', serving_log)
        assert not any(marker in serving_log.lower() for marker in (b'resource.error', b'webui.zip', b'github.com', b'download asn', b'download spam')), 'Unexpected automatic resource activity'
        receipt.update(passed=True, phase='complete', noServingResourceDownloadActivity=True, nativeSmtpImapAttachment=True, uidValidityAndContentUnchanged=True, immutableInputsAndInitializerUnchanged=True, supervisedRestart=args.supervised, createdMessageThisRun=args.create)
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
