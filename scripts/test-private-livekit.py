#!/usr/bin/env python3
"""Authenticated private SFU API plus actual synthetic Chromium media; not Matrix/Android acceptance."""
import argparse
import base64
import hashlib
import hmac
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
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/media/p0-v3/runtime-deployments')
CLI = ROOT / 'platform/build/install/p0-v3-platform/bin/p0-v3-platform'
P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
SDK = Path('/mnt/media/p0-v3/cache/livekit-client-2.15.6.umd.js')
SDK_SHA256 = '71ede404c69bf43c94bf158d979a796a2b546fc8c18256634e75a741b486435f'
WORKER = SDK.with_name('livekit-client-2.15.6.e2ee.worker.js')
WORKER_SHA256 = '6c1aa2363ceb3a7720700c47ebc8d6716ed6ea696306e7a7e0ea24e35b4902fa'


def jwt(key, secret, subject, grant, expiry=300):
    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).rstrip(b'=')
    now = int(time.time())
    body = part({'alg': 'HS256', 'typ': 'JWT'}) + b'.' + part({'iss': key, 'sub': subject, 'nbf': now - 5, 'exp': now + expiry, 'video': grant})
    return (body + b'.' + base64.urlsafe_b64encode(hmac.digest(secret.encode(), body, 'sha256')).rstrip(b'=')).decode()


def write(path, data):
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), 'w') as out:
        out.write(data); out.flush(); os.fsync(out.fileno())


def main():
    assert SDK.is_file() and not SDK.is_symlink() and hashlib.sha256(SDK.read_bytes()).hexdigest() == SDK_SHA256
    assert WORKER.is_file() and not WORKER.is_symlink() and hashlib.sha256(WORKER.read_bytes()).hexdigest() == WORKER_SHA256
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='livekit')
    name = parser.parse_args().name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-rtc-' + uuid.uuid4().hex[:12])
    directory.mkdir(mode=0o700)
    receipt = {'id': directory.name, 'deployment': name, 'scope': 'private-synthetic-sfu-not-matrix-call',
               'passed': False, 'fullStackAcceptance': False, 'publicHttpsTest': False, 'physicalDeviceCapture': False, 'receiverOutputMuted': True,
               'sdkSha256': SDK_SHA256, 'workerSha256': WORKER_SHA256,
               'browserProbeSha256': hashlib.sha256((ROOT / 'acceptance/scripts/LiveKitBrowserProbe.java').read_bytes()).hexdigest(),
               'harnessSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    key, secret = re.search(r'^  "([^"]+)": "([^"]+)"$', (BASE / name / 'livekit.yaml').read_text(), re.M).groups()
    context = ssl.create_default_context(cafile=str(BASE / name / 'ca.pem'))
    jars = []
    cache = Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1')
    for artifact in ('driver', 'driver-bundle', 'playwright'):
        jars += sorted((cache / ('com.microsoft.playwright/' + artifact + '/1.55.0')).glob('*/*.jar'))
    jars += sorted((cache / 'com.google.code.gson/gson/2.12.1').glob('*/*.jar'))
    assert len(jars) == 4

    def runtime(action):
        result = subprocess.run([str(CLI), 'runtime', action, str(BASE / (name + '.json'))], capture_output=True, timeout=1200,
                                env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0, 'Private RTC operation failed; state retained'
        return json.loads(result.stdout.splitlines()[0])

    def audit(process):
        data = json.loads(subprocess.check_output(P + ['inspect', 'p0v3-live-' + name + '-' + process]))[0]
        assert data['Config']['Labels']['io.p0v3.private-deployment'] == name and data['State']['Running']
        assert not data['HostConfig']['PortBindings'] and set(data['NetworkSettings']['Networks']) == {'p0v3-live-' + name + '-net'}
        address = data['NetworkSettings']['Networks']['p0v3-live-' + name + '-net']['IPAddress']
        assert ipaddress.ip_address(address).is_private
        return data, address

    def journey(label):
        data, address = audit('rtc'); _, sfu_address = audit('livekit')
        with socket.create_connection((address, 8443), timeout=15) as raw, context.wrap_socket(raw, server_hostname='rtc') as tls:
            expected = ssl.PEM_cert_to_DER_cert((BASE / name / 'web.pem').read_text())
            assert tls.getpeercert(binary_form=True) == expected
        receipt['certificateSha256'] = hashlib.sha256(expected).hexdigest()
        public = subprocess.check_output(['openssl', 'x509', '-in', str(BASE / name / 'web.pem'), '-pubkey', '-noout'])
        der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=public, capture_output=True, check=True).stdout
        room = 'fixture-' + uuid.uuid4().hex[:12]
        admin = jwt(key, secret, 'fixture-controller', {'roomCreate': True, 'roomList': True, 'roomAdmin': True, 'room': room})
        sender = jwt(key, secret, 'synthetic-sender', {'roomJoin': True, 'room': room, 'canPublish': True, 'canSubscribe': True, 'canPublishData': True})
        receiver = jwt(key, secret, 'synthetic-receiver', {'roomJoin': True, 'room': room, 'canPublish': False, 'canSubscribe': True, 'canPublishData': False})
        invalid = jwt(key, secret + 'invalid', 'denied', {'roomJoin': True, 'room': room})

        def api(method, body, token):
            payload = json.dumps(body).encode()
            with socket.create_connection((address, 8443), timeout=15) as raw, context.wrap_socket(raw, server_hostname='rtc') as tls:
                tls.sendall(('POST /twirp/livekit.RoomService/' + method + ' HTTP/1.1\r\nHost: rtc:8443\r\nContent-Type: application/json\r\nAuthorization: Bearer ' + token + '\r\nContent-Length: ' + str(len(payload)) + '\r\nConnection: close\r\n\r\n').encode() + payload)
                response = http.client.HTTPResponse(tls); response.begin()
                body = response.read(1048576)
                return response.status, json.loads(body) if response.status == 200 else {}

        assert api('ListRooms', {}, 'invalid')[0] == 401
        assert api('CreateRoom', {'name': room}, sender)[0] in (401, 403)
        expired = jwt(key, secret, 'expired', {'roomList': True}, -600)
        assert api('ListRooms', {}, expired)[0] == 401
        status, created = api('CreateRoom', {'name': room, 'max_participants': 2}, admin)
        assert status == 200 and created['name'] == room
        assert api('DeleteRoom', {'room': room}, receiver)[0] in (401, 403)
        inputs = {'directory': str(directory), 'sdk': str(SDK), 'worker': str(WORKER), 'mediaKey': secrets.token_hex(32), 'wrongMediaKey': secrets.token_hex(32), 'spki': base64.b64encode(hashlib.sha256(der).digest()).decode(),
                  'address': address, 'sfuAddress': sfu_address, 'senderToken': sender, 'receiverToken': receiver, 'invalidToken': invalid}
        with tempfile.TemporaryDirectory(prefix='rt-', dir='/mnt/media/p0-v3/cache') as scratch:
            result = subprocess.run(['sudo', '-n', 'nsenter', '--target=' + str(data['State']['Pid']), '--net',
                '--setuid=' + str(os.getuid()), '--setgid=' + str(os.getgid()), '/usr/bin/env', 'HOME=' + scratch, 'TMPDIR=' + scratch,
                '/usr/lib/jvm/java-21-openjdk-amd64/bin/java', '-Djava.io.tmpdir=' + scratch, '--class-path', ':'.join(map(str, jars)),
                str(ROOT / 'acceptance/scripts/LiveKitBrowserProbe.java')], input=json.dumps(inputs), capture_output=True, text=True, timeout=300)
            safe = result.stderr
            for value in (key, secret, admin, sender, receiver, invalid, expired, inputs['mediaKey'], inputs['wrongMediaKey']): safe = safe.replace(value, '[redacted]')
            write(directory / (label + '.log'), safe)
            assert result.returncode == 0, 'Synthetic RTC browser failed; protected diagnostics retained'
            result = json.loads(result.stdout); assert result['passed'] and not result['fullStackAcceptance']
            receipt[label] = result
        assert api('DeleteRoom', {'room': room}, admin)[0] == 200
        assert not api('ListRooms', {'names': [room]}, admin)[1].get('rooms')

    try:
        receipt['phase'] = 'first-media-journey'; runtime('apply-private'); journey('beforeRestart')
        receipt['phase'] = 'restart-and-new-room'; assert all(p['exitCode'] == 0 for p in runtime('stop-private'))
        runtime('apply-private'); journey('afterRestart')
        receipt.update(passed=True, phase='complete', cleanRestartVerified=True, expiredTokenDenied=True,
                       participantAdministrationDenied=True, roomDeletionVerified=True)
    finally:
        write(directory / 'receipt.json', json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    if not __debug__: raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
