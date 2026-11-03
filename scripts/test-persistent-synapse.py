#!/usr/bin/env python3
"""Real local Matrix registration, membership, messages, authenticated media and restart readback.
This is neither E2EE/Element/MAS acceptance nor a federation/public deployment.
"""
import argparse
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import uuid

P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
CLI = Path(__file__).resolve().parents[1] / 'build/install/p0-v3-platform/bin/p0-v3-platform'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def private_write(path, content):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())


def registration_mac(secret, nonce, username, password):
    return hmac.new(secret.encode(), '\0'.join([nonce, username, password, 'notadmin']).encode(), hashlib.sha1).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='synapse')
    name = parser.parse_args().name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    base = Path('/mnt/media/p0-v3/runtime-deployments')
    manifest = base / (name + '.json')
    spec = json.loads(manifest.read_text())
    core = {'postgres-init', 'postgres', 'synapse-db-init', 'signing-key-init', 'synapse'}
    assert spec['name'] == name and {p['id'] for p in spec['processes']} in (core, core | {'element-web', 'caddy'})
    values = dict(line.split('=', 1) for line in (base / name / 'synapse.env').read_text().splitlines())
    nonce = uuid.uuid4().hex[:12]
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-synapse-' + nonce)
    directory.mkdir(mode=0o700)
    users = {who: {'username': 'fixture_' + nonce + '_' + who,
                  'password': hashlib.sha256((values['P0V3_FIXTURE_PASSWORD'] + nonce + who).encode()).hexdigest()}
             for who in ('alice', 'bob')}
    private_write(directory / 'users.json', json.dumps(users).encode())
    payload = secrets.token_bytes(2048)
    private_write(directory / 'media.bin', payload)
    receipt = {'id': directory.name, 'scope': 'persistent-private-synapse-not-full-stack', 'passed': False}
    origin = ''
    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))
    q = lambda value: urllib.parse.quote(value, safe='')

    def runtime(action):
        nonlocal origin
        result = subprocess.run([str(CLI), 'runtime', action, str(manifest)], capture_output=True, text=True, timeout=900,
            env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0, 'Owned Synapse lifecycle failed'
        if action != 'stop-private':
            data = json.loads(subprocess.check_output(P + ['inspect', 'p0v3-live-' + name + '-synapse'], stderr=subprocess.DEVNULL))[0]
            assert data['Config']['Labels']['io.p0v3.private-deployment'] == name
            assert set(data['NetworkSettings']['Networks']) == {'p0v3-live-' + name + '-net'}
            ip = data['NetworkSettings']['Networks']['p0v3-live-' + name + '-net']['IPAddress']
            assert ipaddress.ip_address(ip).is_private and not data['HostConfig']['PortBindings']
            origin = 'http://' + ip + ':8008'
        return json.loads(result.stdout.splitlines()[0])

    def api(path, content=None, token=None, method=None, expected_error=None, binary=False):
        headers = {'Accept': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        body = None
        if content is not None:
            headers['Content-Type'] = 'application/octet-stream' if isinstance(content, bytes) else 'application/json'
            body = content if isinstance(content, bytes) else json.dumps(content).encode()
        try:
            with opener.open(urllib.request.Request(origin + path, data=body, headers=headers, method=method), timeout=30) as response:
                assert expected_error is None, 'Matrix authorization boundary was bypassed'
                raw = response.read(2097153)
                assert len(raw) <= 2097152
                return raw if binary else json.loads(raw)
        except urllib.error.HTTPError as error:
            if error.code == expected_error:
                return json.loads(error.read(65536))
            raise RuntimeError('Private Matrix API returned ' + str(error.code)) from None

    def login(who):
        user = users[who]
        result = api('/_matrix/client/v3/login', {'type': 'm.login.password',
            'identifier': {'type': 'm.id.user', 'user': user['username']}, 'password': user['password']})
        assert result['user_id'] == '@' + user['username'] + ':matrix.private.invalid'
        return result['access_token']

    try:
        runtime('apply-private')
        receipt['phase'] = 'closed-signup-and-registration'
        assert api('/_matrix/client/v3/joined_rooms', expected_error=401)['errcode'] == 'M_MISSING_TOKEN'
        assert api('/_matrix/client/v3/register', {'username': 'blocked_' + nonce, 'password': secrets.token_hex(32)}, expected_error=403)['errcode'] == 'M_FORBIDDEN'
        for user in users.values():
            server_nonce = api('/_synapse/admin/v1/register')['nonce']
            result = api('/_synapse/admin/v1/register', {'nonce': server_nonce, **user, 'admin': False,
                'mac': registration_mac(values['P0V3_REGISTRATION_SECRET'], server_nonce, user['username'], user['password'])})
            assert result['user_id'] == '@' + user['username'] + ':matrix.private.invalid'
        alice, bob = login('alice'), login('bob')
        bob_id = '@' + users['bob']['username'] + ':matrix.private.invalid'
        receipt['phase'] = 'membership-and-messages'
        room = api('/_matrix/client/v3/createRoom', {'preset': 'private_chat', 'name': 'Private fixture ' + nonce,
            'invite': [bob_id]}, alice)['room_id']
        room_path = '/_matrix/client/v3/rooms/' + q(room)
        assert api('/_matrix/client/v3/join/' + q(room), {}, bob)['room_id'] == room
        confidential = api('/_matrix/client/v3/createRoom', {'preset': 'private_chat', 'name': 'Not shared ' + nonce}, alice)['room_id']
        assert api('/_matrix/client/v3/rooms/' + q(confidential) + '/state', token=bob, expected_error=403)['errcode'] == 'M_FORBIDDEN'
        encrypted_room = api('/_matrix/client/v3/createRoom', {'preset': 'private_chat', 'name': 'Encrypted fixture ' + nonce,
            'invite': [bob_id], 'initial_state': [{'type': 'm.room.encryption', 'state_key': '',
                'content': {'algorithm': 'm.megolm.v1.aes-sha2'}}]}, alice)['room_id']
        assert api('/_matrix/client/v3/join/' + q(encrypted_room), {}, bob)['room_id'] == encrypted_room
        message = {'msgtype': 'm.text', 'body': 'Private persisted Matrix message ' + nonce}
        send_path = room_path + '/send/m.room.message/' + nonce
        event = api(send_path, message, alice, method='PUT')['event_id']
        assert api(send_path, message, alice, method='PUT')['event_id'] == event
        assert api(room_path + '/event/' + q(event), token=bob)['content'] == message
        media = api('/_matrix/media/v3/upload?filename=private-fixture.bin', payload, alice)['content_uri']
        parsed = urllib.parse.urlsplit(media)
        assert parsed.scheme == 'mxc' and parsed.netloc == 'matrix.private.invalid'
        assert re.fullmatch(r'/[a-zA-Z0-9_-]{1,128}', parsed.path)
        media_path = '/_matrix/client/v1/media/download/' + q(parsed.netloc) + '/' + q(parsed.path[1:])
        assert api(media_path, token=bob, binary=True) == payload
        assert api(media_path, expected_error=401)['errcode'] == 'M_MISSING_TOKEN'
        attachment = {'msgtype': 'm.file', 'body': 'private-fixture.bin', 'url': media,
                      'info': {'mimetype': 'application/octet-stream', 'size': len(payload)}}
        media_event = api(room_path + '/send/m.room.message/media-' + nonce, attachment, alice, method='PUT')['event_id']
        api(room_path + '/read_markers', {'m.fully_read': media_event, 'm.read': media_event}, bob)
        receipt.update(roomId=room, encryptedRoomId=encrypted_room, textEventId=event, mediaEventId=media_event, contentUri=media,
                       mediaSha256=hashlib.sha256(payload).hexdigest())
        receipt['phase'] = 'restart'
        stopped = runtime('stop-private')
        assert all(p['exitCode'] in (0, 143) for p in stopped)
        runtime('apply-private')
        alice, bob = login('alice'), login('bob')
        assert room in api('/_matrix/client/v3/joined_rooms', token=bob)['joined_rooms']
        assert api(room_path + '/event/' + q(event), token=bob)['content'] == message
        assert api(room_path + '/event/' + q(media_event), token=bob)['content'] == attachment
        assert api(media_path, token=bob, binary=True) == payload
        assert api('/_matrix/client/v3/user/' + q(bob_id) + '/rooms/' + q(room) + '/account_data/m.fully_read', token=bob)['event_id'] == media_event
        assert api('/_matrix/client/v3/rooms/' + q(confidential) + '/state', token=bob, expected_error=403)['errcode'] == 'M_FORBIDDEN'
        receipt.update(passed=True, phase='complete', nativePasswordLoginVerified=True, closedSignupVerified=True,
            privateMembershipEnforced=True, sendTransactionDeduplicated=True, messagesAndMediaPersisted=True,
            readMarkerPersisted=True, browserJourney=False, endToEndEncryptionTest=False, masIntegration=False,
            encryptedRestoreTest=False, federationEnabled=False)
        print(json.dumps(receipt, indent=2))
    finally:
        private_write(directory / 'receipt.json', json.dumps(receipt, indent=2).encode())


if __name__ == '__main__':
    main()
