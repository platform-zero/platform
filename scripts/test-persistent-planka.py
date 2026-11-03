#!/usr/bin/env python3
"""Private Planka project/board/card/comment workflow and clean restart readback, not full acceptance."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request
import uuid

P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
CLI = Path(__file__).resolve().parents[1] / 'build/install/p0-v3-platform/bin/p0-v3-platform'


class ApiError(Exception):
    def __init__(self, status, body):
        super().__init__('Private Planka API returned ' + str(status))
        self.status, self.body = status, body


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='planka-r3')
    parser.add_argument('--canonical-core', action='store_true')
    args = parser.parse_args()
    name = args.name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    base = Path('/mnt/media/p0-v3/runtime-deployments')
    manifest = base / (name + '.json')
    spec = json.loads(manifest.read_text())
    expected = {'postgres-init', 'postgres', 'planka-db-init', 'planka-init', 'planka'}
    if args.canonical_core:
        expected |= {'valkey', 'ntfy', 'postgres-finalize'}
    assert spec['name'] == name and {p['id'] for p in spec['processes']} == expected
    values = dict(line.split('=', 1) for line in (base / name / ('planka-bootstrap.env' if args.canonical_core else 'planka.env')).read_text().splitlines())
    run_id = 'p0v3-planka-' + uuid.uuid4().hex[:12]
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / run_id
    directory.mkdir(mode=0o700)
    receipt = {'id': run_id, 'scope': 'persistent-private-planka-not-full-stack', 'passed': False}
    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))
    origin, token = '', ''

    def runtime(action):
        nonlocal origin
        result = subprocess.run([str(CLI), 'runtime', action, str(manifest)], capture_output=True, text=True, timeout=900,
            env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0, 'Owned Planka runtime lifecycle failed'
        if action != 'stop-private':
            data = json.loads(subprocess.check_output(P + ['container', 'inspect', 'p0v3-live-' + name + '-planka'], stderr=subprocess.DEVNULL))[0]
            assert data['Config']['Labels']['io.p0v3.private-deployment'] == name
            address = data['NetworkSettings']['Networks']['p0v3-live-' + name + ('-planka-web' if args.canonical_core else '-net')]['IPAddress']
            assert ipaddress.ip_address(address).is_private
            origin = 'http://' + address + ':1337'
        return json.loads(result.stdout.splitlines()[0])

    def api(path, payload=None, method=None):
        headers = {'Accept': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        body = None if payload is None else json.dumps(payload).encode()
        if body is not None:
            headers['Content-Type'] = 'application/json'
        try:
            req = urllib.request.Request(origin + '/api' + path, data=body, headers=headers, method=method)
            with opener.open(req, timeout=20) as response:
                raw = response.read(2097153)
                assert len(raw) <= 2097152
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            raw = error.read(2097153)
            assert len(raw) <= 2097152
            raise ApiError(error.code, json.loads(raw)) from None

    def login():
        nonlocal token
        token = ''
        try:
            token = api('/access-tokens', {'emailOrUsername': values['DEFAULT_ADMIN_EMAIL'], 'password': values['DEFAULT_ADMIN_PASSWORD']})['item']
        except ApiError as error:
            assert error.status == 403 and error.body.get('step') == 'accept-terms'
            expected = '# Private automated test instance\n\nSynthetic test accounts and fixture data only. No public service or human end-user agreement is offered here. This notice does not replace upstream software licenses.\n'
            terms = api('/terms')['item']
            assert terms['content'] == expected and terms['signature'] == hashlib.sha256(expected.encode()).hexdigest()
            token = api('/access-tokens/accept-terms', {'pendingToken': error.body['pendingToken'],
                'signature': terms['signature'], 'initialLanguage': 'en-US'})['item']
        assert isinstance(token, str) and token

    try:
        runtime('apply-private')
        login()
        receipt['phase'] = 'project-board'
        project = api('/projects', {'type': 'private', 'name': run_id})['item']
        board = api('/projects/' + project['id'] + '/boards', {'name': 'Private workflow', 'position': 65536})['item']
        todo = api('/boards/' + board['id'] + '/lists', {'type': 'active', 'name': 'To do', 'position': 65536})['item']
        done = api('/boards/' + board['id'] + '/lists', {'type': 'closed', 'name': 'Done', 'position': 131072})['item']
        receipt['phase'] = 'card-move-comment'
        card = api('/lists/' + todo['id'] + '/cards', {'type': 'project', 'name': 'Persistent task ' + run_id,
                   'position': 65536, 'description': 'Real application data, private lifecycle fixture'})['item']
        card_path = '/cards/' + card['id']
        comment = 'Created, moved and retained through restart'
        api(card_path + '/comments', {'text': comment})
        moved = api(card_path, {'listId': done['id'], 'position': 65536}, method='PATCH')['item']
        assert moved['listId'] == done['id']
        receipt['phase'] = 'restart'
        stopped = runtime('stop-private')
        assert all(p['exitCode'] in (0, 143) for p in stopped)
        runtime('apply-private')
        login()
        saved = api(card_path)['item']
        assert saved['name'] == card['name'] and saved['listId'] == done['id']
        assert any(c['text'] == comment for c in api(card_path + '/comments')['items'])
        assert api('/projects/' + project['id'])['item']['name'] == run_id
        receipt.update(passed=True, phase='complete', projectBoardCardWorkflow=True, cardMoveAndCommentPersisted=True,
                       cleanStopRestartVerified=True, encryptedRestoreTest=False, browserJourney=False,
                       projectId=project['id'], boardId=board['id'], cardId=card['id'], doneListId=done['id'])
        print(json.dumps(receipt, indent=2))
    finally:
        fd = os.open(directory / 'receipt.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as out:
            json.dump(receipt, out, indent=2)
            out.flush()
            os.fsync(out.fileno())


if __name__ == '__main__':
    main()
