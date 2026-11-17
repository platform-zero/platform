#!/usr/bin/env python3
"""Private Donetick signup, chore completion/history and restart readback; no external notifications."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import datetime
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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='donetick')
    name = parser.parse_args().name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    base = Path('/mnt/media/p0-v3/runtime-deployments')
    manifest = base / (name + '.json')
    spec = json.loads(manifest.read_text())
    assert spec['name'] == name and [p['id'] for p in spec['processes']] == ['donetick']
    values = dict(line.split('=', 1) for line in (base / name / 'donetick.env').read_text().splitlines())
    nonce = uuid.uuid4().hex[:12]
    user = 'journey-' + nonce
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-donetick-' + nonce)
    directory.mkdir(mode=0o700)
    receipt = {'id': directory.name, 'scope': 'persistent-private-donetick-not-full-stack', 'passed': False}
    origin, token = '', ''
    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))

    def runtime(action):
        nonlocal origin
        result = subprocess.run([str(CLI), 'runtime', action, str(manifest)], capture_output=True, text=True, timeout=900,
            env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0, 'Owned Donetick lifecycle failed'
        if action != 'stop-private':
            data = json.loads(subprocess.check_output(P + ['inspect', 'p0v3-live-' + name + '-donetick'], stderr=subprocess.DEVNULL))[0]
            assert data['Config']['Labels']['io.p0v3.private-deployment'] == name
            address = data['NetworkSettings']['Networks']['p0v3-live-' + name + '-net']['IPAddress']
            assert ipaddress.ip_address(address).is_private
            origin = 'http://' + address + ':2021'
        return json.loads(result.stdout.splitlines()[0])

    def api(path, payload=None):
        headers = {'Accept': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        if payload is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(origin + '/api/v1' + path,
            data=None if payload is None else json.dumps(payload).encode(), headers=headers)
        try:
            with opener.open(req, timeout=20) as response:
                raw = response.read(2097153)
                assert len(raw) <= 2097152
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            raise RuntimeError('Private Donetick API returned ' + str(error.code)) from None

    def login():
        nonlocal token
        token = ''
        result = api('/auth/login', {'username': user, 'password': values['P0V3_FIXTURE_PASSWORD']})
        token = result.get('token') or result.get('access_token')
        assert isinstance(token, str) and token

    try:
        runtime('apply-private')
        receipt['phase'] = 'signup-login'
        api('/auth/', {'username': user, 'password': values['P0V3_FIXTURE_PASSWORD'],
                       'displayName': 'Private Fixture', 'email': user + '@localhost.invalid'})
        login()
        receipt['phase'] = 'chore-completion'
        title = 'Private task ' + nonce
        created = api('/chores/', {'name': title, 'description': 'Private lifecycle fixture', 'frequencyType': 'once',
            'assignStrategy': 'no_assignee', 'assignees': [], 'isActive': True, 'notification': False,
            'nextDueDate': datetime.datetime.now(datetime.timezone.utc).isoformat()})
        chore_id = created['res']
        assert isinstance(chore_id, int)
        path = '/chores/' + str(chore_id)
        assert api(path)['res']['name'] == title
        note = 'Completed private fixture ' + nonce
        api(path + '/do', {'notes': note})
        history = api(path + '/history')['res']
        assert history and any(h.get('notes') == note for h in history)
        receipt['phase'] = 'restart'
        stopped = runtime('stop-private')
        assert all(p['exitCode'] in (0, 143) for p in stopped)
        runtime('apply-private')
        login()
        assert api(path)['res']['name'] == title
        assert any(h.get('notes') == note for h in api(path + '/history')['res'])
        receipt.update(passed=True, phase='complete', signupLoginVerified=True, choreCompleted=True,
                       completionHistoryPersisted=True, cleanStopRestartVerified=True, encryptedRestoreTest=False,
                       browserJourney=False, androidJourney=False)
        print(json.dumps(receipt, indent=2))
    finally:
        fd = os.open(directory / 'receipt.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as out:
            json.dump(receipt, out, indent=2)
            out.flush()
            os.fsync(out.fileno())


if __name__ == '__main__':
    main()
