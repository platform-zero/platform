#!/usr/bin/env python3
"""Home Assistant local onboarding/auth, virtual-device automation and clean restart. No physical devices."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='homeassistant-r2')
    name = parser.parse_args().name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    base = Path('/mnt/media/p0-v3/runtime-deployments')
    manifest = base / (name + '.json')
    spec = json.loads(manifest.read_text())
    assert spec['name'] == name and {p['id'] for p in spec['processes']} == {'config-init', 'homeassistant'}
    values = dict(line.split('=', 1) for line in (base / name / 'homeassistant.env').read_text().splitlines())
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-homeassistant-' + uuid.uuid4().hex[:12])
    directory.mkdir(mode=0o700)
    receipt = {'id': directory.name, 'scope': 'persistent-private-homeassistant-not-full-stack', 'passed': False}
    origin, token = '', ''
    client_id = 'http://homeassistant:8123/'
    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))

    def runtime(action):
        nonlocal origin
        result = subprocess.run([str(CLI), 'runtime', action, str(manifest)], capture_output=True, text=True, timeout=900,
            env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0, 'Owned Home Assistant lifecycle failed'
        if action != 'stop-private':
            data = json.loads(subprocess.check_output(P + ['inspect', 'p0v3-live-' + name + '-homeassistant'], stderr=subprocess.DEVNULL))[0]
            assert data['Config']['Labels']['io.p0v3.private-deployment'] == name
            address = data['NetworkSettings']['Networks']['p0v3-live-' + name + '-net']['IPAddress']
            assert ipaddress.ip_address(address).is_private
            origin = 'http://' + address + ':8123'
        return json.loads(result.stdout.splitlines()[0])

    def api(path, payload=None, form=False, denied=False):
        headers = {'Host': 'homeassistant:8123', 'Accept': 'application/json'}
        if token:
            headers['Authorization'] = 'Bearer ' + token
        body = None
        if payload is not None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
            body = (urllib.parse.urlencode(payload) if form else json.dumps(payload)).encode()
        try:
            with opener.open(urllib.request.Request(origin + path, data=body, headers=headers), timeout=60) as response:
                assert not denied, 'Unauthenticated API access was accepted'
                raw = response.read(2097153)
                assert len(raw) <= 2097152
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as error:
            if denied and error.code == 401:
                return None
            raise RuntimeError('Private Home Assistant API returned ' + str(error.code)) from None

    def exchange(code):
        nonlocal token
        token = api('/auth/token', {'client_id': client_id, 'grant_type': 'authorization_code', 'code': code}, form=True)['access_token']

    def login():
        nonlocal token
        token = ''
        flow = api('/auth/login_flow', {'client_id': client_id, 'handler': ['homeassistant', None], 'redirect_uri': client_id})
        result = api('/auth/login_flow/' + flow['flow_id'], {'client_id': client_id,
            'username': 'p0v3-fixture', 'password': values['P0V3_FIXTURE_PASSWORD']})
        assert result['type'] == 'create_entry'
        exchange(result['result'])

    def wait_running():
        for _ in range(120):
            if api('/api/config')['state'].lower() == 'running':
                return
            time.sleep(1)
        raise AssertionError('Home Assistant integrations did not reach running state')

    try:
        runtime('apply-private')
        receipt['phase'] = 'onboarding'
        api('/api/', denied=True)
        # The onboarding endpoint is no longer registered on fully onboarded restarts.
        try:
            steps = api('/api/onboarding')
        except RuntimeError as error:
            if not str(error).endswith('404'):
                raise
            steps = []
        if any(s['step'] == 'user' and not s['done'] for s in steps):
            result = api('/api/onboarding/users', {'client_id': client_id, 'name': 'Private Fixture', 'username': 'p0v3-fixture',
                'password': values['P0V3_FIXTURE_PASSWORD'], 'language': 'en'})
            exchange(result['auth_code'])
        else:
            login()
        for step in steps:
            if step['step'] == 'user' or step['done']:
                continue
            payload = {'client_id': client_id, 'redirect_uri': client_id} if step['step'] == 'integration' else {}
            api('/api/onboarding/' + step['step'], payload)
        wait_running()
        assert api('/api/config')['location_name'] == 'Private virtual-device fixture'
        receipt['phase'] = 'virtual-automation'
        trigger, result_entity = 'input_boolean.private_probe', 'input_boolean.private_result'
        api('/api/services/input_boolean/turn_off', {'entity_id': [trigger, result_entity]})
        assert api('/api/states/' + result_entity)['state'] == 'off'
        api('/api/services/input_boolean/turn_on', {'entity_id': trigger})
        for _ in range(50):
            if api('/api/states/' + result_entity)['state'] == 'on':
                break
            time.sleep(0.2)
        else:
            raise AssertionError('Virtual-device automation did not execute')
        receipt['phase'] = 'restart'
        stopped = runtime('stop-private')
        assert all(p['exitCode'] in (0, 143) for p in stopped)
        runtime('apply-private')
        login()
        wait_running()
        assert api('/api/states/' + trigger)['state'] == 'on'
        assert api('/api/states/' + result_entity)['state'] == 'on'
        receipt.update(passed=True, phase='complete', nativeOnboardingAuthVerified=True, virtualAutomationExecuted=True,
                       restoredVirtualStateAfterRestart=True, physicalDevicesTouched=False, encryptedRestoreTest=False,
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
