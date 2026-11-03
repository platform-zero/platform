#!/usr/bin/env python3
"""Real Jellyfin onboarding, library scan, streamed audio and favourite persistence; fixture media only."""
import argparse
import hashlib
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
    parser.add_argument('--name', default='jellyfin-r4')
    name = parser.parse_args().name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    base = Path('/mnt/media/p0-v3/runtime-deployments')
    manifest = base / (name + '.json')
    spec = json.loads(manifest.read_text())
    assert spec['name'] == name and {p['id'] for p in spec['processes']} == {'media-init', 'jellyfin'}
    values = dict(line.split('=', 1) for line in (base / name / 'jellyfin.env').read_text().splitlines())
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-jellyfin-' + uuid.uuid4().hex[:12])
    directory.mkdir(mode=0o700)
    receipt = {'id': directory.name, 'scope': 'persistent-private-jellyfin-not-full-stack', 'passed': False}
    origin, token = '', ''
    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))

    def runtime(action):
        nonlocal origin
        result = subprocess.run([str(CLI), 'runtime', action, str(manifest)], capture_output=True, text=True, timeout=900,
            env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0, 'Owned Jellyfin lifecycle failed'
        if action != 'stop-private':
            data = json.loads(subprocess.check_output(P + ['inspect', 'p0v3-live-' + name + '-jellyfin'], stderr=subprocess.DEVNULL))[0]
            assert data['Config']['Labels']['io.p0v3.private-deployment'] == name
            address = data['NetworkSettings']['Networks']['p0v3-live-' + name + '-net']['IPAddress']
            assert ipaddress.ip_address(address).is_private
            origin = 'http://' + address + ':8096'
        return json.loads(result.stdout.splitlines()[0])

    def api(path, payload=None, method=None, binary=False):
        authorization = 'MediaBrowser Client="P0 private probe", Device="Private probe", DeviceId="p0v3-private-media", Version="1"'
        if token:
            authorization += ', Token="' + token + '"'
        headers = {'Authorization': authorization}
        if payload is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(origin + path, data=None if payload is None else json.dumps(payload).encode(), headers=headers, method=method)
        try:
            with opener.open(req, timeout=30) as response:
                raw = response.read(2097153)
                assert len(raw) <= 2097152
                return raw if binary else (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as error:
            raise RuntimeError('Private Jellyfin API returned ' + str(error.code)) from None

    def login():
        nonlocal token
        token = ''
        result = api('/Users/AuthenticateByName', {'Username': 'p0v3-fixture', 'Pw': values['P0V3_FIXTURE_PASSWORD']})
        token = result['AccessToken']
        return result['User']['Id']

    try:
        runtime('apply-private')
        receipt['phase'] = 'onboarding'
        if not api('/System/Info/Public')['StartupWizardCompleted']:
            api('/Startup/Configuration', {'UICulture': 'en-US', 'MetadataCountryCode': 'US', 'PreferredMetadataLanguage': 'en'})
            api('/Startup/User')  # The native wizard GET creates its first-user record before POST updates it.
            api('/Startup/User', {'Name': 'p0v3-fixture', 'Password': values['P0V3_FIXTURE_PASSWORD']})
            api('/Startup/RemoteAccess', {'EnableRemoteAccess': False, 'EnableAutomaticPortMapping': False})
            api('/Startup/Complete', {}, method='POST')
        user = login()
        configuration = api('/System/Configuration')
        # First-start migrations can re-enable the vendor repository despite the seed XML.
        if any(r['Enabled'] for r in configuration['PluginRepositories']):
            for repository in configuration['PluginRepositories']:
                repository['Enabled'] = False
            api('/System/Configuration', configuration, method='POST')
        assert all(not r['Enabled'] for r in api('/System/Configuration')['PluginRepositories']), 'Unattended plugin acquisition must remain disabled'
        receipt['phase'] = 'library-scan'
        libraries = api('/Library/VirtualFolders')
        assert all(v['Name'] == 'Private fixture audio' and v['Locations'] == ['/media'] for v in libraries)
        if not libraries:
            query = urllib.parse.urlencode({'name': 'Private fixture audio', 'collectionType': 'music', 'refreshLibrary': 'true'})
            api('/Library/VirtualFolders?' + query, {'LibraryOptions': {'PathInfos': [{'Path': '/media'}],
                'EnableRealtimeMonitor': False, 'EnableInternetProviders': False,
                'TypeOptions': [{'Type': 'Audio', 'MetadataFetchers': [], 'ImageFetchers': []}]}})
        # Startup completion can already have a scan in flight; request again after it settles.
        for _ in range(60):
            if not any(t['Key'] == 'RefreshLibrary' and t['State'] == 'Running' for t in api('/ScheduledTasks')):
                break
            time.sleep(1)
        else:
            raise AssertionError('Initial library scan did not settle')
        api('/Library/Refresh', {}, method='POST')
        items = []
        for _ in range(60):
            items = api('/Users/' + user + '/Items?Recursive=true&IncludeItemTypes=Audio')['Items']
            if len(items) == 1 and items[0]['Name'] == 'Platform Zero private tone':
                break
            time.sleep(2)
        assert len(items) == 1
        item = items[0]['Id']
        assert items[0]['Name'] == 'Platform Zero private tone'
        receipt['phase'] = 'stream-and-favourite'
        stream_path = '/Audio/' + item + '/stream?static=true'
        audio = api(stream_path, binary=True)
        assert audio[:4] == b'RIFF' and audio[8:12] == b'WAVE' and len(audio) > 250000
        digest = hashlib.sha256(audio).hexdigest()
        api('/Users/' + user + '/FavoriteItems/' + item, {}, method='POST')
        assert api('/Users/' + user + '/Items/' + item)['UserData']['IsFavorite']
        receipt['phase'] = 'restart'
        stopped = runtime('stop-private')
        assert all(p['exitCode'] in (0, 143) for p in stopped)
        runtime('apply-private')
        assert login() == user
        assert all(not r['Enabled'] for r in api('/System/Configuration')['PluginRepositories'])
        assert api('/System/Info/Public')['StartupWizardCompleted']
        assert api('/Users/' + user + '/Items/' + item)['UserData']['IsFavorite']
        assert hashlib.sha256(api(stream_path, binary=True)).hexdigest() == digest
        receipt.update(passed=True, phase='complete', fixtureMediaOnly=True, authenticatedStreamVerified=True,
                       streamSha256=digest, libraryAndFavouritePersisted=True, cleanStopRestartVerified=True,
                       encryptedRestoreTest=False, browserJourney=False, androidJourney=False)
        print(json.dumps(receipt, indent=2))
    finally:
        fd = os.open(directory / 'receipt.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as out:
            json.dump(receipt, out, indent=2)
            out.flush()
            os.fsync(out.fileno())


if __name__ == '__main__':
    main()
