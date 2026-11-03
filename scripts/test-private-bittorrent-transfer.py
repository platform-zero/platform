#!/usr/bin/env python3
"""A real BitTorrent transfer between owned private peers, with generated random data and no trackers.
The temporary seeder is removed; the downloaded file/torrent remain for restart readback.
"""
import argparse
import hashlib
import http.cookiejar
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
ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / 'platform/build/install/p0-v3-platform/bin/p0-v3-platform'
BASE = Path('/mnt/media/p0-v3/runtime-deployments')


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def encode(value):
    if type(value) is int:
        return b'i' + str(value).encode() + b'e'
    if isinstance(value, bytes):
        return str(len(value)).encode() + b':' + value
    if isinstance(value, dict):
        return b'd' + b''.join(encode(k) + encode(value[k]) for k in sorted(value)) + b'e'
    raise TypeError('Unsupported fixture metadata type')


def downloaded_bytes(info):
    # Queued completed torrents can defer folding this session into the persistent counter.
    # Do not sum these counters: on active torrents they can already overlap.
    return max(info['downloaded'], info['downloaded_session'])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='qbittorrent')
    name = parser.parse_args().name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    manifest = BASE / (name + '.json')
    spec = json.loads(manifest.read_text())
    assert spec['name'] == name and {p['id'] for p in spec['processes']} == {'config-init', 'qbittorrent'}
    values = dict(line.split('=', 1) for line in (BASE / name / 'qbittorrent.env').read_text().splitlines())
    selected = next(p for p in spec['processes'] if p['id'] == 'qbittorrent')
    image = selected['image']
    prefix = 'p0v3-transfer-' + uuid.uuid4().hex[:12]
    seed = prefix + '-seeder'
    config, data = prefix + '-config', prefix + '-data'
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / prefix
    directory.mkdir(mode=0o700)
    receipt = {'id': prefix, 'scope': 'private-bittorrent-transfer-not-full-stack', 'passed': False}
    filename = prefix + '.bin'

    def pod(*arguments):
        result = subprocess.run(P + list(arguments), capture_output=True, text=True, timeout=120)
        if result.returncode:
            fd = os.open(directory / ('failure-' + uuid.uuid4().hex[:8] + '.log'), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w') as out:
                out.write(result.stderr)
            raise RuntimeError('Scoped transfer Podman operation failed: ' + arguments[0])
        return result.stdout.strip()

    def runtime(action):
        result = subprocess.run([str(CLI), 'runtime', action, str(manifest)], capture_output=True, text=True, timeout=900,
            env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0, 'Owned transfer runtime lifecycle failed'
        return json.loads(result.stdout.splitlines()[0])

    def address(container):
        inspected = json.loads(pod('inspect', container))[0]
        ip = inspected['NetworkSettings']['Networks']['p0v3-live-' + name + '-net']['IPAddress']
        assert ipaddress.ip_address(ip).is_private and not inspected['HostConfig']['PortBindings']
        return ip

    class Client:
        def __init__(self, ip):
            self.origin = 'http://' + ip + ':8080'
            self.opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}),
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

        def request(self, path, form=None, raw=None, content_type=None, denied=False):
            headers = {'Host': 'qbittorrent:8080', 'Origin': 'http://qbittorrent:8080', 'Referer': 'http://qbittorrent:8080/'}
            if form is not None:
                raw = urllib.parse.urlencode(form).encode()
                content_type = 'application/x-www-form-urlencoded'
            if raw is not None:
                headers['Content-Type'] = content_type
            try:
                with self.opener.open(urllib.request.Request(self.origin + '/api/v2/' + path, data=raw, headers=headers), timeout=20) as response:
                    assert not denied, 'Unauthenticated transfer API accepted access'
                    body = response.read(2097153)
                    assert len(body) <= 2097152
                    return body
            except urllib.error.HTTPError as error:
                if denied and error.code == 403:
                    return None
                raise RuntimeError('Private transfer API returned ' + str(error.code)) from None

        def login(self):
            assert self.request('auth/login', form={'username': 'p0v3-fixture', 'password': values['P0V3_QBIT_PASSWORD']}) in (b'Ok.', b'')
            prefs = json.loads(self.request('app/preferences'))
            assert all(not prefs[key] for key in ('dht', 'pex', 'lsd', 'upnp', 'bypass_local_auth'))

        def add(self, torrent):
            boundary = 'p0v3-' + uuid.uuid4().hex
            body = ('--' + boundary + '\r\nContent-Disposition: form-data; name="torrents"; filename="fixture.torrent"\r\nContent-Type: application/x-bittorrent\r\n\r\n').encode()
            body += torrent + ('\r\n--' + boundary + '--\r\n').encode()
            assert self.request('torrents/add', raw=body, content_type='multipart/form-data; boundary=' + boundary) != b'Fails.'
            # New releases return structured per-file results; exact info-hash state is checked next.

        def info(self, info_hash):
            items = json.loads(self.request('torrents/info?hashes=' + info_hash))
            return items[0] if items else None

    def await_condition(predicate):
        for _ in range(90):
            if predicate():
                return
            time.sleep(1)
        raise AssertionError('Private peer transfer did not converge')

    try:
        runtime('apply-private')
        target_name = 'p0v3-live-' + name + '-qbittorrent'
        client = Client(address(target_name))
        client.request('app/version', denied=True)
        client.login()
        receipt['phase'] = 'seed-fixture'
        for volume in (config, data):
            assert subprocess.run(P + ['volume', 'exists', volume], capture_output=True).returncode == 1
            pod('volume', 'create', '--label=io.p0v3.transfer-probe=' + prefix, volume)
        common = ['--label=io.p0v3.transfer-probe=' + prefix, '--pull=never', '--read-only', '--cap-drop=all', '--security-opt=no-new-privileges',
            '--security-opt=apparmor=p0v3-private-v1', '--user=1000:1000', '--memory=512m', '--pids-limit=256',
            '--image-volume=ignore', '--env=HOME=/config', '--env=XDG_CONFIG_HOME=/config', '--env=XDG_DATA_HOME=/config',
            '--volume=' + config + ':/config:U', '--volume=' + data + ':/downloads:U', '--tmpfs=/tmp:rw,nosuid,nodev,size=64m']
        pod('run', '--rm', '--name=' + prefix + '-init', '--network=none', *common,
            '--volume=' + str(BASE / name / 'qbittorrent.conf') + ':/input.conf:ro', '--entrypoint=/bin/sh', image, '-ec',
            'mkdir -p /config/qBittorrent; cp /input.conf /config/qBittorrent/qBittorrent.conf; chmod 600 /config/qBittorrent/qBittorrent.conf; '
            'dd if=/dev/urandom of=/downloads/' + filename + ' bs=131072 count=1')
        pod('run', '-d', '--name=' + seed, '--network=p0v3-live-' + name + '-net',
            *common, '--entrypoint=/app/qbittorrent-nox', image, '--webui-port=8080')
        seed_ip = address(seed)
        seeder = Client(seed_ip)
        for _ in range(60):
            try:
                seeder.login()
                break
            except (urllib.error.URLError, ConnectionError):
                time.sleep(1)
        else:
            raise AssertionError('Private seeder failed readiness')
        piece = pod('exec', seed, 'sha1sum', '/downloads/' + filename).split()[0]
        expected = pod('exec', seed, 'sha256sum', '/downloads/' + filename).split()[0]
        info = {b'name': filename.encode(), b'length': 131072, b'piece length': 262144, b'pieces': bytes.fromhex(piece), b'private': 1}
        torrent = encode({b'info': info})
        info_hash = hashlib.sha1(encode(info)).hexdigest()
        seeder.add(torrent)
        await_condition(lambda: seeder.info(info_hash) is not None and seeder.info(info_hash)['progress'] == 1)
        client.add(torrent)
        await_condition(lambda: client.info(info_hash) is not None)
        assert client.info(info_hash)['progress'] == 0
        for peer in (seeder, client):
            trackers = json.loads(peer.request('torrents/trackers?hash=' + info_hash))
            assert all(t['url'].startswith('** [') and t['url'].endswith('] **') for t in trackers)
        receipt['phase'] = 'peer-transfer'
        client.request('torrents/addPeers', form={'hashes': info_hash, 'peers': seed_ip + ':6881'})
        await_condition(lambda: client.info(info_hash)['progress'] == 1)
        await_condition(lambda: downloaded_bytes(client.info(info_hash)) >= 131072)
        counters = client.info(info_hash)
        receipt['peerAccounting'] = {k: counters[k] for k in ('downloaded', 'downloaded_session')}
        assert pod('exec', target_name, 'sha256sum', '/downloads/' + filename).split()[0] == expected
        receipt['phase'] = 'restart'
        stopped = runtime('stop-private')
        assert all(p['exitCode'] in (0, 143) for p in stopped)
        runtime('apply-private')
        client = Client(address(target_name))
        client.login()
        await_condition(lambda: client.info(info_hash) is not None and client.info(info_hash)['progress'] == 1)
        assert pod('exec', target_name, 'sha256sum', '/downloads/' + filename).split()[0] == expected
        receipt.update(passed=True, phase='complete', authenticatedApiVerified=True, realPeerBytesTransferred=131072,
            generatedPayloadSha256=expected, trackersAbsent=True, discoveryAndUpnpDisabled=True, downloadedDataPersisted=True,
            encryptedRestoreTest=False, browserJourney=False)
    finally:
        try:
            presence = subprocess.run(P + ['container', 'exists', seed], capture_output=True).returncode
            assert presence in (0, 1), 'Cannot audit private helper presence'
            if presence == 0:
                inspected = json.loads(pod('inspect', seed))[0]
                assert inspected['Config']['Labels'].get('io.p0v3.transfer-probe') == prefix
                assert inspected['Image'].removeprefix('sha256:') == selected['imageId']
                pod('stop', '--time=30', seed)
                inspected = json.loads(pod('inspect', seed))[0]
                assert not inspected['State']['Running'] and inspected['State']['ExitCode'] in (0, 143)
                pod('rm', seed)
        except Exception:
            receipt.update(passed=False, helperQuarantineFailed=True)
            raise
        finally:
            fd = os.open(directory / 'receipt.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, 'w') as out:
                json.dump(receipt, out, indent=2)
                out.flush()
                os.fsync(out.fileno())
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
