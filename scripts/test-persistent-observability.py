#!/usr/bin/env python3
"""Real private Alloy -> Loki -> Grafana and Prometheus/Alertmanager journeys, plus restart persistence.
No public routes, host log mounts, external receivers, or full-stack acceptance claims.
"""
import argparse
import base64
import datetime
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

P = ['sudo', '-n', 'podman', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store',
     '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
CLI = Path(__file__).resolve().parents[1] / 'build/install/p0-v3-platform/bin/p0-v3-platform'
PORTS = {'alertmanager': 9093, 'loki': 3100, 'prometheus': 9090, 'alloy': 3500, 'grafana': 3000}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='observability')
    name = parser.parse_args().name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    base = Path('/mnt/media/p0-v3/runtime-deployments')
    manifest = base / (name + '.json')
    spec = json.loads(manifest.read_text())
    assert spec['name'] == name and {p['id'] for p in spec['processes']} == set(PORTS)
    env = dict(line.split('=', 1) for line in (base / name / 'grafana.env').read_text().splitlines())
    auth = base64.b64encode((env['GF_SECURITY_ADMIN_USER'] + ':' + env['GF_SECURITY_ADMIN_PASSWORD']).encode()).decode()
    run_id = 'p0v3-observability-' + uuid.uuid4().hex[:12]
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / run_id
    directory.mkdir(mode=0o700)
    receipt = {'id': run_id, 'scope': 'persistent-private-observability-not-full-stack', 'deployment': name, 'passed': False}
    addresses = {}
    opener = urllib.request.build_opener(NoRedirect, urllib.request.ProxyHandler({}))

    def runtime(action):
        result = subprocess.run([str(CLI), 'runtime', action, str(manifest)], capture_output=True, text=True, timeout=900,
                                env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0, 'Private runtime lifecycle failed'
        for role in PORTS:
            raw = subprocess.run(P + ['container', 'inspect', 'p0v3-live-' + name + '-' + role], capture_output=True, text=True, timeout=20)
            assert raw.returncode == 0
            data = json.loads(raw.stdout)[0]
            assert data['Config']['Labels']['io.p0v3.private-deployment'] == name
            ip = data['NetworkSettings']['Networks']['p0v3-live-' + name + '-net']['IPAddress']
            if action != 'stop-private':
                assert ipaddress.ip_address(ip).is_private
                addresses[role] = ip
        return json.loads(result.stdout.splitlines()[0])

    def request(role, path, payload=None):
        headers = {'Accept': 'application/json'}
        if role == 'grafana':
            headers['Authorization'] = 'Basic ' + auth
        body = None if payload is None else json.dumps(payload).encode()
        if body is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request('http://' + addresses[role] + ':' + str(PORTS[role]) + path, data=body, headers=headers)
        try:
            with opener.open(req, timeout=15) as response:
                data = response.read(2097153)
                assert len(data) <= 2097152
                return json.loads(data) if data else None
        except urllib.error.HTTPError as error:
            raise RuntimeError(role + ' private API returned ' + str(error.code)) from None

    def await_result(predicate):
        for _ in range(45):
            if predicate():
                return
            time.sleep(2)
        raise AssertionError('Private product readback did not converge')

    try:
        runtime('apply-private')
        receipt['phase'] = 'metrics'
        query = '/api/v1/query?' + urllib.parse.urlencode({'query': 'up'})
        def all_up():
            rows = request('prometheus', query)['data']['result']
            return {r['metric']['job'] for r in rows if r['value'][1] == '1'} == set(PORTS)
        await_result(all_up)
        sources = request('grafana', '/api/datasources')
        assert {s['uid'] for s in sources} == {'p0-prometheus', 'p0-loki'}
        proxied = request('grafana', '/api/datasources/proxy/uid/p0-prometheus' + query)
        assert proxied['status'] == 'success' and len(proxied['data']['result']) == 5
        receipt.update(allFiveScrapeTargetsUp=True, grafanaPrometheusQueryVerified=True)

        receipt['phase'] = 'logs'
        stamp = time.time_ns()
        message = 'Private lifecycle log ' + run_id
        request('alloy', '/loki/api/v1/push', {'streams': [{'stream': {'job': 'p0v3-acceptance', 'run': run_id},
                                                        'values': [[str(stamp), message]]}]})
        def log_path():
            return '/loki/api/v1/query_range?' + urllib.parse.urlencode({'query': '{job="p0v3-acceptance",run="' + run_id + '"}',
                'start': str(stamp - 60_000_000_000), 'end': str(time.time_ns()), 'limit': '20'})
        def logs_found(role='loki', prefix=''):
            data = request(role, prefix + log_path())
            return any(value[1] == message for stream in data['data']['result'] for value in stream['values'])
        await_result(logs_found)
        assert logs_found('grafana', '/api/datasources/proxy/uid/p0-loki')
        receipt.update(alloyToLokiReadbackVerified=True, grafanaLokiQueryVerified=True)

        receipt['phase'] = 'alertmanager'
        now = datetime.datetime.now(datetime.timezone.utc)
        request('alertmanager', '/api/v2/alerts', [{'labels': {'alertname': 'P0PrivateAcceptance', 'run': run_id},
                'annotations': {'summary': 'Private receiver only'}, 'startsAt': now.isoformat(),
                'endsAt': (now + datetime.timedelta(minutes=10)).isoformat()}])
        await_result(lambda: any(a['labels'].get('run') == run_id for a in request('alertmanager', '/api/v2/alerts')))
        receipt['alertmanagerApiVerified'] = True

        receipt['phase'] = 'dashboard'
        uid = 'p0-' + uuid.uuid4().hex[:12]
        created = request('grafana', '/api/dashboards/db', {'dashboard': {'uid': uid,
            'title': 'Private lifecycle check ' + run_id, 'schemaVersion': 41, 'panels': [{
                'id': 1, 'type': 'timeseries', 'title': 'Scrape health', 'datasource': {'type': 'prometheus', 'uid': 'p0-prometheus'},
                'targets': [{'refId': 'A', 'expr': 'up'}], 'gridPos': {'x': 0, 'y': 0, 'w': 12, 'h': 8}}]}, 'overwrite': False})
        assert created['uid'] == uid
        receipt['phase'] = 'restart'
        stopped = runtime('stop-private')
        assert all(p['state'] == 'exited' and p['exitCode'] in (0, 143) for p in stopped)
        runtime('apply-private')
        await_result(all_up)
        await_result(logs_found)
        assert request('grafana', '/api/dashboards/uid/' + uid)['dashboard']['uid'] == uid
        assert logs_found('grafana', '/api/datasources/proxy/uid/p0-loki')
        receipt.update(passed=True, phase='complete', cleanStopRestartVerified=True, lokiLogPersisted=True,
                       grafanaDashboardPersisted=True, encryptedRestoreTest=False, browserJourney=False,
                       outwardAlertReceivers=False)
        print(json.dumps(receipt, indent=2))
    finally:
        fd = os.open(directory / 'receipt.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as out:
            json.dump(receipt, out, indent=2)
            out.flush()
            os.fsync(out.fileno())


if __name__ == '__main__':
    main()
