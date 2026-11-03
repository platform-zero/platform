#!/usr/bin/env python3
"""Native mTLS exporter -> Prometheus, live synthetic metrics, alerting and persisted history.
No host telemetry mounts, outward receivers or full-stack acceptance claims.
"""
if not __debug__:
    raise SystemExit('Optimized Python disables safety checks; refusing effects')
import argparse
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import time
import urllib.parse
import uuid
from pathlib import Path
from probe_receipt import private_receipt

spec = importlib.util.spec_from_file_location('bao_helpers', Path(__file__).with_name('test-private-openbao.py'))
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--name', default='node-metrics-r2'); parser.add_argument('--supervised', action='store_true'); args = parser.parse_args()
    name = args.name; assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    source = B.BASE / name; manifest = B.BASE / (name + '.json')
    assert source.resolve() == source and source.stat().st_mode & 0o777 == 0o700
    deployment = json.loads(manifest.read_text())
    assert deployment['name'] == name and {p['id'] for p in deployment['processes']} == {'metrics-init', 'node', 'prometheus'}
    node = next(p for p in deployment['processes'] if p['id'] == 'node')
    assert node['image'] == 'localhost/p0v3-node-exporter@sha256:daf70dc167702888cd9d949edab429eda1d3abb92a81d788f8bb427711b28a96'
    assert '--collector.disable-defaults' in node['command'] and '--collector.textfile' in node['command']
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-node-' + uuid.uuid4().hex[:12]); directory.mkdir(mode=0o700)
    receipt = {'id': directory.name, 'deployment': name, 'manifestSha256': hashlib.sha256(manifest.read_bytes()).hexdigest(), 'passed': False, 'fullStackAcceptance': False, 'hostMonitoring': False, 'encryptedRecovery': False, 'phase': 'startup'}
    run_id = uuid.uuid4().hex; filename = 'probe-' + run_id + '.prom'; badfile = 'invalid-' + run_id + '.prom'; badbody = b'this is not prometheus exposition !!!\n'
    invalid_attempted = False; remove_attempted = False
    def exec_node(command, data=None):
        return subprocess.run(B.P + ['exec', '-i', 'p0v3-live-' + name + '-node', *command], input=data, capture_output=True, timeout=30)
    def runtime(action, label):
        r = subprocess.run([str(B.CLI), 'runtime', action, str(manifest)], capture_output=True, timeout=600, env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        B.private_write(directory / (label + '.json'), {'stdout': r.stdout.decode(), 'stderr': r.stderr.decode()})
        assert r.returncode == 0, 'Lifecycle failed; protected diagnostics retained'
    def inspect(role):
        data = json.loads(subprocess.run(B.P + ['inspect', 'p0v3-live-' + name + '-' + role], capture_output=True, check=True).stdout)[0]
        network = 'p0v3-live-' + name + '-net'
        assert data['State']['Running'] and not data['HostConfig']['PortBindings'] and set(data['NetworkSettings']['Networks']) == {network}
        assert data['Config']['Labels']['io.p0v3.private-deployment'] == name
        address = data['NetworkSettings']['Networks'][network]['IPAddress']; assert ipaddress.ip_address(address).is_private
        return data, address
    def write_metric(file, payload, previous=None):
        assert re.fullmatch(r'(probe|invalid)-[a-f0-9]{32}\.prom', file)
        label = file + '-' + hashlib.sha256(payload).hexdigest()[:12]
        B.private_write(directory / (label + '-intent.json'), {'file': file, 'sha256': hashlib.sha256(payload).hexdigest()})
        guard = 'test ! -e "$1"; test ! -L "$1"' if previous is None else 'test -f "$1"; test ! -L "$1"; test "$(sha256sum "$1" | cut -d " " -f 1)" = "$2"'
        script = 'set -eu; umask 077; ' + guard + '; test ! -e "$1.tmp"; test ! -L "$1.tmp"; cat > "$1.tmp"; sync; mv "$1.tmp" "$1"; sync'
        r = exec_node(['/bin/sh', '-c', script, 'sh', '/synthetic/' + file, previous or ''], payload)
        assert r.returncode == 0, 'Synthetic write failed; never automatically replayed'
        return hashlib.sha256(payload).hexdigest()
    def remove_bad():
        nonlocal remove_attempted
        path = '/synthetic/' + badfile
        absent = exec_node(['/bin/sh', '-c', 'test ! -e "$1" && test ! -L "$1"', 'sh', path])
        if absent.returncode == 0: return
        assert exec_node(['/bin/sh', '-c', 'test -f "$1" && test ! -L "$1"', 'sh', path]).returncode == 0
        r = exec_node(['/bin/sha256sum', path]); assert r.returncode == 0 and r.stdout.decode().split()[0] == hashlib.sha256(badbody).hexdigest()
        assert not remove_attempted, 'Uncertain removal still visible; manual reconciliation required'
        remove_attempted = True
        assert exec_node(['/bin/rm', '--', path]).returncode == 0
        assert exec_node(['/bin/sh', '-c', 'test ! -e "$1" && test ! -L "$1"', 'sh', path]).returncode == 0
    with private_receipt(receipt, lambda value: B.private_write(directory / 'receipt.json', value)):
        try:
            runtime('apply-private', 'apply')
            before = {role: inspect(role)[0] for role in ('node', 'prometheus')}
            node_address = inspect('node')[1]; prom_address = inspect('prometheus')[1]
            ctx = ssl.create_default_context(cafile=str(source / 'ca.pem')); ctx.load_cert_chain(str(source / 'admin.pem'), str(source / 'admin-key.pem'))
            leaf = ssl.PEM_cert_to_DER_cert((source / 'node.pem').read_text())
            def metrics(context=ctx, path='/metrics', hostname='node', expected=200):
                with socket.create_connection((node_address, 9100), timeout=10) as raw, context.wrap_socket(raw, server_hostname=hostname) as tls:
                    assert tls.getpeercert(binary_form=True) == leaf
                    tls.sendall(('GET ' + path + ' HTTP/1.1\r\nHost: node:9100\r\nConnection: close\r\n\r\n').encode())
                    with http.client.HTTPResponse(tls) as response:
                        response.begin(); body = response.read(1048577); assert len(body) <= 1048576 and response.status == expected
                        return body.decode()
            def api(path):
                connection = http.client.HTTPConnection(prom_address, 9090, timeout=10)
                try:
                    connection.request('GET', path); response = connection.getresponse(); content = response.read(1048577)
                    assert response.status == 200 and len(content) <= 1048576
                    data = json.loads(content); assert data['status'] == 'success'; return data['data']
                finally: connection.close()
            def query(expression, at=None):
                params = {'query': expression}
                if at is not None: params['time'] = str(at)
                return api('/api/v1/query?' + urllib.parse.urlencode(params))['result']
            def value(expression, expected):
                for _ in range(60):
                    result = query(expression)
                    if len(result) == 1 and float(result[0]['value'][1]) == expected: return result[0]
                    time.sleep(1)
                raise AssertionError('Native scrape/evaluation observation exhausted')
            receipt['phase'] = 'mutual-tls'
            text = metrics(); assert 'node_exporter_build_info{' in text and 'version="1.12.1"' in text
            assert 'p0v3_synthetic_probe{fixture="node-exporter"} 42' in text
            assert all(prefix not in text for prefix in ('node_cpu_seconds_total', 'node_memory_', 'node_filesystem_', 'node_network_', 'node_uname_info'))
            metrics(path='/metrics?collect%5B%5D=cpu', expected=400)
            for context, hostname in [(ssl.create_default_context(cafile=str(source / 'ca.pem')), 'node'), (ssl.create_default_context(), 'node'), (ctx, 'not-node')]:
                try: metrics(context, hostname=hostname)
                except ssl.SSLError: pass
                else: raise AssertionError('Invalid TLS authentication unexpectedly accepted')
            foreign_key = directory / 'foreign-key.pem'; foreign_cert = directory / 'foreign.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=foreign-client', '-addext', 'extendedKeyUsage=clientAuth', '-keyout', str(foreign_key), '-out', str(foreign_cert)], capture_output=True, check=True)
            foreign_key.chmod(0o600); foreign_cert.chmod(0o600)
            wrong = ssl.create_default_context(cafile=str(source / 'ca.pem')); wrong.load_cert_chain(str(foreign_cert), str(foreign_key))
            try: metrics(wrong)
            except ssl.SSLError: pass
            else: raise AssertionError('Untrusted client certificate accepted')
            target = api('/api/v1/targets')['activeTargets']; assert len(target) == 1 and target[0]['scrapeUrl'] == 'https://node:9100/metrics'
            value('up{job="private-node"}', 1); value('p0v3_synthetic_probe{job="private-node"}', 42)
            receipt['phase'] = 'live-metric-change'
            expression = 'p0v3_mutable_probe{run="' + run_id + '"}'
            def payload(n): return ('# HELP p0v3_mutable_probe Synthetic per-run gauge.\n# TYPE p0v3_mutable_probe gauge\np0v3_mutable_probe{run="' + run_id + '"} ' + str(n) + '\n').encode()
            previous = write_metric(filename, payload(42)); value(expression, 42)
            sample_time = float(query('timestamp(' + expression + ')')[0]['value'][1])
            write_metric(filename, payload(43), previous); value(expression, 43)
            receipt['phase'] = 'native-alert'
            invalid_attempted = True; write_metric(badfile, badbody)
            value('node_textfile_scrape_error{job="private-node"}', 1)
            value('ALERTS{alertname="PrivateTextfileInvalid",alertstate="firing",scope="synthetic-only"}', 1)
            alert_time = float(query('timestamp(node_textfile_scrape_error{job="private-node"})')[0]['value'][1])
            remove_bad(); invalid_attempted = False
            value('node_textfile_scrape_error{job="private-node"}', 0)
            for _ in range(60):
                if not query('ALERTS{alertname="PrivateTextfileInvalid",alertstate="firing"}'): break
                time.sleep(1)
            else: raise AssertionError('Synthetic alert did not resolve')
            receipt['phase'] = 'restart-history'
            journal = hashlib.sha256((source / 'runtime.jobs').read_bytes()).hexdigest()
            if args.supervised:
                unit = 'p0v3-private-' + name + '.service'; subprocess.run(['systemctl', 'is-enabled', '--quiet', unit], check=True)
                subprocess.run(['sudo', '-n', 'systemctl', 'restart', unit], check=True, timeout=600)
                subprocess.run(['systemctl', 'is-active', '--quiet', unit], check=True)
            else:
                runtime('stop-private', 'stop'); runtime('apply-private', 'restart')
            node_address = inspect('node')[1]; prom_address = inspect('prometheus')[1]
            assert 'p0v3_synthetic_probe{fixture="node-exporter"} 42' in metrics()
            value(expression, 43)
            assert float(query(expression, sample_time)[0]['value'][1]) == 42
            assert float(query('node_textfile_scrape_error{job="private-node"}', alert_time)[0]['value'][1]) == 1
            assert hashlib.sha256((source / 'runtime.jobs').read_bytes()).hexdigest() == journal
            for role in before:
                after = inspect(role)[0]; assert after['Id'] == before[role]['Id'] and after['State']['StartedAt'] != before[role]['State']['StartedAt']
            receipt.update(passed=True, phase='complete', nativeTlsAuthenticatedScrape=True, untrustedClientDenied=True, missingClientDenied=True, defaultTrustDenied=True, wrongHostnameDenied=True, disabledCollectorQueryDenied=True, noHostMetrics=True, liveGaugeChange=True, nativeAlertFiredAndResolved=True, nativeTsdbHistorySurvivedRestart=True, persistentFixture=True, initializerJournalUnchanged=True, supervised=args.supervised, sampleTime=sample_time, alertTime=alert_time)
        finally:
            if invalid_attempted: remove_bad()
    print(json.dumps(receipt))


if __name__ == '__main__': main()
