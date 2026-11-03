#!/usr/bin/env python3
"""Actual mTLS indexing/search, authorization denial and restart persistence; private fixtures only."""
import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import uuid

P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / 'platform/build/install/p0-v3-platform/bin/p0-v3-platform'
BASE = Path('/mnt/media/p0-v3/runtime-deployments')


def private_write(path, text):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as out:
        out.write(text)
        out.flush()
        os.fsync(out.fileno())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='opensearch-r2')
    name = parser.parse_args().name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    spec = json.loads((BASE / (name + '.json')).read_text())
    assert spec['name'] == name and {p['id'] for p in spec['processes']} == {'search-config-init', 'opensearch', 'search-security-init'}
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-search-' + uuid.uuid4().hex[:12])
    directory.mkdir(mode=0o700)
    index = directory.name
    receipt = {'id': index, 'deployment': name, 'scope': 'private-opensearch-not-full-stack', 'passed': False,
        'fullStackAcceptance': False, 'encryptedRestoreTest': False}
    address = ''

    def runtime(action):
        nonlocal address
        result = subprocess.run([str(CLI), 'runtime', action, str(BASE / (name + '.json'))], capture_output=True,
            text=True, timeout=900, env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0, 'Owned search lifecycle failed; state retained'
        if action != 'stop-private':
            data = json.loads(subprocess.check_output(P + ['inspect', 'p0v3-live-' + name + '-opensearch'], stderr=subprocess.DEVNULL))[0]
            assert data['Config']['Labels']['io.p0v3.private-deployment'] == name and data['State']['Running']
            assert set(data['NetworkSettings']['Networks']) == {'p0v3-live-' + name + '-net'}
            assert not data['HostConfig']['PortBindings']
            address = data['NetworkSettings']['Networks']['p0v3-live-' + name + '-net']['IPAddress']
            assert ipaddress.ip_address(address).is_private
        return json.loads(result.stdout.splitlines()[0])

    def api(method, path, body=None, identity='admin', expected=200):
        context = ssl.create_default_context(cafile=str(BASE / name / 'ca.pem'))
        if identity:
            context.load_cert_chain(str(BASE / name / (identity + '.pem')), str(BASE / name / (identity + '-key.pem')))
        with context.wrap_socket(socket.create_connection((address, 9200), timeout=10), server_hostname='opensearch') as connection:
            client = http.client.HTTPConnection('opensearch', 9200, timeout=15)
            client.sock = connection
            client.request(method, path, body=None if body is None else json.dumps(body), headers={'Content-Type': 'application/json'})
            response = client.getresponse()
            assert response.status == expected, 'Private search API status: ' + str(response.status)
            raw = response.read(2097153)
            assert len(raw) <= 2097152
            client.close()
            return json.loads(raw) if raw else None

    try:
        receipt['phase'] = 'tls-and-authorization'
        runtime('apply-private')
        assert api('GET', '/')['version']['distribution'] == 'opensearch'
        denied = False
        try:
            api('GET', '/', identity=None)
        except ssl.SSLError:
            denied = True
        assert denied, 'Client certificate was not required'
        assert api('GET', '/_cluster/health', identity='node')['status'] in ('yellow', 'green')
        api('PUT', '/' + index + '-denied', {}, identity='node', expected=403)
        api('GET', '/' + index + '-denied', expected=404)
        receipt['phase'] = 'index-and-query'
        assert api('PUT', '/' + index, {'settings': {'number_of_shards': 1, 'number_of_replicas': 0},
            'mappings': {'properties': {'text': {'type': 'text'}, 'rank': {'type': 'integer'}, 'category': {'type': 'keyword'}}}})['acknowledged']
        docs = {'a': {'text': 'Synthetic red comet', 'rank': 10, 'category': 'sky'},
                'b': {'text': 'Synthetic blue comet', 'rank': 30, 'category': 'sky'},
                'c': {'text': 'Synthetic green forest', 'rank': 40, 'category': 'land'}}
        for key, doc in docs.items():
            assert api('PUT', '/' + index + '/_doc/' + key + '?refresh=wait_for', doc, expected=201)['result'] == 'created'
        query = {'query': {'bool': {'must': [{'match': {'text': 'comet'}}], 'filter': [{'range': {'rank': {'gte': 20}}}]}}}
        hits = api('POST', '/' + index + '/_search', query)['hits']
        assert hits['total']['value'] == 1 and hits['hits'][0]['_id'] == 'b' and hits['hits'][0]['_source'] == docs['b']
        api('GET', '/' + index + '/_search', identity='node', expected=403)
        assert api('DELETE', '/' + index + '/_doc/c?refresh=wait_for')['result'] == 'deleted'
        jobs = hashlib.sha256((BASE / name / 'runtime.jobs').read_bytes()).hexdigest()
        receipt['phase'] = 'restart'
        assert all(p['exitCode'] in (0, 143) for p in runtime('stop-private'))
        runtime('apply-private')
        assert hashlib.sha256((BASE / name / 'runtime.jobs').read_bytes()).hexdigest() == jobs
        assert api('GET', '/' + index + '/_doc/b')['_source'] == docs['b']
        assert api('GET', '/' + index + '/_count')['count'] == 2
        assert api('POST', '/' + index + '/_search', query)['hits']['hits'][0]['_id'] == 'b'
        api('GET', '/' + index + '/_doc/c', expected=404)
        api('GET', '/' + index + '/_search', identity='node', expected=403)
        receipt.update(passed=True, phase='complete', index=index, caAndHostnameVerified=True, clientCertificateRequired=True,
            monitorCannotReadOrWriteIndexes=True, realIndexingAndFilteredSearch=True, deletionPersisted=True,
            searchAndDocumentsPersisted=True, initializationJournalUnchanged=True, browserJourney=False)
    finally:
        private_write(directory / 'receipt.json', json.dumps(receipt, indent=2))
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
