#!/usr/bin/env python3
"""Functional persistence test through the real Kotlin runtime; leaves the selected private services running.
Not an encrypted backup/restore or full-stack acceptance test.
"""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store',
     '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
CLI = Path(__file__).resolve().parents[1] / 'build/install/p0-v3-platform/bin/p0-v3-platform'


def command(args, data=None):
    result = subprocess.run(args, input=data, capture_output=True, text=True, timeout=180,
                            env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
    if result.returncode:
        raise RuntimeError('Private foundation command failed; inspect owned runtime logs')
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='foundation-r3')
    parser.add_argument('--canonical-core', action='store_true')
    args = parser.parse_args()
    name = args.name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    manifest = Path('/mnt/media/p0-v3/runtime-deployments') / (name + '.json')
    spec = json.loads(manifest.read_text())
    expected = {'postgres-init', 'postgres', 'valkey', 'ntfy'}
    if args.canonical_core:
        expected |= {'planka-db-init', 'planka-init', 'postgres-finalize', 'planka'}
    assert spec['name'] == name and {p['id'] for p in spec['processes']} == expected
    initializers = {p['id'] for p in spec['processes'] if p.get('oneShot', False)}
    run_id = 'p0v3-runtime-check-' + uuid.uuid4().hex[:12]
    receipts = Path('/mnt/media/p0-v3/image-acquisition-receipts') / run_id
    receipts.mkdir(mode=0o700)
    receipt = {'id': run_id, 'scope': 'persistent-private-foundation-not-full-stack', 'passed': False, 'deployment': name}
    container = lambda role: 'p0v3-live-' + name + '-' + role
    runtime = lambda action: json.loads(command([str(CLI), 'runtime', action, str(manifest)]).splitlines()[0])
    podman = lambda *args, data=None: command(P + list(args), data)
    valkey = lambda operation: podman('exec', container('valkey'), '/bin/sh', '-ec',
        'export REDISCLI_AUTH="$(sed -n \'s/^requirepass //p\' /etc/valkey/valkey.conf)"; valkey-cli ' + operation)
    root = manifest.parent / name
    hashes = lambda: {f: hashlib.sha256((root / f).read_bytes()).hexdigest() for f in ('postgres.env', 'valkey.conf')}
    try:
        before = hashes()
        runtime('apply-private')
        ids = {role: json.loads(podman('container', 'inspect', container(role)))[0]['Id']
               for role in ('postgres-init', 'postgres', 'valkey', 'ntfy')}
        marker = uuid.uuid4().hex
        sql = "CREATE SCHEMA IF NOT EXISTS p0v3_acceptance; CREATE TABLE IF NOT EXISTS p0v3_acceptance.runtime_checks (id text PRIMARY KEY, value text NOT NULL); "
        sql += "INSERT INTO p0v3_acceptance.runtime_checks VALUES ('" + run_id + "','" + marker + "'); CHECKPOINT;"
        podman('exec', '-i', container('postgres'), 'psql', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1', data=sql)
        assert valkey('SET ' + run_id + ' ' + marker) == 'OK'
        topic = run_id
        published = json.loads(podman('exec', container('ntfy'), 'wget', '-q', '-O', '-',
                                     '--post-data=' + marker, 'http://127.0.0.1:8080/' + topic))
        assert published['message'] == marker
        receipt.update(postgresCheckpointSucceeded=True, valkeyWriteSucceeded=True, ntfyPublishSucceeded=True)
        stopped = runtime('stop-private')
        assert all(p['state'] == 'exited' and p['exitCode'] == 0 for p in stopped)
        started = runtime('apply-private')
        assert all(p['state'] == ('exited' if p['id'] in initializers else 'running') for p in started)
        runtime('apply-private')  # A second apply must neither reinitialize data nor recreate containers.
        assert podman('exec', container('postgres'), 'psql', '-U', 'postgres', '-tAc',
                      "SELECT value FROM p0v3_acceptance.runtime_checks WHERE id='" + run_id + "'") == marker
        assert valkey('GET ' + run_id) == marker
        messages = [json.loads(line) for line in podman('exec', container('ntfy'), 'wget', '-q', '-O', '-',
                    'http://127.0.0.1:8080/' + topic + '/json?poll=1&since=all').splitlines()]
        assert any(m.get('id') == published['id'] and m.get('message') == marker for m in messages)
        assert before == hashes()
        assert ids == {role: json.loads(podman('container', 'inspect', container(role)))[0]['Id'] for role in ids}
        receipt.update(passed=True, cleanStopVerified=True, restartReadbackVerified=True,
                       idempotentApplyVerified=True, credentialsPreserved=True, encryptedRestoreTest=False)
        print(json.dumps(receipt, indent=2))
    finally:
        fd = os.open(receipts / 'receipt.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as out:
            json.dump(receipt, out, indent=2)
            out.flush()
            os.fsync(out.fileno())


if __name__ == '__main__':
    main()
