#!/usr/bin/env python3
"""Real MariaDB transaction/durability and Memcached protocol checks; not a backup/restore claim."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import uuid

P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
CLI = Path(__file__).resolve().parents[1] / 'build/install/p0-v3-platform/bin/p0-v3-platform'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--name', default='sql-cache')
    name = parser.parse_args().name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name)
    manifest = Path('/mnt/media/p0-v3/runtime-deployments') / (name + '.json')
    spec = json.loads(manifest.read_text())
    assert spec['name'] == name and {p['id'] for p in spec['processes']} == {'mariadb-init', 'mariadb', 'memcached'}
    nonce = uuid.uuid4().hex[:12]
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-sql-cache-' + nonce)
    directory.mkdir(mode=0o700)
    receipt = {'id': directory.name, 'scope': 'persistent-private-sql-cache-not-full-stack', 'passed': False}

    def runtime(action):
        result = subprocess.run([str(CLI), 'runtime', action, str(manifest)], capture_output=True, text=True, timeout=900,
            env={**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'})
        assert result.returncode == 0, 'Owned SQL/cache lifecycle failed'
        return json.loads(result.stdout.splitlines()[0])

    def sql(statement, password=True):
        command = 'MYSQL_PWD="$MARIADB_ROOT_PASSWORD" ' if password else ''
        command += 'mariadb --socket=/tmp/mysql.sock -u root --batch --skip-column-names'
        result = subprocess.run(P + ['exec', '-i', 'p0v3-live-' + name + '-mariadb', '/bin/sh', '-ec', command],
            input=statement, text=True, capture_output=True, timeout=30)
        if password:
            assert result.returncode == 0, 'Owned MariaDB SQL failed'
            return result.stdout.strip()
        assert result.returncode != 0, 'Passwordless root access must be denied'

    def cache(write=False):
        data = json.loads(subprocess.check_output(P + ['inspect', 'p0v3-live-' + name + '-memcached'], stderr=subprocess.DEVNULL))[0]
        assert data['Config']['Labels']['io.p0v3.private-deployment'] == name
        address = data['NetworkSettings']['Networks']['p0v3-live-' + name + '-net']['IPAddress']
        assert ipaddress.ip_address(address).is_private
        key, value = ('p0v3-' + nonce).encode(), ('private-' + nonce).encode()
        request = (b'set ' + key + b' 0 0 ' + str(len(value)).encode() + b'\r\n' + value + b'\r\n') if write else b''
        request += b'get ' + key + b'\r\nquit\r\n'
        with socket.create_connection((address, 11211), timeout=5) as client:
            client.sendall(request)
            output = b''
            while True:
                part = client.recv(4096)
                if not part:
                    break
                output += part
                assert len(output) < 65536
        if write:
            assert output.startswith(b'STORED\r\nVALUE ') and value + b'\r\nEND\r\n' in output
        else:
            assert output == b'END\r\n', 'Memcached is intentionally ephemeral, not durable user state'

    try:
        runtime('apply-private')
        receipt['phase'] = 'transactions'
        sql('SELECT 1;', password=False)
        assert sql("SELECT COUNT(*) FROM mysql.global_priv WHERE User = '' OR (User = 'root' AND Host <> 'localhost');") == '0'
        table = 'p0v3_acceptance.probe_' + nonce
        sql('CREATE DATABASE IF NOT EXISTS p0v3_acceptance; CREATE TABLE ' + table + ' (id INT PRIMARY KEY, value VARCHAR(64)) ENGINE=InnoDB; '
            "INSERT INTO " + table + " VALUES (1, 'committed-" + nonce + "'); START TRANSACTION; INSERT INTO " + table + " VALUES (2, 'rolled-back'); ROLLBACK;")
        assert sql('SELECT COUNT(*) FROM ' + table) == '1'
        cache(write=True)
        receipt['phase'] = 'restart'
        stopped = runtime('stop-private')
        assert all(p['exitCode'] in (0, 143) for p in stopped)
        runtime('apply-private')
        assert sql('SELECT value FROM ' + table + ' WHERE id=1') == 'committed-' + nonce
        assert sql('SELECT COUNT(*) FROM ' + table) == '1'
        cache()
        cache(write=True)
        receipt.update(passed=True, phase='complete', authenticatedSql=True, anonymousAndRemoteRootRemoved=True,
                       committedRowPersisted=True, rolledBackRowAbsent=True, memcachedProtocolVerified=True,
                       cacheColdRestartVerified=True, encryptedRestoreTest=False)
        print(json.dumps(receipt, indent=2))
    finally:
        fd = os.open(directory / 'receipt.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'w') as out:
            json.dump(receipt, out, indent=2)
            out.flush()
            os.fsync(out.fileno())


if __name__ == '__main__':
    main()
