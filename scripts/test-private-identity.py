#!/usr/bin/env python3
"""Actual optimized Keycloak/PostgreSQL onboarding over private browser HTTP.
Generated disposable identities only; no published ports or production realm mutation.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import uuid

P = ['sudo', '-n', 'podman', '--root=/mnt/media/p0-v3/release-runtime/graph',
     '--runroot=/run/p0-v3-release-runtime/store',
     '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
ROOT = Path('/mnt/media/p0-v3/image-acquisition-receipts')

def run(*args, data=None, timeout=90):
    r = subprocess.run(P + list(args), input=data, text=True, capture_output=True, timeout=timeout)
    if r.returncode:
        raise RuntimeError('Identity command failed (exit ' + str(r.returncode) + '): ' + r.stderr[-1500:])
    return r.stdout.strip()

def pinned(product):
    d = json.loads((ROOT / (product + '.json')).read_text())
    actual = json.loads(run('image', 'inspect', d['pinnedImage']))[0]
    assert actual['Id'] == d['imageId']
    return d['pinnedImage']

def private_file(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(content)
        f.flush()
        os.fsync(f.fileno())

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--chromium', action='store_true', help='Run the actual Playwright Chromium journey instead of the HTTP form driver')
    options = parser.parse_args()
    prefix = 'p0v3-identity-' + uuid.uuid4().hex[:12]
    network, db, keycloak, client = [prefix + suffix for suffix in ('-net', '-db', '-kc', '-client')]
    volume = prefix + '-data'
    files = ROOT / prefix
    files.mkdir(mode=0o700)
    pg_password, app_password = secrets.token_hex(32), secrets.token_hex(32)
    temporary, permanent = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    private_file(files / 'db.env', 'POSTGRES_PASSWORD=' + pg_password + '\n')
    private_file(files / 'keycloak.env', '\n'.join([
        'KC_DB_URL=jdbc:postgresql://' + db + ':5432/keycloak', 'KC_DB_USERNAME=keycloak',
        'KC_DB_PASSWORD=' + app_password, 'KC_HTTP_ENABLED=true', 'KC_HOSTNAME=http://' + keycloak + ':8080']) + '\n')
    realm = {'realm': 'p0v3', 'enabled': True, 'sslRequired': 'none', 'registrationAllowed': False,
        'clients': [{'clientId': 'onboarding-probe', 'enabled': True, 'publicClient': True,
            'standardFlowEnabled': True, 'directAccessGrantsEnabled': True,
            'redirectUris': ['http://127.0.0.1:18765/callback'],
            'attributes': {'pkce.code.challenge.method': 'S256'}}],
        'users': [{'username': 'new-human', 'enabled': True, 'emailVerified': True,
            'email': 'new-human@example.invalid', 'firstName': 'Test', 'lastName': 'Human',
            'requiredActions': ['UPDATE_PASSWORD', 'CONFIGURE_TOTP'],
            'credentials': [{'type': 'password', 'value': temporary, 'temporary': True}]}]}
    private_file(files / 'realm.json', json.dumps(realm))
    # The parent stays mode 0700; only the explicitly bound file is readable by container UID 1000.
    os.chmod(files / 'realm.json', 0o444)
    containers = []
    networks = []
    receipt = {'id': prefix, 'scope': 'private-keycloak-postgres-component-not-full-stack', 'passed': False,
               'databaseVolume': volume}
    try:
        run('network', 'create', '--internal', network)
        networks.append(network)
        subnet = json.loads(run('network', 'inspect', network))[0]['subnets'][0]['subnet']
        import ipaddress
        ipaddress.ip_network(subnet)
        def start_database(name, data_volume, isolated_network=network, isolated_subnet=subnet):
            run('volume', 'create', data_volume)
            run('run', '--rm', '--pull=never', '--network=none', '--read-only',
                '--cap-drop=all', '--security-opt=no-new-privileges', '--user=999:999',
                '--tmpfs=/tmp:rw,nosuid,nodev,size=64m', '--volume', data_volume + ':/var/lib/postgresql/data:U',
                '--env-file', str(files / 'db.env'), '--entrypoint', '/bin/sh', pinned('postgres'), '-ec',
                'umask 077; printf "%s" "$POSTGRES_PASSWORD" > /tmp/pw; '
                '/usr/lib/postgresql/17/bin/initdb -D /var/lib/postgresql/data --username=postgres '
                '--pwfile=/tmp/pw --auth-host=scram-sha-256 --auth-local=trust; '
                'printf "host keycloak keycloak %s scram-sha-256\\n" "$1" >> /var/lib/postgresql/data/pg_hba.conf', 'init', isolated_subnet)
            run('run', '-d', '--name', name, '--pull=never', '--network', isolated_network, '--read-only',
                '--cap-drop=all', '--security-opt=no-new-privileges', '--user=999:999',
                '--tmpfs=/tmp:rw,nosuid,nodev,size=64m', '--tmpfs=/var/run/postgresql:rw,mode=1777,size=16m',
                '--volume', data_volume + ':/var/lib/postgresql/data:U', '--entrypoint', '/usr/lib/postgresql/17/bin/postgres',
                pinned('postgres'), '-D', '/var/lib/postgresql/data', '-c', 'listen_addresses=*')
            containers.append(name)
            for _ in range(50):
                try:
                    run('exec', name, 'pg_isready', '-U', 'postgres', timeout=5)
                    break
                except RuntimeError:
                    time.sleep(1)
            else:
                raise RuntimeError('PostgreSQL readiness failed')
            run('exec', '-i', name, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', data=
                "CREATE ROLE keycloak LOGIN PASSWORD '" + app_password + "';\nCREATE DATABASE keycloak OWNER keycloak;\n")
        start_database(db, volume)
        kc_info = json.loads(run('image', 'inspect', 'localhost/p0v3-keycloak:candidate-1'))[0]
        kc_image = kc_info['Id']
        receipt['keycloakImageId'] = kc_image
        run('run', '-d', '--name', keycloak, '--pull=never', '--network', network, '--read-only',
            '--cap-drop=all', '--security-opt=no-new-privileges', '--user=1000:0',
            '--tmpfs=/tmp:rw,nosuid,nodev,size=64m', '--tmpfs=/opt/keycloak/data:rw,mode=1777,size=128m',
            '--volume', str(files / 'realm.json') + ':/opt/keycloak/data/import/p0v3-realm.json:ro',
            '--env-file', str(files / 'keycloak.env'), kc_image, 'start', '--optimized', '--import-realm')
        containers.append(keycloak)
        run('run', '-d', '--name', client, '--pull=never', '--network', network, '--read-only',
            '--sysctl=net.ipv4.ip_forward=0', '--cap-drop=all', '--security-opt=no-new-privileges', '--tmpfs=/tmp:rw,nosuid,nodev,size=64m',
            '--entrypoint', '/bin/sleep', pinned('jupyter-notebook'), '900')
        containers.append(client)
        last_readiness_error = ''
        for _ in range(90):
            try:
                run('exec', client, 'python', '-c',
                    "import urllib.request; urllib.request.urlopen('http://" + keycloak + ":9000/health/ready',timeout=3).read()", timeout=8)
                break
            except RuntimeError as error:
                last_readiness_error = str(error)
                if run('inspect', '--format', '{{.State.Running}}', keycloak) != 'true':
                    raise RuntimeError('Keycloak exited before readiness; private logs retained')
                time.sleep(2)
        else:
            raise RuntimeError('Keycloak database-backed readiness failed: ' + last_readiness_error)
        browser = Path(__file__).with_name('identity-browser-probe.py').read_text()
        def probe(server_name, restored=False):
            inputs = {'base': 'http://' + server_name + ':8080',
                      'temporaryPassword': temporary, 'newPassword': permanent}
            if restored:
                inputs['mode'] = 'restored'
            if not options.chromium:
                return json.loads(run('exec', '-i', client, 'python', '-c', browser, data=json.dumps(inputs), timeout=120))
            client_info = json.loads(run('inspect', client))[0]
            assert client_info['Name'] == client and client_info['State']['Running']
            pid = int(client_info['State']['Pid'])
            assert pid > 1
            server_info = json.loads(run('inspect', server_name))[0]
            addresses = list(server_info['NetworkSettings']['Networks'].values())
            assert len(addresses) == 1
            inputs.update(address=addresses[0]['IPAddress'], directory=str(files))
            ipaddress.ip_address(inputs['address'])
            cache = Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1')
            jars = [jar for artifact in ('driver', 'driver-bundle', 'playwright')
                    for jar in sorted((cache / ('com.microsoft.playwright/' + artifact + '/1.55.0')).glob('*/*.jar'))]
            jars += sorted((cache / 'com.google.code.gson/gson/2.12.1').glob('*/*.jar'))
            assert len(jars) == 4, 'Expected pinned Playwright 1.55.0 and Gson 2.12.1'
            # Chromium's Unix-domain socket names must stay below sockaddr_un's path limit.
            scratch = Path('/mnt/media/p0-v3/cache') / ('cb-' + prefix[-12:])
            scratch.mkdir(mode=0o700, exist_ok=True)
            receipt['chromiumScratchDirectory'] = str(scratch)
            source = Path(__file__).resolve().parents[2] / 'acceptance/scripts/IdentityBrowserProbe.java'
            command = ['sudo', '-n', 'nsenter', '--target=' + str(pid), '--net',
                       '--setuid=' + str(os.getuid()), '--setgid=' + str(os.getgid()),
                       '/usr/bin/env', 'HOME=' + str(scratch), 'TMPDIR=' + str(scratch),
                       '/usr/lib/jvm/java-21-openjdk-amd64/bin/java', '-Djava.io.tmpdir=' + str(scratch),
                       '--class-path', ':'.join(map(str, jars)), str(source)]
            process = subprocess.run(command, input=json.dumps(inputs), text=True, capture_output=True, timeout=180)
            private_file(files / ('chromium-restored.log' if restored else 'chromium-onboarding.log'), process.stderr)
            assert process.returncode == 0, 'Chromium journey failed; private diagnostics retained'
            return json.loads(process.stdout)
        result = probe(keycloak)
        required = run('exec', db, 'psql', '-U', 'postgres', '-d', 'keycloak', '-tAc',
            "SELECT count(*) FROM user_required_action a JOIN user_entity u ON a.user_id=u.id WHERE u.username='new-human'")
        otp = run('exec', db, 'psql', '-U', 'postgres', '-d', 'keycloak', '-tAc',
            "SELECT count(*) FROM credential c JOIN user_entity u ON c.user_id=u.id WHERE u.username='new-human' AND c.type='otp'")
        assert required == '0' and otp == '1'
        receipt.update(result, databaseRequiredActionsCleared=True, databaseOtpCredentialPresent=True)
        # Backup is a consistent logical dump, never a copy of a live PostgreSQL data directory.
        dump = subprocess.run(P + ['exec', db, 'pg_dump', '-U', 'postgres', '-d', 'keycloak', '-Fc'],
                              capture_output=True, timeout=90)
        assert dump.returncode == 0 and dump.stdout.startswith(b'PGDMP')
        run('exec', db, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'keycloak', '-c',
            'CREATE TABLE p0v3_after_snapshot (id integer PRIMARY KEY); INSERT INTO p0v3_after_snapshot VALUES (1);')
        dump_path = files / 'keycloak.dump'
        fd = os.open(dump_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(dump.stdout)
            out.flush()
            os.fsync(out.fileno())
        backup_volume, config_volume, export_volume = prefix + '-kopia', prefix + '-kopia-config', prefix + '-export'
        for owned_volume in (backup_volume, config_volume, export_volume):
            run('volume', 'create', owned_volume)
        private_file(files / 'kopia.env', 'KOPIA_PASSWORD=' + secrets.token_urlsafe(48) + '\n')
        def kopia(*args):
            return run('run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=all',
                '--security-opt=no-new-privileges', '--user=' + str(os.getuid()) + ':' + str(os.getgid()),
                '--tmpfs=/tmp:rw,nosuid,nodev,size=64m', '--env=HOME=/tmp', '--env=KOPIA_CACHE_DIRECTORY=/tmp/cache',
                '--env-file', str(files / 'kopia.env'), '--volume', str(files) + ':/source:ro',
                '--volume', backup_volume + ':/repository:U', '--volume', config_volume + ':/config:U',
                '--volume', export_volume + ':/export:U', pinned('kopia'), '--disable-file-logging',
                '--config-file=/config/repository.config', *args, timeout=120)
        kopia('repository', 'create', 'filesystem', '--path=/repository', '--no-check-for-updates')
        snapshot = json.loads(kopia('snapshot', 'create', '--json', '/source/keycloak.dump'))
        snapshot_id = snapshot['rootEntry']['obj']
        kopia('snapshot', 'verify', '--verify-files-percent=100')
        kopia('snapshot', 'restore', '--no-overwrite-files', '--no-overwrite-directories', '--no-overwrite-symlinks',
              '--skip-owners', '--flush-files', snapshot_id, '/export/keycloak.dump')
        exported = subprocess.run(P + ['run', '--rm', '--pull=never', '--network=none', '--read-only', '--cap-drop=all',
            '--user=' + str(os.getuid()) + ':' + str(os.getgid()), '--volume', export_volume + ':/export:ro',
            '--entrypoint', '/bin/cat', pinned('caddy'), '/export/keycloak.dump'], capture_output=True, timeout=60)
        assert exported.returncode == 0 and exported.stdout == dump.stdout, 'Encrypted dump restore differs from source'
        restored_db, restored_kc = prefix + '-restored-db', prefix + '-restored-kc'
        restored_volume = prefix + '-restored-data'
        restored_network = prefix + '-restored-net'
        run('network', 'create', '--internal', restored_network)
        networks.append(restored_network)
        restored_subnet = json.loads(run('network', 'inspect', restored_network))[0]['subnets'][0]['subnet']
        ipaddress.ip_network(restored_subnet)
        start_database(restored_db, restored_volume, restored_network, restored_subnet)
        run('network', 'connect', restored_network, client)
        source_kc_ip = json.loads(run('inspect', keycloak))[0]['NetworkSettings']['Networks'][network]['IPAddress']
        ipaddress.ip_address(source_kc_ip)
        isolation = subprocess.run(P + ['exec', restored_db, 'timeout', '3', 'bash', '-c',
            'exec 3<>/dev/tcp/' + source_kc_ip + '/7800'], capture_output=True, timeout=8)
        assert isolation.returncode in (1, 124), 'Restore can reach source cluster or isolation check failed'
        tables = run('exec', restored_db, 'psql', '-U', 'postgres', '-d', 'keycloak', '-tAc',
                     "SELECT count(*) FROM pg_tables WHERE schemaname='public'")
        assert tables == '0', 'Contaminated restore database'
        restore = subprocess.run(P + ['exec', '-i', restored_db, 'pg_restore', '-U', 'postgres', '-d', 'keycloak',
                                      '--exit-on-error', '--no-owner', '--role=keycloak'], input=exported.stdout,
                                 capture_output=True, timeout=90)
        assert restore.returncode == 0, 'Logical database restore failed'
        assert run('exec', restored_db, 'psql', '-U', 'postgres', '-d', 'keycloak', '-tAc',
                   "SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename='p0v3_after_snapshot'") == '0'
        assert run('exec', db, 'psql', '-U', 'postgres', '-d', 'keycloak', '-tAc',
                   'SELECT count(*) FROM p0v3_after_snapshot') == '1'
        private_file(files / 'restored-keycloak.env', (files / 'keycloak.env').read_text()
                     .replace(db + ':5432', restored_db + ':5432').replace(keycloak + ':8080', restored_kc + ':8080'))
        run('run', '-d', '--name', restored_kc, '--pull=never', '--network', restored_network, '--read-only',
            '--cap-drop=all', '--security-opt=no-new-privileges', '--user=1000:0',
            '--tmpfs=/tmp:rw,nosuid,nodev,size=64m', '--tmpfs=/opt/keycloak/data:rw,mode=1777,size=128m',
            '--env-file', str(files / 'restored-keycloak.env'), kc_image, 'start', '--optimized')
        containers.append(restored_kc)
        for _ in range(90):
            try:
                run('exec', client, 'python', '-c',
                    "import urllib.request; urllib.request.urlopen('http://" + restored_kc + ":9000/health/ready',timeout=3).read()", timeout=8)
                break
            except RuntimeError:
                if run('inspect', '--format', '{{.State.Running}}', restored_kc) != 'true':
                    raise RuntimeError('Restored Keycloak exited')
                time.sleep(2)
        else:
            raise RuntimeError('Restored Keycloak readiness failed')
        restored_result = probe(restored_kc, restored=True)
        receipt.update(restored_result, passed=True, restoredDatabaseVolume=restored_volume,
                       logicalDumpFile=str(dump_path), encryptedBackup=True, sourceMutationPreserved=True,
                       kopiaVolume=backup_volume, kopiaSnapshotId=snapshot_id, restoreNetworkIsolated=True)
        print(json.dumps(receipt, indent=2))
    finally:
        for name in reversed(containers):
            logs = subprocess.run(P + ['logs', name], capture_output=True, text=True, timeout=15)
            private_file(files / (name + '.log'), logs.stdout + logs.stderr)
            state = subprocess.run(P + ['inspect', '--format', '{{json .State}}', name], capture_output=True, text=True, timeout=15)
            private_file(files / (name + '-state.json'), state.stdout)
            subprocess.run(P + ['rm', '-f', name], capture_output=True, timeout=40)
        for owned_network in reversed(networks):
            subprocess.run(P + ['network', 'rm', owned_network], capture_output=True, timeout=40)
        private_file(files / 'receipt.json', json.dumps(receipt, indent=2) + '\n')

if __name__ == '__main__':
    main()
