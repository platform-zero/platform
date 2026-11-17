#!/usr/bin/python3
"""Distinct no-replay serving readback of the stopped dev owner component.

Uses only its retained PostgreSQL/Forgejo volumes and internal-only network. Does not
install Quadlets, export a port, enable Actions, grant production custody or qualify.
"""
if not __debug__:
    raise SystemExit('Optimized Python refused')
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from test_forgejo_pg_owner_native import ROOT, NET, DATABASE, STORE, PREFIX, INVENTORY, save, canonical, command, effect


def main():
    intent = ROOT / 'functional.intent.json'
    assert not intent.exists(), 'Original functional attempt exists; reconcile, do not replay'
    original = (ROOT / 'attempt.intent.json').read_bytes()
    completed = (ROOT / 'attempt.result.json').read_bytes()
    source = json.loads(completed)
    assert source['originalIntentSha256'] == hashlib.sha256(original).hexdigest()
    assert source['postgresStopped'] and source['ownerAccountListed'] and not source['ownerLoginAuthenticated']
    initResult = (ROOT / 'owner-init.result.json').read_bytes()
    assert json.loads(initResult)['exitCode'] == 0
    secret = ROOT / 'bootstrap/owner.result'
    contents = secret.read_bytes()
    prefix = b"generated random password is '"
    suffix = b"'\nNew user 'p0v3-bootstrap' has been successfully created!\n"
    assert contents.startswith(prefix) and contents.endswith(suffix) and len(contents[len(prefix):-len(suffix)]) == 64
    password = contents[len(prefix):-len(suffix)].decode('ascii')
    images = {i['product']: i for i in json.loads(INVENTORY.read_bytes())['images']}
    originalId = (ROOT / 'postgres-start.stdout').read_text().strip()
    assert re.fullmatch(r'[a-f0-9]{64}', originalId)
    details = command(['inspect', '--format', '{{.Id}} {{.Image}} {{.State.Status}} {{index .Config.Labels "io.p0v3.component-attempt"}}', originalId])
    assert details.returncode == 0 and details.stdout.decode().split() == [originalId, images['postgres-timescale']['imageId'], 'exited', 'forgejo-pg-owner-r1']
    network = command(['network', 'inspect', NET])
    assert network.returncode == 0 and len(network.stdout) <= 8192
    state = json.loads(network.stdout)[0]
    assert state['name'] == NET and state['internal'] is True
    env = (ROOT / 'roles.env').read_text().splitlines()
    roles = {part.split('=', 1)[0]: part.split('=', 1)[1] for part in env}
    assert set(roles) == {'FORGEJO_MIGRATION_PASSWORD', 'FORGEJO_RUNTIME_PASSWORD'}
    priorIni = (ROOT / 'app.ini').read_text()
    old = 'USER = forgejo_migrate\nPASSWD = ' + roles['FORGEJO_MIGRATION_PASSWORD'] + '\n'
    new = 'USER = forgejo\nPASSWD = ' + roles['FORGEJO_RUNTIME_PASSWORD'] + '\n'
    assert priorIni.count(old) == 1 and priorIni.count('JWT_SECRET = ') == 1
    prepared = priorIni.replace(old, new)
    assert 'INSTALL_LOCK = true' in prepared and 'ENABLED = false' in prepared
    oldEnv = (ROOT / 'forgejo.env').read_text()
    runtimeEnv = oldEnv.replace('PGUSER=forgejo_migrate\n', 'PGUSER=forgejo\n').replace(
        'PGPASSWORD=' + roles['FORGEJO_MIGRATION_PASSWORD'] + '\n',
        'PGPASSWORD=' + roles['FORGEJO_RUNTIME_PASSWORD'] + '\n')
    assert runtimeEnv != oldEnv and runtimeEnv.count('PGUSER=forgejo\n') == 1
    save(intent, canonical({'schemaVersion': 1, 'priorSuccessSha256': hashlib.sha256(completed).hexdigest(),
        'originalOwnerOutputSha256': hashlib.sha256(contents).hexdigest(), 'originalPostgresId': originalId,
        'network': NET, 'scope': 'isolated-serving-component-not-release', 'replay': False}))
    save(ROOT / 'runtime-app.ini', prepared.encode())
    save(ROOT / 'runtime.env', runtimeEnv.encode())
    postgres = effect('functional-postgres-resume', ['start', originalId], timeout=60)
    assert postgres == originalId
    ready = False
    for _ in range(50):
        probe = command(['exec', originalId, 'pg_isready', '-U', 'postgres'], timeout=10)
        if probe.returncode == 0:
            ready = True; break
        time.sleep(1)
    assert ready, 'original PostgreSQL resume uncertain; no retry'
    sql = ("set -eu\nexport PGPASSWORD=" + roles['FORGEJO_RUNTIME_PASSWORD'] +
        "\nexport PGSSLMODE=verify-full PGSSLROOTCERT=/tls/server.crt\n" +
        "psql -X -At -h postgres -U forgejo -d forgejo " +
        "-c 'SELECT current_user,(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())'\n")
    tls = effect('functional-runtime-tls', ['run', '--rm=false', '--name', NET + '-runtime-tls',
        '--network=' + NET, '--pull=never', '--memory=128m', '--user=999:999',
        '--volume=' + str(ROOT / 'tls') + ':/tls:ro', '-i', '--entrypoint=/bin/sh',
        images['postgres-timescale']['imageId'], '-s'], sql.encode())
    assert tls == 'forgejo|t', 'serving role not authenticated over pinned TLS'
    server = effect('functional-web-start', ['run', '-d', '--rm=false', '--name', NET + '-web',
        '--network=' + NET, '--pull=never', '--memory=1024m', '--pids-limit=256',
        '--read-only', '--tmpfs=/tmp:rw,nosuid,nodev,size=128m', '--user=1000:1000',
        '--volume=' + str(ROOT / 'data') + ':/data',
        '--volume=' + str(ROOT / 'runtime-app.ini') + ':/etc/forgejo/app.ini:ro',
        '--volume=' + str(ROOT / 'tls') + ':/tls:ro', '--env-file=' + str(ROOT / 'runtime.env'),
        '--entrypoint=/usr/local/bin/forgejo', images['forgejo']['imageId'], '--work-path', '/data',
        '--config', '/etc/forgejo/app.ini', 'web'], timeout=90)
    assert re.fullmatch(r'[a-f0-9]{64}', server)
    observed = command(['inspect', '--format', '{{.Id}} {{.Image}} {{.State.Status}} {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}', server])
    parts = observed.stdout.decode().split()
    assert observed.returncode == 0 and len(parts) == 4 and parts[:3] == [server, images['forgejo']['imageId'], 'running']
    address = parts[3]
    import ipaddress
    assert ipaddress.ip_address(address).is_private and not ipaddress.ip_address(address).is_loopback
    # Host bridge access remains internal-only; no published port, public DNS or external credential transport.
    health = None
    for _ in range(40):
        response = subprocess.run(['/usr/bin/curl', '--silent', '--show-error', '--max-time', '5',
            '--connect-timeout', '3', 'http://' + address + ':3000/api/healthz'], capture_output=True, timeout=8)
        if response.returncode == 0 and len(response.stdout) <= 2048 and b'"status":"pass"' in response.stdout.replace(b' ', b''):
            health = response.stdout; break
        time.sleep(1)
    assert health is not None, 'private app readiness uncertain; no web restart'
    save(ROOT / 'functional-health.json', health)
    token = base64.b64encode(b'p0v3-bootstrap:' + password.encode()).decode()
    config = ('silent\nshow-error\nmax-time = 20\nconnect-timeout = 5\n' +
              'header = "Authorization: Basic ' + token + '"\n' +
              'url = "http://' + address + ':3000/api/v1/user"\n').encode()
    save(ROOT / 'functional-auth.intent.json', canonical({'method': 'GET', 'path': '/api/v1/user',
        'ownerOutputSha256': hashlib.sha256(contents).hexdigest(), 'originalWebId': server,
        'configSha256': hashlib.sha256(config).hexdigest()}))
    response = subprocess.run(['/usr/bin/curl', '--config', '-'], input=config, capture_output=True,
                              env={'PATH': '/usr/bin:/bin', 'LANG': 'C'}, timeout=25)
    assert len(response.stdout) <= 100000 and len(response.stderr) <= 100000
    save(ROOT / 'functional-auth.stdout', response.stdout or b'\n')
    save(ROOT / 'functional-auth.stderr', response.stderr or b'\n')
    save(ROOT / 'functional-auth.result.json', canonical({'exitCode': response.returncode,
        'intentSha256': hashlib.sha256((ROOT / 'functional-auth.intent.json').read_bytes()).hexdigest(),
        'stdoutSha256': hashlib.sha256(response.stdout or b'\n').hexdigest()}))
    assert response.returncode == 0, 'original owner API authentication uncertain; do not retry'
    profile = json.loads(response.stdout)
    assert profile['login'] == 'p0v3-bootstrap' and profile['is_admin'] is True, 'native owner API identity mismatch'
    effect('functional-web-stop', ['stop', '--time=15', server], timeout=45)
    effect('functional-postgres-stop', ['stop', '--time=15', originalId], timeout=45)
    save(ROOT / 'functional.result.json', canonical({'schemaVersion': 1,
        'originalIntentSha256': hashlib.sha256(intent.read_bytes()).hexdigest(),
        'originalWebId': server, 'originalPostgresId': originalId, 'tlsRuntimeRole': True,
        'privateWebReadiness': True, 'originalBootstrapLogin': True, 'ownerIsAdmin': True,
        'webStopped': True, 'postgresStopped': True, 'networkInternal': True,
        'releaseCredentialCustody': False, 'kopiaRecovered': False, 'releaseQualified': False}))
    print('Isolated serving/owner API readback passed; retained stopped, no Kopia or release claim')

if __name__ == '__main__':
    main()
