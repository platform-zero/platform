#!/usr/bin/env python3
"""Native SOGo fixture and restart proof. Explicit, exclusive creation; never replays a write."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import base64
import datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import uuid
from probe_receipt import private_receipt
from sogo_mail_safety import redact_diagnostics
from restored_sogo_fixture import fixture_hash

ROOT = Path(__file__).resolve().parents[2]
BASE = Path('/mnt/media/p0-v3/runtime-deployments')
P = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph', '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
CLI = ROOT / 'platform/build/install/p0-v3-platform/bin/p0-v3-platform'


def durable(path, value, exclusive=False):
    with path.open('x' if exclusive else 'w') as stream:
        json.dump(value, stream, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--name', default='sogo-r2'); parser.add_argument('--create', action='store_true'); parser.add_argument('--supervised', action='store_true'); parser.add_argument('--restored-from'); args = parser.parse_args()
    assert re.fullmatch('[a-z][a-z0-9-]{0,39}', args.name)
    os.umask(0o077)
    manifest, inputs = BASE / (args.name + '.json'), BASE / args.name
    fingerprint = hashlib.sha256(manifest.read_bytes()).hexdigest(); deployment = json.loads(manifest.read_text())
    roles = {p['id'] for p in deployment['processes']}
    base_roles = {'database-init', 'database', 'accounts-init', 'cache', 'sogod', 'groupware'}
    oracle_hash = fixture_hash(BASE, args.name, args.restored_from, mutating=args.create)
    composite = roles == base_roles | {'mail', 'mail-init'} | ({'home-restore-check'} if args.restored_from else set())
    assert composite or roles == base_roles
    out = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-sogo-' + uuid.uuid4().hex[:12]); out.mkdir(mode=0o700)
    receipt = {'id': out.name, 'deployment': args.name, 'manifestSha256': fingerprint, 'passed': False, 'fullStackAcceptance': False, 'realOwnerOnboarding': False, 'encryptedRecovery': False, 'mailIntegration': False, 'publicHttps': False, 'phase': 'audit'}
    def runtime(action):
        r = subprocess.run([str(CLI), 'runtime', action, str(manifest)], env=dict(os.environ, JAVA_HOME='/usr/lib/jvm/java-21-openjdk-amd64'), capture_output=True, timeout=600)
        (out / (action + '-' + uuid.uuid4().hex[:8] + '.log')).write_bytes(r.stdout + r.stderr)
        assert r.returncode == 0, 'Runtime failed; protected logs retained'
    def containers():
        result = {}
        for process in deployment['processes']:
            if process.get('oneShot', False):
                continue
            s = json.loads(subprocess.check_output(P + ['inspect', 'p0v3-live-' + args.name + '-' + process['id']]))[0]
            assert s['State']['Running'] and not s['HostConfig']['PortBindings'] and not s['BoundingCaps'] and not s['EffectiveCaps']
            assert s['HostConfig']['ReadonlyRootfs'] and s['Config']['User'] == str(process['userId']) + ':' + str(process.get('groupId', process['userId']))
            assert 'no-new-privileges' in s['HostConfig']['SecurityOpt']
            assert set(s['NetworkSettings']['Networks']) == {'p0v3-live-' + args.name + '-net'}
            result[process['id']] = {'id': s['Id'], 'start': s['State']['StartedAt'], 'ip': next(iter(s['NetworkSettings']['Networks'].values()))['IPAddress']}
        return result
    def hashes():
        names = {p['environmentFile'] for p in deployment['processes'] if p.get('environmentFile')} | {f['file'] for p in deployment['processes'] for f in p.get('files', [])} | {'runtime.owner', 'runtime.jobs'}
        return {n: hashlib.sha256((inputs / n).read_bytes()).hexdigest() for n in sorted(names)}
    with private_receipt(receipt, lambda value: durable(out / 'receipt.json', value)):
        runtime('status-private'); before = containers(); frozen = hashes(); durable(out / 'before-containers.json', before); durable(out / 'input-hashes.json', frozen)
        context = ssl.create_default_context(cafile=str(inputs / 'ca.pem')); address = before['groupware']['ip']
        with socket.create_connection((address, 8443), timeout=10) as raw, context.wrap_socket(raw, server_hostname='groupware') as transport:
            assert transport.getpeercert(binary_form=True) == ssl.PEM_cert_to_DER_cert((inputs / 'web.pem').read_text())
        try:
            with socket.create_connection((address, 8443), timeout=10) as raw, ssl.create_default_context().wrap_socket(raw, server_hostname='groupware'):
                pass
        except ssl.SSLCertVerificationError:
            receipt['defaultTrustDenied'] = True
        else:
            raise AssertionError('Private certificate unexpectedly trusted globally')
        env = dict(line.split('=', 1) for line in (inputs / 'bootstrap.env').read_text().splitlines())
        def request(method, path, user=None, body=None, headers=None, password=None):
            assert path.startswith('/SOGo') or path == '/'
            fields = {'Host': 'groupware:8443', 'User-Agent': 'p0v3-native-DAV-fixture'}
            if user:
                assert user in ('alice', 'bob', 'outsider')
                fields['Authorization'] = 'Basic ' + base64.b64encode((user + ':' + (password if password is not None else env[user.upper() + '_PASSWORD'])).encode()).decode()
            fields.update(headers or {})
            with socket.create_connection((address, 8443), timeout=20) as raw, context.wrap_socket(raw, server_hostname='groupware') as transport:
                client = http.client.HTTPConnection('groupware', 8443, timeout=20); client.sock = transport
                client.request(method, path, body, fields); response = client.getresponse(); data = response.read(1048577)
                assert len(data) <= 1048576
                return response.status, dict((k.lower(), v) for k, v in response.getheaders()), data
        assert request('GET', '/SOGo/', headers={'Host': 'foreign.invalid'})[0] == 421
        assert request('GET', '/SOGo/', headers={'Origin': 'https://foreign.invalid'})[0] == 403
        if not composite:
            assert request('GET', '/SOGo/so/alice/Mail/')[0] == 503
        receipt['standaloneMailRouteDisabled'] = not composite
        assert request('PROPFIND', '/SOGo/dav/alice/Calendar/', headers={'Depth': '0', 'x-webobjects-remote-user': 'alice'})[0] == 401
        assert request('PROPFIND', '/SOGo/dav/alice/Calendar/', 'alice', headers={'Depth': '0'}, password='wrong-fixture-password')[0] == 401
        receipt['originHostProxyAuthAndWrongPasswordDenied'] = True
        state_root = Path('/mnt/media/p0-v3/sogo-probe-state'); state_root.mkdir(mode=0o700, exist_ok=True)
        assert state_root.resolve() == state_root and state_root.stat().st_uid == os.getuid() and state_root.stat().st_mode & 0o777 == 0o700
        fixture = state_root / (oracle_hash + '.fixture.json')
        if args.create:
            durable(fixture, {'manifestSha256': fingerprint, 'nonce': uuid.uuid4().hex[:12], 'day': datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d')}, exclusive=True)
        assert not fixture.is_symlink() and fixture.stat().st_uid == os.getuid() and fixture.stat().st_mode & 0o777 == 0o600 and fixture.stat().st_size < 8192
        values = json.loads(fixture.read_text()); assert values['manifestSha256'] == oracle_hash and re.fullmatch('[a-f0-9]{12}', values['nonce']) and re.fullmatch('[0-9]{8}', values['day'])
        nonce, day = values['nonce'], values['day']; event = '/SOGo/dav/alice/Calendar/personal/' + nonce + '.ics'; contact = '/SOGo/dav/alice/Contacts/personal/' + nonce + '.vcf'
        ics = ('BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//P0V3//Synthetic fixture//EN\r\nBEGIN:VEVENT\r\nUID:p0v3-' + nonce + '@localhost.invalid\r\nDTSTAMP:' + day + 'T090000Z\r\nDTSTART:' + day + 'T100000Z\r\nDTEND:' + day + 'T110000Z\r\nSUMMARY:Private event ' + nonce + '\r\nDESCRIPTION:Synthetic original description\r\nCLASS:PRIVATE\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n').encode()
        updated = ics.replace(b'Synthetic original description', b'Synthetic updated description')
        vcf = ('BEGIN:VCARD\r\nVERSION:3.0\r\nUID:p0v3-' + nonce + '\r\nFN:Private contact ' + nonce + '\r\nN:' + nonce + ';Private;;;\r\nEMAIL:fixture-' + nonce + '@localhost.invalid\r\nNOTE:Synthetic contact only\r\nEND:VCARD\r\n').encode()
        def write_once(label, method, path, body, headers, expected):
            intent = state_root / (fingerprint + '.' + label + '.intent')
            durable(intent, {'manifestSha256': fingerprint, 'fixtureSha256': hashlib.sha256(fixture.read_bytes()).hexdigest(), 'method': method, 'path': path, 'bodySha256': hashlib.sha256(body).hexdigest(), 'headers': headers}, exclusive=True)
            status, response_headers, response = request(method, path, 'alice', body, headers)
            durable(Path(str(intent) + '.outcome'), {'status': status, 'bodySha256': hashlib.sha256(response).hexdigest()}, exclusive=True)
            assert status in expected, 'Native write failed; retained intent forbids replay'
            return status, response_headers, response
        if args.create:
            receipt['phase'] = 'create'
            assert request('GET', event, 'alice')[0] == 404 and request('GET', contact, 'alice')[0] == 404
            write_once('event-create', 'PUT', event, ics, {'Content-Type': 'text/calendar', 'If-None-Match': '*'}, {201})
            status, fields, body = request('GET', event, 'alice'); assert status == 200 and 'etag' in fields
            write_once('event-update', 'PUT', event, updated, {'Content-Type': 'text/calendar', 'If-Match': fields['etag']}, {204})
            status, fields, body = request('GET', event, 'alice'); assert status == 200 and b'Synthetic updated description' in body
            stale = '"p0-stale-' + nonce + '"'; assert stale != fields['etag']
            write_once('stale-version', 'PUT', event, updated, {'Content-Type': 'text/calendar', 'If-Match': stale}, {412})
            assert request('GET', event, 'alice')[2] == body
            write_once('contact-create', 'PUT', contact, vcf, {'Content-Type': 'text/vcard', 'If-None-Match': '*'}, {201})
        for label, method, path, body, expected_status in [('event-create', 'PUT', event, ics, 201), ('event-update', 'PUT', event, updated, 204), ('stale-version', 'PUT', event, updated, 412), ('contact-create', 'PUT', contact, vcf, 201)]:
            intent = state_root / (oracle_hash + '.' + label + '.intent'); outcome = Path(str(intent) + '.outcome')
            for file in (intent, outcome):
                assert not file.is_symlink() and file.stat().st_uid == os.getuid() and file.stat().st_mode & 0o777 == 0o600 and file.stat().st_size < 8192
            operation = json.loads(intent.read_text()); result = json.loads(outcome.read_text())
            assert operation['manifestSha256'] == oracle_hash and operation['fixtureSha256'] == hashlib.sha256(fixture.read_bytes()).hexdigest()
            assert operation['method'] == method and operation['path'] == path and operation['bodySha256'] == hashlib.sha256(body).hexdigest()
            assert result['status'] == expected_status
        receipt['durableWriteOutcomesAndStaleEtagDenialVerified'] = True
        def verify(label):
            result = {}
            for kind, path, expected in [('event', event, b'Synthetic updated description'), ('contact', contact, b'Synthetic contact only')]:
                status, headers, body = request('GET', path, 'alice'); assert status == 200 and expected in body and nonce.encode() in body
                result[kind] = {'sha256': hashlib.sha256(body).hexdigest(), 'etag': headers['etag']}; (out / (label + '-' + kind + '.body')).write_bytes(body)
                for user in ('bob', 'outsider'):
                    denied = request('GET', path, user); assert denied[0] in (403, 404) and expected not in denied[2]
                assert request('GET', path)[0] == 401
            durable(out / (label + '-objects.json'), result); return result
        def browser(label):
            directory = out / (label + '-browser'); directory.mkdir(mode=0o700)
            public = subprocess.check_output(['openssl', 'x509', '-in', str(inputs / 'web.pem'), '-pubkey', '-noout'])
            der = subprocess.run(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=public, capture_output=True, check=True).stdout
            data = json.loads(subprocess.check_output(P + ['inspect', 'p0v3-live-' + args.name + '-groupware']))[0]
            values = {'address': address, 'pin': base64.b64encode(hashlib.sha256(der).digest()).decode(), 'directory': str(directory), 'nonce': nonce, 'day': day, 'password': env['ALICE_PASSWORD']}
            cache = Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1')
            jars = [jar for artifact in ('driver', 'driver-bundle', 'playwright') for jar in (cache / ('com.microsoft.playwright/' + artifact + '/1.55.0')).glob('*/*.jar')] + list((cache / 'com.google.code.gson/gson/2.12.1').glob('*/*.jar'))
            assert len(jars) == 4
            with tempfile.TemporaryDirectory(prefix='sogo-', dir='/mnt/media/p0-v3/cache') as scratch:
                result = subprocess.run(['sudo', '-n', 'nsenter', '--target=' + str(data['State']['Pid']), '--net', '/usr/bin/setpriv', '--reuid=' + str(os.getuid()), '--regid=' + str(os.getgid()), '--clear-groups', '--no-new-privs', '/usr/bin/env', 'HOME=' + scratch, 'TMPDIR=' + scratch, '/usr/lib/jvm/java-21-openjdk-amd64/bin/java', '-Djava.io.tmpdir=' + scratch, '--class-path', ':'.join(map(str, jars)), str(ROOT / 'acceptance/scripts/SogoBrowserProbe.java')], input=json.dumps(values).encode(), capture_output=True, timeout=350)
                (directory / 'browser.log').write_text(redact_diagnostics(result.stderr, [v for k, v in env.items() if 'PASSWORD' in k]))
                assert result.returncode == 0, 'Native browser failed; protected evidence retained'
                proof = json.loads(result.stdout); assert proof['nativeCalendarAndContactUi'] and proof['secureHttpOnlySession'] and not proof['createdObjectsThisRun']
                durable(directory / 'proof.json', proof)
        def database_security(label):
            code = '''if not __debug__:raise SystemExit('Optimized Python refused')
import ctypes as C,json,sys,re,socket
v=json.load(sys.stdin);assert all(re.fullmatch('[a-f0-9]{64}',v[k]) for k in ('password','initializer'))
lib=C.CDLL('libpq.so.5')
for name,restype,argtypes in [('PQconnectdb',C.c_void_p,[C.c_char_p]),('PQstatus',C.c_int,[C.c_void_p]),('PQfinish',None,[C.c_void_p]),('PQexec',C.c_void_p,[C.c_void_p,C.c_char_p]),('PQresultStatus',C.c_int,[C.c_void_p]),('PQgetvalue',C.c_char_p,[C.c_void_p,C.c_int,C.c_int]),('PQresultErrorField',C.c_char_p,[C.c_void_p,C.c_int]),('PQclear',None,[C.c_void_p])]:
 f=getattr(lib,name);f.restype=restype;f.argtypes=argtypes
def connect(user,password,extra=''):
 return lib.PQconnectdb(('host=database dbname=sogo user='+user+' password='+password+' connect_timeout=5 '+extra).encode())
def query(connection,sql,denied=False):
 result=lib.PQexec(connection,sql.encode());assert result
 try:
  if denied:assert lib.PQresultStatus(result)==7 and lib.PQresultErrorField(result,ord('C'))==b'42501';return None
  assert lib.PQresultStatus(result)==2
  return lib.PQgetvalue(result,0,0).decode()
 finally:lib.PQclear(result)
connection=connect('sogo',v['password']);assert lib.PQstatus(connection)==0
try:
 assert query(connection,"SELECT bool_and(ssl) FROM pg_stat_ssl JOIN pg_stat_activity USING(pid) WHERE usename=current_user")=='t'
 assert query(connection,"SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole) FROM pg_roles WHERE rolname=current_user")=='t'
 assert query(connection,"SELECT rolcanlogin FROM pg_roles WHERE rolname='initializer'")=='f'
 assert query(connection,"SELECT has_table_privilege(current_user,'users','UPDATE')")=='f'
 identity=json.loads(query(connection,"SELECT json_build_object('count',count(*),'bcrypt',bool_and(c_password LIKE '$2a$12$%'),'hash',encode(digest(string_agg(c_uid||c_password,',' ORDER BY c_uid),'sha256'),'hex')) FROM users"));assert identity['count']==3 and identity['bcrypt']
 query(connection,'SELECT * FROM pg_authid',True)
 query(connection,'UPDATE users SET c_cn=c_cn WHERE FALSE',True)
finally:lib.PQfinish(connection)
for user,password,extra in [('initializer',v['initializer'],''),('sogo',v['password'],'sslmode=disable'),('sogo',v['password'],'sslrootcert=/etc/ssl/certs/ca-certificates.crt'),('sogo',v['password'],'host=foreign.invalid hostaddr='+v['database'])]:
 connection=connect(user,password,extra)
 try:assert lib.PQstatus(connection)!=0
 finally:lib.PQfinish(connection)
with socket.create_connection(('cache',11211),timeout=8) as stream:
 stream.sendall(b'stats'+bytes([13,10]));reader=stream.makefile('rb');stats={}
 for _ in range(128):
  line=reader.readline(8193);assert len(line)<=8192
  if line.strip()==b'END':break
  fields=line.split();assert len(fields)==3 and fields[0]==b'STAT';stats[fields[1]]=fields[2]
 else:raise AssertionError('Unbounded cache response')
 assert int(stats[b'cmd_get'])>0 and int(stats[b'cmd_set'])>0
print(json.dumps({'identity':identity,'scopedSqlRole':True,'nativeConnectionsTls':True,'initializerDenied':True,'plaintextWrongCaWrongHostnameDenied':True,'nativeCacheUsed':True}))'''
            result = subprocess.run(P + ['exec', '-i', 'p0v3-live-' + args.name + '-sogod', '/usr/bin/python3', '-c', code], input=json.dumps({'password': env['SOGO_PASSWORD'], 'initializer': env['PGPASSWORD'], 'database': containers()['database']['ip']}).encode(), capture_output=True, timeout=60)
            (out / (label + '-database.log')).write_bytes(result.stdout + result.stderr)
            assert result.returncode == 0, 'Database boundary check failed; protected evidence retained'
            return json.loads(result.stdout)
        receipt['phase'] = 'before-restart'; baseline = verify('before'); security = database_security('before'); browser('before')
        receipt['phase'] = 'restart'
        if args.supervised:
            unit = 'p0v3-private-' + args.name + '.service'
            subprocess.run(['systemctl', 'is-enabled', unit], capture_output=True, check=True, timeout=20)
            subprocess.run(['sudo', '-n', 'systemctl', 'stop', unit], capture_output=True, check=True, timeout=300)
            subprocess.run(['sudo', '-n', 'systemctl', 'start', unit], capture_output=True, check=True, timeout=600)
        else:
            runtime('stop-private'); runtime('apply-private')
        after = containers(); durable(out / 'after-containers.json', after)
        assert all(before[r]['id'] == after[r]['id'] and before[r]['start'] != after[r]['start'] for r in before)
        address = after['groupware']['ip']; assert frozen == hashes() and hashlib.sha256(manifest.read_bytes()).hexdigest() == fingerprint
        receipt['phase'] = 'after-restart'; assert baseline == verify('after'); assert security == database_security('after'); browser('after'); runtime('status-private')
        receipt.update(passed=True, phase='complete', nativeCalendarContactAndDenials=True, scopedDatabaseAndTlsDenials=True, unchangedBcryptIdentityRows=True, daemonsRestarted=len(before), immutableInputsAndInitializersUnchanged=True, supervisedRestart=args.supervised, createdFixtureThisRun=args.create, diagnosticOnly=False, browserJourney=True)
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
