#!/usr/bin/env python3
"""Existing native multi-user Hub fixture, authorization and clean restart proof; never creates notebooks."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import uuid
from probe_receipt import private_receipt

spec = importlib.util.spec_from_file_location('hub_diagnostic', Path(__file__).with_name('inspect-private-hub.py'))
D = importlib.util.module_from_spec(spec); spec.loader.exec_module(D)
H = D.H


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--name', default='jupyterhub-r8'); parser.add_argument('--supervised', action='store_true'); args = parser.parse_args()
    assert re.fullmatch('[a-z][a-z0-9-]{0,39}', args.name)
    os.umask(0o077)
    manifest, inputs = H.BASE / (args.name + '.json'), H.BASE / args.name
    fingerprint = hashlib.sha256(manifest.read_bytes()).hexdigest(); deployment = json.loads(manifest.read_text())
    assert {p['id'] for p in deployment['processes']} == {'alice', 'bob', 'hub', 'controller'}
    assert {v['id'] for v in deployment['volumes']} == {'alice', 'bob', 'hub'}
    directory = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-hub-' + uuid.uuid4().hex[:12]); directory.mkdir(mode=0o700)
    receipt = {'id': directory.name, 'deployment': args.name, 'manifestSha256': fingerprint, 'passed': False, 'fullStackAcceptance': False, 'createdNotebookThisRun': False, 'realOwnerOnboarding': False, 'encryptedRecovery': False, 'publicHttps': False, 'phase': 'audit'}
    def write(name, value):
        with (directory / name).open('wb') as stream:
            stream.write(value if isinstance(value, bytes) else (json.dumps(value, indent=2) + '\n').encode()); stream.flush(); os.fsync(stream.fileno())
    write('receipt.json', receipt)
    def runtime(action):
        result = subprocess.run([str(H.CLI), 'runtime', action, str(manifest)], env=dict(os.environ, JAVA_HOME='/usr/lib/jvm/java-21-openjdk-amd64'), capture_output=True, timeout=600)
        write(action + '-' + uuid.uuid4().hex[:8] + '.log', result.stdout + result.stderr)
        assert result.returncode == 0, 'Runtime lifecycle failed; protected logs retained'
    def containers(label):
        result = {}
        for role in ('alice', 'bob', 'hub', 'controller'):
            data = json.loads(subprocess.check_output(H.P + ['inspect', 'p0v3-live-' + args.name + '-' + role]))[0]
            assert data['State']['Running'] and not data['HostConfig']['PortBindings'] and not data['BoundingCaps'] and not data['EffectiveCaps']
            assert data['HostConfig']['ReadonlyRootfs'] and data['Config']['User'] == '1000:1000'
            assert set(data['NetworkSettings']['Networks']) == {'p0v3-live-' + args.name + '-net'}
            result[role] = {'id': data['Id'], 'start': data['State']['StartedAt'], 'image': data['Image']}
        write(label + '-containers.json', result); return result
    def hashes():
        names = {p['environmentFile'] for p in deployment['processes']} | {f['file'] for p in deployment['processes'] for f in p['files']} | {'runtime.owner'}
        return {name: hashlib.sha256((inputs / name).read_bytes()).hexdigest() for name in sorted(names)}
    def browser(label):
        for user in ('alice', 'bob'):
            result = subprocess.run(['python3', str(Path(__file__).with_name('inspect-private-hub.py')), '--name', args.name, '--user', user, '--mode', 'verify'], capture_output=True, timeout=380)
            write(label + '-' + user + '.log', result.stdout + result.stderr)
            assert result.returncode == 0, 'Native Hub browser verification failed'
            evidence = json.loads(result.stdout)
            assert evidence['foreignOriginHostAndLoginOriginNotebookDenied']
            assert evidence['manifestSha256'] == fingerprint and evidence['nativeSavedKernelOutput'] and evidence['crossUserDenied'] and evidence['hostOnlyPrefixedCookies'] and not evidence['createdNotebookThisRun']
            receipt[label + '-' + user] = evidence['id']
    def boundaries(label):
        settings = json.loads((inputs / 'hub-settings.json').read_text())
        files = {u: json.loads((Path('/mnt/media/p0-v3/hub-probe-state') / (fingerprint + '.' + u + '.intent')).read_text())['file'] for u in ('alice', 'bob')}
        code = '''import json,sys,ssl,urllib.request,urllib.error,sqlite3,hashlib
v=json.load(sys.stdin);context=ssl.create_default_context(cafile='/run/secrets/trust.pem');opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
def get(url,token,scheme='token'):
 req=urllib.request.Request(url,headers={'Authorization':scheme+' '+token})
 try:
  with opener.open(req,timeout=10) as r:return r.status,r.read(65537)
 except urllib.error.HTTPError as e:return e.code,e.read(65537)
for user in ('alice','bob'):
 other='bob' if user=='alice' else 'alice';token=v['settings']['servers'][user]['serverToken'];control=v['settings']['servers'][user]['controlKey']
 status,body=get('https://hub:8443/hub/api/user',token);assert status==200 and json.loads(body)['name']==user
 assert get('https://hub:8443/hub/api/users',token)[0]==403
 assert get('https://'+user+':8888/user/'+user+'/api/status',token)[0]==200
 assert get('https://'+other+':8888/user/'+other+'/api/contents/'+v['files'][other],token)[0]==403
 assert get('https://'+user+':8888/user/'+user+'/api/contents/'+v['files'][other],token)[0]==404
 status,body=get('https://'+user+':8444/state',control,'Bearer');assert status==200 and json.loads(body)['state']=='running'
 assert get('https://'+user+':8444/state','0'*64,'Bearer')[0]==403
connection=sqlite3.connect('file:/state/hub.sqlite?mode=ro',uri=True)
users=connection.execute('SELECT id,name,admin FROM users ORDER BY id').fetchall();assert {row[1] for row in users}=={'alice','bob','outsider'} and all(not row[2] for row in users)
from pathlib import Path
print(json.dumps({'users':users,'cookieSecretSha256':hashlib.sha256(Path('/state/cookie-secret').read_bytes()).hexdigest(),'serverTokenIdentityAndScopeDenied':True,'separateHomeContents':True,'authenticatedControl':True}))'''
        result = subprocess.run(H.P + ['exec', '-i', 'p0v3-live-' + args.name + '-controller', '/srv/venv/bin/python', '-c', code], input=json.dumps({'settings': settings, 'files': files}).encode(), capture_output=True, timeout=60)
        write(label + '-api.log', result.stdout + result.stderr); assert result.returncode == 0, 'Native authorization check failed'
        proof = json.loads(result.stdout)
        peer = '''import ssl,urllib.request,urllib.error
from pathlib import Path
assert not Path('/run/secrets/hub-settings.json').exists()
try:
 urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile='/run/secrets/trust.pem'))).open('https://alice:8444/health',timeout=8)
except (urllib.error.URLError,ConnectionError,ssl.SSLError):pass
else:raise AssertionError('Peer reached lifecycle controller')
print('peer-control-denied')'''
        result = subprocess.run(H.P + ['exec', 'p0v3-live-' + args.name + '-bob', '/opt/conda/bin/python', '-c', peer], capture_output=True, timeout=20)
        write(label + '-peer.log', result.stdout + result.stderr); assert result.returncode == 0 and result.stdout == b'peer-control-denied\n'
        proof['peerControlDenied'] = True; write(label + '-authorization.json', proof); return proof
    with private_receipt(receipt, lambda value: write('receipt.json', value)):
        runtime('status-private'); before = containers('before'); frozen = hashes(); write('frozen-inputs.json', frozen)
        receipt['phase'] = 'before-restart'; browser('before'); security = boundaries('before')
        receipt['phase'] = 'restart'
        if args.supervised:
            unit = 'p0v3-private-' + args.name + '.service'
            subprocess.run(['systemctl', 'is-enabled', unit], capture_output=True, check=True, timeout=20)
            subprocess.run(['sudo', '-n', 'systemctl', 'stop', unit], capture_output=True, check=True, timeout=300)
            subprocess.run(['sudo', '-n', 'systemctl', 'start', unit], capture_output=True, check=True, timeout=600)
        else:
            runtime('stop-private'); runtime('apply-private')
        after = containers('after'); assert all(before[r]['id'] == after[r]['id'] and before[r]['start'] != after[r]['start'] for r in before)
        assert frozen == hashes() and fingerprint == hashlib.sha256(manifest.read_bytes()).hexdigest()
        receipt['phase'] = 'after-restart'; browser('after'); assert security == boundaries('after'); runtime('status-private')
        receipt.update(passed=True, phase='complete', daemonsRestarted=4, supervisedRestart=args.supervised, nativeUserIdsAndCookieSecretUnchanged=True, immutableInputsUnchanged=True, nativeKernelOutputAndCrossUserDenial=True)
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
