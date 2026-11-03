#!/usr/bin/env python3
"""Private native social OAuth/streaming/direct-message journey, with no outward RSS/federation."""
import argparse
import base64
import hashlib
import http.client
import importlib.util
import ipaddress
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

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/media/p0-v3/runtime-deployments')
CLI=ROOT/'platform/build/install/p0-v3-platform/bin/p0-v3-platform'
P=['sudo','-n','podman','--remote=false','--root=/mnt/media/p0-v3/release-runtime/graph','--runroot=/run/p0-v3-release-runtime/store','--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
ENV={**os.environ,'JAVA_HOME':'/usr/lib/jvm/java-21-openjdk-amd64'}


def write(path,data):
    with os.fdopen(os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'w') as out:
        out.write(data);out.flush();os.fsync(out.fileno())


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--name',default='mastodon-r4')
    group=parser.add_mutually_exclusive_group();group.add_argument('--fixture',type=Path);group.add_argument('--verify-fixture',type=Path)
    parser.add_argument('--recovered-inputs',type=Path);parser.add_argument('--with-media',action='store_true');parser.add_argument('--supervised',action='store_true');args=parser.parse_args();name=args.name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}',name)
    directory=Path('/mnt/media/p0-v3/image-acquisition-receipts')/('p0v3-social-'+uuid.uuid4().hex[:12]);directory.mkdir(mode=0o700)
    receipt={'id':directory.name,'deployment':name,'passed':False,'fullStackAcceptance':False,'scope':'private-social-not-rss-publication',
             'outwardPosting':False,'publicHttpsTest':False,'ownerSsoTest':False}
    spec=json.loads((BASE/(name+'.json')).read_text());image=next(p['image'] for p in spec['processes'] if p['id']=='mastodon')
    ca=ssl.create_default_context(cafile=str(BASE/name/'ca.pem'))
    inputs={'directory':str(directory),'nonce':uuid.uuid4().hex[:12]}
    cache=Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1')
    jars=[j for a in ('driver','driver-bundle','playwright') for j in (cache/('com.microsoft.playwright/'+a+'/1.55.0')).glob('*/*.jar')]
    jars+=list((cache/'com.google.code.gson/gson/2.12.1').glob('*/*.jar'));assert len(jars)==4

    def runtime(action):
        r=subprocess.run([str(CLI),'runtime',action,str(BASE/(name+'.json'))],capture_output=True,env=ENV,timeout=1200)
        assert r.returncode==0,'Private social lifecycle failed; state retained'
        return json.loads(r.stdout.splitlines()[0])

    def audit():
        d=json.loads(subprocess.check_output(P+['inspect','p0v3-live-'+name+'-social']))[0]
        assert d['Config']['Labels']['io.p0v3.private-deployment']==name and d['State']['Running']
        assert not d['HostConfig']['PortBindings'] and set(d['NetworkSettings']['Networks'])=={'p0v3-live-'+name+'-net'}
        address=d['NetworkSettings']['Networks']['p0v3-live-'+name+'-net']['IPAddress'];assert ipaddress.ip_address(address).is_private
        inputs['address']=address
        return d,address

    def api(path,body):
        _,address=audit();payload=json.dumps(body).encode()
        with socket.create_connection((address,8443),timeout=20) as raw,ca.wrap_socket(raw,server_hostname='social') as tls:
            expected=ssl.PEM_cert_to_DER_cert((BASE/name/'web.pem').read_text());assert tls.getpeercert(binary_form=True)==expected
            receipt['certificateSha256']=hashlib.sha256(expected).hexdigest()
            tls.sendall(('POST '+path+' HTTP/1.1\r\nHost: social:8443\r\nContent-Type: application/json\r\nContent-Length: '+str(len(payload))+'\r\nConnection: close\r\n\r\n').encode()+payload)
            response=http.client.HTTPResponse(tls);response.begin();assert response.status==200,'Native application registration failed (status '+str(response.status)+')'
            return json.loads(response.read(1048576))

    def browser(label):
        d,_=audit()
        with tempfile.TemporaryDirectory(prefix='ms-',dir='/mnt/media/p0-v3/cache') as scratch:
            r=subprocess.run(['sudo','-n','nsenter','--target='+str(d['State']['Pid']),'--net','--setuid='+str(os.getuid()),'--setgid='+str(os.getgid()),
                '/usr/bin/env','HOME='+scratch,'TMPDIR='+scratch,'/usr/lib/jvm/java-21-openjdk-amd64/bin/java','-Djava.io.tmpdir='+scratch,
                '--class-path',':'.join(map(str,jars)),str(ROOT/'acceptance/scripts/MastodonBrowserProbe.java')],input=json.dumps(inputs),capture_output=True,text=True,timeout=900)
            safe=r.stderr
            for v in (inputs['ownerPassword'],inputs['readerPassword'],inputs['ownerApp']['client_secret'],inputs['readerApp']['client_secret']):safe=safe.replace(v,'[redacted]')
            write(directory/(label+'.log'),safe)
            assert r.returncode==0,'Native social browser failed; private diagnostics retained'
            result=json.loads(r.stdout);assert result['passed'] and not result['fullStackAcceptance'];return result

    reused=None
    fixture=args.fixture or args.verify_fixture
    if fixture:
        assert not fixture.is_symlink() and fixture.stat().st_uid==os.getuid() and fixture.stat().st_mode & 0o777==0o700
        source=fixture/'inputs.json'
        assert not source.is_symlink() and source.stat().st_uid==os.getuid() and source.stat().st_mode & 0o777==0o600
        previous=json.loads((fixture/'receipt.json').read_text())
        if previous['deployment']!=name:
            assert args.recovered_inputs is not None and json.loads((args.recovered_inputs/'source-spec.json').read_text())['name']==previous['deployment']
            # Existing target must match the constrained recovery recipe and every recovered input byte.
            check=subprocess.run([str(CLI),'runtime','prepare-mastodon-restore',str(ROOT/'platform/release/downloaded-candidate-inventory.json'),str(args.recovered_inputs),name],capture_output=True,env=ENV,timeout=120)
            assert check.returncode==0,'Recovered social recipe/input binding failed'
        reused=json.loads(source.read_text())
        if args.verify_fixture:
            assert previous['passed'] and previous['phase']=='complete' and not (fixture/'receipt-invalidated.json').exists() and re.fullmatch(r'[0-9]{1,32}',previous['statusId'])
            inputs.update(nonce=previous['fixtureNonce'],statusId=previous['statusId'])
        receipt['createdDirectMessage']=not bool(args.verify_fixture)
    inputs['withMedia']=args.with_media or bool(reused and reused.get('withMedia'))
    with private_receipt(receipt,lambda r:write(directory/'receipt.json',json.dumps(r,indent=2))):
        receipt['phase']='native-onboarding-and-direct-message';runtime('apply-private')
        for user in ('owner','reader'):
            r=subprocess.run(P+['run','--rm','--pull=never','--network=none','--read-only','--cap-drop=all','--security-opt=no-new-privileges','--security-opt=apparmor=p0v3-private-v1',
                '--user=991:991','--memory=128m','--pids-limit=64','--image-volume=ignore','--volume','p0v3-live-'+name+'-volume-bootstrap:/bootstrap:ro',
                '--entrypoint=/usr/local/bin/ruby',image,'-e','print File.read(ARGV[0])','/bootstrap/'+user+'.txt'],capture_output=True,text=True,timeout=60)
            assert r.returncode==0;inputs[user+'Password']=re.search(r'^New password: (\S+)$',r.stdout,re.M)[1]
            scopes='read:accounts read:statuses read:notifications'
            if user=='owner':
                scopes+=' write:statuses'
                if inputs['withMedia']:scopes+=' write:media'
            if reused:assert set(scopes.split())<=set(reused[user+'App']['fixture_scopes'].split()),'Fixture application lacks requested scopes; register a new fixture explicitly'
            app=reused[user+'App'] if reused else api('/api/v1/apps',{'client_name':'Private '+user+' '+inputs['nonce'],'redirect_uris':'https://social:8443/fixture-callback','scopes':scopes})
            app['fixture_scopes']=scopes;inputs[user+'App']=app
        public=subprocess.check_output(['openssl','x509','-in',str(BASE/name/'web.pem'),'-pubkey','-noout'])
        der=subprocess.run(['openssl','pkey','-pubin','-outform','DER'],input=public,capture_output=True,check=True).stdout
        inputs['spki']=base64.b64encode(hashlib.sha256(der).digest()).decode()
        write(directory/'inputs.json',json.dumps(inputs))
        receipt.update(browser('create'));inputs['statusId']=receipt['statusId']
        jobs=hashlib.sha256((BASE/name/'runtime.jobs').read_bytes()).hexdigest()
        receipt['phase']='clean-restart-and-readback'
        if args.supervised:
            unit_path=Path('/etc/systemd/system')/('p0v3-private-'+name+'.service')
            assert not unit_path.is_symlink() and unit_path.stat().st_uid==0 and unit_path.stat().st_mode & 0o777==0o644
            unit=unit_path.read_text();manifest_hash=hashlib.sha256((BASE/(name+'.json')).read_bytes()).hexdigest()
            assert 'runtime boot-apply '+name+' '+manifest_hash in unit and 'User='+str(os.getuid()) in unit
            module_spec=importlib.util.spec_from_file_location('boot',ROOT/'platform/scripts/test-private-boot-supervision.py')
            boot=importlib.util.module_from_spec(module_spec);module_spec.loader.exec_module(boot);boot.NAMES=[name]
            before=boot.inventory();initializers=boot.initializer_states()
            subprocess.run(['sudo','-n','systemctl','restart',unit_path.name],capture_output=True,check=True,timeout=900)
            assert subprocess.run(['systemctl','is-active','--quiet',unit_path.name]).returncode==0
            assert subprocess.run(['systemctl','is-enabled','--quiet',unit_path.name]).returncode==0
            after=boot.inventory();assert before.keys()==after.keys() and all(before[k]['id']==after[k]['id'] and before[k]['started']!=after[k]['started'] for k in before)
            assert initializers==boot.initializer_states()
            receipt.update(pinnedSystemdRestartVerified=True,sameContainersNewStarts=True,initializerContainersNotReplayed=True,
                unitSha256=hashlib.sha256(unit.encode()).hexdigest(),hostRebootTest=False)
        else:
            assert all(p['exitCode'] in (0,143) for p in runtime('stop-private'))
            runtime('apply-private')
        assert hashlib.sha256((BASE/name/'runtime.jobs').read_bytes()).hexdigest()==jobs
        receipt.update(browser('verify'))
        receipt.update(passed=True,phase='complete',initializationJournalUnchanged=True,cleanRestartVerified=True,fixtureNonce=inputs['nonce'])
    print(json.dumps(receipt,indent=2))


if __name__=='__main__':
    if not __debug__:raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
