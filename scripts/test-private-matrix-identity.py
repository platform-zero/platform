#!/usr/bin/env python3
"""Native private MAS/Keycloak/Synapse authorization and message persistence; never touches matrix-r2."""
import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
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


def write(path,content):
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as out:out.write(content);out.flush();os.fsync(out.fileno())


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--name',default='matrix-identity-r4');parser.add_argument('--fixture',type=Path);parser.add_argument('--supervised',action='store_true');args=parser.parse_args();name=args.name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}',name)
    path=BASE/(name+'.json');manifest_hash=hashlib.sha256(path.read_bytes()).hexdigest()
    directory=Path('/mnt/media/p0-v3/image-acquisition-receipts')/('p0v3-matrix-id-'+uuid.uuid4().hex[:12]);directory.mkdir(mode=0o700)
    receipt={'id':directory.name,'deployment':name,'passed':False,'fullStackAcceptance':False,'publicHttpsTest':False,'ownerOnboarding':False,'manifestSha256':manifest_hash}
    realm=json.loads((BASE/name/'realm.json').read_text())
    if args.fixture:
        fixture=args.fixture;assert fixture.resolve()==fixture and fixture.stat().st_mode & 0o777==0o700 and fixture.stat().st_uid==os.getuid()
        assert not (fixture/'state.next').exists(),'Interrupted credential state requires reconciliation'
        assert json.loads((fixture/'receipt.json').read_text())['manifestSha256']==manifest_hash
        state_path=fixture/'state.json';assert not state_path.is_symlink() and state_path.stat().st_mode & 0o777==0o600 and state_path.stat().st_uid==os.getuid()
        state=json.loads(state_path.read_text())
    else:
        state={'users':{u['username']:{'initialPassword':u['credentials'][0]['value'],'password':secrets.token_hex(24),'subject':u['id'],'changed':False,'enrolled':False,'totpSecret':''} for u in realm['users']},'nonce':uuid.uuid4().hex[:12]}
    write(directory/'state.json',json.dumps(state))
    receipt['startedWithEnrolledIdentity']=all(state['users'][u]['enrolled'] for u in ('owner','reader'))
    cache=Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1')
    jars=[j for a in ('driver','driver-bundle','playwright') for j in (cache/('com.microsoft.playwright/'+a+'/1.55.0')).glob('*/*.jar')]
    jars+=list((cache/'com.google.code.gson/gson/2.12.1').glob('*/*.jar'));assert len(jars)==4
    ctx=ssl.create_default_context(cafile=str(BASE/name/'trusted-ca.pem'))
    def runtime(action):
        r=subprocess.run([str(CLI),'runtime',action,str(path)],capture_output=True,env=ENV,timeout=1200)
        assert r.returncode==0,'Private delegated identity lifecycle failed; state retained'
        return json.loads(r.stdout.splitlines()[0])
    def inspect(process):return json.loads(subprocess.check_output(P+['inspect','p0v3-live-'+name+'-'+process]))[0]
    def topology():
        ips={};pins=[];certs={}
        for host in ('auth','identity','element'):
            d=inspect(host);assert d['Config']['Labels']['io.p0v3.private-deployment']==name and d['State']['Running'] and not d['HostConfig']['PortBindings']
            assert set(d['NetworkSettings']['Networks'])=={'p0v3-live-'+name+'-net'}
            address=d['NetworkSettings']['Networks']['p0v3-live-'+name+'-net']['IPAddress'];assert ipaddress.ip_address(address).is_private;ips[host]=address
            try:
                with socket.create_connection((address,8443),timeout=15) as raw,ssl.create_default_context().wrap_socket(raw,server_hostname=host):pass
            except ssl.SSLCertVerificationError:pass
            else:raise AssertionError('Untrusted private CA unexpectedly accepted')
            with socket.create_connection((address,8443),timeout=15) as raw,ctx.wrap_socket(raw,server_hostname=host) as tls:
                expected=ssl.PEM_cert_to_DER_cert((BASE/name/(host+'-web.pem')).read_text());assert tls.getpeercert(binary_form=True)==expected;certs[host]=hashlib.sha256(expected).hexdigest()
            pub=subprocess.check_output(['openssl','x509','-in',str(BASE/name/(host+'-web.pem')),'-pubkey','-noout'])
            der=subprocess.run(['openssl','pkey','-pubin','-outform','DER'],input=pub,capture_output=True,check=True).stdout;pins.append(base64.b64encode(hashlib.sha256(der).digest()).decode())
        receipt['certificateSha256']=certs
        return ips,','.join(pins)
    def browser(mode,label):
        ips,pins=topology();d=inspect('element')
        values={'directory':str(directory),'mode':mode,'nonce':state['nonce'],'hosts':', '.join('MAP '+host+' '+ip for host,ip in ips.items())+', MAP * ~NOTFOUND','pins':pins}
        with tempfile.TemporaryDirectory(prefix='mi-',dir='/mnt/media/p0-v3/cache') as scratch:
            r=subprocess.run(['sudo','-n','nsenter','--target='+str(d['State']['Pid']),'--net','--setuid='+str(os.getuid()),'--setgid='+str(os.getgid()),
                '/usr/bin/env','HOME='+scratch,'TMPDIR='+scratch,'/usr/lib/jvm/java-21-openjdk-amd64/bin/java','-Djava.io.tmpdir='+scratch,'--class-path',':'.join(map(str,jars)),str(ROOT/'acceptance/scripts/MatrixIdentityBrowserProbe.java')],
                input=json.dumps(values),capture_output=True,text=True,timeout=600)
            write(directory/(label+'.log'),r.stderr);assert r.returncode==0,'Native delegated identity browser failed; protected state/diagnostics retained'
            result=json.loads(r.stdout);assert result['passed'] and not result['fullStackAcceptance'];return result
    def database_checks():
        current=json.loads((directory/'state.json').read_text())
        def sql(database,statement):
            return subprocess.check_output(P+['exec','--user','999','p0v3-live-'+name+'-postgres','psql','-U','postgres','-d',database,'-At','-F','\t','-c',statement],text=True,timeout=30).strip().splitlines()
        def ulid(value):
            assert re.fullmatch(r'[0-7][0-9A-HJKMNP-TV-Z]{25}',value)
            number=0
            for c in value:number=number*32+'0123456789ABCDEFGHJKMNPQRSTVWXYZ'.index(c)
            return str(uuid.UUID(int=number))
        linked=sql('mas','SELECT u.username,l.subject,l.upstream_oauth_provider_id::text,u.user_id::text,u.can_request_admin FROM users u JOIN upstream_oauth_links l ON l.user_id=u.user_id ORDER BY u.username')
        assert len(linked)==2
        for row in linked:
            user,subject,provider,mas_id,admin=row.split('\t');assert user in ('owner','reader')
            assert subject==current['users'][user]['subject'] and provider==ulid('01HFVBY12TMNTYTBV8W921M5FA') and mas_id==ulid(current['tokens'][user]['subject']) and admin=='f'
        assert sql('mas',"SELECT count(*) FROM users WHERE username='outsider'")==['0']
        assert sql('keycloak',"SELECT u.username,(SELECT count(*) FROM user_required_action a WHERE a.user_id=u.id),(SELECT count(*) FROM credential c WHERE c.user_id=u.id AND c.type='otp') FROM user_entity u JOIN realm r ON r.id=u.realm_id WHERE r.name='p0v3' AND u.username IN ('owner','reader') ORDER BY u.username")==['owner\t0\t1','reader\t0\t1']
        d=inspect('synapse');assert d['State']['Running'] and d['Config']['Labels']['io.p0v3.private-deployment']==name
        assert set(d['NetworkSettings']['Networks'])=={'p0v3-live-'+name+'-net'}
        address=d['NetworkSettings']['Networks']['p0v3-live-'+name+'-net']['IPAddress'];assert ipaddress.ip_address(address).is_private
        for user in ('owner','reader'):
            connection=http.client.HTTPConnection(address,8008,timeout=15)
            try:
                connection.request('GET','/_synapse/admin/v2/users?limit=1',headers={'Authorization':'Bearer '+current['tokens'][user]['access_token']})
                response=connection.getresponse();data=json.loads(response.read(65536));assert response.status==403 and data['errcode']=='M_FORBIDDEN'
            finally:connection.close()
        receipt.update(exactUpstreamSubjectBinding=True,unprovisionedUserAbsent=True,nativeAdminDenied=True,requiredActionsCompleteAndTotpPresent=True,untrustedCaDenied=True)
    with private_receipt(receipt,lambda r:write(directory/'receipt.json',json.dumps(r,indent=2))):
        runtime('apply-private');jobs=hashlib.sha256((BASE/name/'runtime.jobs').read_bytes()).hexdigest()
        receipt['phase']='native-delegated-identity';receipt.update(browser('verify' if state.get('roomId') else 'create','beforeRestart'))
        database_checks()
        receipt['phase']='restart-and-fresh-login'
        if args.supervised:
            unit='p0v3-private-'+name+'.service'
            subprocess.run(['systemctl','is-enabled','--quiet',unit],check=True,timeout=30)
            subprocess.run(['systemctl','is-active','--quiet',unit],check=True,timeout=30)
            daemons=[p['id'] for p in json.loads(path.read_text())['processes'] if not p.get('oneShot',False)]
            before={p:inspect(p) for p in daemons}
            subprocess.run(['sudo','-n','systemctl','restart',unit],check=True,capture_output=True,timeout=1200)
            for process in daemons:
                after=inspect(process);assert after['Id']==before[process]['Id'] and after['State']['Running'] and after['State']['StartedAt']!=before[process]['State']['StartedAt']
            receipt.update(supervisedRestartVerified=True,unitSha256=hashlib.sha256((Path('/etc/systemd/system')/unit).read_bytes()).hexdigest())
        else:
            assert all(p['exitCode'] in (0,143) for p in runtime('stop-private'))
            runtime('apply-private')
        assert hashlib.sha256((BASE/name/'runtime.jobs').read_bytes()).hexdigest()==jobs
        receipt.update(browser('verify','afterRestart'));database_checks();receipt.update(passed=True,phase='complete',cleanRestartVerified=True,initializerJournalUnchanged=True)
    print(json.dumps(receipt,indent=2))

if __name__=='__main__':
    if not __debug__:raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
