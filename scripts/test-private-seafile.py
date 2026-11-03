#!/usr/bin/env python3
"""Native private Seafile upload/download, sharing isolation, revocation and restart."""
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
import urllib.parse
import uuid
from probe_receipt import private_receipt

_s=importlib.util.spec_from_file_location('helpers',Path(__file__).with_name('test-private-searxng.py'))
H=importlib.util.module_from_spec(_s);_s.loader.exec_module(H)
BASE,CLI,P,ENV=H.BASE,H.CLI,H.P,H.ENV


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--name',default='seafile-r4');parser.add_argument('--supervised',action='store_true');args=parser.parse_args();name=args.name
    assert re.fullmatch('[a-z][a-z0-9-]{0,39}',name)
    manifest=BASE/(name+'.json');inputs=BASE/name;spec=json.loads(manifest.read_text());passwords=json.loads((inputs/'users.json').read_text())
    directory=Path('/mnt/media/p0-v3/image-acquisition-receipts')/('p0v3-files-'+uuid.uuid4().hex[:12]);directory.mkdir(mode=0o700)
    receipt={'id':directory.name,'deployment':name,'manifestSha256':hashlib.sha256(manifest.read_bytes()).hexdigest(),'passed':False,'fullStackAcceptance':False,'publicHttpsTest':False,'officeEditingTest':False,'realOwnerOnboarding':False}
    def inspect(process):return json.loads(subprocess.check_output(P+['inspect','p0v3-live-'+name+'-'+process]))[0]
    def address():
        d=inspect('files');assert d['State']['Running'] and not d['HostConfig']['PortBindings'] and d['Config']['Labels']['io.p0v3.private-deployment']==name
        assert set(d['NetworkSettings']['Networks'])=={'p0v3-live-'+name+'-net'}
        ip=d['NetworkSettings']['Networks']['p0v3-live-'+name+'-net']['IPAddress'];assert ipaddress.ip_address(ip).is_private;return ip
    def runtime(action):
        r=subprocess.run([str(CLI),'runtime',action,str(manifest)],capture_output=True,env=ENV,timeout=900)
        if r.returncode:H.write(directory/(action+'.log'),r.stderr.decode(errors='replace'))
        assert r.returncode==0,'Native file runtime failed; state retained';return json.loads(r.stdout.splitlines()[0])
    ctx=ssl.create_default_context(cafile=str(inputs/'ca.pem'))
    def request(path,method='GET',token=None,form=None,body=None,content_type=None):
        if path.startswith('https://'):
            u=urllib.parse.urlsplit(path);assert u.scheme=='https' and u.netloc=='files:8443' and not u.username and not u.fragment
            path=u.path+('?' + u.query if u.query else '')
        assert path.startswith('/') and '\r' not in path and '\n' not in path
        c=http.client.HTTPConnection('files',8443,timeout=30);c.sock=ctx.wrap_socket(socket.create_connection((address(),8443),timeout=15),server_hostname='files')
        headers={}
        if token:headers['Authorization']='Token '+token
        if form is not None:body=urllib.parse.urlencode(form);content_type='application/x-www-form-urlencoded'
        if content_type:headers['Content-Type']=content_type
        try:
            c.request(method,path,body=body,headers=headers);r=c.getresponse();data=r.read(2*1024*1024+1);assert len(data)<=2*1024*1024
            if r.status>=500:H.write(directory/('server-error-'+uuid.uuid4().hex[:8]+'.html'),data.decode(errors='replace'))
            return r.status,data
        finally:c.close()
    def browser(label,upload):
        cache=Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1')
        jars=[j for a in ('driver','driver-bundle','playwright') for j in (cache/('com.microsoft.playwright/'+a+'/1.55.0')).glob('*/*.jar')]+list((cache/'com.google.code.gson/gson/2.12.1').glob('*/*.jar'));assert len(jars)==4
        pub=subprocess.check_output(['openssl','x509','-in',str(inputs/'web.pem'),'-pubkey','-noout']);der=subprocess.run(['openssl','pkey','-pubin','-outform','DER'],input=pub,capture_output=True,check=True).stdout
        values={'address':address(),'pin':base64.b64encode(hashlib.sha256(der).digest()).decode(),'directory':str(directory),'password':passwords['owner'],'label':label,'upload':upload,'phase':'beforeRestart' if upload else 'afterRestart'}
        d=inspect('files')
        with tempfile.TemporaryDirectory(prefix='sf-',dir='/mnt/media/p0-v3/cache') as scratch:
            r=subprocess.run(['sudo','-n','nsenter','--target='+str(d['State']['Pid']),'--net','--setuid='+str(os.getuid()),'--setgid='+str(os.getgid()),'/usr/bin/env','HOME='+scratch,'TMPDIR='+scratch,'/usr/lib/jvm/java-21-openjdk-amd64/bin/java','-Djava.io.tmpdir='+scratch,'--class-path',':'.join(map(str,jars)),str(H.ROOT/'acceptance/scripts/SeafileBrowserProbe.java')],input=json.dumps(values),capture_output=True,text=True,timeout=300)
            H.write(directory/(values['phase']+'-browser.log'),r.stderr);assert r.returncode==0,'Native file browser failed; diagnostics retained'
            result=json.loads(r.stdout);assert result.pop('passed');receipt.update(result)
    def api(path,method='GET',token=None,form=None):
        status,data=request(path,method,token,form);assert status in (200,201),f'Native API returned {status}; protected diagnostics retained';return json.loads(data)
    def login(role):
        data=api('/api2/auth-token/','POST',form={'username':role+'@localhost.invalid','password':passwords[role]});assert re.fullmatch('[a-f0-9]{40}',data['token']);return data['token']
    def upload(repo,token,filename,payload):
        link=api('/api2/repos/'+repo+'/upload-link/',token=token);boundary='p0v3'+uuid.uuid4().hex
        body=('--'+boundary+'\r\nContent-Disposition: form-data; name="parent_dir"\r\n\r\n/\r\n--'+boundary+'\r\nContent-Disposition: form-data; name="file"; filename="'+filename+'"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()+payload+('\r\n--'+boundary+'--\r\n').encode()
        status,data=request(link+('?ret-json=1' if '?' not in link else '&ret-json=1'),'POST',token,body=body,content_type='multipart/form-data; boundary='+boundary)
        assert status==200,'Native upload failed';result=json.loads(data);assert result[0]['name']==filename
    def download(repo,token,filename):
        link=api('/api2/repos/'+repo+'/file/?'+urllib.parse.urlencode({'p':'/'+filename}),token=token)
        status,data=request(link,token=token);assert status==200;return data
    with private_receipt(receipt,lambda r:H.write(directory/'receipt.json',json.dumps(r,indent=2))):
        runtime('apply-private');jobs=hashlib.sha256((inputs/'runtime.jobs').read_bytes()).hexdigest();ip=address()
        try:
            with socket.create_connection((ip,8443),timeout=15) as raw,ssl.create_default_context().wrap_socket(raw,server_hostname='files'):pass
        except ssl.SSLCertVerificationError:pass
        else:raise AssertionError('Untrusted private certificate accepted')
        with socket.create_connection((ip,8443),timeout=15) as raw,ctx.wrap_socket(raw,server_hostname='files') as tls:
            cert=tls.getpeercert(binary_form=True);assert cert==ssl.PEM_cert_to_DER_cert((inputs/'web.pem').read_text());receipt['certificateSha256']=hashlib.sha256(cert).hexdigest()
        receipt['phase']='database-scope'
        def sql(script):return subprocess.run(P+['exec','--user','999','p0v3-live-'+name+'-mariadb','/bin/sh','-ec',script],capture_output=True,text=True,timeout=30)
        r=sql('MYSQL_PWD="$MARIADB_ROOT_PASSWORD" mariadb --socket=/tmp/mysql.sock -u root -Nse "SELECT COUNT(*) FROM mysql.global_priv WHERE User=\'\' OR (User=\'root\' AND Host<>\'localhost\');"');assert r.returncode==0 and r.stdout.strip()=='0'
        r=sql('MYSQL_PWD="$APP_PASSWORD" mariadb -h127.0.0.1 -u seafile -Nse "SELECT 1"');assert r.returncode==0 and r.stdout.strip()=='1'
        r=sql('MYSQL_PWD="$APP_PASSWORD" mariadb -h127.0.0.1 -u seafile -Nse "SELECT COUNT(*) FROM mysql.global_priv"');assert r.returncode!=0 and 'denied' in r.stderr.lower()
        receipt['databaseScopeVerified']=True
        receipt['phase']='native-login';tokens={role:login(role) for role in passwords}
        assert request('/api2/repos/')[0] in (401,403)
        assert request('/api2/repos/',token='0'*40)[0] in (401,403)
        receipt['phase']='upload'
        label='Private fixture '+uuid.uuid4().hex[:12];repo=api('/api2/repos/','POST',tokens['owner'],{'name':label,'desc':'Synthetic files only'})['repo_id'];assert re.fullmatch('[a-f0-9-]{36}',repo)
        payload=(b'Platform Zero synthetic library fixture\n'+bytes(range(256)))*128;filename='fixture.bin';digest=hashlib.sha256(payload).hexdigest()
        upload(repo,tokens['owner'],filename,payload);assert download(repo,tokens['owner'],filename)==payload
        assert request('/api2/repos/'+repo+'/dir/',token=tokens['outsider'])[0] in (403,404)
        assert request('/api2/repos/'+repo+'/upload-link/',token=tokens['reader'])[0] in (403,404)
        assert request('/api2/repos/'+repo+'/file/?p=/fixture.bin',token=tokens['reader'])[0] in (403,404)
        receipt['phase']='read-only-share'
        api('/api2/shared-repos/'+repo+'/?'+urllib.parse.urlencode({'share_type':'personal','user':'reader@localhost.invalid','permission':'r'}),'PUT',tokens['owner'])
        assert download(repo,tokens['reader'],filename)==payload
        assert request('/api2/repos/'+repo+'/upload-link/',token=tokens['reader'])[0] in (403,404)
        assert request('/api2/repos/'+repo+'/dir/',token=tokens['outsider'])[0] in (403,404)
        H.write(directory/'fixture.json',json.dumps({'repo':repo,'label':label,'filename':filename,'sha256':digest}))
        receipt['phase']='native-browser';browser(label,True)
        assert download(repo,tokens['owner'],'browser.txt')==b'Native browser upload: synthetic only.\n'
        receipt['nativeBrowserUploadVerified']=True
        before={p['id']:inspect(p['id']) for p in spec['processes'] if not p.get('oneShot',False)};receipt['phase']='restart'
        if args.supervised:
            unit='p0v3-private-'+name+'.service';subprocess.run(['systemctl','is-enabled','--quiet',unit],check=True,timeout=30);subprocess.run(['systemctl','is-active','--quiet',unit],check=True,timeout=30)
            subprocess.run(['sudo','-n','systemctl','restart',unit],capture_output=True,check=True,timeout=900);receipt['supervisedRestartVerified']=True
        else:
            assert all(p['exitCode'] in (0,143) for p in runtime('stop-private'));runtime('apply-private')
        for process,old in before.items():
            new=inspect(process);assert new['State']['Running'] and old['Id']==new['Id'] and old['State']['StartedAt']!=new['State']['StartedAt']
        assert hashlib.sha256((inputs/'runtime.jobs').read_bytes()).hexdigest()==jobs
        tokens={role:login(role) for role in passwords};assert download(repo,tokens['owner'],filename)==payload and download(repo,tokens['reader'],filename)==payload
        assert request('/api2/repos/'+repo+'/upload-link/',token=tokens['reader'])[0] in (403,404)
        receipt['phase']='browser-after-restart';browser(label,False)
        assert download(repo,tokens['owner'],'browser.txt')==b'Native browser upload: synthetic only.\n'
        receipt['phase']='share-revocation'
        status,_=request('/api2/shared-repos/'+repo+'/?'+urllib.parse.urlencode({'share_type':'personal','user':'reader@localhost.invalid'}),'DELETE',tokens['owner']);assert status==200
        assert request('/api2/repos/'+repo+'/dir/',token=tokens['reader'])[0] in (403,404)
        assert request('/api2/repos/'+repo+'/file/?p=/fixture.bin',token=tokens['reader'])[0] in (403,404)
        assert download(repo,tokens['owner'],filename)==payload
        receipt.update(passed=True,phase='complete',nativeLogin=True,nativeUploadDownload=True,contentSha256=digest,bytes=len(payload),readOnlySharingVerified=True,outsiderDenied=True,sharingRevoked=True,persistentContentAndPermissions=True,initializerJournalUnchanged=True,untrustedCaDenied=True)
    print(json.dumps(receipt,indent=2))

if __name__=='__main__':
    if not __debug__:raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
