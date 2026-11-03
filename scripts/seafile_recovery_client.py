"""Private native Seafile API/browser client for isolated recovery checks, not publication."""
if not __debug__:raise SystemExit('Optimized Python disables safety checks; refusing effects')
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

_s=importlib.util.spec_from_file_location('file_probe',Path(__file__).with_name('test-private-seafile.py'))
F=importlib.util.module_from_spec(_s);_s.loader.exec_module(F)
BASE,CLI,P,ENV,ROOT=F.BASE,F.CLI,F.P,F.ENV,F.H.ROOT


class Client:
    def __init__(self,name):
        assert re.fullmatch('[a-z][a-z0-9-]{0,39}',name)
        self.name=name;self.inputs=BASE/name;self.ctx=ssl.create_default_context(cafile=str(self.inputs/'ca.pem'))
        self.leaf=ssl.PEM_cert_to_DER_cert((self.inputs/'web.pem').read_text());self.passwords=json.loads((self.inputs/'users.json').read_text());self.tokens={}

    def inspect(self,process='files'):
        d=json.loads(subprocess.check_output(P+['inspect','p0v3-live-'+self.name+'-'+process]))[0]
        assert d['State']['Running'] and d['Config']['Labels']['io.p0v3.private-deployment']==self.name and not d['HostConfig']['PortBindings']
        assert set(d['NetworkSettings']['Networks'])=={'p0v3-live-'+self.name+'-net'}
        return d

    def address(self,process='files'):
        d=self.inspect(process);ip=d['NetworkSettings']['Networks']['p0v3-live-'+self.name+'-net']['IPAddress'];assert ipaddress.ip_address(ip).is_private;return ip

    def request(self,path,role=None,method='GET',form=None,body=None,content_type=None):
        if path.startswith('https://'):
            u=urllib.parse.urlsplit(path);assert u.scheme=='https' and u.netloc=='files:8443' and not u.username and not u.fragment
            path=u.path+('?' + u.query if u.query else '')
        assert path.startswith('/') and '\r' not in path and '\n' not in path
        c=http.client.HTTPConnection('files',8443,timeout=30)
        c.sock=socket.create_connection((self.address(),8443),timeout=15)
        try:
            c.sock=self.ctx.wrap_socket(c.sock,server_hostname='files')
            assert c.sock.getpeercert(binary_form=True)==self.leaf
            headers={}
            if role:headers['Authorization']='Token '+self.tokens[role]
            if form is not None:body=urllib.parse.urlencode(form);content_type='application/x-www-form-urlencoded'
            if content_type:headers['Content-Type']=content_type
            c.request(method,path,body=body,headers=headers);r=c.getresponse();data=r.read(16*1024*1024+1);assert len(data)<=16*1024*1024
            return r.status,data
        finally:c.close()

    def api(self,path,role=None,method='GET',form=None):
        status,data=self.request(path,role,method,form);assert status in (200,201),f'Native file API returned {status}'
        return json.loads(data)

    def login(self):
        for role,password in self.passwords.items():
            data=self.api('/api2/auth-token/',method='POST',form={'username':role+'@localhost.invalid','password':password})
            assert re.fullmatch('[a-f0-9]{40}',data['token']);self.tokens[role]=data['token']

    def share(self,repo,grant):
        query=urllib.parse.urlencode({'share_type':'personal','user':'reader@localhost.invalid','permission':'r'})
        return self.api('/api2/shared-repos/'+repo+'/?'+query,'owner','PUT' if grant else 'DELETE')

    def revoke_if_shared(self,repo,allow_revoke=True):
        # Reconcile an uncertain mutation with a native read, never blindly retry DELETE.
        rows=self.api('/api2/repos/','reader');assert isinstance(rows,list)
        matches=[row for row in rows if row['id']==repo];assert len(matches)<=1
        if matches:
            if not allow_revoke:raise RuntimeError('Uncertain revoke still visible; manual reconciliation required')
            self.share(repo,False)
        return bool(matches)

    def file_status(self,repo,filename,role='owner'):
        return self.request('/api2/repos/'+repo+'/file/?'+urllib.parse.urlencode({'p':'/'+filename}),role)[0]

    def download(self,repo,filename,role='owner'):
        link=self.api('/api2/repos/'+repo+'/file/?'+urllib.parse.urlencode({'p':'/'+filename}),role)
        status,data=self.request(link,role);assert status==200;return data

    def upload(self,repo,filename,payload):
        assert re.fullmatch('[a-z0-9.-]+',filename)
        link=self.api('/api2/repos/'+repo+'/upload-link/','owner');boundary='p0v3'+uuid.uuid4().hex
        body=('--'+boundary+'\r\nContent-Disposition: form-data; name="parent_dir"\r\n\r\n/\r\n--'+boundary+'\r\nContent-Disposition: form-data; name="file"; filename="'+filename+'"\r\nContent-Type: application/octet-stream\r\n\r\n').encode()+payload+('\r\n--'+boundary+'--\r\n').encode()
        status,data=self.request(link+('?ret-json=1' if '?' not in link else '&ret-json=1'),'owner','POST',body=body,content_type='multipart/form-data; boundary='+boundary)
        assert status==200 and json.loads(data)[0]['name']==filename

    def browser(self,fixture,directory,label):
        cache=Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1')
        jars=[j for a in ('driver','driver-bundle','playwright') for j in (cache/('com.microsoft.playwright/'+a+'/1.55.0')).glob('*/*.jar')]+list((cache/'com.google.code.gson/gson/2.12.1').glob('*/*.jar'));assert len(jars)==4
        pub=subprocess.check_output(['openssl','x509','-in',str(self.inputs/'web.pem'),'-pubkey','-noout']);der=subprocess.run(['openssl','pkey','-pubin','-outform','der'],input=pub,capture_output=True,check=True).stdout
        values={'address':self.address(),'pin':base64.b64encode(hashlib.sha256(der).digest()).decode(),'directory':str(directory),'password':self.passwords['owner'],'label':fixture['label'],'upload':False,'phase':label}
        with tempfile.TemporaryDirectory(prefix='sf-',dir='/mnt/media/p0-v3/cache') as scratch:
            r=subprocess.run(['sudo','-n','nsenter','--target='+str(self.inspect()['State']['Pid']),'--net','--setuid='+str(os.getuid()),'--setgid='+str(os.getgid()),'/usr/bin/env','HOME='+scratch,'TMPDIR='+scratch,'/usr/lib/jvm/java-21-openjdk-amd64/bin/java','-Djava.io.tmpdir='+scratch,'--class-path',':'.join(map(str,jars)),str(ROOT/'acceptance/scripts/SeafileBrowserProbe.java')],input=json.dumps(values),capture_output=True,text=True,timeout=300)
            F.H.write(directory/(label+'-browser.log'),r.stderr);assert r.returncode==0,'Recovered browser failed; diagnostics retained'
            assert json.loads(r.stdout)['passed']
