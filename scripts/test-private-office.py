#!/usr/bin/env python3
"""Native private office editing: synthetic document only; no public or restoration claim."""
if not __debug__:raise SystemExit('Optimized Python disables safety checks; refusing effects')
import argparse
import base64
import hashlib
import hmac
import http.client
import socket
import ssl
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid
import zipfile
import xml.etree.ElementTree as ET
from seafile_recovery_client import Client,F,BASE,CLI,P,ENV,ROOT
from probe_receipt import private_receipt


def document():
    data=io.BytesIO()
    with zipfile.ZipFile(data,'w',zipfile.ZIP_DEFLATED) as z:
        z.writestr('[Content_Types].xml','<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>')
        z.writestr('_rels/.rels','<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        z.writestr('word/document.xml','<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Synthetic private office document.</w:t></w:r></w:p><w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440"/></w:sectPr></w:body></w:document>')
    return data.getvalue()


def text(data):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        assert len(z.infolist())<500 and sum(i.file_size for i in z.infolist())<10*1024*1024
        return ''.join(ET.fromstring(z.read('word/document.xml')).itertext())


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--name',default='files-office-r7');parser.add_argument('--supervised',action='store_true');args=parser.parse_args();name=args.name
    directory=Path('/mnt/media/p0-v3/image-acquisition-receipts')/('p0v3-office-'+uuid.uuid4().hex[:12]);directory.mkdir(mode=0o700)
    receipt={'id':directory.name,'deployment':name,'passed':False,'fullStackAcceptance':False,'publicHttpsTest':False,'encryptedRecovery':False,'activeSessionRecovery':False,'realOwnerOnboarding':False,'phase':'startup'}
    with private_receipt(receipt,lambda value:F.H.write(directory/'receipt.json',json.dumps(value,indent=2))):
        result=subprocess.run([str(CLI),'runtime','apply-private',str(BASE/(name+'.json'))],capture_output=True,env=ENV,timeout=600);assert result.returncode==0
        client=Client(name);client.login();receipt['manifestSha256']=hashlib.sha256((BASE/(name+'.json')).read_bytes()).hexdigest()
        assert client.request('/onlyoffice/editor-callback/',method='POST',body=b'{"key":"invalid","status":6,"url":"https://office:8443/cache/files/invalid"}',content_type='application/json')[0]==403
        label='Office fixture '+uuid.uuid4().hex[:12];repo=client.api('/api2/repos/','owner','POST',{'name':label,'desc':'Synthetic office editing only'})['repo_id'];original=document();client.upload(repo,'draft.docx',original);assert client.download(repo,'draft.docx')==original
        marker='Native office edit '+uuid.uuid4().hex[:12]
        F.H.write(directory/'fixture.json',json.dumps({'repo':repo,'label':label,'marker':marker}))
        pins=[]
        for filename in ('web.pem','office-web.pem'):
            pub=subprocess.check_output(['openssl','x509','-in',str(BASE/name/filename),'-pubkey','-noout']);der=subprocess.run(['openssl','pkey','-pubin','-outform','der'],input=pub,capture_output=True,check=True).stdout;pins.append(base64.b64encode(hashlib.sha256(der).digest()).decode())
        cache=Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1');jars=[j for a in ('driver','driver-bundle','playwright') for j in (cache/('com.microsoft.playwright/'+a+'/1.55.0')).glob('*/*.jar')]+list((cache/'com.google.code.gson/gson/2.12.1').glob('*/*.jar'));assert len(jars)==4
        def browser(role,edit,content):
            cfg={'address':client.address(),'officeAddress':client.address('office'),'pins':','.join(pins),'directory':str(directory),'password':client.passwords[role],'role':role,'edit':edit,'repo':repo,'label':label,'marker':content}
            with tempfile.TemporaryDirectory(prefix='of-',dir='/mnt/media/p0-v3/cache') as scratch:
                r=subprocess.run(['sudo','-n','nsenter','--target='+str(client.inspect()['State']['Pid']),'--net','--setuid='+str(os.getuid()),'--setgid='+str(os.getgid()),'/usr/bin/env','HOME='+scratch,'TMPDIR='+scratch,'/usr/lib/jvm/java-21-openjdk-amd64/bin/java','-Djava.io.tmpdir='+scratch,'--class-path',':'.join(map(str,jars)),str(ROOT/'acceptance/scripts/OfficeBrowserProbe.java')],input=json.dumps(cfg),capture_output=True,text=True,timeout=360)
                F.H.write(directory/(role+'-browser.log'),r.stderr);assert r.returncode==0,'Native office browser failed; protected diagnostics retained';assert json.loads(r.stdout)['passed']
        receipt['phase']='browser-edit';browser('owner',True,marker)
        receipt['phase']='callback-save-readback'
        # Read-only observations may wait; neither keyboard edits nor callbacks are retried.
        for _ in range(30):
            updated=client.download(repo,'draft.docx')
            if marker in text(updated):break
            time.sleep(2)
        assert marker in text(updated) and hashlib.sha256(updated).digest()!=hashlib.sha256(original).digest()
        assert client.file_status(repo,'draft.docx','outsider') in (403,404)
        receipt['phase']='read-only-browser'
        client.share(repo,True);denied_marker='Reader must not edit '+uuid.uuid4().hex[:12];browser('reader',False,denied_marker)
        assert client.download(repo,'draft.docx')==updated and denied_marker not in text(updated)
        assert client.download(repo,'draft.docx','reader')==updated
        receipt['phase']='security-and-persistence'
        for host,ca,leaf in [('files','ca.pem','web.pem'),('office','office-ca.pem','office-web.pem')]:
            address=client.address(host)
            with socket.create_connection((address,8443),timeout=10) as raw:
                with ssl.create_default_context(cafile=str(BASE/name/ca)).wrap_socket(raw,server_hostname=host) as tls:
                    assert tls.getpeercert(binary_form=True)==ssl.PEM_cert_to_DER_cert((BASE/name/leaf).read_text())
            try:
                with socket.create_connection((address,8443),timeout=10) as raw:
                    with ssl.create_default_context().wrap_socket(raw,server_hostname=host):pass
            except ssl.SSLCertVerificationError:pass
            else:raise AssertionError('Private office certificate unexpectedly trusted')
        def office_request(path,method='GET',body=None):
            conn=http.client.HTTPConnection('office',8443,timeout=30)
            conn.sock=ssl.create_default_context(cafile=str(BASE/name/'office-ca.pem')).wrap_socket(socket.create_connection((client.address('office'),8443),timeout=10),server_hostname='office')
            try:
                conn.request(method,path,body=body,headers={'Content-Type':'application/json','Accept':'application/json'});response=conn.getresponse();return response.status,response.read(100000)
            finally:conn.close()
        status,body=office_request('/ConvertService.ashx','POST',json.dumps({'key':'unsigned','filetype':'docx','outputtype':'pdf','url':'https://files:8443/missing'}));assert status in (401,403) or (status==200 and json.loads(body).get('error')==-8)
        assert office_request('/cache/files/missing/output.docx')[0]==403 and office_request('/internal/cluster')[0]==403
        secret=json.loads((BASE/name/'office.json').read_text())['services']['CoAuthoring']['secret']['outbox']['string']
        def signed(payload,purpose='callback'):
            now=int(time.time());claims={**payload,'operation':purpose,'iat':now,'exp':now+300}
            encode=lambda value:base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
            content=encode({'alg':'HS256'})+'.'+encode(claims)
            token=content+'.'+base64.urlsafe_b64encode(hmac.new(secret.encode(),content.encode(),hashlib.sha256).digest()).decode().rstrip('=')
            return json.dumps({**payload,'token':token}).encode()
        callback='/onlyoffice/editor-callback/'
        def callback_post(body):return client.request(callback,method='POST',body=body,content_type='application/json')
        payload={'key':'guard-'+uuid.uuid4().hex[:12],'status':1}
        assert callback_post(signed(payload,'convert'))[0]==403
        assert callback_post(signed({**payload,'status':6,'url':'http://169.254.169.254/latest/meta-data/'}))[0]==403
        invalid=json.loads(signed(payload));invalid['status']=4;assert callback_post(json.dumps(invalid).encode())[0]==403
        typed=json.loads(signed({**payload,'history':{'version':1}}));typed['history']['version']=True;assert callback_post(json.dumps(typed).encode())[0]==403
        uncertain=signed(payload);status,body=callback_post(uncertain);assert status==200 and json.loads(body)=={'error':1}
        assert callback_post(uncertain)[0]==409
        spec=json.loads((BASE/(name+'.json')).read_text());before={p['id']:client.inspect(p['id']) for p in spec['processes'] if not p.get('oneShot',False)}
        journal=hashlib.sha256((BASE/name/'runtime.jobs').read_bytes()).hexdigest()
        if args.supervised:
            import re
            unit='p0v3-private-'+name+'.service';unit_path=Path('/etc/systemd/system')/unit
            assert unit_path.stat().st_uid==0 and not unit_path.is_symlink()
            assert re.search(r'^ExecStart=/mnt/media/p0-v3/runtime-supervision/releases/[a-f0-9]{64}/bin/p0-v3-platform runtime boot-apply '+name+' '+receipt['manifestSha256']+'$',unit_path.read_text(),re.M)
            for action in ('is-enabled','is-active','restart','is-active'):
                r=subprocess.run(['sudo','-n','systemctl',action,unit],capture_output=True,text=True,timeout=600);assert r.returncode==0
            receipt['supervisedRestartVerified']=True
        else:
            for action in ('stop-private','apply-private'):
                r=subprocess.run([str(CLI),'runtime',action,str(BASE/(name+'.json'))],capture_output=True,env=ENV,timeout=600);F.H.write(directory/(action+'.log'),r.stdout.decode()+r.stderr.decode());assert r.returncode==0
        for process,state in before.items():
            after=client.inspect(process);assert after['Id']==state['Id'] and after['State']['StartedAt']!=state['State']['StartedAt']
        assert hashlib.sha256((BASE/name/'runtime.jobs').read_bytes()).hexdigest()==journal
        client.login();assert client.download(repo,'draft.docx')==updated and client.download(repo,'draft.docx','reader')==updated
        assert callback_post(uncertain)[0]==409
        client.share(repo,False);assert client.file_status(repo,'draft.docx','reader') in (403,404)
        receipt.update(passed=True,phase='complete',nativeBrowserEditing=True,nativeSavedDocumentReadback=True,unsignedCallbackDenied=True,outsiderDenied=True,readOnlyBrowserEditDenied=True,shareRevocationVerified=True,wrongPurposeAndBodyDenied=True,callbackOriginRestricted=True,unsignedConversionDenied=True,unsignedCacheDownloadDenied=True,uncertainCallbackReplayDeniedAfterRestart=True,privateTlsVerified=True,persistentDocumentVerified=True,initializerJournalUnchanged=True)
    print(json.dumps(receipt,indent=2))

if __name__=='__main__':main()
