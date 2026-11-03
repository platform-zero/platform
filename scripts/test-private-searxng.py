#!/usr/bin/env python3
"""Native SearXNG SQLite FTS/HTTPS/browser and restart checks. No external engines or documents."""
import argparse
import base64
import hashlib
import http.client
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

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/media/p0-v3/runtime-deployments')
CLI=ROOT/'platform/build/install/p0-v3-platform/bin/p0-v3-platform'
P=['sudo','-n','podman','--remote=false','--root=/mnt/media/p0-v3/release-runtime/graph','--runroot=/run/p0-v3-release-runtime/store','--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
ENV={**os.environ,'JAVA_HOME':'/usr/lib/jvm/java-21-openjdk-amd64'}


def write(path,data):
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'w') as f:f.write(data);f.flush();os.fsync(f.fileno())


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--name',default='searxng-r2');parser.add_argument('--supervised',action='store_true');args=parser.parse_args();name=args.name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}',name)
    manifest=BASE/(name+'.json');inputs=BASE/name
    directory=Path('/mnt/media/p0-v3/image-acquisition-receipts')/('p0v3-metasearch-'+uuid.uuid4().hex[:12]);directory.mkdir(mode=0o700)
    receipt={'id':directory.name,'deployment':name,'passed':False,'phase':'preflight','fullStackAcceptance':False,'publicSearchTest':False,'manifestSha256':hashlib.sha256(manifest.read_bytes()).hexdigest()}
    def inspect(process):return json.loads(subprocess.check_output(P+['inspect','p0v3-live-'+name+'-'+process]))[0]
    def runtime(action):
        r=subprocess.run([str(CLI),'runtime',action,str(manifest)],capture_output=True,env=ENV,timeout=1200)
        assert r.returncode==0,'Private search lifecycle failed; state retained'
        return json.loads(r.stdout.splitlines()[0])
    ctx=ssl.create_default_context(cafile=str(inputs/'ca.pem'))
    cache=Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1')
    jars=[j for a in ('driver','driver-bundle','playwright') for j in (cache/('com.microsoft.playwright/'+a+'/1.55.0')).glob('*/*.jar')]+list((cache/'com.google.code.gson/gson/2.12.1').glob('*/*.jar'));assert len(jars)==4
    def check(label):
        d=inspect('search');assert d['State']['Running'] and d['Config']['Labels']['io.p0v3.private-deployment']==name and not d['HostConfig']['PortBindings']
        assert set(d['NetworkSettings']['Networks'])=={'p0v3-live-'+name+'-net'}
        ip=d['NetworkSettings']['Networks']['p0v3-live-'+name+'-net']['IPAddress'];assert ipaddress.ip_address(ip).is_private
        try:
            with socket.create_connection((ip,8443),timeout=15) as raw,ssl.create_default_context().wrap_socket(raw,server_hostname='search'):pass
        except ssl.SSLCertVerificationError:pass
        else:raise AssertionError('Untrusted CA accepted')
        with socket.create_connection((ip,8443),timeout=15) as raw,ctx.wrap_socket(raw,server_hostname='search') as tls:
            cert=tls.getpeercert(binary_form=True);assert cert==ssl.PEM_cert_to_DER_cert((inputs/'web.pem').read_text());receipt['certificateSha256']=hashlib.sha256(cert).hexdigest()
        def get(path):
            connection=http.client.HTTPConnection('search',8443,timeout=30)
            connection.sock=ctx.wrap_socket(socket.create_connection((ip,8443),timeout=30),server_hostname='search')
            try:
                connection.request('GET',path);r=connection.getresponse();assert r.status==200
                data=r.read(2097153);assert len(data)<=2097152;return json.loads(data)
            finally:connection.close()
        config=get('/config');assert [e['name'] for e in config['engines']]==['private corpus']
        def search(query,page=1):
            data=get('/search?'+urllib.parse.urlencode({'q':query,'format':'json','pageno':page}))
            assert not data['unresponsive_engines'];assert all(r['engine']=='private corpus' for r in data['results']);return data['results']
        assert {r['title'] for r in search('otter')}=={'Otter habitat','Otter astronomy'}
        assert [r['title'] for r in search('"river otter"')]==['Otter habitat']
        assert [r['title'] for r in search('alpine')]==['Alpine botany']
        assert search('zzmissingfixturezz')==[]
        first,second=search('quasar'),search('quasar',2);assert len(first)==10 and len(second)==2 and len({r['url'] for r in first+second})==12
        pub=subprocess.check_output(['openssl','x509','-in',str(inputs/'web.pem'),'-pubkey','-noout'])
        der=subprocess.run(['openssl','pkey','-pubin','-outform','DER'],input=pub,capture_output=True,check=True).stdout
        values={'address':ip,'pin':base64.b64encode(hashlib.sha256(der).digest()).decode(),'directory':str(directory),'label':label}
        with tempfile.TemporaryDirectory(prefix='sx-',dir='/mnt/media/p0-v3/cache') as scratch:
            r=subprocess.run(['sudo','-n','nsenter','--target='+str(d['State']['Pid']),'--net','--setuid='+str(os.getuid()),'--setgid='+str(os.getgid()),'/usr/bin/env','HOME='+scratch,'TMPDIR='+scratch,'/usr/lib/jvm/java-21-openjdk-amd64/bin/java','-Djava.io.tmpdir='+scratch,'--class-path',':'.join(map(str,jars)),str(ROOT/'acceptance/scripts/SearxngBrowserProbe.java')],input=json.dumps(values),capture_output=True,text=True,timeout=180)
            write(directory/(label+'.log'),r.stderr);assert r.returncode==0,'Private search browser failed; evidence retained';receipt.update(json.loads(r.stdout))
        receipt.update(nativeFullTextSearch=True,phraseAndEmptySearch=True,paginationDistinct=True,onlyOfflineEngine=True,untrustedCaDenied=True)
    def corpus_hash():
        result=subprocess.check_output(P+['exec','--user','977','p0v3-live-'+name+'-searxng','sha256sum','/corpus/documents.db'],text=True).split()[0];assert re.fullmatch('[a-f0-9]{64}',result);return result
    with private_receipt(receipt,lambda r:write(directory/'receipt.json',json.dumps(r,indent=2))):
        runtime('apply-private');jobs=hashlib.sha256((inputs/'runtime.jobs').read_bytes()).hexdigest();corpus=corpus_hash()
        receipt['phase']='before-restart';check('beforeRestart')
        before={p:inspect(p) for p in ('searxng','search')}
        if args.supervised:
            unit='p0v3-private-'+name+'.service'
            subprocess.run(['systemctl','is-enabled','--quiet',unit],check=True,timeout=30);subprocess.run(['systemctl','is-active','--quiet',unit],check=True,timeout=30)
            subprocess.run(['sudo','-n','systemctl','restart',unit],capture_output=True,check=True,timeout=1200);receipt['supervisedRestartVerified']=True
        else:
            assert all(s['exitCode'] in (0,143) for s in runtime('stop-private'));runtime('apply-private')
        for process,old in before.items():
            after=inspect(process);assert old['Id']==after['Id'] and old['State']['StartedAt']!=after['State']['StartedAt'] and after['State']['Running']
        assert hashlib.sha256((inputs/'runtime.jobs').read_bytes()).hexdigest()==jobs and corpus_hash()==corpus
        receipt['phase']='after-restart';check('afterRestart');assert corpus_hash()==corpus
        receipt.update(passed=True,phase='complete',initializerJournalUnchanged=True,corpusSha256=corpus,corpusUnchanged=True,cleanRestartVerified=True)
    print(json.dumps(receipt,indent=2))

if __name__=='__main__':
    if not __debug__:raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
