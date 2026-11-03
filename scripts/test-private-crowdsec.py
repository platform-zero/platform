#!/usr/bin/env python3
"""Native isolated CrowdSec decisions: synthetic logs only; no firewall/public enforcement."""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import time
import uuid
from probe_receipt import private_receipt

_spec=importlib.util.spec_from_file_location('search_helpers',Path(__file__).with_name('test-private-searxng.py'))
H=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(H)
BASE,CLI,P,ENV=H.BASE,H.CLI,H.P,H.ENV


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--name',default='crowdsec-r4');parser.add_argument('--supervised',action='store_true');args=parser.parse_args();name=args.name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}',name)
    manifest=BASE/(name+'.json');inputs=BASE/name;spec=json.loads(manifest.read_text())
    directory=Path('/mnt/media/p0-v3/image-acquisition-receipts')/('p0v3-guard-'+uuid.uuid4().hex[:12]);directory.mkdir(mode=0o700)
    receipt={'id':directory.name,'deployment':name,'manifestSha256':hashlib.sha256(manifest.read_bytes()).hexdigest(),'passed':False,'fullStackAcceptance':False,'publicEnforcement':False,'hostLogIngestion':False,'centralApiSharing':False}
    container='p0v3-live-'+name+'-guard'
    def inspect():return json.loads(subprocess.check_output(P+['inspect',container]))[0]
    def runtime(action):
        r=subprocess.run([str(CLI),'runtime',action,str(manifest)],capture_output=True,env=ENV,timeout=600)
        if r.returncode:H.write(directory/(action+'.log'),r.stderr.decode(errors='replace'))
        assert r.returncode==0,'CrowdSec lifecycle failed; state retained';return json.loads(r.stdout.splitlines()[0])
    def native(*args):
        r=subprocess.run(P+['exec','--user','1000',container,'/usr/local/bin/cscli','-c','/run/secrets/crowdsec.yaml',*args],capture_output=True,text=True,timeout=60)
        H.write(directory/('native-'+uuid.uuid4().hex[:8]+'.log'),r.stderr)
        assert r.returncode==0,'Native CrowdSec operation failed; diagnostics retained'
        return r.stdout
    def address():
        d=inspect();assert d['State']['Running'] and d['Config']['Labels']['io.p0v3.private-deployment']==name and not d['HostConfig']['PortBindings']
        assert set(d['NetworkSettings']['Networks'])=={'p0v3-live-'+name+'-net'}
        ip=d['NetworkSettings']['Networks']['p0v3-live-'+name+'-net']['IPAddress'];assert ipaddress.ip_address(ip).is_private
        assert not any(m.get('Destination')=='/bootstrap' for m in d['Mounts'])
        return ip
    ctx=ssl.create_default_context(cafile=str(inputs/'ca.pem'))
    class Connection(http.client.HTTPSConnection):
        def __init__(self):super().__init__('guard',8443,timeout=15,context=ctx)
        def connect(self):self.sock=ctx.wrap_socket(socket.create_connection((address(),8443),timeout=15),server_hostname='guard')
    def api(path,key=None,method='GET',body=None):
        assert path.startswith('/v1/') and '\r' not in path and '\n' not in path
        c=Connection();headers={'Accept':'application/json'}
        if key is not None:headers['X-Api-Key']=key
        try:
            c.request(method,path,body=body,headers=headers);r=c.getresponse();data=r.read(1024*1024+1);assert len(data)<=1024*1024
            return r.status,data
        finally:c.close()
    def decisions(ip):
        status,data=api('/v1/decisions?ip='+str(ipaddress.ip_address(ip)),key);assert status==200
        result=json.loads(data);assert result is None or isinstance(result,list);return result or []
    def append(lines):
        # Fixed synthetic file; no host log mount, arbitrary path, or shell interpolation of data.
        data=''.join(datetime.now(timezone.utc).isoformat()+' '+ip+' '+str(status)+' GET /fixture/private\n' for ip,status in lines)
        subprocess.run(P+['exec','--user','1000','-i',container,'/bin/sh','-ec','cat >> /synthetic-logs/http.log'],input=data,text=True,capture_output=True,check=True,timeout=30)
    def metrics():
        c=http.client.HTTPConnection(address(),6060,timeout=10)
        try:
            c.request('GET','/metrics');r=c.getresponse();data=r.read(4*1024*1024+1);assert r.status==200 and len(data)<=4*1024*1024;return data.decode()
        finally:c.close()
    def parsed_count(text):
        return sum(float(line.rsplit(' ',1)[1]) for line in text.splitlines() if line.startswith('cs_parser_hits_ok_total{') and 'source="/synthetic-logs/http.log"' in line)
    def bucket_count(text,metric):
        return sum(float(line.rsplit(' ',1)[1]) for line in text.splitlines() if line.startswith(metric+'{') and 'name="p0v3/private-http-abuse"' in line)
    with private_receipt(receipt,lambda r:H.write(directory/'receipt.json',json.dumps(r,indent=2))):
        runtime('apply-private');jobs=hashlib.sha256((inputs/'runtime.jobs').read_bytes()).hexdigest();ip=address()
        try:
            with socket.create_connection((ip,8443),timeout=15) as raw,ssl.create_default_context().wrap_socket(raw,server_hostname='guard'):pass
        except ssl.SSLCertVerificationError:pass
        else:raise AssertionError('System CA unexpectedly trusted private certificate')
        with socket.create_connection((ip,8443),timeout=15) as raw,ctx.wrap_socket(raw,server_hostname='guard') as tls:
            cert=tls.getpeercert(binary_form=True);assert cert==ssl.PEM_cert_to_DER_cert((inputs/'web.pem').read_text());receipt['certificateSha256']=hashlib.sha256(cert).hexdigest()
        image=next(p['image'] for p in spec['processes'] if p['id']=='guard')
        key=subprocess.check_output(P+['run','--rm','--name','p0v3-guard-key-'+uuid.uuid4().hex[:12],'--pull=never','--network=none','--read-only','--cap-drop=all','--security-opt=no-new-privileges','--security-opt=apparmor=p0v3-private-v1','--user=1000:1000','--memory=128m','--pids-limit=32','--image-volume=ignore','--volume','p0v3-live-'+name+'-volume-bootstrap:/bootstrap:ro','--entrypoint=/bin/sh',image,'-ec','cat /bootstrap/bouncer-key'],timeout=60).decode().strip()
        assert re.fullmatch(r'[A-Za-z0-9_+/=-]{20,256}',key)
        receipt['phase']='authorization'
        assert api('/v1/decisions')[0] in (401,403)
        assert api('/v1/decisions',secrets.token_hex(32))[0] in (401,403)
        assert api('/v1/alerts',key)[0] in (401,403)
        assert api('/v1/decisions?ip=198.51.100.253',key,'DELETE')[0] in (401,403)
        native('lapi','status')
        for _ in range(250):
            suffix=10+secrets.randbelow(240);attack='192.0.2.'+str(suffix);benign='198.51.100.'+str(suffix);expiring='203.0.113.'+str(suffix)
            if not decisions(attack) and not decisions(benign) and not decisions(expiring):break
        else:raise AssertionError('Synthetic address pool exhausted; refusing to clear decisions')
        receipt.update(attackAddress=attack,benignAddress=benign)
        # Only benign warm-up lines may be retried while native tailing starts.
        baseline=parsed_count(metrics())
        for _ in range(20):
            append([(benign,200)]);time.sleep(1);text=metrics()
            if parsed_count(text)>baseline:break
        else:
            H.write(directory/'metrics.txt',text);raise AssertionError('Native parser did not consume synthetic warm-up')
        assert 'cs_features{feature="capi"} 0' in text and 'cs_features{feature="papi"} 0' in text
        receipt['phase']='threshold';baseline=parsed_count(text)
        poured= bucket_count(text,'cs_bucket_poured_total');overflows=bucket_count(text,'cs_bucket_overflowed_total')
        append([(attack,401)]*2+[(benign,200)]*5)
        end=time.monotonic()+15
        while time.monotonic()<end:
            text=metrics()
            if parsed_count(text)>=baseline+7 and bucket_count(text,'cs_bucket_poured_total')>=poured+2:break
            time.sleep(.5)
        else:raise AssertionError('Threshold fixture was not fully parsed')
        time.sleep(3);text=metrics();H.write(directory/'below-threshold-metrics.txt',text)
        assert bucket_count(text,'cs_bucket_overflowed_total')==overflows,'Bucket overflowed below the declared threshold'
        assert not decisions(attack) and not decisions(benign),'Below-threshold or benign traffic was banned'
        append([(attack,401)])
        end=time.monotonic()+90
        while time.monotonic()<end:
            found=decisions(attack)
            if found:break
            time.sleep(1)
        else:
            H.write(directory/'metrics.txt',metrics());raise AssertionError('Native scenario did not produce a decision')
        text=metrics();H.write(directory/'decision-metrics.txt',text)
        assert bucket_count(text,'cs_bucket_overflowed_total')==overflows+1
        assert len(found)==1;decision=found[0]
        assert decision['value']==attack and decision['type']=='ban' and decision['scope']=='Ip' and decision['scenario']=='p0v3/private-http-abuse'
        assert not decisions(benign);receipt['decisionId']=decision['id']
        H.write(directory/'decision.json',json.dumps(decision,indent=2))
        receipt['phase']='revocation';temporary='fixture-'+uuid.uuid4().hex[:12];revoked=False
        try:
            temporary_key=native('bouncers','add',temporary,'-o','raw').strip();assert re.fullmatch(r'[A-Za-z0-9_+/=-]{20,256}',temporary_key)
            assert api('/v1/decisions?ip='+attack,temporary_key)[0]==200
            native('decisions','add','--ip',expiring,'--duration','10s','--reason','private-expiry-fixture')
            assert len(decisions(expiring))==1
            status,data=api('/v1/decisions/stream?startup=true',temporary_key);assert status==200
            stream=json.loads(data);assert any(d['value']==attack and d['id']==decision['id'] for d in stream['new'])
            assert any(d['value']==expiring for d in stream['new'])
            end=time.monotonic()+60
            while time.monotonic()<end:
                if not decisions(expiring):break
                time.sleep(1)
            else:raise AssertionError('Native short-lived decision did not expire')
            status,data=api('/v1/decisions/stream?startup=false',temporary_key);assert status==200
            assert any(d['value']==expiring for d in json.loads(data)['deleted'])
            receipt.update(nativeDecisionStreamVerified=True,nativeExpiryVerified=True)
            native('bouncers','delete',temporary);revoked=True
            end=time.monotonic()+60
            while time.monotonic()<end:
                if api('/v1/decisions',temporary_key)[0] in (401,403):break
                time.sleep(1)
            else:raise AssertionError('Revoked bouncer retained API access')
        finally:
            if not revoked:native('bouncers','delete',temporary)
        before=inspect();receipt['phase']='restart'
        if args.supervised:
            unit='p0v3-private-'+name+'.service';subprocess.run(['systemctl','is-enabled','--quiet',unit],check=True,timeout=30);subprocess.run(['systemctl','is-active','--quiet',unit],check=True,timeout=30)
            subprocess.run(['sudo','-n','systemctl','restart',unit],capture_output=True,check=True,timeout=600);receipt['supervisedRestartVerified']=True
        else:
            assert all(p['exitCode']==0 for p in runtime('stop-private'));runtime('apply-private')
        after=inspect();assert after['State']['Running'] and before['Id']==after['Id'] and before['State']['StartedAt']!=after['State']['StartedAt']
        assert hashlib.sha256((inputs/'runtime.jobs').read_bytes()).hexdigest()==jobs
        restored=decisions(attack);assert len(restored)==1 and restored[0]['id']==decision['id'] and restored[0]['scenario']==decision['scenario'] and not decisions(benign)
        assert api('/v1/decisions',temporary_key)[0] in (401,403) and not decisions(expiring)
        receipt.update(passed=True,phase='complete',nativeParserAndThreshold=True,benignTrafficNotBanned=True,anonymousAndInvalidKeyDenied=True,bouncerAdministrationDenied=True,bouncerRevocationVerified=True,persistentDecisionVerified=True,initializerJournalUnchanged=True,untrustedCaDenied=True)
    print(json.dumps(receipt,indent=2))

if __name__=='__main__':
    if not __debug__:raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
