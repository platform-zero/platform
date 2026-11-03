#!/usr/bin/env python3
"""Private ERPNext native setup/customer/quotation, queued work, and restart persistence."""
import argparse
import base64
import hashlib
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
import tempfile
import uuid
from probe_receipt import private_receipt

_spec=importlib.util.spec_from_file_location('search_helpers',Path(__file__).with_name('test-private-searxng.py'))
H=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(H)
ROOT,BASE,CLI,P,ENV=H.ROOT,H.BASE,H.CLI,H.P,H.ENV


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--name',default='erpnext-r7');parser.add_argument('--fixture',type=Path);parser.add_argument('--supervised',action='store_true');args=parser.parse_args();name=args.name
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}',name)
    manifest=BASE/(name+'.json');inputs=BASE/name;fingerprint=hashlib.sha256(manifest.read_bytes()).hexdigest()
    directory=Path('/mnt/media/p0-v3/image-acquisition-receipts')/('p0v3-erp-'+uuid.uuid4().hex[:12]);directory.mkdir(mode=0o700)
    receipt={'id':directory.name,'deployment':name,'manifestSha256':fingerprint,'passed':False,'fullStackAcceptance':False,'realOwnerOnboarding':False,'publicHttpsTest':False}
    if args.fixture:
        fixture=args.fixture;assert fixture.resolve()==fixture and fixture.stat().st_uid==os.getuid() and fixture.stat().st_mode & 0o777==0o700
        assert json.loads((fixture/'receipt.json').read_text())['manifestSha256']==fingerprint and not (fixture/'state.next').exists()
        path=fixture/'state.json';assert not path.is_symlink() and path.stat().st_mode & 0o777==0o600 and path.stat().st_uid==os.getuid();state=json.loads(path.read_text())
    else:
        bootstrap=dict(line.split('=',1) for line in (inputs/'bootstrap.env').read_text().splitlines())
        state={'adminPassword':bootstrap['ADMIN_PASSWORD'],'ownerPassword':secrets.token_hex(24),'setupDone':False,'nonce':uuid.uuid4().hex[:12]}
    H.write(directory/'state.json',json.dumps(state));receipt['startedWithSetupComplete']=state['setupDone']
    cache=Path('/mnt/media/p0-v3/cache/gradle-user/caches/modules-2/files-2.1');jars=[j for a in ('driver','driver-bundle','playwright') for j in (cache/('com.microsoft.playwright/'+a+'/1.55.0')).glob('*/*.jar')]+list((cache/'com.google.code.gson/gson/2.12.1').glob('*/*.jar'));assert len(jars)==4
    def inspect(process):return json.loads(subprocess.check_output(P+['inspect','p0v3-live-'+name+'-'+process]))[0]
    def runtime(action):
        r=subprocess.run([str(CLI),'runtime',action,str(manifest)],capture_output=True,env=ENV,timeout=1200)
        if r.returncode:H.write(directory/(action+'-'+uuid.uuid4().hex[:8]+'.log'),r.stderr.decode(errors='replace'))
        assert r.returncode==0,'ERP lifecycle failed; state retained';return json.loads(r.stdout.splitlines()[0])
    def browser(label):
        d=inspect('erp');assert d['State']['Running'] and d['Config']['Labels']['io.p0v3.private-deployment']==name and not d['HostConfig']['PortBindings']
        assert set(d['NetworkSettings']['Networks'])=={'p0v3-live-'+name+'-net'}
        ip=d['NetworkSettings']['Networks']['p0v3-live-'+name+'-net']['IPAddress'];assert ipaddress.ip_address(ip).is_private
        try:
            with socket.create_connection((ip,8443),timeout=15) as raw,ssl.create_default_context().wrap_socket(raw,server_hostname='erp'):pass
        except ssl.SSLCertVerificationError:pass
        else:raise AssertionError('Untrusted private CA accepted')
        ctx=ssl.create_default_context(cafile=str(inputs/'ca.pem'))
        with socket.create_connection((ip,8443),timeout=15) as raw,ctx.wrap_socket(raw,server_hostname='erp') as tls:
            cert=tls.getpeercert(binary_form=True);assert cert==ssl.PEM_cert_to_DER_cert((inputs/'web.pem').read_text());receipt['certificateSha256']=hashlib.sha256(cert).hexdigest()
        pub=subprocess.check_output(['openssl','x509','-in',str(inputs/'web.pem'),'-pubkey','-noout']);der=subprocess.run(['openssl','pkey','-pubin','-outform','DER'],input=pub,capture_output=True,check=True).stdout
        values={'address':ip,'pin':base64.b64encode(hashlib.sha256(der).digest()).decode(),'directory':str(directory),'label':label}
        with tempfile.TemporaryDirectory(prefix='er-',dir='/mnt/media/p0-v3/cache') as scratch:
            r=subprocess.run(['sudo','-n','nsenter','--target='+str(d['State']['Pid']),'--net','--setuid='+str(os.getuid()),'--setgid='+str(os.getgid()),'/usr/bin/env','HOME='+scratch,'TMPDIR='+scratch,'/usr/lib/jvm/java-21-openjdk-amd64/bin/java','-Djava.io.tmpdir='+scratch,'--class-path',':'.join(map(str,jars)),str(ROOT/'acceptance/scripts/ErpNextBrowserProbe.java')],input=json.dumps(values),capture_output=True,text=True,timeout=600)
            H.write(directory/(label+'.log'),r.stderr);assert r.returncode==0,'Native ERP browser failed; protected fixture state retained'
            result=json.loads(r.stdout);assert result['passed'];receipt.update(result)
            receipt[label+'Actions']=json.loads((directory/(label+'-actions.json')).read_text())
    def backend_checks():
        r=subprocess.run(P+['exec','--user','999','p0v3-live-'+name+'-mariadb','/bin/sh','-ec',"MYSQL_PWD=\"$MARIADB_ROOT_PASSWORD\" mariadb --socket=/tmp/mysql.sock -u root -Nse \"SELECT COUNT(*) FROM mysql.global_priv WHERE User='frappe_installer' OR (User='root' AND Host<>'localhost');\""],capture_output=True,text=True,timeout=30);assert r.returncode==0 and r.stdout.strip()=='0'
        code="""
if not __debug__:raise SystemExit('Optimized Python refused')
import frappe,json,time,uuid
frappe.init(site='erp.private.invalid');frappe.connect();frappe.set_user('erp-owner@localhost.invalid')
from frappe.utils.scheduler import is_scheduler_inactive
assert frappe.conf.pause_scheduler == 1 and is_scheduler_inactive() and frappe.conf.disable_telemetry == 1
job=frappe.enqueue('frappe.client.get_count',doctype='Customer',queue='short',job_id='p0v3-'+uuid.uuid4().hex)
end=time.monotonic()+90
while time.monotonic()<end:
    job.refresh(); status=job.get_status(); status=getattr(status,'value',status)
    if status=='finished':
        assert int(job.result)>=1
        print(json.dumps({'finished':True,'customerCount':int(job.result)}));break
    if status in ('failed','stopped','canceled'):raise RuntimeError('Fixture queue job failed')
    time.sleep(1)
else:raise RuntimeError('Fixture queue job timeout')
frappe.destroy()
"""
        r=subprocess.run(P+['exec','--user','1000','--workdir=/home/frappe/frappe-bench/sites','p0v3-live-'+name+'-backend','/home/frappe/frappe-bench/env/bin/python','-c',code],capture_output=True,text=True,timeout=120)
        H.write(directory/('queue-'+uuid.uuid4().hex[:8]+'.log'),r.stderr);assert r.returncode==0,'Native queued job failed; diagnostics retained'
        assert json.loads(r.stdout.splitlines()[-1])['finished'];receipt.update(nativeQueuedWorkVerified=True,installerDatabasePrivilegeRetired=True,remoteDatabaseRootAbsent=True,schedulerPauseVerified=True,telemetryDisabled=True)
    with private_receipt(receipt,lambda r:H.write(directory/'receipt.json',json.dumps(r,indent=2))):
        runtime('apply-private');jobs=hashlib.sha256((inputs/'runtime.jobs').read_bytes()).hexdigest();receipt['phase']='before-restart';browser('beforeRestart');backend_checks()
        daemons=[p['id'] for p in json.loads(manifest.read_text())['processes'] if not p.get('oneShot',False)];before={p:inspect(p) for p in daemons}
        if args.supervised:
            unit='p0v3-private-'+name+'.service';subprocess.run(['systemctl','is-enabled','--quiet',unit],check=True,timeout=30);subprocess.run(['systemctl','is-active','--quiet',unit],check=True,timeout=30)
            subprocess.run(['sudo','-n','systemctl','restart',unit],capture_output=True,check=True,timeout=1200);receipt['supervisedRestartVerified']=True
        else:
            assert all(p['exitCode'] in (0,143) for p in runtime('stop-private'));runtime('apply-private')
        for process,old in before.items():
            after=inspect(process);assert after['State']['Running'] and old['Id']==after['Id'] and old['State']['StartedAt']!=after['State']['StartedAt']
        assert hashlib.sha256((inputs/'runtime.jobs').read_bytes()).hexdigest()==jobs
        receipt['phase']='after-restart';browser('afterRestart');backend_checks();receipt.update(passed=True,phase='complete',initializerJournalUnchanged=True,cleanRestartVerified=True,untrustedCaDenied=True)
    print(json.dumps(receipt,indent=2))

if __name__=='__main__':
    if not __debug__:raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
