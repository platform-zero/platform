#!/usr/bin/env python3
"""Fenced encrypted search-corpus/configuration recovery into a new isolated deployment."""
import fcntl
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import urllib.parse
import uuid
from probe_receipt import private_receipt

spec=importlib.util.spec_from_file_location('search_probe',Path(__file__).with_name('test-private-searxng.py'))
S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
ROOT,BASE,CLI,P,ENV=S.ROOT,S.BASE,S.CLI,S.P,S.ENV
INVENTORY=ROOT/'platform/release/downloaded-candidate-inventory.json'
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    source='searxng-r2';nonce=uuid.uuid4().hex[:12];target='sxrestore-'+nonce
    directory=Path('/mnt/media/p0-v3/image-acquisition-receipts')/('p0v3-search-restore-'+nonce);directory.mkdir(mode=0o700)
    snapshot=directory/'snapshot';export=directory/'export';snapshot.mkdir(mode=0o700);export.mkdir(mode=0o700)
    source_path=BASE/(source+'.json');source_bytes=source_path.read_bytes();source_spec=json.loads(source_bytes);source_hash=digest(source_path)
    assert not (BASE/(target+'.json')).exists() and not (BASE/target).exists()
    assert source_spec['volumes']==[{'id':'corpus','userId':977}]
    unit='p0v3-private-'+source+'.service';unit_path=Path('/etc/systemd/system')/unit
    assert not unit_path.is_symlink() and unit_path.stat().st_uid==0
    assert re.search(r'^ExecStart=/mnt/media/p0-v3/runtime-supervision/releases/[a-f0-9]{64}/bin/p0-v3-platform runtime boot-apply '+source+' '+source_hash+'$',unit_path.read_text(),re.M)
    images=json.loads(INVENTORY.read_text())['images'];image=next(i['pinnedImage'] for i in images if i['product']=='searxng');kopia_image=next(i['pinnedImage'] for i in images if i['product']=='kopia')
    repo=directory.name+'-repository';config=directory.name+'-config';S.write(directory/'kopia.env','KOPIA_PASSWORD='+secrets.token_hex(32)+'\n')
    receipt={'id':directory.name,'source':source,'restore':target,'passed':False,'fullStackAcceptance':False,'offHostBackup':False,'publicSearchTest':False,'sourceManifestSha256':source_hash}
    lock=None;fence=None;maintenance=False
    def run(command,data=None,ok=True):
        r=subprocess.run(command,input=data,capture_output=True,env=ENV,timeout=1200)
        if ok and r.returncode:
            S.write(directory/('failure-'+uuid.uuid4().hex[:8]+'.log'),r.stderr.decode(errors='replace'))
            raise RuntimeError('Search recovery operation failed; protected diagnostics retained')
        return r.stdout if ok else r
    def runtime(action,name):return json.loads(run([str(CLI),'runtime',action,str(BASE/(name+'.json'))]).splitlines()[0])
    def system(*args):return run(['sudo','-n','systemctl',*args,unit])
    def inspect(name,process):return json.loads(run(P+['inspect','p0v3-live-'+name+'-'+process]))[0]
    def volume(name,readonly,command,data=None,ok=True):
        return run(P+['run','--rm','--interactive','--pull=never','--network=none','--read-only','--cap-drop=all','--security-opt=no-new-privileges','--security-opt=apparmor=p0v3-private-v1','--user=977:977','--memory=512m','--pids-limit=128','--image-volume=ignore','--tmpfs=/tmp:rw,nosuid,nodev,size=64m','--volume','p0v3-live-'+name+'-volume-corpus:/corpus:'+('ro' if readonly else 'rw'),'--entrypoint=/bin/sh',image,'-ec',command],data,ok)
    def blob(name):
        result=volume(name,True,'test ! -L /corpus/documents.db; test "$(stat -c %s /corpus/documents.db)" -le 16777216; cat /corpus/documents.db')
        assert 0<len(result)<=16777216;return result
    def release():
        nonlocal fence
        if fence is None:
            assert runtime('maintenance-status',source) is None,'Uncertain maintenance identity; source remains fenced'
            return
        runtime('stop-private',source)
        run([str(CLI),'runtime','maintenance-leave',str(source_path),fence['id']]);fence=None
    def insert(name,word):
        assert re.fullmatch('[a-z0-9]+',word)
        code="import sqlite3,sys,json; d=json.load(sys.stdin); c=sqlite3.connect('/corpus/documents.db'); c.execute('INSERT INTO documents(title,url,content) VALUES(?,?,?)',d); c.commit(); c.close()"
        run(P+['exec','--interactive','--user','977','p0v3-live-'+name+'-searxng','/usr/local/searxng/.venv/bin/python','-c',code],json.dumps([word,'https://example.invalid/fixture/'+word,'Synthetic recovery record '+word]).encode())
    def search(name,word):
        d=inspect(name,'search');assert d['State']['Running'] and d['Config']['Labels']['io.p0v3.private-deployment']==name
        assert set(d['NetworkSettings']['Networks'])=={'p0v3-live-'+name+'-net'}
        address=d['NetworkSettings']['Networks']['p0v3-live-'+name+'-net']['IPAddress'];ctx=ssl.create_default_context(cafile=str(BASE/name/'ca.pem'))
        connection=http.client.HTTPConnection('search',8443,timeout=15);connection.sock=ctx.wrap_socket(socket.create_connection((address,8443),timeout=15),server_hostname='search')
        try:
            connection.request('GET','/search?'+urllib.parse.urlencode({'q':word,'format':'json'}));r=connection.getresponse();assert r.status==200
            data=json.loads(r.read(1048576));assert not data['unresponsive_engines'];return [item['title'] for item in data['results']]
        finally:connection.close()
    def kopia(*args,password_file=None,configuration='/config/repository.config',ok=True):
        return run(P+['run','--rm','--pull=never','--network=none','--read-only','--cap-drop=all','--security-opt=no-new-privileges','--security-opt=apparmor=p0v3-private-v1','--user=1000:1000','--memory=1024m','--pids-limit=256','--image-volume=ignore','--tmpfs=/tmp:rw,nosuid,nodev,size=128m','--volume',repo+':/repository:U','--volume',config+':/config:U','--volume',str(snapshot)+':/snapshot:ro','--volume',str(export)+':/restore:rw','--env-file',str(password_file or directory/'kopia.env'),'--env=HOME=/tmp','--env=KOPIA_CACHE_DIRECTORY=/tmp/cache',kopia_image,'--config-file='+configuration,'--disable-file-logging',*args],ok=ok)
    with private_receipt(receipt,lambda r:S.write(directory/'receipt.json',json.dumps(r,indent=2))):
        try:
            assert system('is-enabled').strip()==b'enabled' and system('is-active').strip()==b'active'
            runtime('apply-private',source)
            old='snapshot'+nonce;new='source'+nonce;restored='restored'+nonce
            insert(source,old);assert search(source,old)==[old]
            jobs=digest(BASE/source/'runtime.jobs');receipt['phase']='fenced-capture'
            maintenance=True;system('disable','--now');assert runtime('maintenance-status',source) is None
            fence=json.loads(run([str(CLI),'runtime','maintenance-enter',str(source_path),'backup']))
            assert run([str(CLI),'runtime','apply-private',str(source_path)],ok=False).returncode!=0
            lock=(BASE/source/'runtime.lock').open('r+b');fcntl.lockf(lock,fcntl.LOCK_EX)
            frozen={p['id']:inspect(source,p['id']) for p in source_spec['processes']};assert all(not d['State']['Running'] for d in frozen.values())
            inputs={p['environmentFile'] for p in source_spec['processes'] if p.get('environmentFile')}|{f['file'] for p in source_spec['processes'] for f in p.get('files',[])}
            S.write(snapshot/'source-spec.json',source_bytes.decode())
            for name in inputs:
                path=BASE/source/name;assert not path.is_symlink() and path.stat().st_mode & 0o777==0o600
                S.write(snapshot/name,path.read_text())
            # This adapter captures one quiesced SQLite file, never silently discarding WAL/journals or extra state.
            volume(source,True,'test "$(ls -A /corpus)" = documents.db')
            captured=blob(source)
            with os.fdopen(os.open(snapshot/'documents.db',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as f:f.write(captured);f.flush();os.fsync(f.fileno())
            hashes={p.name:digest(p) for p in snapshot.iterdir()};S.write(snapshot/'manifest.json',json.dumps(hashes,sort_keys=True));receipt['archiveManifestSha256']=digest(snapshot/'manifest.json')
            for name in (repo,config):
                assert run(P+['volume','exists',name],ok=False).returncode==1
                run(P+['volume','create','--label=io.p0v3.restore-probe='+directory.name,name])
            kopia('repository','create','filesystem','--path=/repository','--no-check-for-updates')
            snapshot_id=json.loads(kopia('snapshot','create','--json','/snapshot'))['rootEntry']['obj'];receipt['snapshotId']=snapshot_id
            kopia('snapshot','verify','--verify-files-percent=100')
            S.write(directory/'wrong-password.env','KOPIA_PASSWORD=wrong-'+nonce+'\n')
            denied=kopia('repository','connect','filesystem','--path=/repository','--no-check-for-updates',password_file=directory/'wrong-password.env',configuration='/tmp/wrong.config',ok=False)
            assert denied.returncode!=0 and b'invalid repository password' in denied.stderr.lower()
            receipt['wrongRepositoryPasswordDenied']=True
            kopia('snapshot','restore','--no-overwrite-files','--no-overwrite-directories','--no-overwrite-symlinks','--skip-owners','--flush-files',snapshot_id,'/restore/recovered')
            assert blob(source)==captured and digest(source_path)==source_hash and digest(BASE/source/'runtime.jobs')==jobs
            for name in inputs:assert digest(BASE/source/name)==hashes[name]
            for name,before in frozen.items():
                after=inspect(source,name);assert before['Id']==after['Id'] and before['State']['StartedAt']==after['State']['StartedAt'] and not after['State']['Running']
            lock.close();lock=None;release();system('enable','--now');maintenance=False
            insert(source,new);assert search(source,new)==[new]
            recovered=export/'recovered';assert not recovered.is_symlink() and digest(recovered/'manifest.json')==receipt['archiveManifestSha256']
            assert {p.name for p in recovered.iterdir()}==set(hashes)|{'manifest.json'}
            for name,checksum in hashes.items():
                path=recovered/name;assert path.is_file() and not path.is_symlink() and digest(path)==checksum;path.chmod(0o600)
            recovered.chmod(0o700)
            run([str(CLI),'runtime','prepare-searxng-restore',str(INVENTORY),str(recovered),target]);runtime('provision-private',target)
            guard=json.loads((BASE/(target+'.json')).read_text())['processes'][0]['command'][-1]
            restored_blob=(recovered/'documents.db').read_bytes()
            receipt['phase']='guarded-import'
            with (BASE/target/'runtime.lock').open('r+b') as target_lock:
                fcntl.lockf(target_lock,fcntl.LOCK_EX)
                assert volume(target,True,guard,ok=False).returncode!=0
                volume(target,False,'test -z "$(ls -A /corpus)"; umask 077; touch /corpus/.restore-in-progress; cat > /corpus/documents.db; sync',restored_blob)
                assert volume(target,True,guard,ok=False).returncode!=0
                assert blob(target)==captured
                volume(target,False,'rm /corpus/.restore-in-progress; ln -s nonexistent /corpus/.restore-in-progress')
                assert volume(target,True,guard,ok=False).returncode!=0
                volume(target,False,"printf '%s\\n' wrong-manifest > /corpus/.p0v3-restore-complete; rm /corpus/.restore-in-progress; sync")
                assert volume(target,True,guard,ok=False).returncode!=0
                volume(target,False,"rm /corpus/.p0v3-restore-complete; printf '%s\\n' "+source_hash+" > /corpus/foreign-marker; ln -s foreign-marker /corpus/.p0v3-restore-complete; sync")
                assert volume(target,True,guard,ok=False).returncode!=0
                volume(target,False,"rm /corpus/.p0v3-restore-complete /corpus/foreign-marker; printf '%s\\n' "+source_hash+" > /corpus/.p0v3-restore-complete; sync")
                volume(target,True,guard)
            runtime('apply-private',target);assert search(target,old)==[old] and search(target,new)==[]
            receipt['phase']='restored-native-browser'
            result=json.loads(run(['python3',str(ROOT/'platform/scripts/test-private-searxng.py'),'--name',target]));assert result['passed'] and result['phase']=='complete' and result['nativeBrowserSearch'];receipt['restoredBrowserReceipt']=result['id']
            insert(target,restored);assert search(target,restored)==[restored] and search(source,restored)==[]
            runtime('stop-private',target);runtime('apply-private',target)
            system('restart');assert digest(BASE/source/'runtime.jobs')==jobs
            assert system('is-enabled').strip()==b'enabled' and system('is-active').strip()==b'active' and runtime('maintenance-status',source) is None
            assert search(source,old)==[old] and search(source,restored)==[]
            assert search(target,old)==[old] and search(target,restored)==[restored] and search(target,new)==[] and search(source,new)==[new]
            data=inspect(target,'search')
            for process,port in (('search',8443),('searxng',8080)):
                d=inspect(source,process);ip=d['NetworkSettings']['Networks']['p0v3-live-'+source+'-net']['IPAddress']
                code='import socket; s=socket.socket(); s.settimeout(3); assert s.connect_ex(('+repr(ip)+','+str(port)+'))!=0'
                run(['sudo','-n','nsenter','--target='+str(data['State']['Pid']),'--net','--setuid='+str(os.getuid()),'--setgid='+str(os.getgid()),'/usr/bin/python3','-c',code])
            receipt.update(passed=True,phase='complete',durableSourceFence=True,encryptedExportVerified=True,missingIncompleteForeignMarkerDenied=True,symlinkMarkersDenied=True,nativeRestoredSearch=True,postSnapshotWriteExcluded=True,divergentWritesIsolated=True,sourceTcpBlocked=True,restoredRestartVerified=True,sourceSupervisedRestartVerified=True)
        finally:
            if lock:lock.close()
            cleanup_failed=False
            if maintenance:
                try:release();system('enable','--now')
                except Exception:cleanup_failed=True;receipt['sourceResumeFailed']=True
            if (BASE/(target+'.json')).exists():
                try:assert all(p['state']!='running' for p in runtime('stop-private',target))
                except Exception:cleanup_failed=True;receipt['restoreQuarantineFailed']=True
            if cleanup_failed:raise RuntimeError('Recovery cleanup incomplete; retained state requires review')
    print(json.dumps(receipt,indent=2))

if __name__=='__main__':
    if not __debug__:raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
