#!/usr/bin/env python3
"""Coordinated fenced Seafile SQL/files/identity recovery, isolated from the active source."""
if not __debug__:raise SystemExit('Optimized Python disables safety checks; refusing effects')
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import uuid
from financial_restore_archive import inventory as tar_inventory
from probe_receipt import private_receipt
from seafile_recovery_client import Client, F, BASE, CLI, P, ENV, ROOT

INVENTORY=ROOT/'platform/release/downloaded-candidate-inventory.json'
LIMIT=128*1024*1024

def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def write_bytes(path,data):
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as out:
        out.write(data);out.flush();os.fsync(out.fileno())


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--fixture',type=Path,required=True);args=parser.parse_args()
    fixture_dir=args.fixture;assert fixture_dir.is_absolute() and fixture_dir.resolve()==fixture_dir and fixture_dir.stat().st_uid==os.getuid() and fixture_dir.stat().st_mode & 0o777==0o700
    receipt_path=fixture_dir/'receipt.json';assert not receipt_path.is_symlink() and receipt_path.stat().st_uid==os.getuid() and receipt_path.stat().st_mode & 0o777==0o600
    invalidation=fixture_dir/'receipt-invalidated.json'
    fixture_receipt=json.loads(receipt_path.read_text());assert fixture_receipt['passed'] and fixture_receipt['phase']=='complete' and not invalidation.exists() and not invalidation.is_symlink()
    fixture_path=fixture_dir/'fixture.json';assert not fixture_path.is_symlink() and fixture_path.stat().st_mode & 0o777==0o600
    fixture=json.loads(fixture_path.read_text());source='seafile-r4';assert fixture_receipt['deployment']==source
    nonce=uuid.uuid4().hex[:12];target='sfrestore-'+nonce;source_path=BASE/(source+'.json');source_spec=json.loads(source_path.read_text());source_hash=digest(source_path)
    assert fixture_receipt['manifestSha256']==source_hash and not (BASE/(target+'.json')).exists() and not (BASE/target).exists()
    directory=Path('/mnt/media/p0-v3/image-acquisition-receipts')/('p0v3-files-restore-'+nonce);directory.mkdir(mode=0o700)
    snapshot=directory/'snapshot';export=directory/'export';snapshot.mkdir(mode=0o700);export.mkdir(mode=0o700)
    unit='p0v3-private-'+source+'.service';unit_path=Path('/etc/systemd/system')/unit
    assert not unit_path.is_symlink() and unit_path.stat().st_uid==0
    assert re.search(r'^ExecStart=/mnt/media/p0-v3/runtime-supervision/releases/[a-f0-9]{64}/bin/p0-v3-platform runtime boot-apply '+source+' '+source_hash+'$',unit_path.read_text(),re.M)
    images=json.loads(INVENTORY.read_text())['images'];image=next(i['pinnedImage'] for i in images if i['product']=='seafile');kopia_image=next(i['pinnedImage'] for i in images if i['product']=='kopia')
    repo=directory.name+'-repository';config=directory.name+'-config';F.H.write(directory/'kopia.env','KOPIA_PASSWORD='+secrets.token_hex(32)+'\n')
    receipt={'id':directory.name,'source':source,'restore':target,'sourceManifestSha256':source_hash,'passed':False,'fullStackAcceptance':False,'offHostBackup':False,'officeEditingTest':False,'activeSessionRecovery':False}
    fences={};lock=None;maintenance=False;source_share=False;source_revoke_attempted=False
    def run(command,data=None,ok=True):
        r=subprocess.run(command,input=data,capture_output=True,env=ENV,timeout=1200)
        if ok and r.returncode:
            F.H.write(directory/('failure-'+uuid.uuid4().hex[:8]+'.log'),r.stderr.decode(errors='replace'))
            raise RuntimeError('File recovery operation failed; protected diagnostics retained')
        return r.stdout if ok else r
    def runtime(action,name):return json.loads(run([str(CLI),'runtime',action,str(BASE/(name+'.json'))]).splitlines()[0])
    def system(*args):return run(['sudo','-n','systemctl',*args,unit])
    def inspect(name,process):return json.loads(run(P+['inspect','p0v3-live-'+name+'-'+process]))[0]
    def fence(name,reason):
        assert runtime('maintenance-status',name) is None
        fences[name]=json.loads(run([str(CLI),'runtime','maintenance-enter',str(BASE/(name+'.json')),reason,'mariadb']))
    def release(name):
        # Quarantine even when a fence identity is uncertain; never release an unknown generation.
        runtime('stop-private',name)
        if name not in fences:
            assert runtime('maintenance-status',name) is None,'Unknown fence identity; retained for review'
            return
        run([str(CLI),'runtime','maintenance-leave',str(BASE/(name+'.json')),fences[name]['id']]);del fences[name]
    def stage(name):return json.loads(run([str(CLI),'runtime','stage-private',str(BASE/(name+'.json')),'mariadb']).splitlines()[0])
    def volume(name,readonly,command,data=None,ok=True):
        return run(P+['run','--rm','--interactive','--pull=never','--network=none','--read-only','--cap-drop=all','--security-opt=no-new-privileges','--security-opt=apparmor=p0v3-private-v1','--user=1000:1000','--memory=512m','--pids-limit=128','--image-volume=ignore','--tmpfs=/tmp:rw,nosuid,nodev,size=64m','--volume','p0v3-live-'+name+'-volume-state:/state:'+('ro' if readonly else 'rw'),'--entrypoint=/bin/sh',image,'-ec',command],data,ok)
    def capture(name,path):
        data=volume(name,True,'test "$(du --apparent-size -sm /state | cut -f1)" -le 128; tar -cf - -C /state . | head -c 134217729')
        assert 0<len(data)<=LIMIT;write_bytes(path,data);return tar_inventory(path,max_entries=100000,max_bytes=LIMIT)
    def sql(name,statement=None,dump=False):
        command='MYSQL_PWD="$MARIADB_ROOT_PASSWORD" '
        command+=('mariadb-dump --socket=/tmp/mysql.sock -u root --single-transaction --hex-blob --skip-comments --no-create-db --databases ccnet_db seafile_db seahub_db' if dump else 'mariadb --socket=/tmp/mysql.sock -u root --binary-mode --default-character-set=utf8mb4')
        return run(P+['exec','--interactive','--user','999','p0v3-live-'+name+'-mariadb','/bin/sh','-ec',command],statement)
    def kopia(*args,password_file=None,configuration='/config/repository.config',ok=True):
        return run(P+['run','--rm','--pull=never','--network=none','--read-only','--cap-drop=all','--security-opt=no-new-privileges','--security-opt=apparmor=p0v3-private-v1','--user=1000:1000','--memory=1024m','--pids-limit=256','--image-volume=ignore','--tmpfs=/tmp:rw,nosuid,nodev,size=128m','--volume',repo+':/repository:U','--volume',config+':/config:U','--volume',str(snapshot)+':/snapshot:ro','--volume',str(export)+':/restore:rw','--env-file',str(password_file or directory/'kopia.env'),'--env=HOME=/tmp','--env=KOPIA_CACHE_DIRECTORY=/tmp/cache',kopia_image,'--config-file='+configuration,'--disable-file-logging',*args],ok=ok)
    def validate(client,expected_reader):
        assert hashlib.sha256(client.download(fixture['repo'],fixture['filename'])).hexdigest()==fixture['sha256']
        assert client.download(fixture['repo'],'browser.txt')==b'Native browser upload: synthetic only.\n'
        if expected_reader:
            assert hashlib.sha256(client.download(fixture['repo'],fixture['filename'],'reader')).hexdigest()==fixture['sha256']
            assert client.request('/api2/repos/'+fixture['repo']+'/upload-link/','reader')[0] in (403,404)
        else:assert client.file_status(fixture['repo'],fixture['filename'],'reader') in (403,404)
        assert client.file_status(fixture['repo'],fixture['filename'],'outsider') in (403,404)
    with private_receipt(receipt,lambda r:F.H.write(directory/'receipt.json',json.dumps(r,indent=2))):
        try:
            assert system('is-enabled').strip()==b'enabled' and system('is-active').strip()==b'active'
            runtime('apply-private',source);active=Client(source);active.login();validate(active,False)
            old='snapshot-'+nonce+'.txt';new='source-'+nonce+'.txt';recovered_name='restored-'+nonce+'.txt'
            active.upload(fixture['repo'],old,old.encode());source_share=True;active.share(fixture['repo'],True);validate(active,True)
            assert active.download(fixture['repo'],old)==old.encode()
            jobs=digest(BASE/source/'runtime.jobs');receipt['phase']='fenced-capture';maintenance=True
            system('disable','--now');fence(source,'backup')
            assert run([str(CLI),'runtime','apply-private',str(source_path)],ok=False).returncode!=0
            stage(source);lock=(BASE/source/'runtime.lock').open('r+b');fcntl.lockf(lock,fcntl.LOCK_EX)
            frozen={p['id']:inspect(source,p['id']) for p in source_spec['processes']}
            assert all(d['State']['Running']==(name=='mariadb') for name,d in frozen.items())
            input_names={p['environmentFile'] for p in source_spec['processes'] if p.get('environmentFile')}|{f['file'] for p in source_spec['processes'] for f in p.get('files',[])}
            F.H.write(snapshot/'source-spec.json',source_path.read_text());F.H.write(snapshot/'fixture.json',json.dumps(fixture))
            for name in input_names:
                path=BASE/source/name;assert not path.is_symlink() and path.stat().st_mode & 0o777==0o600
                F.H.write(snapshot/name,path.read_text())
            dump=sql(source,dump=True);assert 0<len(dump)<=LIMIT;write_bytes(snapshot/'databases.sql',dump)
            tree=capture(source,snapshot/'state.tar');assert not any('.restore-in-progress' in name or '.p0v3-' in name for name in tree)
            hashes={p.name:digest(p) for p in snapshot.iterdir()};F.H.write(snapshot/'manifest.json',json.dumps(hashes,sort_keys=True));receipt['archiveManifestSha256']=digest(snapshot/'manifest.json')
            descriptor=os.open(snapshot,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:os.fsync(descriptor)
            finally:os.close(descriptor)
            for name in (repo,config):
                assert run(P+['volume','exists',name],ok=False).returncode==1
                run(P+['volume','create','--label=io.p0v3.restore-probe='+directory.name,name])
            kopia('repository','create','filesystem','--path=/repository','--no-check-for-updates')
            snapshot_id=json.loads(kopia('snapshot','create','--json','/snapshot'))['rootEntry']['obj'];receipt['snapshotId']=snapshot_id
            kopia('snapshot','verify','--verify-files-percent=100')
            F.H.write(directory/'wrong-password.env','KOPIA_PASSWORD=wrong-'+nonce+'\n')
            denied=kopia('repository','connect','filesystem','--path=/repository','--no-check-for-updates',password_file=directory/'wrong-password.env',configuration='/tmp/wrong.config',ok=False)
            assert denied.returncode!=0 and b'invalid repository password' in denied.stderr.lower()
            kopia('snapshot','restore','--no-overwrite-files','--no-overwrite-directories','--no-overwrite-symlinks','--skip-owners','--flush-files',snapshot_id,'/restore/recovered')
            assert capture(source,directory/'frozen-state.tar')==tree and digest(source_path)==source_hash and digest(BASE/source/'runtime.jobs')==jobs
            for name in input_names:assert digest(BASE/source/name)==hashes[name]
            for name,before in frozen.items():
                after=inspect(source,name);assert before['Id']==after['Id'] and before['State']['StartedAt']==after['State']['StartedAt'] and after['State']['Running']==(name=='mariadb')
            lock.close();lock=None;release(source);system('enable','--now');maintenance=False
            active=Client(source);active.login();source_revoke_attempted=True;active.share(fixture['repo'],False);source_share=False
            active.upload(fixture['repo'],new,new.encode());validate(active,False)
            recovered=export/'recovered';assert not recovered.is_symlink() and digest(recovered/'manifest.json')==receipt['archiveManifestSha256']
            assert {p.name for p in recovered.iterdir()}==set(hashes)|{'manifest.json'}
            for name,checksum in hashes.items():
                path=recovered/name;assert path.is_file() and not path.is_symlink() and digest(path)==checksum;path.chmod(0o600)
            recovered.chmod(0o700);assert tar_inventory(recovered/'state.tar',max_entries=100000,max_bytes=LIMIT)==tree
            run([str(CLI),'runtime','prepare-seafile-restore',str(INVENTORY),str(recovered),target]);runtime('provision-private',target)
            target_spec=json.loads((BASE/(target+'.json')).read_text());guard=next(p for p in target_spec['processes'] if p['id']=='schema-init')['command'][1].split('; exec /usr/bin/python3')[0]
            assert volume(target,True,guard,ok=False).returncode!=0
            stage(target);fence(target,'restore');stage(target)
            assert run([str(CLI),'runtime','apply-private',str(BASE/(target+'.json'))],ok=False).returncode!=0
            receipt['phase']='guarded-import'
            with (BASE/target/'runtime.lock').open('r+b') as target_lock:
                fcntl.lockf(target_lock,fcntl.LOCK_EX)
                running=run(P+['ps','--filter','label=io.p0v3.private-deployment='+target,'--format','{{.Names}}']).decode().splitlines()
                assert running==['p0v3-live-'+target+'-mariadb']
                # Native SQL import is only allowed into the freshly bootstrapped empty app databases.
                empty=sql(target,b"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema IN ('ccnet_db','seafile_db','seahub_db');\n")
                assert empty.decode().splitlines()[-1]=='0'
                volume(target,False,'test -z "$(ls -A /state)"; umask 077; touch /state/.restore-in-progress; tar --no-same-owner --same-permissions -xf - -C /state; sync',(recovered/'state.tar').read_bytes())
                assert volume(target,True,guard,ok=False).returncode!=0
                actual=capture(target,directory/'imported-state.tar');assert {k:v for k,v in actual.items() if k!='.restore-in-progress'}==tree
                sql(target,(recovered/'databases.sql').read_bytes())
                volume(target,False,"printf '%s\\n' "+source_hash+" > /state/.p0v3-restore-complete; printf '%s\\n' "+source_hash+" > /state/.p0v3-database-import-complete; sync")
                # Valid completion records isolate each pending-marker test from missing-marker failures.
                assert volume(target,True,guard,ok=False).returncode!=0
                volume(target,False,'rm /state/.restore-in-progress; ln -s missing /state/.restore-in-progress')
                assert volume(target,True,guard,ok=False).returncode!=0
                volume(target,False,"rm /state/.restore-in-progress; printf '%s\\n' wrong > /state/.p0v3-restore-complete; printf '%s\\n' "+source_hash+" > /state/.p0v3-database-import-complete")
                assert volume(target,True,guard,ok=False).returncode!=0
                volume(target,False,"rm /state/.p0v3-restore-complete; ln -s .p0v3-database-import-complete /state/.p0v3-restore-complete")
                assert volume(target,True,guard,ok=False).returncode!=0
                volume(target,False,"rm /state/.p0v3-restore-complete; printf '%s\\n' "+source_hash+" > /state/.p0v3-restore-complete; printf '%s\\n' wrong > /state/.p0v3-database-import-complete; sync")
                assert volume(target,True,guard,ok=False).returncode!=0
                volume(target,False,'rm /state/.p0v3-database-import-complete; ln -s .p0v3-restore-complete /state/.p0v3-database-import-complete')
                assert volume(target,True,guard,ok=False).returncode!=0
                volume(target,False,"rm /state/.p0v3-database-import-complete; printf '%s\\n' "+source_hash+" > /state/.p0v3-database-import-complete; sync")
                volume(target,True,guard)
            release(target);runtime('apply-private',target);restored=Client(target);restored.login();validate(restored,True)
            assert restored.download(fixture['repo'],old)==old.encode() and restored.file_status(fixture['repo'],new)==404
            receipt['phase']='native-restored-journeys';restored.browser(fixture,directory,'restored')
            restored.upload(fixture['repo'],recovered_name,recovered_name.encode())
            assert restored.download(fixture['repo'],recovered_name,'reader')==recovered_name.encode() and active.file_status(fixture['repo'],recovered_name)==404
            restored_jobs=digest(BASE/target/'runtime.jobs')
            before_restart={(name,p['id']):inspect(name,p['id']) for name in (source,target) for p in source_spec['processes'] if not p.get('oneShot',False)}
            assert all(p['state']!='running' for p in runtime('stop-private',target))
            runtime('apply-private',target);system('restart')
            for (name,process),before in before_restart.items():
                after=inspect(name,process);assert after['Id']==before['Id'] and after['State']['Running'] and after['State']['StartedAt']!=before['State']['StartedAt']
            assert digest(BASE/target/'runtime.jobs')==restored_jobs and digest(BASE/source/'runtime.jobs')==jobs
            active=Client(source);active.login();restored=Client(target);restored.login();validate(active,False);validate(restored,True)
            assert active.download(fixture['repo'],new)==new.encode() and restored.file_status(fixture['repo'],new)==404
            assert restored.download(fixture['repo'],recovered_name)==recovered_name.encode() and active.file_status(fixture['repo'],recovered_name)==404
            restored.browser(fixture,directory,'restored-after-restart')
            target_pid=restored.inspect()['State']['Pid']
            for process,port in (('files',8443),('backend',8000),('backend',8082),('mariadb',3306),('cache',6379)):
                address=active.address(process)
                code='import socket; s=socket.socket(); s.settimeout(3); raise SystemExit(0 if s.connect_ex(('+repr(address)+','+str(port)+'))!=0 else 1)'
                run(['sudo','-n','nsenter','--target='+str(target_pid),'--net','--setuid='+str(os.getuid()),'--setgid='+str(os.getgid()),'/usr/bin/python3','-c',code])
            assert system('is-enabled').strip()==b'enabled' and system('is-active').strip()==b'active' and runtime('maintenance-status',source) is None
            receipt.update(passed=True,phase='complete',durableSourceAndTargetFences=True,encryptedExportVerified=True,wrongRepositoryPasswordDenied=True,guardRejectionVerified=True,symlinkMarkersDenied=True,nativeRestoredBrowser=True,threeDatabaseAndFileRecovery=True,postSnapshotWriteExcluded=True,snapshotPermissionsRecovered=True,sourcePermissionRevocationIsolated=True,divergentWritesIsolated=True,sourceTcpBlocked=True,restoredRestartVerified=True,sourceSupervisedRestartVerified=True,ephemeralCacheAndRpcRecreated=True)
        finally:
            if lock:lock.close()
            failed=False
            if maintenance:
                try:release(source);system('enable','--now')
                except Exception:failed=True;receipt['sourceResumeFailed']=True
            if source_share and not failed:
                try:
                    active=Client(source);active.login();active.revoke_if_shared(fixture['repo'],allow_revoke=not source_revoke_attempted)
                except Exception:failed=True;receipt['sourceShareCleanupFailed']=True
            if (BASE/(target+'.json')).exists():
                try:
                    release(target);assert all(p['state']!='running' for p in runtime('stop-private',target))
                except Exception:failed=True;receipt['restoreQuarantineFailed']=True
            if failed:raise RuntimeError('Recovery cleanup incomplete; state retained for review')
    print(json.dumps(receipt,indent=2))

if __name__=='__main__':main()
