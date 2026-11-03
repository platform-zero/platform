#!/usr/bin/env python3
"""Fenced social DB/cache/uploads/keys/bot-token/RSS-state recovery; no publication or public routing."""
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

ROOT=Path(__file__).resolve().parents[2]
BASE=Path('/mnt/media/p0-v3/runtime-deployments')
CLI=ROOT/'platform/build/install/p0-v3-platform/bin/p0-v3-platform'
INVENTORY=ROOT/'platform/release/downloaded-candidate-inventory.json'
P=['sudo','-n','podman','--remote=false','--root=/mnt/media/p0-v3/release-runtime/graph','--runroot=/run/p0-v3-release-runtime/store','--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
JAVA={**os.environ,'JAVA_HOME':'/usr/lib/jvm/java-21-openjdk-amd64'}


def write(path,data):
    with os.fdopen(os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as out:
        out.write(data);out.flush();os.fsync(out.fileno())


def digest(path):
    assert path.is_file() and not path.is_symlink()
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--source',default='mastodon-r4');parser.add_argument('--fixture',type=Path,required=True)
    args=parser.parse_args();source=args.source;fixture=args.fixture
    assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}',source)
    assert fixture.is_absolute() and fixture.resolve()==fixture and fixture.stat().st_mode & 0o777==0o700
    original=json.loads((fixture/'receipt.json').read_text());assert original['passed'] and original['phase']=='complete' and not (fixture/'receipt-invalidated.json').exists() and original['deployment']==source and original['nativeStoredMediaVerified']
    nonce=uuid.uuid4().hex[:12];prefix='p0v3-social-restore-'+nonce;target='srestore-'+nonce
    directory=Path('/mnt/media/p0-v3/image-acquisition-receipts')/prefix;directory.mkdir(mode=0o700)
    snapshot,export=directory/'snapshot',directory/'export';snapshot.mkdir(mode=0o700);export.mkdir(mode=0o700)
    for folder in ('inputs','fixture','rss'):(snapshot/folder).mkdir(mode=0o700)
    source_bytes=(BASE/(source+'.json')).read_bytes();source_hash=hashlib.sha256(source_bytes).hexdigest();spec=json.loads(source_bytes)
    assert spec['name']==source
    images=json.loads(INVENTORY.read_text())['images'];image=next(i['pinnedImage'] for i in images if i['product']=='mastodon');kopia_image=next(i['pinnedImage'] for i in images if i['product']=='kopia')
    assert next(p['image'] for p in spec['processes'] if p['id']=='mastodon')==image
    inputs=sorted({p['environmentFile'] for p in spec['processes'] if p.get('environmentFile')}|{f['file'] for p in spec['processes'] for f in p.get('files',[])})
    unit='p0v3-private-'+source+'.service';unit_path=Path('/etc/systemd/system')/unit
    assert unit_path.is_file() and not unit_path.is_symlink() and unit_path.stat().st_uid==0
    assert re.search(r'^ExecStart=/mnt/media/p0-v3/runtime-supervision/releases/[a-f0-9]{64}/bin/p0-v3-platform runtime boot-apply '+re.escape(source)+' '+source_hash+'$',unit_path.read_text(),re.M)
    repo,config=prefix+'-repository',prefix+'-config';write(directory/'kopia.env',('KOPIA_PASSWORD='+secrets.token_hex(32)+'\n').encode())
    receipt={'id':prefix,'scope':'private-social-rss-encrypted-recovery-not-full-stack','source':source,'restore':target,'passed':False,
        'fullStackAcceptance':False,'offHostBackup':False,'publicationEnabled':False,'sourceManifestSha256':source_hash,'sourceFixture':original['id']}
    maintenance=False;lock=None;rss_lock=None;target_lock=None;fence=None
    rss=Path('/mnt/media/p0-v3/rss-staging-state');volumes={'uploads':991,'bootstrap':991,'valkey':999}

    def run(command,stdin=None,stdout=None,timeout=1200):
        result=subprocess.run(command,stdin=stdin,stdout=stdout or subprocess.PIPE,stderr=subprocess.PIPE,env=JAVA,timeout=timeout)
        if result.returncode:
            write(directory/('failure-'+uuid.uuid4().hex[:8]+'.log'),result.stderr)
            raise RuntimeError('Scoped social recovery operation failed; private diagnostics retained')
        return result.stdout
    def runtime(action,name,*extra):return json.loads(run([str(CLI),'runtime',action,str(BASE/(name+'.json')),*extra]).splitlines()[0])
    def system(*arguments):return run(['sudo','-n','systemctl',*arguments,unit])
    def inspect(name,process):return json.loads(run(P+['inspect','p0v3-live-'+name+'-'+process]))[0]
    def release_fence():
        nonlocal fence
        if fence is None:
            assert runtime('maintenance-status',source) is None,'Uncertain maintenance identity; retaining fence'
            return
        runtime('stop-private',source);run([str(CLI),'runtime','maintenance-leave',str(BASE/(source+'.json')),fence['id']]);fence=None
    def browser(name,path,verify=False,recovered=None):
        command=['python3',str(ROOT/'platform/scripts/test-private-mastodon.py'),'--name',name,'--verify-fixture' if verify else '--fixture',str(path)]
        if recovered:command+=['--recovered-inputs',str(recovered)]
        result=json.loads(run(command));assert result['passed'] and result['nativeStoredMediaVerified'] and not result['fullStackAcceptance'];return result
    def volume_helper(name,volume,readonly,command,stdin=None,stdout=None):
        uid=volumes[volume];mount='p0v3-live-'+name+'-volume-'+volume+':/data:'+('ro' if readonly else 'U')
        return run(P+['run','--rm','-i','--pull=never','--network=none','--read-only','--cap-drop=all','--security-opt=no-new-privileges',
            '--security-opt=apparmor=p0v3-private-v1','--user='+str(uid)+':'+str(uid),'--memory=512m','--pids-limit=128','--image-volume=ignore',
            '--tmpfs=/tmp:rw,nosuid,nodev,size=64m','--volume',mount,'--entrypoint=/bin/sh',image,'-ec',command],stdin,stdout)
    def archive(name,volume,path):
        with os.fdopen(os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as out:
            volume_helper(name,volume,True,'tar -cf - -C /data .',stdout=out);out.flush();os.fsync(out.fileno())
        return tar_inventory(path)
    def kopia(*command):
        return run(P+['run','--rm','--pull=never','--network=none','--read-only','--cap-drop=all','--security-opt=no-new-privileges',
            '--security-opt=apparmor=p0v3-private-v1','--user=1000:1000','--memory=1024m','--pids-limit=256','--image-volume=ignore',
            '--tmpfs=/tmp:rw,nosuid,nodev,size=128m','--volume',repo+':/repository:U','--volume',config+':/config:U',
            '--volume',str(snapshot)+':/snapshot:ro','--volume',str(export)+':/restore:rw','--env-file',str(directory/'kopia.env'),
            '--env=HOME=/tmp','--env=KOPIA_CACHE_DIRECTORY=/tmp/cache',kopia_image,'--config-file=/config/repository.config','--disable-file-logging',*command])
    def denied_valkey_start():
        result=subprocess.run([str(CLI),'runtime','stage-private',str(BASE/(target+'.json')),'valkey'],capture_output=True,env=JAVA,timeout=180)
        assert result.returncode!=0 and b'Runtime daemon exited: valkey' in result.stderr
        data=inspect(target,'valkey');assert not data['State']['Running'] and data['State']['ExitCode'] in (1,2)
        assert all(p['state']=='absent' for p in runtime('status-private',target) if p['id'] in ('mastodon-migrate','mastodon-accounts','mastodon-rss-accounts','mastodon','social','sidekiq','streaming'))
    def redis(name,*arguments):
        return run(P+['exec','p0v3-live-'+name+'-valkey','/bin/sh','-ec',
            'export REDISCLI_AUTH="$(sed -n \'s/^requirepass //p\' /etc/valkey/valkey.conf)"; exec valkey-cli --raw "$@"','redis-probe',*arguments]).strip()
    def count_status(name,status_id):
        assert re.fullmatch(r'[0-9]{1,32}',status_id)
        return int(run(P+['exec','p0v3-live-'+name+'-postgres','psql','-X','-U','postgres','-d','mastodon','-At','-c','SELECT count(*) FROM statuses WHERE id='+status_id]).strip())
    def rss_hashes():
        assert rss.resolve()==rss and rss.stat().st_mode & 0o777==0o700
        allowed={'rss-state.json','rss-state.previous','rss-state.lock'}
        assert {p.name for p in rss.iterdir()}<=allowed and (rss/'rss-state.json').is_file()
        for p in rss.iterdir():assert p.is_file() and not p.is_symlink() and p.stat().st_mode & 0o777==0o600 and 0<p.stat().st_size<=1048576
        return {p.name:digest(p) for p in rss.iterdir()}
    try:
        receipt['phase']='source-media-and-identity-readback'
        assert system('is-enabled').strip()==b'enabled' and system('is-active').strip()==b'active'
        verified=browser(source,fixture,verify=True);assert verified['mediaSha256']==original['mediaSha256']
        redis_key='p0v3:restore-probe:'+nonce
        assert redis(source,'EXISTS',redis_key,redis_key+':source',redis_key+':target')==b'0'
        assert redis(source,'SET',redis_key,'snapshot-before')==b'OK'
        jobs=digest(BASE/source/'runtime.jobs')
        receipt['phase']='fence-and-coordinated-capture';maintenance=True;system('disable','--now')
        assert runtime('maintenance-status',source) is None
        fence=json.loads(run([str(CLI),'runtime','maintenance-enter',str(BASE/(source+'.json')),'backup','postgres']))
        blocked=subprocess.run([str(CLI),'runtime','apply-private',str(BASE/(source+'.json'))],capture_output=True,env=JAVA,timeout=120);assert blocked.returncode!=0
        staged=runtime('stage-private',source,'postgres');assert {p['id'] for p in staged if p['state']=='running'}=={'postgres'}
        lock=(BASE/source/'runtime.lock').open('r+b');fcntl.lockf(lock,fcntl.LOCK_EX)
        rss_hashes();rss_lock=os.fdopen(os.open(rss/'rss-state.lock',os.O_RDWR|os.O_NOFOLLOW),'r+b');fcntl.lockf(rss_lock,fcntl.LOCK_EX)
        state_hashes=rss_hashes()
        frozen={p['id']:inspect(source,p['id']) for p in spec['processes']};assert {p for p,d in frozen.items() if d['State']['Running']}=={'postgres'}
        write(snapshot/'inputs/source-spec.json',source_bytes)
        for file in inputs:
            assert re.fullmatch(r'[a-z][a-z0-9.-]{0,79}',file);path=BASE/source/file
            assert not path.is_symlink() and path.stat().st_mode & 0o777==0o600
            write(snapshot/'inputs'/file,path.read_bytes())
        for file in ('receipt.json','inputs.json'):
            path=fixture/file;assert not path.is_symlink() and path.stat().st_mode & 0o777==0o600;write(snapshot/'fixture'/file,path.read_bytes())
        for file in state_hashes:write(snapshot/'rss'/file,(rss/file).read_bytes())
        with os.fdopen(os.open(snapshot/'postgres.dump',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),'wb') as out:
            run(P+['exec','p0v3-live-'+source+'-postgres','pg_dump','-U','postgres','-d','mastodon','--format=custom','--no-owner','--no-privileges'],stdout=out);out.flush();os.fsync(out.fileno())
        trees={volume:archive(source,volume,snapshot/(volume+'.tar')) for volume in volumes}
        assert any(path.endswith('.png') for path in trees['uploads']), 'No real stored media in archive'
        hashes={str(p.relative_to(snapshot)):digest(p) for p in snapshot.rglob('*') if p.is_file()}
        write(snapshot/'manifest.json',json.dumps(hashes,sort_keys=True).encode());receipt['archiveManifestSha256']=digest(snapshot/'manifest.json')
        receipt['phase']='encrypted-export-verification'
        for volume in (repo,config):
            assert subprocess.run(P+['volume','exists',volume],capture_output=True).returncode==1
            run(P+['volume','create','--label=io.p0v3.restore-probe='+prefix,volume])
        kopia('repository','create','filesystem','--path=/repository','--no-check-for-updates')
        snapshot_id=json.loads(kopia('snapshot','create','--json','/snapshot'))['rootEntry']['obj'];receipt['snapshotId']=snapshot_id
        kopia('snapshot','verify','--verify-files-percent=100')
        kopia('snapshot','restore','--no-overwrite-files','--no-overwrite-directories','--no-overwrite-symlinks','--skip-owners','--flush-files',snapshot_id,'/restore/recovered')
        for process,before in frozen.items():
            after=inspect(source,process);assert before['Id']==after['Id'] and before['State']['StartedAt']==after['State']['StartedAt'] and before['State']['Running']==after['State']['Running']
        assert digest(BASE/source/'runtime.jobs')==jobs and digest(BASE/(source+'.json'))==source_hash and rss_hashes()==state_hashes
        rss_lock.close();rss_lock=None;lock.close();lock=None
        release_fence();system('enable','--now');maintenance=False
        assert redis(source,'GET',redis_key)==b'snapshot-before'
        assert redis(source,'SET',redis_key,'source-after')==b'OK' and redis(source,'SET',redis_key+':source','source-only')==b'OK'
        source_only=browser(source,fixture);receipt['sourceAfterSnapshotReceipt']=source_only['id']
        recovered=export/'recovered'
        assert digest(recovered/'manifest.json')==receipt['archiveManifestSha256'] and json.loads((recovered/'manifest.json').read_text())==hashes
        assert {str(p.relative_to(recovered)) for p in recovered.rglob('*') if p.is_file()}==set(hashes)|{'manifest.json'}
        for file,expected in hashes.items():assert digest(recovered/file)==expected
        receipt['phase']='isolated-target-import'
        assert not (BASE/(target+'.json')).exists()
        run([str(CLI),'runtime','prepare-mastodon-restore',str(INVENTORY),str(recovered/'inputs'),target])
        assert all(p['state']=='absent' for p in runtime('provision-private',target))
        denied_valkey_start()  # Missing completion marker cannot start even the recovered cache.
        volume_helper(target,'valkey',True,'test -z "$(ls -A /data)"')
        staged=runtime('stage-private',target,'mastodon-db-init');assert {p['id'] for p in staged if p['state']=='running'}=={'postgres'}
        target_lock=(BASE/target/'runtime.lock').open('r+b');fcntl.lockf(target_lock,fcntl.LOCK_EX)
        with (recovered/'postgres.dump').open('rb') as data:
            run(P+['exec','-i','p0v3-live-'+target+'-postgres','pg_restore','-U','postgres','-d','mastodon','--role=mastodon','--no-owner','--no-privileges','--exit-on-error'],stdin=data)
        for volume in volumes:
            assert tar_inventory(recovered/(volume+'.tar'))==trees[volume]
            with (recovered/(volume+'.tar')).open('rb') as data:
                volume_helper(target,volume,False,'test -z "$(ls -A /data)"; touch /data/.restore-in-progress; tar --no-same-owner -xpf - -C /data',stdin=data)
            actual=archive(target,volume,directory/('restored-'+volume+'.tar'));assert '.restore-in-progress' in actual
            del actual['.restore-in-progress'];assert actual==trees[volume]
            if volume!='valkey':
                volume_helper(target,volume,False,"printf '%s\\n' '"+source_hash+"' > /data/.p0v3-restore-complete; sync; rm /data/.restore-in-progress; sync")
        target_lock.close();target_lock=None
        runtime('stop-private',target)
        volume_helper(target,'valkey',False,"printf '%s\\n' '"+source_hash+"' > /data/.p0v3-restore-complete; sync")
        denied_valkey_start()  # Correct manifest marker is insufficient while import is incomplete.
        assert source_hash!='b'*64
        volume_helper(target,'valkey',False,"printf '%s\\n' '"+'b'*64+"' > /data/.p0v3-restore-complete; rm /data/.restore-in-progress; sync")
        denied_valkey_start()  # A marker bound to a different source manifest is also denied.
        guarded=archive(target,'valkey',directory/'guarded-valkey.tar');del guarded['.p0v3-restore-complete'];assert guarded==trees['valkey']
        volume_helper(target,'valkey',False,"printf '%s\\n' '"+source_hash+"' > /data/.p0v3-restore-complete; sync")
        runtime('apply-private',target)
        source_ip=inspect(source,'social')['NetworkSettings']['Networks']['p0v3-live-'+source+'-net']['IPAddress'];assert re.fullmatch(r'[0-9.]+',source_ip)
        run(P+['exec','p0v3-live-'+target+'-mastodon','ruby','-rsocket','-rtimeout','-e','begin; Timeout.timeout(3) { TCPSocket.new(ARGV.fetch(0),8443) }; exit 1; rescue SystemCallError, Timeout::Error; exit 0; end',source_ip])
        receipt['phase']='native-restored-social-and-rss-workflows'
        assert redis(target,'GET',redis_key)==b'snapshot-before' and redis(target,'GET',redis_key+':source')==b''
        assert redis(target,'SET',redis_key+':target','target-only')==b'OK' and redis(source,'GET',redis_key+':target')==b''
        readback=browser(target,recovered/'fixture',verify=True,recovered=recovered/'inputs');assert readback['mediaSha256']==original['mediaSha256']
        assert count_status(target,source_only['statusId'])==0
        restored_only=browser(target,recovered/'fixture',recovered=recovered/'inputs')
        assert count_status(source,restored_only['statusId'])==0 and count_status(target,restored_only['statusId'])==1 and count_status(source,source_only['statusId'])==1
        assert redis(target,'GET',redis_key+':target')==b'target-only' and redis(target,'GET',redis_key)==b'snapshot-before'
        assert redis(source,'GET',redis_key)==b'source-after' and redis(source,'GET',redis_key+':target')==b''
        accounts=json.loads(run(['python3',str(ROOT/'platform/scripts/test-mastodon-rss-accounts.py'),'--name',target]));assert accounts['passed'] and accounts['zeroFeedStatuses'] and accounts['reviewGateBlockedBeforeHttp']
        jars=sorted((ROOT/'platform/build/install/p0-v3-platform/lib').glob('*.jar'));assert jars
        state=json.loads(run(['/usr/lib/jvm/java-21-openjdk-amd64/bin/java','--class-path',':'.join(map(str,jars)),str(ROOT/'acceptance/scripts/RssRecoveryProbe.java'),str(recovered/'rss'),str(directory/'first-poll-fixture')]))
        assert state['passed'] and state['posts']==0 and state['restoredPending']==0
        assert {file:digest(recovered/'rss'/file) for file in state_hashes}==state_hashes and rss_hashes()==state_hashes
        browser(source,fixture,verify=True)
        receipt.update(passed=True,phase='complete',durableSourceFenceVerified=True,encryptedSnapshotVerified=True,recoveredInputsAndKeys=True,
            missingIncompleteForeignMarkersDenied=True,targetImportLocked=True,nativeValkeyReadbackAndDivergence=True,nativeMediaHashPreserved=True,mediaSha256=readback['mediaSha256'],applicationInitializersNotReplayed=True,sourceMutationExcluded=True,
            restoredWritesIsolated=True,sourceTcpBlockedFromRestore=True,sourceRssStateUnchanged=True,restoredRssState=state,
            restoredReadbackReceipt=readback['id'],restoredWriteReceipt=restored_only['id'],restoredBotAccountReceipt=accounts['id'])
    finally:
        if target_lock is not None:target_lock.close()
        if rss_lock is not None:rss_lock.close()
        if lock is not None:lock.close()
        if maintenance:
            try:release_fence();system('enable','--now')
            except Exception:receipt.update(passed=False,sourceResumeFailed=True)
        if (BASE/(target+'.json')).exists():
            try:runtime('stop-private',target)
            except Exception:receipt.update(passed=False,quarantineFailed=True)
        write(directory/'receipt.json',json.dumps(receipt,indent=2).encode())
    assert receipt['passed'];print(json.dumps(receipt,indent=2))

if __name__=='__main__':
    if not __debug__:raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
