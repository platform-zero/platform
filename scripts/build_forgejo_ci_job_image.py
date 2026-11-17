#!/usr/bin/env python3
"""Fixed local Bash-only private CI fixture image without inherited symlinks.

Exact host tool/loader hashes, no third-party actions, COPY-only scratch build,
serial headroom and one-use native artifact intent/result. This is a local
fixture source, not acceptance of checkout or artifact-upload transport.
"""
import hashlib,json,os,shutil,subprocess
from pathlib import Path
from export_full_private_adapted_images import encode,save,filehash,verify_archive
ROOT=Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-ci-job-minimal-r1')
TAG='localhost/p0v3-ci-job:reviewed-bash-r1'
CMD=['sudo','-n','/usr/bin/podman','--remote=false','--module=/mnt/media/p0-v3/runtime-stores/canonical-v2/containers.conf','--root=/mnt/media/p0-v3/runtime-stores/canonical-v2/graph','--runroot=/run/p0-v3-canonical-v2/store','--network-config-dir=/mnt/media/p0-v3/runtime-stores/canonical-v2/networks']
TOOLS={'bash':('/usr/bin/bash','223fe8564b60636bc738b6178d3ba9a50ef7d791266b0efae6363bb716e4c47f'),
 'mkdir':('/usr/bin/mkdir','bd3d9b36a1cc1c63b8dca7967003f4e5b0bb8556c87cbb7c1916aa358bf3f053'),
 'tee':('/usr/bin/tee','c56e1654da83434ff80c9700c179f8947dd88ce5137c866a6ea2511342925a3c'),
 'libc':('/lib/x86_64-linux-gnu/libc.so.6','9792e3cbb541c8f44c7acf5f14f4022ea62998ecc787d326bed4d8b6547dfd92'),
 'libtinfo':('/lib/x86_64-linux-gnu/libtinfo.so.6','4013e7651ac68f547d8333517def25b2366c97eec7de7f06e105dbf3444ffebf'),
 'loader':('/lib64/ld-linux-x86-64.so.2','c8438e4fde1934e61c88311633f00949ff645d5c04cdb8671fa3d78164d2f307')}
# mkdir's transitive dependencies: pinned before any copy/build.
TOOLS.update({'selinux':('/lib/x86_64-linux-gnu/libselinux.so.1',None),
              'pcre2':('/lib/x86_64-linux-gnu/libpcre2-8.so.0',None)})
def sha(x):return hashlib.sha256(x).hexdigest()
def main():
 if ROOT.is_symlink():raise ValueError('Symlinked job artifact directory')
 ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
 context=ROOT/'context'
 hashes={k:filehash(Path(path)) for k,(path,pin) in TOOLS.items()}
 if any(hashes[k]!=pin for k,(_,pin) in TOOLS.items() if pin):raise ValueError('Pinned host CLI or loader changed')
 if not context.exists():
  context.mkdir(mode=0o700)
  for name,(path,_) in TOOLS.items():
   with (context/name).open('xb') as out,Path(path).open('rb') as src:
    os.fchmod(out.fileno(),0o600);shutil.copyfileobj(src,out,1048576)
  save(context/'placeholder',b'fixed-mount-placeholder\n')
  cf='FROM scratch\n'
  targets={'bash':'/bin/bash','mkdir':'/usr/bin/mkdir','tee':'/usr/bin/tee',
    'libc':'/lib/x86_64-linux-gnu/libc.so.6','libtinfo':'/lib/x86_64-linux-gnu/libtinfo.so.6',
    'loader':'/lib64/ld-linux-x86-64.so.2','selinux':'/lib/x86_64-linux-gnu/libselinux.so.1',
    'pcre2':'/lib/x86_64-linux-gnu/libpcre2-8.so.0'}
  for name,target in targets.items():cf+='COPY '+name+' '+target+'\n'
  cf+='COPY placeholder /etc/ssl/certs/p0v3-ci-forgejo-ca.pem\nCOPY placeholder /tmp/.keep\nUSER 0:0\nENTRYPOINT ["/bin/bash"]\n'
  save(context/'Containerfile',cf.encode())
 if any(filehash(context/name)!=hashes[name] for name in TOOLS):raise ValueError('Pinned local tool context changed')
 claim=encode({'schemaVersion':1,'source':'host-pinned-local-fixture-no-upstream-action',
               'tools':hashes,'containerfileSha256':filehash(context/'Containerfile'),'tag':TAG,
               'effect':'one-use scratch-only pinned Bash job OCI build'})
 intent=ROOT/'build.intent.json';result=ROOT/'build.result.json';archive=ROOT/'job.oci.tar'
 if intent.exists():
  if not result.is_file() or intent.read_bytes()!=claim:raise RuntimeError('Original job image build uncertain; no replay')
  old=json.loads(result.read_bytes())
  if old['archiveSha256']!=filehash(archive) or old['ociManifestDigest']!=verify_archive(archive,old['imageId']):raise RuntimeError('Original job image receipt changed')
  print('Original local job image verified');return
 m=int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))//1024
 if m<20480 or shutil.disk_usage(ROOT).free//1048576<14336:raise RuntimeError('CI fixture build violates headroom')
 save(intent,claim)
 p=subprocess.run(CMD+['build','--pull=never','--network=none','--format=oci','-f',str(context/'Containerfile'),'-t',TAG,str(context)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=900)
 if p.returncode:raise RuntimeError('Original job image build failed; intent retained')
 native=json.loads(subprocess.check_output(CMD+['image','inspect',TAG],timeout=40))[0]
 image=native['Id'].removeprefix('sha256:')
 with archive.open('xb') as out:os.fchmod(out.fileno(),0o600)
 p=subprocess.run(CMD+['save','--format=oci-archive','--output='+str(archive),TAG],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=600)
 if p.returncode:raise RuntimeError('Original job image export failed; intent retained')
 manifest=verify_archive(archive,image)
 save(result,encode({'schemaVersion':1,'intentSha256':sha(claim),'imageId':image,
     'ociManifestDigest':manifest,'archiveSha256':filehash(archive),'archiveBytes':archive.stat().st_size,
     'applicationStarted':False,'qualificationEvidence':False,'thirdPartyActions':False}))
 print('Local Bash-only job OCI image sealed',image,manifest,flush=True)
if __name__=='__main__':main()
