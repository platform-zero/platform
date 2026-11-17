#!/usr/bin/env python3
"""One-use export of EXACT selected Mastodon image for offline rendered-Lua review.

Does not run a Mastodon process, Redis, container, image pull or script load.
The export has its own original intent/exit/result, never native RSS acceptance.
"""
import pathlib,json,hashlib,os,subprocess,fcntl,shutil
from export_full_private_adapted_images import verify_archive
GEN='q-5962a9fda75b'
ROOT=pathlib.Path('/mnt/media/p0-v3/release-bootstrap-anchors/assembly')/GEN
ARCH=ROOT/'mastodon-script-source.oci.tar';INTENT=ROOT/'mastodon-script-source.intent.json'
EXIT=ROOT/'mastodon-script-source-exit.result.json';RESULT=ROOT/'mastodon-script-source.result.json'
BASE=['sudo','-n','/usr/bin/podman','--root','/mnt/media/p0-v3/runtime-stores/canonical-v2/graph',
 '--runroot','/run/p0-v3-canonical-v2/store','--module','/mnt/media/p0-v3/runtime-stores/canonical-v2/containers.conf']
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for data in iter(lambda:f.read(1048576),b''):h.update(data)
 return h.hexdigest()
def save(path,data):
 if path.exists() or path.is_symlink():raise RuntimeError('Original source export exists or uncertain')
 fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 d=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(d)
 finally:os.close(d)
def encode(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def main():
 with (ROOT/'control.lock').open('a+b') as lock:
  fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
  if any(p.exists() or p.is_symlink() for p in (ARCH,INTENT,EXIT,RESULT)):
   raise RuntimeError('Selected image export was previously attempted; do not replay')
  inv=ROOT/'inventory.json';image=next(x for x in json.loads(inv.read_bytes())['images'] if x['product']=='mastodon')
  verify=subprocess.run(BASE+['image','inspect',image['pinnedImage']],capture_output=True,text=True,timeout=45,check=True)
  inspected=json.loads(verify.stdout)
  assert len(inspected)==1 and inspected[0]['Id'].removeprefix('sha256:')==image['imageId']
  assert inspected[0]['Digest']==image['selectedManifestDigest'] and inspected[0]['Os']=='linux' and inspected[0]['Architecture']=='amd64'
  mem=int(next(line.split()[1] for line in pathlib.Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))//1024
  if mem<16384+4096 or shutil.disk_usage(ROOT).free//1048576<10240+16384:
   raise RuntimeError('Mastodon source export violates host floor')
  save(INTENT,encode({'schemaVersion':1,'generation':GEN,'inventorySha256':sha(inv),'product':'mastodon',
   'imageId':image['imageId'],'selectedManifestDigest':image['selectedManifestDigest'],
   'effect':'OCI export for actual rendered-script source inspection, no application startup'}))
  with open(os.devnull,'wb') as log:
   p=subprocess.run(BASE+['save','--format','oci-archive','--output',str(ARCH),image['pinnedImage']],
     stdout=log,stderr=log,timeout=1200)
  save(EXIT,encode({'schemaVersion':1,'intentSha256':sha(INTENT),'subprocessExitCode':p.returncode}))
  if p.returncode:raise RuntimeError('Selected image export returned no original success; preserve intent')
  os.chmod(ARCH,0o600)
  manifest=verify_archive(ARCH,image['imageId'])
  save(RESULT,encode({'schemaVersion':1,'generation':GEN,'originalExportExitSha256':sha(EXIT),
   'inventorySha256':sha(inv),'imageId':image['imageId'],'archiveSha256':sha(ARCH),
   'archiveBytes':ARCH.stat().st_size,'ociManifestDigest':manifest,
   'nativeAppStarted':False,'renderedScriptsProven':False,'qualificationEvidence':False}))
  print('Pinned Mastodon OCI source exported; scripts/rendered digests still require exact producer inspection')
if __name__=='__main__':main()
