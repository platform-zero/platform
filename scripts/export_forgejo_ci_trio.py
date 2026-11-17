#!/usr/bin/env python3
"""Read-only canonical-store export of the exact CI runner/job/transport trio.

One-use, serial, SHA-checked OCI archives; no account, registration, container
startup or native application effects. A missing export result is not an ACK.
"""
import fcntl, hashlib, json, os, shutil, subprocess, tarfile
from pathlib import Path
from export_full_private_adapted_images import encode, save, filehash, verify_archive
ROOT=Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-ci-trio-oci-r1')
INV=Path('/mnt/media/p0-v3/image-acquisition-receipts/canonical-private-assembled-stack-images/combined-private-development-keycloak-optimized-inventory.json')
RUNNER=Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-ci-runner-image-r1/pull.result.json')
CMD=['sudo','-n','/usr/bin/podman','--remote=false','--module=/mnt/media/p0-v3/runtime-stores/canonical-v2/containers.conf','--root=/mnt/media/p0-v3/runtime-stores/canonical-v2/graph','--runroot=/run/p0-v3-canonical-v2/store','--network-config-dir=/mnt/media/p0-v3/runtime-stores/canonical-v2/networks']
def sha(data):return hashlib.sha256(data).hexdigest()
def headroom():
 m=int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))//1024
 if m<20480 or shutil.disk_usage(ROOT).free//1048576<14336:raise RuntimeError('CI archive export violates headroom')
def diffids(path):
 with tarfile.open(path,'r:*') as tar:
  index=json.load(tar.extractfile('index.json'))
  m=index['manifests'][0]['digest'].removeprefix('sha256:')
  manifest=json.load(tar.extractfile('blobs/sha256/'+m))
  config=manifest['config']['digest'].removeprefix('sha256:')
  rootfs=json.load(tar.extractfile('blobs/sha256/'+config))['rootfs']
  result=rootfs.get('diff_ids',[])
  if rootfs['type']!='layers' or not result or len(result)>128 or any(not d.startswith('sha256:') or len(d)!=71 for d in result):
   raise RuntimeError('OCI archive lacks authenticated native diff IDs')
  return result

def main():
 if ROOT.is_symlink():raise RuntimeError('Symlink CI receipt directory')
 ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
 inventory=json.loads(INV.read_bytes())
 if len(inventory['images'])!=56:raise RuntimeError('Development source inventory changed')
 runner=json.loads(RUNNER.read_bytes())
 intent=RUNNER.with_name('pull.intent.json')
 if (not intent.is_file() or runner['intentSha256']!=filehash(intent) or
     runner['qualificationEvidence'] or runner['applicationStarted']):
  raise RuntimeError('CI runner image has no original sealed source receipt')
 sources={kind: next(i for i in inventory['images'] if i['product']==product) for kind,product in
          (('job','java-runtime'),('transport','caddy'))}
 sources['runner']={'imageId':runner['imageId'],'pinnedImage':runner['image'],'selectedManifestDigest':runner['manifestDigest']}
 with (ROOT/'export.lock').open('a+b') as lock:
  fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
  for kind in ('job','transport','runner'):
   headroom()
   source=sources[kind]; image=source['pinnedImage']; identity=source['imageId'].removeprefix('sha256:')
   read=subprocess.run(CMD+['image','inspect',image],capture_output=True,timeout=45,check=True)
   native=json.loads(read.stdout)[0]
   if native['Id'].removeprefix('sha256:')!=identity or native['Digest']!=source['selectedManifestDigest'] or native['Architecture']!='amd64' or native['Os']!='linux':
    raise RuntimeError('Native CI source image differs: '+kind)
   claim=encode({'schemaVersion':1,'kind':kind,'originalImage':image,'imageId':identity,
                 'sourceInventorySha256':filehash(INV) if kind!='runner' else filehash(RUNNER),
                 'effect':'read-only-ci-image-export-to-sealed-oci-archive'})
   intent=ROOT/(kind+'.export.intent.json');result=ROOT/(kind+'.export.result.json');archive=ROOT/(kind+'.oci.tar')
   if intent.exists():
    if not result.is_file() or intent.read_bytes()!=claim:raise RuntimeError('Uncertain original CI archive export; no replay')
    saved=json.loads(result.read_bytes())
    if saved['intentSha256']!=sha(claim) or saved['archiveSha256']!=filehash(archive) or saved['imageId']!=identity or saved['ociManifestDigest']!=verify_archive(archive,identity):
     raise RuntimeError('Sealed CI archive changed: '+kind)
    print(kind,'existing original archive verified',flush=True);continue
   if archive.exists():raise RuntimeError('Unowned CI archive exists: '+kind)
   save(intent,claim)
   with archive.open('xb') as fd:os.fchmod(fd.fileno(),0o600)
   effect=subprocess.run(CMD+['save','--format=oci-archive','--output='+str(archive),image],
                         stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=1200)
   if effect.returncode:raise RuntimeError('CI image export failed; original intent retained: '+kind)
   manifest_digest=verify_archive(archive,identity)
   layers=diffids(archive)
   save(result,encode({'schemaVersion':1,'kind':kind,'intentSha256':sha(claim),
          'imageId':identity,'sourceImageReference':image,'ociManifestDigest':manifest_digest,
          'archiveSha256':filehash(archive),'archiveBytes':archive.stat().st_size,
          'diffIds':layers,'applicationStarted':False,'qualificationEvidence':False}))
   print(kind,'sealed original OCI archive',archive.stat().st_size,'bytes',flush=True)
if __name__=='__main__':main()
