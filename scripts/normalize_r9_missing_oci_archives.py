#!/usr/bin/env python3
"""One-use OCI index rebinding of seven missing selected r9 image sources.

No image pull, import, container or application effect. Original manifest,
config and layer blobs are checked byte-for-byte; uncertain copy retains intent.
"""
import fcntl,hashlib,io,json,os,tarfile,shutil
from pathlib import Path
from export_full_private_adapted_images import verify_archive,encode,save,filehash
ROOT=Path('/mnt/media/p0-v3/image-acquisition-receipts/full-private-r9-bound-oci-r1')
BASE=Path('/mnt/media/p0-v3/image-acquisition-receipts')
INV=Path('/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-5962a9fda75b/inventory.json')
SIX=BASE/'full-private-adapted-oci-archives-r1'
SEVEN=BASE/'full-private-auth-gateway-independent-archive-r1'
NAMES=('huly-caddy-adapted','huly-elasticsearch-adapted','huly-kvs-adapted','keykeeper-adapted','mail-bootstrap-adapted','mailserver-adapted','keycloak-auth-gateway')
def sha(value):return hashlib.sha256(value).hexdigest()
def main():
 if ROOT.is_symlink() or ROOT.exists():
  if not ROOT.is_dir() or ROOT.stat().st_mode&0o077:raise RuntimeError('Nonprivate or foreign OCI binding root')
 else:ROOT.mkdir(mode=0o700)
 inv=json.loads(INV.read_bytes());images={x['product']:x for x in inv['images']}
 if set(NAMES)-images.keys() or len(images)!=66:raise RuntimeError('Changed selected whole-family inventory')
 with (ROOT/'source.lock').open('a+b') as lock:
  os.chmod(ROOT/'source.lock',0o600);fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
  for kind in NAMES:
   source,receipt=((SIX/(kind+'.oci.tar'),SIX/(kind+'.export.result.json')) if kind!=NAMES[-1]
        else (SEVEN/'auth-gateway.oci.tar',SEVEN/'archive-export.result.json'))
   proof=json.loads(receipt.read_bytes());target=images[kind]
   if (proof['imageId']!=target['imageId'] or proof['ociManifestDigest']!=target['selectedManifestDigest'] or
       proof['archiveSha256']!=filehash(source) or proof['archiveBytes']!=source.stat().st_size or
       proof['applicationStarted'] or proof['qualificationEvidence'] or
       verify_archive(source,proof['imageId'])!=proof['ociManifestDigest']):
    raise RuntimeError('Original local OCI source/ACK changed: '+kind)
   name=target['pinnedImage'];digest=target['selectedManifestDigest']
   if not name.endswith('@'+digest):raise RuntimeError('Selected image not digest-bound')
   intent=ROOT/(kind+'.index-bind.intent.json');result=ROOT/(kind+'.index-bind.result.json');output=ROOT/(kind+'.oci.tar')
   claim=encode({'schemaVersion':1,'product':kind,'generation':'q-5962a9fda75b',
     'inventorySha256':filehash(INV),'originalResultSha256':filehash(receipt),
     'originalArchiveSha256':proof['archiveSha256'],'selectedImageId':target['imageId'],
     'selectedManifestDigest':digest,'selectedImageReference':name,
     'effect':'OCI index ref-only source normalization; no native image import'})
   if intent.exists():
    if not result.exists() or intent.read_bytes()!=claim:
     raise RuntimeError('Original OCI normalization uncertain; no replay: '+kind)
    recorded=json.loads(result.read_bytes())
    if recorded['intentSha256']!=sha(claim) or recorded['archiveSha256']!=filehash(output) or verify_archive(output,target['imageId'])!=digest:
     raise RuntimeError('Sealed normalized OCI bytes changed: '+kind)
    continue
   if result.exists() or output.exists():raise RuntimeError('Unowned OCI source output: '+kind)
   available=int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:')))//1024
   if available<16384+2048 or shutil.disk_usage(ROOT).free//1048576<10240+2*(source.stat().st_size//1048576+1)+4096:
    raise RuntimeError('OCI source copy violates protected headroom')
   save(intent,claim)
   with tarfile.open(source,'r:') as origin,tarfile.open(output,'x:') as dest:
    os.chmod(output,0o600)
    for item in origin:
     if item.name=='index.json':
      index=json.load(origin.extractfile(item))
      if index.get('schemaVersion')!=2 or len(index.get('manifests',[]))!=1 or index['manifests'][0]['digest']!=digest:
       raise RuntimeError('Original OCI index changed')
      index['manifests'][0]['annotations']={'org.opencontainers.image.ref.name':name}
      index['manifests'][0]['platform']={'os':'linux','architecture':'amd64'}
      data=encode(index);item.size=len(data)
      dest.addfile(item,io.BytesIO(data))
     elif item.isfile():dest.addfile(item,origin.extractfile(item))
     else:dest.addfile(item)
   if verify_archive(output,target['imageId'])!=digest:raise RuntimeError('Normalized OCI blob identity changed')
   save(result,encode({'schemaVersion':1,'product':kind,'intentSha256':sha(claim),
     'archiveSha256':filehash(output),'imageId':target['imageId'],'ociManifestDigest':digest,
     'applicationStarted':False,'nativeStoreImported':False,'qualificationEvidence':False}))
   print(kind,'source-bound archive ready; native image store not imported',flush=True)
if __name__=='__main__':main()
