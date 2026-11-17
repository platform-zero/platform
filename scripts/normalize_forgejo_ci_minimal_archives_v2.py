#!/usr/bin/env python3
"""Seal platform-bound CI OCI archives derived from authenticated raw exports.

Only index.json platform/ref-name metadata changes; manifest/config/layer bytes
are SHA-checked. No source replay, native load, application or registration.
The earlier uncertain upstream-runner export is NOT consumed: use the distinct
versioned CLI/Caddy COPY-only runner image with its own original build receipt.
"""
import hashlib,json,os,shutil,tarfile
from pathlib import Path
from export_full_private_adapted_images import encode,save,filehash,verify_archive
ROOT=Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-ci-minimal-bound-r2')
SOURCES={kind: Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-ci-'+kind+'-minimal-r2')
         for kind in ('job','transport','runner')}
def sha(x):return hashlib.sha256(x).hexdigest()
def main():
 if ROOT.is_symlink():raise ValueError('Symlink CI archive root')
 ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
 for kind in ('job','transport','runner'):
  src=SOURCES[kind]/(kind+'.oci.tar')
  result=SOURCES[kind]/'build.result.json'
  raw=json.loads(result.read_bytes())
  if raw['archiveSha256']!=filehash(src) or raw['applicationStarted'] or raw['qualificationEvidence'] or \
      raw['ociManifestDigest']!=verify_archive(src,raw['imageId']):
   raise RuntimeError('Source OCI export lacks original result or changed: '+kind)
  source_sha=filehash(result)
  if kind=='runner' and raw['priorUpstreamRunnerExportAcknowledged']:
   raise RuntimeError('Uncertain upstream runner effect was never acknowledged')
  intent=ROOT/(kind+'.normalize.intent.json');done=ROOT/(kind+'.normalize.result.json')
  dest=ROOT/(kind+'.oci.tar')
  claim=encode({'schemaVersion':1,'kind':kind,'originalArchiveSha256':raw['archiveSha256'],
                'originalResultSha256':source_sha,'originalImageId':raw['imageId'],
                'selectedOciManifestDigest':raw['ociManifestDigest'],
                'effect':'source-only OCI index platform and local ref binding'})
  if intent.exists():
   if not done.is_file() or intent.read_bytes()!=claim:
    raise RuntimeError('CI OCI normalization original result missing; no replay: '+kind)
   proof=json.loads(done.read_bytes())
   if proof['intentSha256']!=sha(claim) or proof['archiveSha256']!=filehash(dest) or \
      proof['ociManifestDigest']!=verify_archive(dest,raw['imageId']):
    raise RuntimeError('Bound CI archive mutated: '+kind)
   print(kind,'bound archive verified',flush=True);continue
  if dest.exists():raise RuntimeError('Unowned bound archive exists: '+kind)
  m=int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))//1024
  if m<20480 or shutil.disk_usage(ROOT).free//1048576<14336:
   raise RuntimeError('Bound OCI copy violates reserved headroom')
  save(intent,claim)
  with tarfile.open(src,'r:') as origin,tarfile.open(dest,'x:') as target:
   os.chmod(dest,0o600)
   for member in origin:
    if member.name=='index.json':
     index=json.load(origin.extractfile(member))
     if index.get('schemaVersion')!=2 or len(index.get('manifests',[]))!=1 or \
        index['manifests'][0]['digest']!=raw['ociManifestDigest']:
      raise RuntimeError('Original OCI index changed')
     platform=index['manifests'][0].get('platform')
     if platform and platform!={'os':'linux','architecture':'amd64'}:
      raise RuntimeError('Ambiguous OCI archive platform')
     index['manifests'][0]['platform']={'os':'linux','architecture':'amd64'}
     index['manifests'][0]['annotations']={'org.opencontainers.image.ref.name':
         'localhost/p0v3-ci-'+kind+'@'+raw['ociManifestDigest']}
     data=json.dumps(index,sort_keys=True,separators=(',',':')).encode()
     member.size=len(data);import io
     target.addfile(member,io.BytesIO(data))
    elif member.isfile():target.addfile(member,origin.extractfile(member))
    else:target.addfile(member)
  actual=verify_archive(dest,raw['imageId'])
  if actual!=raw['ociManifestDigest']:
   raise RuntimeError('Selected CI OCI manifest changed')
  with tarfile.open(dest,'r:') as t:
   i=json.load(t.extractfile('index.json'))
   if i['manifests'][0]['platform']!={'os':'linux','architecture':'amd64'}:
    raise RuntimeError('OCI platform not bound')
   manifest=json.load(t.extractfile('blobs/sha256/'+actual.removeprefix('sha256:')))
   config=json.load(t.extractfile('blobs/sha256/'+raw['imageId']))
   diffids=config['rootfs']['diff_ids']
  save(done,encode({'schemaVersion':1,'kind':kind,'intentSha256':sha(claim),
    'archiveSha256':filehash(dest),'archiveBytes':dest.stat().st_size,'imageId':raw['imageId'],
    'ociManifestDigest':actual,'sourceImageReference':'localhost/p0v3-ci-'+kind+'@'+actual,
    'originalSourceImageReference':raw.get('sourceImageReference',raw.get('binarySha256')),
    'diffIds':diffids,'applicationStarted':False,'qualificationEvidence':False}))
  print(kind,'platform-bound OCI archive sealed',dest.stat().st_size,flush=True)
if __name__=='__main__':main()
