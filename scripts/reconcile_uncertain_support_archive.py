#!/usr/bin/env python3
"""Separate OCI-export authority for a pinned support image with an uncertain pull.

Never backfill/replay original pull or call observation an original ACK. Bind
original missing result, immutable OLD descriptor, read-only native identity,
and a *new* one-use export result to an independently checked archive.
"""
import hashlib,json,os,re,shutil,subprocess
from pathlib import Path
from export_full_private_adapted_images import encode,save,filehash,verify_archive
from acquire_full_private_support_images import CMD,OLD,SOURCES,ROOT as OLD_ROOT
ROOT=OLD_ROOT.with_name('full-private-auth-gateway-independent-archive-r1')
def sha(x):return hashlib.sha256(x).hexdigest()
def main():
 product,image,source_hash=SOURCES[0]
 original=OLD_ROOT/(product+'.pull.intent.json')
 if (OLD_ROOT/(product+'.pull.result.json')).exists():raise RuntimeError('Original result unexpectedly appeared; reassess authority')
 source=OLD/product/'legacy/stack.runtime.yaml'
 original_bytes=original.read_bytes();source_bytes=source.read_bytes()
 claim=json.loads(original_bytes)
 if claim['image']!=image or claim['sourceSha256']!=source_hash or \
    sha(source_bytes)!=source_hash or claim['effect']!='pinned-artifact-pull-only':
  raise RuntimeError('Untrusted OLD provenance or original pull intent')
 inspect=subprocess.run(CMD+['image','inspect',image],capture_output=True,timeout=40,check=True)
 native=json.loads(inspect.stdout)[0]
 image_id=native['Id'].removeprefix('sha256:')
 if not re.fullmatch('[a-f0-9]{64}',image_id) or native['Digest']!=image.rsplit('@',1)[1] or \
    native['Architecture']!='amd64' or native['Os']!='linux':
  raise RuntimeError('Missing independent pinned canonical-store image identity')
 if ROOT.is_symlink():raise RuntimeError('Foreign archive directory')
 ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
 mem=int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))//1024
 if mem<20480 or shutil.disk_usage(ROOT).free//1048576<14336:raise RuntimeError('Export would violate headroom')
 binding=encode({'schemaVersion':1,'product':product,'originalPullIntentSha256':sha(original_bytes),
   'originalPullResultPresent':False,'oldDescriptorSha256':source_hash,'canonicalStoreImage':image,
   'nativeImageId':image_id,'effect':'distinct one-use OCI export, not missing original pull ACK'})
 intent=ROOT/'archive-export.intent.json';result=ROOT/'archive-export.result.json';archive=ROOT/'auth-gateway.oci.tar'
 if intent.exists():
  if not result.is_file() or intent.read_bytes()!=binding:raise RuntimeError('Independent export uncertain; no replay')
  proof=json.loads(result.read_bytes())
  if proof['intentSha256']!=sha(binding) or proof['archiveSha256']!=filehash(archive) or \
     proof['ociManifestDigest']!=verify_archive(archive,proof['imageId']):
   raise RuntimeError('Changed original independent archive proof')
  print('Independent support-image archive verified; original pull still uncertain');return
 if result.exists() or archive.exists():raise RuntimeError('Unowned export result or path')
 save(intent,binding)
 with archive.open('xb') as target:os.fchmod(target.fileno(),0o600)
 exported=subprocess.run(CMD+['save','--format=oci-archive','--output='+str(archive),image],
     stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=900)
 if exported.returncode:raise RuntimeError('Original independent export uncertain; no retry')
 manifest=verify_archive(archive,image_id)
 save(result,encode({'schemaVersion':1,'intentSha256':sha(binding),'imageId':image_id,
    'ociManifestDigest':manifest,'archiveSha256':filehash(archive),'archiveBytes':archive.stat().st_size,
    'originalPullAcknowledged':False,'separateExportAcknowledged':True,
    'applicationStarted':False,'qualificationEvidence':False}))
 print('Independent support-image archive sealed; original pull remains unacknowledged',manifest)
if __name__=='__main__':main()
