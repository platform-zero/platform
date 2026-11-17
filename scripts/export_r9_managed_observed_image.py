#!/usr/bin/env python3
"""Separate observed-content OCI export, NEVER a missing original build ACK.

Does not rebuild, relabel, start, remove or alter source image. Its own one-use
export intent, subprocess exit and OCI blob readback are independent authority.
"""
import hashlib,json,os,pathlib,subprocess,shutil,tarfile,fcntl
from export_full_private_adapted_images import verify_archive
ROOT=pathlib.Path('/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/q-5962a9fda75b')
OBS=pathlib.Path('/home/gerald/p0_v3/.coord/rapid-completion/core-r9-managed-original-readonly-reconcile-526.json')
ARCHIVE=ROOT/'worklane-observed.oci.tar';INTENT=ROOT/'worklane-export.intent.json';EXIT=ROOT/'worklane-export-exit.result.json';RESULT=ROOT/'worklane-export.result.json'
TAG='localhost/p0v3-r9-worklane:source-1'
BASE=['/usr/bin/podman','--root',str(ROOT/'fresh-image-build-store'),'--runroot',str(ROOT/'fresh-image-build-run'),
 '--storage-driver','vfs','--cgroup-manager','cgroupfs','--events-backend','file']
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for data in iter(lambda:f.read(1048576),b''):h.update(data)
 return h.hexdigest()
def save(path,data):
 if path.exists() or path.is_symlink():raise RuntimeError('Original observed-content export already attempted')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(d)
 finally:os.close(d)
def encode(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
def main():
 assert ROOT.is_dir() and ROOT.stat().st_mode&0o077==0
 with (ROOT/'control.lock').open('a+b') as lock:
  fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
  if any(x.exists() or x.is_symlink() for x in (ARCHIVE,INTENT,EXIT,RESULT)):
   raise RuntimeError('Existing or uncertain OCI export cannot be replayed')
  observed=json.loads(OBS.read_bytes())
  assert observed['scope']=='independent-readonly-original-source-content-observation-not-build-ack'
  assert observed['originalBuildAcknowledged'] is False and observed['imageContentObserved'] is True
  assert observed['imageSourceTag']==TAG and observed['nativeLaneStarted'] is False
  assert observed['originalBuildIntentSha256']==sha(ROOT/'fresh-image-build.intent.json')
  assert observed['originalBuildLogSha256']==sha(ROOT/'fresh-image-build.log')
  if int(next(x.split()[1] for x in pathlib.Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))//1024<16384+4096 or \
     shutil.disk_usage(ROOT).free//1048576<10240+32768:
   raise RuntimeError('Source OCI export violates protected host floor')
  inspect=json.loads(subprocess.run(BASE+['image','inspect',TAG],capture_output=True,text=True,timeout=45,check=True).stdout)
  assert len(inspect)==1 and inspect[0]['Id'].removeprefix('sha256:')==observed['imageId'].removeprefix('sha256:')
  assert inspect[0]['RootFS']['Layers']==observed['layerDiffIds'] and inspect[0]['Size']==observed['imageSizeBytes']
  save(INTENT,encode({'schemaVersion':1,'generation':'q-5962a9fda75b','observationSha256':sha(OBS),
    'sourceImageId':observed['imageId'],'originalBuildAcknowledged':False,
    'effect':'independent one-use content export, no rebuild/tag/app start'}))
  with open(os.devnull,'wb') as output:
   process=subprocess.run(BASE+['save','--format','oci-archive','--output',str(ARCHIVE),TAG],
    stdout=output,stderr=output,timeout=1200)
  save(EXIT,encode({'schemaVersion':1,'intentSha256':sha(INTENT),'subprocessExitCode':process.returncode}))
  if process.returncode:raise RuntimeError('Original OCI export failed; retain intent/output')
  if ARCHIVE.is_symlink() or not ARCHIVE.is_file():raise RuntimeError('Missing observed OCI export')
  os.chmod(ARCHIVE,0o600)
  manifest=verify_archive(ARCHIVE,observed['imageId'].removeprefix('sha256:'))
  with tarfile.open(ARCHIVE,'r:') as tar:
   index=json.load(tar.extractfile('index.json'))
   desc=index['manifests'][0]
   assert desc['digest']==manifest and len(index['manifests'])==1
   import re
   assert re.fullmatch(r'sha256:[a-f0-9]{64}',manifest)
  save(RESULT,encode({'schemaVersion':1,'generation':'q-5962a9fda75b','exportExitSha256':sha(EXIT),
    'observationSha256':sha(OBS),'originalBuildAcknowledged':False,'separateExportAcknowledged':True,
    'imageId':observed['imageId'],'ociManifestDigest':manifest,'archiveSha256':sha(ARCHIVE),
    'archiveBytes':ARCHIVE.stat().st_size,'imageSizeBytes':observed['imageSizeBytes'],
    'layerDiffIds':observed['layerDiffIds'],'nativeLaneStarted':False,'qualificationEvidence':False}))
  print('Observed-content OCI export sealed separately; original build ACK remains absent')
if __name__=='__main__':main()
