#!/usr/bin/env python3
"""Bind successful original OCI export with owner-only custody; never rerun save."""
import pathlib,json,hashlib,os,subprocess,fcntl,stat
from export_full_private_adapted_images import verify_archive
ROOT=pathlib.Path('/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-5962a9fda75b')
ARCH=ROOT/'mastodon-script-source.oci.tar';INTENT=ROOT/'mastodon-script-export-custody.intent.json'
RESULT=ROOT/'mastodon-script-export-custody.result.json'
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1048576),b''):h.update(block)
 return h.hexdigest()
def save(path,value):
 fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(value);f.flush();os.fsync(f.fileno())
 d=os.open(ROOT,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(d)
 finally:os.close(d)
def encode(x):return (json.dumps(x,sort_keys=True,separators=(',',':'))+'\n').encode()
def main():
 with (ROOT/'control.lock').open('a+b') as lock:
  fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
  if INTENT.exists() or RESULT.exists():raise RuntimeError('Prior custody attempt; no replay')
  original=ROOT/'mastodon-script-source.intent.json';exit=ROOT/'mastodon-script-source-exit.result.json'
  proof=json.loads(exit.read_bytes());source=json.loads(original.read_bytes());image=next(x for x in
   json.loads((ROOT/'inventory.json').read_bytes())['images'] if x['product']=='mastodon')
  if (proof!={'schemaVersion':1,'intentSha256':sha(original),'subprocessExitCode':0} or
      source['imageId']!=image['imageId'] or source['selectedManifestDigest']!=image['selectedManifestDigest']):
   raise RuntimeError('Missing exact original successful OCI export')
  if ARCH.is_symlink() or not ARCH.is_file() or ARCH.stat().st_uid!=0 or ARCH.stat().st_size<=1024:
   raise RuntimeError('Foreign exported source inode')
  digest=verify_archive(ARCH,image['imageId']);sourceHash=sha(ARCH)
  claim={'schemaVersion':1,'originalExportExitSha256':sha(exit),'sourceArchiveSha256':sourceHash,
   'imageId':image['imageId'],'ociManifestDigest':digest,'effect':'owner-only custody metadata, no OCI re-export'}
  save(INTENT,encode(claim))
  subprocess.run(['sudo','-n','/usr/bin/chown',str(os.getuid())+':'+str(os.getgid()),str(ARCH)],check=True,timeout=15)
  os.chmod(ARCH,0o600)
  if ARCH.stat().st_uid!=os.getuid() or stat.S_IMODE(ARCH.stat().st_mode)!=0o600 or sha(ARCH)!=sourceHash:
   raise RuntimeError('Custody permission change had uncertain or altered source bytes')
  save(RESULT,encode({'schemaVersion':1,'intentSha256':sha(INTENT),'archiveSha256':sourceHash,
   'imageId':image['imageId'],'ociManifestDigest':digest,'originalExportAcknowledged':True,
   'renderedScriptsProven':False,'appStarted':False,'qualificationEvidence':False}))
  print('Original exported OCI source protected, unchanged; no native script hash claimed')
if __name__=='__main__':main()
