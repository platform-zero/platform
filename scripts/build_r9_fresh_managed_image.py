#!/usr/bin/env python3
"""One-use fresh rootless Worklane source build; never starts a lane or copies OLD state.

An interrupted build retains its intent/store/log for owner reconciliation. A
successful image still needs exact OCI export, native UID784 import/readback and
real broker/issuer enrollment before any whole-release request is executable.
"""
import hashlib,json,os,subprocess,shutil,pathlib,fcntl
ROOT=pathlib.Path('/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/q-5962a9fda75b')
SRC=pathlib.Path('/home/gerald/p0_v3/worklane')
INTENT=ROOT/'fresh-image-build.intent.json'; RESULT=ROOT/'fresh-image-build.result.json'
LOG=ROOT/'fresh-image-build.log'; STORE=ROOT/'fresh-image-build-store'; RUN=ROOT/'fresh-image-build-run'
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1048576),b''):h.update(block)
 return h.hexdigest()
def save(path,value):
 if path.exists() or path.is_symlink():raise RuntimeError('Prior or uncertain managed image build effect')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(value);f.flush();os.fsync(f.fileno())
 d=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(d)
 finally:os.close(d)
def main():
 assert ROOT.is_dir() and ROOT.stat().st_mode&0o077==0
 with (ROOT/'control.lock').open('a+b') as lock:
  os.chmod(ROOT/'control.lock',0o600);fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
  if any(p.exists() or p.is_symlink() for p in (INTENT,RESULT,LOG,STORE,RUN)):
   raise RuntimeError('Managed native image source build already attempted; no replay')
  content={n:sha(SRC/n) for n in ('Containerfile.v3','assets/v3/pi/package.json','assets/v3/pi/package-lock.json')}
  avail=int(next(x.split()[1] for x in pathlib.Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))//1024
  if avail<16384+8192 or shutil.disk_usage(ROOT).free//1048576<10240+32768:
   raise RuntimeError('Fresh source image build violates protected host capacity')
  claim={'schemaVersion':1,'generation':'q-5962a9fda75b','scope':'fresh-managed-source-only-not-native-lane',
    'sourceHashes':content,'worklaneCandidateSha256':'9a5d277c7fb7da3f5e2d61739e11aae5445e9b1723e8188d0f8c4e550be31016',
    'outputTag':'localhost/p0v3-r9-worklane:source-1','nativeLaneStarted':False}
  save(INTENT,(json.dumps(claim,sort_keys=True,separators=(',',':'))+'\n').encode())
  STORE.mkdir(mode=0o700);RUN.mkdir(mode=0o700)
  command=['/usr/bin/podman','--root',str(STORE),'--runroot',str(RUN),'--storage-driver','vfs',
    '--cgroup-manager','cgroupfs','--events-backend','file','build','--pull=always',
    '--no-cache','--platform','linux/amd64','-f','Containerfile.v3','-t',claim['outputTag'],'.']
  fd=os.open(LOG,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as output:
   process=subprocess.run(command,cwd=SRC,stdout=output,stderr=subprocess.STDOUT,timeout=2700)
   output.flush();os.fsync(output.fileno())
  if process.returncode:raise RuntimeError('Fresh source build failed or uncertain; preserve original log/intent')
  # A new invocation must persist the original subprocess exit BEFORE any
  # optional inspect; this does not repair the earlier q5962 missing ACK.
  save(ROOT/'fresh-image-build-exit.result.json',
    (json.dumps({'schemaVersion':1,'intentSha256':sha(INTENT),'exitCode':process.returncode,
      'logSha256':sha(LOG)},sort_keys=True,separators=(',',':'))+'\n').encode())
  inspect=subprocess.run(command[:command.index('build')]+['image','inspect',claim['outputTag']],
    capture_output=True,text=True,timeout=45,check=True)
  image=json.loads(inspect.stdout)
  assert len(image)==1 and image[0]['Id'].removeprefix('sha256:').isalnum() and len(image[0]['Id'].removeprefix('sha256:'))==64 and image[0]['Architecture']=='amd64' and image[0]['Os']=='linux'
  save(RESULT,(json.dumps({'schemaVersion':1,'originalIntentSha256':sha(INTENT),
    'originalBuildLogSha256':sha(LOG),'imageId':image[0]['Id'],
    'sourceTag':claim['outputTag'],'nativeLaneStarted':False,'qualificationEvidence':False},
    sort_keys=True,separators=(',',':'))+'\n').encode())
  print('Fresh managed image source built; no lane or model started; native issuance pending')
if __name__=='__main__':main()
