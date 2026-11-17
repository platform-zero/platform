#!/usr/bin/env python3
"""Compile the pinned Forgejo v3.5.1 CLI for host-side one-use registration.

Source commit/go.sum are fixed; Go module checksums remain enabled. No runner
registration, account provisioning, container start, or public application.
An uncertain build retains its original intent, never overwritten.
"""
import hashlib,json,os,shutil,subprocess
from pathlib import Path
SRC=Path('/tmp/p0-forgejo-runner-v3.5.1')
ROOT=Path('/mnt/media/p0-v3/ci-runner')
RECEIPT=Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-runner-binary-r2')
COMMIT='a10469b382eab091576abc0968cacd8dc67b314f'
MOD='80d067907a6cbc0320298ec9e1a88016460c7c835b81701194b55f243d93101e'
SUM='c9c47f2121dd02259e1a29832ea1cd1eb327e4b8a384b09c973afbde3d590ee0'
def sha(x):return hashlib.sha256(x).hexdigest()
def encode(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def save(path,b):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as s:s.write(b);s.flush();os.fsync(s.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def filehash(path):
 h=hashlib.sha256()
 with path.open('rb') as src:
  for chunk in iter(lambda:src.read(1048576),b''):h.update(chunk)
 return h.hexdigest()
def main():
 if any(path.is_symlink() for path in (SRC,ROOT,RECEIPT)):
  raise ValueError('Symlinked binary source/output')
 actual=subprocess.check_output(['git','-C',str(SRC),'rev-parse','HEAD']).decode().strip()
 dirty=subprocess.check_output(['git','-C',str(SRC),'status','--porcelain'])
 if actual!=COMMIT or dirty or filehash(SRC/'go.mod')!=MOD or filehash(SRC/'go.sum')!=SUM:
  raise RuntimeError('Foreign runner version or dependency lock')
 m=int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))//1024
 if m<20480 or shutil.disk_usage('/mnt/media/p0-v3').free//1048576<14336:
  raise RuntimeError('Go artifact build violates host headroom')
 ROOT.mkdir(mode=0o700,exist_ok=True)
 RECEIPT.mkdir(mode=0o700,exist_ok=True)
 binpath=ROOT/'bin/forgejo-runner-v3.5.1'
 intent=RECEIPT/'build.intent.json';result=RECEIPT/'build.result.json'
 claim=encode({'sourceRepository':'code.forgejo.org/forgejo/runner','sourceCommit':COMMIT,
               'goModSha256':MOD,'goSumSha256':SUM,'goCompiler':'go1.24.4','embeddedVersion':'3.5.1',
               'effect':'module-checksummed-host-binary-build-only','binaryPath':str(binpath)})
 if intent.exists():
  if not result.is_file() or intent.read_bytes()!=claim:
   raise RuntimeError('Original runner binary build uncertain; no replay')
  saved=json.loads(result.read_bytes())
  if saved['intentSha256']!=sha(claim) or saved['binarySha256']!=filehash(binpath):
   raise RuntimeError('Original runner binary changed')
  print('Existing authenticated runner CLI binary verified');return
 if binpath.exists():raise RuntimeError('Unowned runner binary exists')
 (ROOT/'bin').mkdir(mode=0o700,exist_ok=True) if not (ROOT/'bin').exists() else None
 save(intent,claim)
 env={**os.environ,'GOPROXY':'https://proxy.golang.org','GOSUMDB':'sum.golang.org',
      'GOTOOLCHAIN':'local','CGO_ENABLED':'0','GOFLAGS':'-mod=readonly',
      'GOPATH':'/mnt/media/p0-v3/cache/go-ci-runner',
      'GOCACHE':'/mnt/media/p0-v3/cache/go-ci-runner-build'}
 with (RECEIPT/'build.stdout').open('xb') as stdout,(RECEIPT/'build.stderr').open('xb') as stderr:
  p=subprocess.run(['/usr/bin/go','build','-trimpath','-buildvcs=false','-tags=netgo,osusergo',
                    '-ldflags=-X gitea.com/gitea/act_runner/internal/pkg/ver.version=3.5.1 -s -w','-o',str(binpath),'.'],cwd=SRC,env=env,
                   stdout=stdout,stderr=stderr,timeout=1200)
 if p.returncode or not binpath.is_file() or binpath.stat().st_size<1024:
  raise RuntimeError('Original pinned runner binary build failed; intent retained')
 os.chmod(binpath,0o700)
 save(result,encode({'schemaVersion':1,'intentSha256':sha(claim),'binarySha256':filehash(binpath),
                     'binaryBytes':binpath.stat().st_size,'applicationStarted':False,
                     'runnerRegistered':False,'qualificationEvidence':False}))
 print('Sealed pinned runner CLI binary:',filehash(binpath))
if __name__=='__main__':main()
