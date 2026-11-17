#!/usr/bin/env python3
"""One-use pull of the OLD v3.5.1 runner's observed immutable AMD64 manifest.
No runner registration or application startup. Missing ACK fences this effect.
"""
import hashlib, json, os
from pathlib import Path
import shutil, subprocess
ROOT=Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-ci-runner-image-r1')
MANIFEST=Path(__file__).resolve().parents[2]/'.coord/rapid-completion/forgejo-runner-v3.5.1-manifest-readonly-105.json'
IMAGE='code.forgejo.org/forgejo/runner@sha256:c6b28f34f0c23a44468e5f3284e0c9be144878de57f1a55d39014a7b3f8dfffe'
CMD=['sudo','-n','/usr/bin/podman','--remote=false','--module=/mnt/media/p0-v3/runtime-stores/canonical-v2/containers.conf','--root=/mnt/media/p0-v3/runtime-stores/canonical-v2/graph','--runroot=/run/p0-v3-canonical-v2/store','--network-config-dir=/mnt/media/p0-v3/runtime-stores/canonical-v2/networks']
def sha(x):return hashlib.sha256(x).hexdigest()
def encode(x):return (json.dumps(x,sort_keys=True,indent=2)+'\n').encode()
def save(path, data):
 fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def headroom():
 m=int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))//1024
 if m < 20480 or shutil.disk_usage(ROOT).free//1048576 < 14336:raise RuntimeError('CI artifact pull violates reserved headroom')
def main():
 if ROOT.is_symlink():raise ValueError('Symlink receipt dir')
 ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
 headroom()
 manifest=MANIFEST.read_bytes()
 entries=json.loads(manifest)['manifests']
 if len(entries)!=2 or len([entry for entry in entries if entry['platform']=={'architecture':'amd64','os':'linux'} and entry['digest']==IMAGE.rsplit('@',1)[1]])!=1:
  raise ValueError('Runner index/architecture changed')
 claim=encode({'sourceTag':'code.forgejo.org/forgejo/runner:3.5.1','observedIndexSha256':sha(manifest),'image':IMAGE,'effect':'pinned-ci-artifact-pull-only'})
 intent=ROOT/'pull.intent.json'; result=ROOT/'pull.result.json'
 if intent.exists():
  if not result.exists() or intent.read_bytes()!=claim:raise RuntimeError('Uncertain original CI image pull; no replay')
  saved=json.loads(result.read_bytes())
  if saved['intentSha256']!=sha(claim):raise RuntimeError('Original CI image pull receipt changed')
  print('CI runner original image receipt already sealed');return
 save(intent,claim)
 process=subprocess.run(CMD+['pull','--platform=linux/amd64',IMAGE],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=900)
 if process.returncode:raise RuntimeError('Pinned CI image pull failed; intent retained')
 inspected=subprocess.run(CMD+['image','inspect',IMAGE],capture_output=True,timeout=45,check=True)
 image=json.loads(inspected.stdout)[0]
 if image['Digest']!=IMAGE.rsplit('@',1)[1] or image['Os']!='linux' or image['Architecture']!='amd64' or len(image['Id'].removeprefix('sha256:'))!=64:
  raise RuntimeError('CI native identity differs; no ACK')
 save(result,encode({'schemaVersion':1,'intentSha256':sha(claim),'image':IMAGE,'imageId':image['Id'].removeprefix('sha256:'),'manifestDigest':image['Digest'],'applicationStarted':False,'qualificationEvidence':False}))
 print('CI runner image pull ACK sealed; imageId',image['Id'].removeprefix('sha256:'))
if __name__=='__main__':main()
