#!/usr/bin/env python3
"""Read-only exact-source managed build reconciliation, never an original ACK.

No cleanup, build, tag, image mount/export, container effect or retry. stdout
reports content identity only; caller may seal it as separate observation.
"""
import hashlib,json,pathlib,subprocess,stat
ROOT=pathlib.Path('/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/q-5962a9fda75b')
SRC=pathlib.Path('/home/gerald/p0_v3/worklane')
TAG='localhost/p0v3-r9-worklane:source-1'
BASE=['/usr/bin/podman','--root',str(ROOT/'fresh-image-build-store'),
 '--runroot',str(ROOT/'fresh-image-build-run'),'--storage-driver','vfs',
 '--cgroup-manager','cgroupfs','--events-backend','file']
def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for block in iter(lambda:f.read(1048576),b''):h.update(block)
 return h.hexdigest()
def readonly(args):
 r=subprocess.run(BASE+args,capture_output=True,timeout=45)
 if r.returncode or not r.stdout or len(r.stdout)>4*1024*1024:
  raise RuntimeError('Original isolated source store readback unavailable')
 return r.stdout
def main():
 for part in (ROOT,ROOT/'fresh-image-build-store',ROOT/'fresh-image-build-run'):
  if part.is_symlink() or not part.is_dir() or part.stat().st_mode&0o077:
   raise RuntimeError('Foreign or nonprivate managed source store')
 intent=ROOT/'fresh-image-build.intent.json';log=ROOT/'fresh-image-build.log'
 if (ROOT/'fresh-image-build.result.json').exists() or (ROOT/'fresh-image-build-exit.result.json').exists():
  raise RuntimeError('Original result changed; reconciliation is not an ACK repair')
 if any(p.is_symlink() or not p.is_file() or p.stat().st_mode&0o077 for p in (intent,log)):
  raise RuntimeError('Unprotected or changed original intent/log')
 claim=json.loads(intent.read_bytes());lines=log.read_text(errors='strict').splitlines()
 assert claim['generation']=='q-5962a9fda75b' and claim['outputTag']==TAG and claim['nativeLaneStarted'] is False
 assert claim['scope']=='fresh-managed-source-only-not-native-lane' and claim['sourceHashes']=={
  name:digest(SRC/name) for name in ('Containerfile.v3','assets/v3/pi/package.json','assets/v3/pi/package-lock.json')}
 assert len(lines)>100 and lines[-2]=='Successfully tagged '+TAG
 image=json.loads(readonly(['image','inspect',TAG]))
 assert len(image)==1
 item=image[0];actual=item['Id'].removeprefix('sha256:')
 assert len(actual)==64 and lines[-1]==actual and item['Architecture']=='amd64' and item['Os']=='linux'
 assert TAG in item['RepoTags'] and int(item['Size'])>1048576
 layers=item.get('RootFS',{}).get('Layers',[])
 assert 1<=len(layers)<=128 and all(value.startswith('sha256:') and len(value)==71 for value in layers)
 containers=readonly(['ps','--all','--format','json'])
 assert json.loads(containers)==[] # no app or build container retained as an active cohort
 print(json.dumps({'schemaVersion':1,'generation':claim['generation'],
  'scope':'independent-readonly-original-source-content-observation-not-build-ack',
  'originalBuildIntentSha256':digest(intent),'originalBuildLogSha256':digest(log),
  'originalBuildAcknowledged':False,'originalBuildResultPresent':False,
  'imageId':'sha256:'+actual,'imageSizeBytes':int(item['Size']),
  'layerDiffIds':layers,'imageSourceTag':TAG,'imageContentObserved':True,
  'activeOrExitedContainers':False,'nativeLaneStarted':False,
  'qualificationEvidence':False},sort_keys=True,separators=(',',':')))
if __name__=='__main__':main()
