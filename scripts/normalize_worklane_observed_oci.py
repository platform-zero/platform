#!/usr/bin/env python3
"""Once-only local OCI index normalization of an acknowledged export, not a build ACK.

Original Worklane build result remains missing; original image, immutable export,
config and layer blobs are neither rebuilt nor re-labeled as an original build.
Only the locally repacked index descriptor receives the platform verified from
its original content-addressed config. No Podman load or native process starts.
"""
import copy,hashlib,io,json,os,shutil,tarfile
from pathlib import Path

OLD=Path('/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/q-5962a9fda75b')
NEW=Path('/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/worklane-platform-r2')
PRIOR=Path('/home/gerald/p0_v3/.coord/rapid-completion/core-worklane-oci-normalize-first-1077.log')
OBS=Path('/home/gerald/p0_v3/.coord/rapid-completion/core-r9-managed-original-readonly-reconcile-526.json')
TERMINAL=Path('/mnt/media/p0-v3/release-generations/q-dd36ebcf43ef/failed-pre-unit-stage-v1.disposition.json')
ORIGINAL=OLD/'worklane-observed.oci.tar'
ARCHIVE=NEW/'worklane-platform.oci.tar'
MAX=512*1024*1024

def digest(b):return hashlib.sha256(b).hexdigest()
def filehash(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()
def encode(v):return (json.dumps(v,sort_keys=True,separators=(',',':'))+'\n').encode()
def save(p,b):
 fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
 fd=os.open(p.parent,os.O_DIRECTORY|os.O_RDONLY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def private(p):
 if not p.is_file() or p.is_symlink() or p.stat().st_mode&0o777!=0o600 or p.stat().st_nlink!=1:raise RuntimeError('Changed private source '+str(p))
 return p.read_bytes()
def members(t):
 found={}
 for m in t.getmembers():
  if m.name in found or m.name.startswith('/') or '..' in m.name.split('/') or not (m.isfile() or m.isdir()):raise RuntimeError('Unsafe or duplicate OCI tar entry')
  found[m.name]=m
 return found
def inspect(p,receipt):
 with tarfile.open(p,'r:') as tar:
  entry=members(tar)
  def content(name,limit=2*1024*1024):
   m=entry.get(name)
   if m is None or not m.isfile() or m.size>limit:raise RuntimeError('Missing or oversized OCI member '+name)
   return tar.extractfile(m).read()
  indexBytes=content('index.json'); index=json.loads(indexBytes)
  if index.get('schemaVersion')!=2 or len(index.get('manifests',[]))!=1:raise RuntimeError('Unexpected OCI index shape')
  descriptor=index['manifests'][0];manifestDigest=receipt['ociManifestDigest']
  if descriptor.get('digest')!=manifestDigest or descriptor.get('mediaType')!='application/vnd.oci.image.manifest.v1+json':raise RuntimeError('Source descriptor changed')
  manifestBytes=content('blobs/sha256/'+manifestDigest.removeprefix('sha256:'))
  if digest(manifestBytes)!=manifestDigest.removeprefix('sha256:'):raise RuntimeError('Manifest blob changed')
  manifest=json.loads(manifestBytes);imageID=receipt['imageId']
  if manifest['config'].get('digest')!=imageID:raise RuntimeError('Config descriptor changed')
  configBytes=content('blobs/sha256/'+imageID.removeprefix('sha256:'))
  if digest(configBytes)!=imageID.removeprefix('sha256:'):raise RuntimeError('Original config blob changed')
  config=json.loads(configBytes)
  if (config.get('os'),config.get('architecture'))!=('linux','amd64') or config.get('rootfs',{}).get('diff_ids')!=receipt['layerDiffIds']:
   raise RuntimeError('Original config does not independently prove linux/amd64 and exact rootfs')
  layers=manifest.get('layers') or []
  if len(layers)!=len(receipt['layerDiffIds']) or any('blobs/sha256/'+layer['digest'].removeprefix('sha256:') not in entry for layer in layers):
   raise RuntimeError('Incomplete original selected layer chain')
  return {'indexSha256':digest(indexBytes),'descriptorSha256':digest(encode(descriptor)),
    'configSha256':digest(configBytes),'manifestSha256':digest(manifestBytes),
    'imageId':imageID,'manifestDigest':manifestDigest,'layers':[x['digest'] for x in layers],
    'platform':descriptor.get('platform'), 'configPlatform':{'os':config['os'],'architecture':config['architecture']}}
def main():
 source=private(OLD/'worklane-export.result.json');r=json.loads(source)
 obsBytes=OBS.read_bytes();obs=json.loads(obsBytes)
 term=private(TERMINAL)
 if digest(term)!='1ffd7dea5f9b6c5141f19d263e9f817ceaf9180ce39d413579fa06e94bfd0ee3':raise RuntimeError('Pre-unit failure not terminal')
 if r.get('originalBuildAcknowledged') is not False or r.get('separateExportAcknowledged') is not True or r.get('qualificationEvidence') is not False or \
    obs.get('originalBuildAcknowledged') is not False or obs.get('originalBuildResultPresent') is not False or \
    obs.get('originalBuildIntentSha256')!=filehash(OLD/'fresh-image-build.intent.json') or \
    r.get('observationSha256')!=digest(obsBytes) or r.get('exportExitSha256')!=filehash(OLD/'worklane-export-exit.result.json'):
  raise RuntimeError('Original lost build ACK or separate export lineage changed')
 if not ORIGINAL.is_file() or ORIGINAL.is_symlink() or ORIGINAL.stat().st_mode&0o777!=0o600 or ORIGINAL.stat().st_size!=r['archiveBytes'] or \
    filehash(ORIGINAL)!=r['archiveSha256']:raise RuntimeError('Immutable source OCI archive changed')
 before=inspect(ORIGINAL,r)
 if before['platform'] is not None:raise RuntimeError('Original archive is not the diagnosed missing-descriptor source')
 memory=int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))//1024
 if memory<20480 or shutil.disk_usage('/mnt/media/p0-v3').free//1048576<14336+2*MAX//1048576:
  raise RuntimeError('Original normalization exceeds host floor')
 if filehash(PRIOR)!='3c9bf5fac38365f733549729245ef9c342bee47ee42687e6bb1e522eab39d46e' or \
    Path('/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/worklane-platform-r1').exists():
  raise RuntimeError('Original pre-effect normalization refusal is not preserved')
 if NEW.exists():raise RuntimeError('Normalization already attempted; never replay')
 NEW.mkdir(mode=0o700)
 fd=os.open(NEW.parent,os.O_DIRECTORY|os.O_RDONLY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 claim=encode({'schemaVersion':2,'priorReadOnlyRefusalSha256':filehash(PRIOR),
  'action':'local-oci-index-platform-normalization-not-build-ack',
  'originalArchiveSha256':r['archiveSha256'],'originalExportResultSha256':digest(source),
  'originalLostBuildObservationSha256':digest(obsBytes),'originalBuildIntentSha256':obs['originalBuildIntentSha256'],
  'failedPreUnitTerminalSha256':digest(term),'before':before,'appStarted':False,'qualificationEvidence':False})
 save(NEW/'normalize.intent.json',claim)
 with tarfile.open(ORIGINAL,'r:') as origin,tarfile.open(ARCHIVE,'x:') as target:
  os.chmod(ARCHIVE,0o600)
  for member in origin:
   m=copy.copy(member)
   if m.name=='index.json':
    index=json.load(origin.extractfile(member));index['manifests'][0]['platform']=before['configPlatform']
    raw=json.dumps(index,sort_keys=True,separators=(',',':')).encode();m.size=len(raw)
    target.addfile(m,io.BytesIO(raw))
   elif m.isfile():target.addfile(m,origin.extractfile(member))
   else:target.addfile(m)
 with ARCHIVE.open('rb') as f:os.fsync(f.fileno())
 fd=os.open(NEW,os.O_DIRECTORY|os.O_RDONLY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 after=inspect(ARCHIVE,r)
 if after['platform']!=before['configPlatform'] or after['indexSha256']==before['indexSha256'] or \
    any(after[key]!=before[key] for key in ('imageId','manifestDigest','configSha256','manifestSha256','layers','configPlatform')):
  raise RuntimeError('Changed original OCI content or missing derived platform after normalization; retain intent')
 with tarfile.open(ORIGINAL,'r:') as a,tarfile.open(ARCHIVE,'r:') as b:
  original=members(a);target=members(b)
  if original.keys()!=target.keys():raise RuntimeError('Changed OCI tar member inventory')
  for name in original:
   if name=='index.json' or not original[name].isfile():continue
   if original[name].size!=target[name].size or digest(a.extractfile(original[name]).read())!=digest(b.extractfile(target[name]).read()):
    raise RuntimeError('Non-index OCI member changed')
 proof=encode({'schemaVersion':1,'intentSha256':digest(claim),'originalArchiveSha256':r['archiveSha256'],
  'archiveSha256':filehash(ARCHIVE),'archiveBytes':ARCHIVE.stat().st_size,'originalBuildAcknowledged':False,
  'separateExportAcknowledged':True,'nativeImportOccurred':False,'nativeApplicationStarted':False,
  'qualificationEvidence':False,'before':before,'after':after})
 save(NEW/'normalize.result.json',proof)
 print(json.dumps({'normalizedArchive':str(ARCHIVE),'sha256':filehash(ARCHIVE),
    'originalImageId':r['imageId'],'originalBuildAcknowledged':False,'nativeImportOccurred':False},sort_keys=True))
if __name__=='__main__':main()
