#!/usr/bin/env python3
"""Build a link-free CI-only transport from pinned, verified Caddy OCI binary.

No application startup. Replaces inherited Alpine absolute symlinks rejected
by the rootless OCI verifier, not that verifier's confinement policy. One-use
artifact build and export; an incomplete effect remains fenced.
"""
import hashlib,json,os,shutil,subprocess,tarfile
from pathlib import Path
from export_full_private_adapted_images import encode,save,filehash,verify_archive
ROOT=Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-ci-transport-minimal-r2')
SOURCE=Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-ci-trio-bound-r1/transport.oci.tar')
SOURCE_RESULT=SOURCE.with_name('transport.normalize.result.json')
CMD=['sudo','-n','/usr/bin/podman','--remote=false','--module=/mnt/media/p0-v3/runtime-stores/canonical-v2/containers.conf','--root=/mnt/media/p0-v3/runtime-stores/canonical-v2/graph','--runroot=/run/p0-v3-canonical-v2/store','--network-config-dir=/mnt/media/p0-v3/runtime-stores/canonical-v2/networks']
TAG='localhost/p0v3-ci-transport:executable-caddy-r2'
def sha(x):return hashlib.sha256(x).hexdigest()
def main():
 if ROOT.is_symlink() or SOURCE.is_symlink():raise ValueError('Foreign CI image source')
 ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
 original=json.loads(SOURCE_RESULT.read_bytes())
 if original['archiveSha256']!=filehash(SOURCE) or original['imageId']!='3067cc4e02c091399edbd5d65f85a3ff4d511574aecadb47f280c3761e68852e' or \
    original['ociManifestDigest']!=verify_archive(SOURCE,original['imageId']):
  raise ValueError('Caddy source archive has no authenticated original identity')
 context=ROOT/'context'
 if not context.exists():
  context.mkdir(mode=0o700)
  found=0
  with tarfile.open(SOURCE,'r:') as image:
   index=json.load(image.extractfile('index.json'));manifest=json.load(image.extractfile(
       'blobs/sha256/'+index['manifests'][0]['digest'].removeprefix('sha256:')))
   for layer in manifest['layers']:
    with tarfile.open(fileobj=image.extractfile('blobs/sha256/'+layer['digest'].removeprefix('sha256:')),mode='r|gz') as stream:
     for member in stream:
      if member.name.removeprefix('./')=='usr/bin/caddy':
       if found or member.size not in range(1024,128*1024*1024) or not member.isfile():raise ValueError('Ambiguous Caddy binary')
       with (context/'caddy').open('xb') as output:
        os.fchmod(output.fileno(),0o600);shutil.copyfileobj(stream.extractfile(member),output,1048576)
       found+=1
  if found!=1:raise ValueError('Pinned source Caddy binary missing')
  cf='FROM scratch\nCOPY --chmod=0755 caddy /usr/bin/caddy\nCOPY placeholder /etc/caddy/Caddyfile\n'
  for item in ('forgejo-leaf.pem','forgejo-leaf-key.pem','forgejo-ca.pem'):
   cf+='COPY placeholder /etc/ci/'+item+'\n'
  cf+='USER 0:0\nENTRYPOINT ["/usr/bin/caddy"]\n'
  save(context/'Containerfile',cf.encode());save(context/'placeholder',b'fixed-mount-placeholder\n')
 caddy=context/'caddy'
 if caddy.stat().st_size not in range(1024,128*1024*1024):raise ValueError('Modified source binary')
 source=encode({'schemaVersion':1,'sourceResultSha256':filehash(SOURCE_RESULT),'sourceArchiveSha256':filehash(SOURCE),
                'caddyBinarySha256':filehash(caddy),'containerfileSha256':filehash(context/'Containerfile'),
                'tag':TAG,'effect':'scratch-only COPY of pinned Caddy for rootless CI transport'})
 intent=ROOT/'build.intent.json';result=ROOT/'build.result.json';archive=ROOT/'transport.oci.tar'
 if intent.exists():
  if not result.is_file() or intent.read_bytes()!=source:raise RuntimeError('Original minimal transport build uncertain; no replay')
  old=json.loads(result.read_bytes())
  if old['archiveSha256']!=filehash(archive) or old['ociManifestDigest']!=verify_archive(archive,old['imageId']):raise RuntimeError('Bound transport archive changed')
  print('Original minimal transport image verified');return
 mem=int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))//1024
 if mem<20480 or shutil.disk_usage(ROOT).free//1048576<14336:raise RuntimeError('Transport build violates headroom')
 save(intent,source)
 p=subprocess.run(CMD+['build','--pull=never','--network=none','--format=oci','-f',str(context/'Containerfile'),'-t',TAG,str(context)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=900)
 if p.returncode:raise RuntimeError('Original transport build failed; intent retained')
 native=json.loads(subprocess.check_output(CMD+['image','inspect',TAG],timeout=35))[0]
 identity=native['Id'].removeprefix('sha256:')
 with archive.open('xb') as f:os.fchmod(f.fileno(),0o600)
 p=subprocess.run(CMD+['save','--format=oci-archive','--output='+str(archive),TAG],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=600)
 if p.returncode:raise RuntimeError('Original transport export failed; intent retained')
 manifest=verify_archive(archive,identity)
 save(result,encode({'schemaVersion':1,'intentSha256':sha(source),'imageId':identity,'ociManifestDigest':manifest,
                    'archiveSha256':filehash(archive),'archiveBytes':archive.stat().st_size,
                    'applicationStarted':False,'qualificationEvidence':False}))
 print('Link-free CI transport image sealed',identity,flush=True)
if __name__=='__main__':main()
