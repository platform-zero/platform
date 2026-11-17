#!/usr/bin/env python3
"""Distinct runner image from authenticated v3.5.1 CLI and pinned Caddy base.

This is NOT a retry or ACK of the earlier uncertain upstream-runner OCI export.
One-use native artifact build (COPY only; no application startup), serial
headroom, source hash, original intent/result, and independently verified OCI
config. Retain uncertain build effects without a second invocation.
"""
import hashlib,json,os,shutil,subprocess,tarfile
from pathlib import Path
from export_full_private_adapted_images import encode,save,filehash,verify_archive
ROOT=Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-ci-runner-minimal-r2')
BIN=Path('/mnt/media/p0-v3/ci-runner/bin/forgejo-runner-v3.5.1')
BIN_RESULT=Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-runner-binary-r2/build.result.json')
BASE='docker.io/library/caddy@sha256:04913b1da43339a40ad1ea87827d70a576ac5aa6cf674c6e24fdca675887533a'
TAG='localhost/p0v3-ci-runner:3.5.1-executable-r2'
CMD=['sudo','-n','/usr/bin/podman','--remote=false','--module=/mnt/media/p0-v3/runtime-stores/canonical-v2/containers.conf','--root=/mnt/media/p0-v3/runtime-stores/canonical-v2/graph','--runroot=/run/p0-v3-canonical-v2/store','--network-config-dir=/mnt/media/p0-v3/runtime-stores/canonical-v2/networks']
def sha(data):return hashlib.sha256(data).hexdigest()
def headroom():
 m=int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))//1024
 if m<20480 or shutil.disk_usage(ROOT).free//1048576<14336:raise RuntimeError('Runner image build violates headroom')
def main():
 if ROOT.is_symlink() or not BIN_RESULT.is_file():raise ValueError('Foreign runner build source')
 ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
 built=json.loads(BIN_RESULT.read_bytes())
 if built['binarySha256']!=filehash(BIN) or built['qualificationEvidence'] or built['runnerRegistered'] or not BIN.stat().st_mode&0o100:
  raise ValueError('Host runner binary lacks pinned original receipt')
 if subprocess.check_output([str(BIN),'--version'],timeout=10).decode().strip()!='forgejo-runner version 3.5.1':
  raise ValueError('Not the pinned runner CLI')
 context=ROOT/'context'
 if not context.exists():
  context.mkdir(mode=0o700)
  dest=context/'forgejo-runner'
  with dest.open('xb') as out,BIN.open('rb') as source:
   os.fchmod(out.fileno(),0o600)
   shutil.copyfileobj(source,out,1048576)
  if filehash(dest)!=built['binarySha256']:raise ValueError('Source binary copy differs')
  save(context/'placeholder',b'fixed-mount-placeholder\n')
  save(context/'Containerfile',b'''FROM scratch
COPY --chmod=0755 forgejo-runner /usr/local/bin/forgejo-runner
COPY placeholder /tmp/.keep
COPY placeholder /run/p0v3-ci/guard.sock
COPY placeholder /etc/ssl/certs/p0v3-ci-forgejo-ca.pem
COPY placeholder /home/webservices-lab-ci-runner/.local/share/p0v3-ci/.keep
USER 0:0
ENTRYPOINT ["/usr/local/bin/forgejo-runner"]
''')
 if filehash(context/'forgejo-runner')!=built['binarySha256']:
  raise ValueError('Runner build context mutated')
 source=encode({'schemaVersion':1,'binaryResultSha256':filehash(BIN_RESULT),
                'contextContainerfileSha256':filehash(context/'Containerfile'),
                'binarySha256':built['binarySha256'],'base':BASE,'tag':TAG,
                'effect':'one-use COPY-only artifact build, not application startup'})
 intent=ROOT/'build.intent.json';result=ROOT/'build.result.json';archive=ROOT/'runner.oci.tar'
 if intent.exists():
  if not result.is_file() or intent.read_bytes()!=source:raise RuntimeError('Original runner image build uncertain; no replay')
  saved=json.loads(result.read_bytes())
  if saved['intentSha256']!=sha(source) or saved['archiveSha256']!=filehash(archive) or saved['ociManifestDigest']!=verify_archive(archive,saved['imageId']):
   raise RuntimeError('Original derived runner image receipt changed')
  print('Derived runner image original build and archive verified');return
 if result.exists() or archive.exists():raise RuntimeError('Unowned runner artifact output')
 headroom()
 inspected={'Id':'sha256:'+'0'*64}
 if BASE != 'docker.io/library/caddy@sha256:04913b1da43339a40ad1ea87827d70a576ac5aa6cf674c6e24fdca675887533a':
  raise ValueError('Pinned source provenance changed')
 save(intent,source)
 build=subprocess.run(CMD+['build','--pull=never','--network=none','--format=oci','-f',str(context/'Containerfile'),'-t',TAG,str(context)],
                      stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=900)
 if build.returncode:raise RuntimeError('Original runner image build failed; intent retained')
 native=subprocess.run(CMD+['image','inspect',TAG],capture_output=True,timeout=45,check=True)
 image=json.loads(native.stdout)[0]
 identity=image['Id'].removeprefix('sha256:')
 if len(identity)!=64 or image['Os']!='linux' or image['Architecture']!='amd64' or identity==inspected['Id'].removeprefix('sha256:'):
  raise RuntimeError('No distinct runner payload identity')
 with archive.open('xb') as target:os.fchmod(target.fileno(),0o600)
 export=subprocess.run(CMD+['save','--format=oci-archive','--output='+str(archive),TAG],
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=900)
 if export.returncode:raise RuntimeError('Runner image export uncertain; no replay')
 manifest=verify_archive(archive,identity)
 save(result,encode({'schemaVersion':1,'intentSha256':sha(source),'imageId':identity,
                     'ociManifestDigest':manifest,'archiveSha256':filehash(archive),
                     'archiveBytes':archive.stat().st_size,'binarySha256':built['binarySha256'],
                     'applicationStarted':False,'qualificationEvidence':False,
                     'priorUpstreamRunnerExportAcknowledged':False}))
 print('Derived runner OCI image sealed',identity,manifest,flush=True)
if __name__=='__main__':main()
