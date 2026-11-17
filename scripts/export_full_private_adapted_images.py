#!/usr/bin/env python3
"""Serially export six original, PINNED locally built images as new OCI archives.

Read-only source store, no application startup or canonical-store mutation.
Authenticates existing build receipts and live image identities before each
one-use export; checks OCI config digest and all indexed blobs afterwards.
Missing original export result is fenced; never retry or infer an ACK.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

MANIFEST = Path(__file__).resolve().parents[1] / 'release/full-source-local-builds.json'
SOURCE_ROOT = Path('/mnt/media/p0-v3/image-acquisition-receipts')
ROOT = SOURCE_ROOT / 'full-private-adapted-oci-archives-r1'
SOURCE = ['sudo','-n','/usr/bin/podman','--remote=false',
          '--root=/mnt/media/p0-v3/release-runtime/graph',
          '--runroot=/run/p0-v3-release-runtime/store',
          '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']

def sha(data): return hashlib.sha256(data).hexdigest()
def encode(obj): return (json.dumps(obj, indent=2, sort_keys=True)+'\n').encode()
def sync(path):
    fd=os.open(path,os.O_DIRECTORY|os.O_RDONLY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
def save(path,data):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as output:
        output.write(data);output.flush();os.fsync(output.fileno())
    sync(path.parent)
def filehash(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''): h.update(block)
    return h.hexdigest()
def preflight():
    if ROOT.is_symlink(): raise ValueError('Symlinked archive directory')
    ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    if ROOT.stat().st_mode&0o077: raise ValueError('Archive directory not private')
    m=int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines()
               if x.startswith('MemAvailable:')))//1024
    if m<16384+4096 or shutil.disk_usage(ROOT).free//1048576<10240+4096:
        raise ValueError('Pinned artifact export cannot preserve host headroom')
def readback(image):
    proc=subprocess.run(SOURCE+['image','inspect',image],capture_output=True,timeout=45)
    if proc.returncode or len(proc.stdout)>131072: raise RuntimeError('Original pinned source image unavailable')
    return json.loads(proc.stdout)[0]
def verify_archive(path, image_id):
    if path.is_symlink() or not path.is_file() or path.stat().st_size not in range(1024,12*1024**3):
        raise RuntimeError('Foreign or unbounded OCI archive')
    with tarfile.open(path,'r:*') as tar:
        entries={e.name:e for e in tar if e.isfile()}
        if len(entries) not in range(4,1024) or 'index.json' not in entries or 'oci-layout' not in entries:
            raise RuntimeError('No bounded OCI index')
        index=json.load(tar.extractfile(entries['index.json']))
        manifests=index.get('manifests',[])
        if len(manifests)!=1: raise RuntimeError('Archive has ambiguous manifest')
        descriptor=manifests[0]
        name=descriptor['digest'].replace('sha256:','blobs/sha256/')
        if name not in entries or entries[name].size!=descriptor['size']:
            raise RuntimeError('Indexed manifest missing')
        manifest=json.load(tar.extractfile(entries[name]))
        config=manifest['config']
        if config['digest']!='sha256:'+image_id or config['size']!=entries['blobs/sha256/'+image_id].size:
            raise RuntimeError('OCI archive config ID differs from pinned build')
        for item in [descriptor,config]+manifest.get('layers',[]):
            hashname=item['digest'].removeprefix('sha256:')
            entry=entries.get('blobs/sha256/'+hashname)
            if not re.fullmatch('[a-f0-9]{64}',hashname) or entry is None or entry.size!=item['size']:
                raise RuntimeError('OCI archive blob/size mismatch')
            digest=hashlib.sha256()
            with tar.extractfile(entry) as stream:
                for block in iter(lambda:stream.read(1048576),b''):digest.update(block)
            if digest.hexdigest()!=hashname: raise RuntimeError('OCI blob hash mismatch')
    return descriptor['digest']
def main():
    preflight()
    source=json.loads(MANIFEST.read_bytes())
    if source['scope']!='offline-source-provenance-only-not-runtime-inventory-or-native-admission' or len(source['images'])!=6:
        raise ValueError('Changed locally built source inventory')
    with (ROOT/'export.lock').open('a+b') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        for item in source['images']:
            preflight()
            kind=item['artifact']
            if not re.fullmatch('[a-z][a-z0-9-]{1,63}',kind):raise ValueError('Foreign artifact name')
            receipt=SOURCE_ROOT/item['receipt']/'receipt.json'
            if receipt.is_symlink() or not receipt.is_file():raise ValueError('Missing original local build receipt')
            proof=json.loads(receipt.read_bytes())
            observed=readback(item['image'])
            if (observed['Id'].removeprefix('sha256:')!=item['imageId'] or
                observed['Digest']!=item['image'].rsplit('@',1)[1] or
                observed['Architecture']!='amd64' or observed['Os']!='linux'):
                raise RuntimeError('Native original local build identity changed: '+kind)
            if (proof.get('imageId')!=item['imageId'] or proof.get('image',proof.get('digest',proof.get('imageDigest'))) not in
                (item['image'],item['image'].rsplit('@',1)[1])) and not any(
                    im.get('id')==item['imageId'] and im.get('reference')==item['image']
                    for im in proof.get('images',[])):
                raise ValueError('Original local build receipt does not authenticate image: '+kind)
            claim=encode({'schemaVersion':1,'artifact':kind,'sourceBuildReceiptSha256':filehash(receipt),
                'sourceInventorySha256':filehash(MANIFEST),'originalImage':item['image'],
                'imageId':item['imageId'],'effect':'read-only-image-export-to-new-sealed-oci-archive'})
            intent=ROOT/(kind+'.export.intent.json'); result=ROOT/(kind+'.export.result.json')
            archive=ROOT/(kind+'.oci.tar')
            if intent.exists():
                if not result.is_file() or intent.read_bytes()!=claim:
                    raise RuntimeError('Uncertain original artifact export; no replay: '+kind)
                saved=json.loads(result.read_bytes())
                if saved['intentSha256']!=sha(claim) or saved['archiveSha256']!=filehash(archive) or \
                        saved['imageId']!=item['imageId'] or saved['ociManifestDigest']!=verify_archive(archive,item['imageId']):
                    raise RuntimeError('Original OCI artifact receipt changed: '+kind)
                print(kind,'original OCI export and receipt verified',flush=True);continue
            if archive.exists():raise RuntimeError('Unowned archive path exists: '+kind)
            save(intent,claim)
            with archive.open('xb') as fd: os.fchmod(fd.fileno(),0o600)
            # The output path now belongs to this operation; an interrupted
            # save leaves an intent and incomplete file. Never attempt again.
            proc=subprocess.run(SOURCE+['save','--format=oci-archive','--output='+str(archive),item['image']],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=1200)
            if proc.returncode: raise RuntimeError('Original export failed; retain intent: '+kind)
            native_manifest=verify_archive(archive,item['imageId'])
            save(result,encode({'schemaVersion':1,'artifact':kind,'intentSha256':sha(claim),
                'sourceImage':item['image'],'imageId':item['imageId'],
                'ociManifestDigest':native_manifest,'archiveSha256':filehash(archive),
                'archiveBytes':archive.stat().st_size,'applicationStarted':False,
                'qualificationEvidence':False}))
            print(kind,'sealed OCI archive',archive.stat().st_size,'bytes',flush=True)

if __name__=='__main__':main()
