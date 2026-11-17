#!/usr/bin/env python3
"""Acquire two OLD-pinned public support images into the canonical artifact store.

No application/container startup. Immutable digest, source SHA, private one-use
intent/result, serial pull, store identity and host headroom checks. A missing
result is uncertain; inspection NEVER backfills a missing original ACK.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT = Path('/mnt/media/p0-v3/image-acquisition-receipts/full-private-support-images-r1')
STORE = '/mnt/media/p0-v3/runtime-stores/canonical-v2/graph'
RUN = '/run/p0-v3-canonical-v2/store'
CMD = ['/usr/bin/sudo', '-n', '/usr/bin/podman', '--remote=false',
       '--module=/mnt/media/p0-v3/runtime-stores/canonical-v2/containers.conf',
       '--root=' + STORE, '--runroot=' + RUN,
       '--network-config-dir=/mnt/media/p0-v3/runtime-stores/canonical-v2/networks']
OLD = Path('/tmp/p0-old-full-36b6b7/modules')
SOURCES = (
    ('keycloak-auth-gateway', 'quay.io/oauth2-proxy/oauth2-proxy@sha256:aa0bd8dd5ab0c78e4c91c92755ad573a5f92241f88138b4141b8ec803463b4fd',
     'd38afc14334e8eeacffdcc30a4b5824ec75077e20a1c5707e122b72a02d46c12'),
    ('portal', 'ghcr.io/gethomepage/homepage@sha256:a0b71c8e757298d02560186bab9fbe3fc2d375c523a62cc1019177b37e48aa28',
     '7fa7c373df9cfa73b3785108868ff2bd6ed0de40b9b43765f979801eddb03de4'),
)

def sha(data): return hashlib.sha256(data).hexdigest()
def record(data): return (json.dumps(data, indent=2, sort_keys=True) + '\n').encode()
def sync(path):
    fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)
def save(path, value):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as target:
        target.write(value); target.flush(); os.fsync(target.fileno())
    sync(path.parent)
def preflight():
    if ROOT.is_symlink(): raise ValueError('Symlink receipt root')
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if ROOT.stat().st_mode & 0o077: raise ValueError('Receipt directory is not private')
    m = next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:'))
    if int(m)//1024 < 16384+4096 or shutil.disk_usage(ROOT).free//1048576 < 10240+4096:
        raise ValueError('Artifact acquisition violates reserved memory/disk headroom')
def native(args, timeout=60):
    proc = subprocess.run(CMD+args, capture_output=True, timeout=timeout)
    if proc.returncode or len(proc.stdout) > 262144 or len(proc.stderr)>8192:
        raise RuntimeError('Canonical image/store readback failed (no ACK manufactured)')
    return proc.stdout

def main():
    global ROOT, SOURCES
    if sys.argv[1:] == ['--portal-only']:
        # The earlier oauth2-proxy pull's original result is missing due to an
        # over-strict image-ID format check. Keep its original intent fenced;
        # the independent portal source may be acquired under a distinct ID.
        ROOT = ROOT.with_name('full-private-portal-image-r2')
        SOURCES = SOURCES[1:]
    elif sys.argv[1:] == ['--firefly-importer-only']:
        # Independently journal this OLD-pinned support artifact. Its presence
        # does not itself bind an executable importer or approve old credentials.
        ROOT = Path('/mnt/media/p0-v3/image-acquisition-receipts/fresh-r9-firefly-importer-image-r1')
        SOURCES = (('firefly-iii',
            'docker.io/fireflyiii/data-importer@sha256:2627644321afdcb52b49b258126bfe98312c2f93a709cc3a07c90327854e6aa2',
            '0a5ee8c35ddd4662d13e9ca46c8499a4c0e7bfd520b164745f5083683e20f0b6'),)
    elif sys.argv[1:] == ['--firefly-sso-only']:
        ROOT = Path('/mnt/media/p0-v3/image-acquisition-receipts/fresh-r9-firefly-sso-image-r1')
        SOURCES = (('firefly-iii',
            'quay.io/oauth2-proxy/oauth2-proxy@sha256:8caf464e485b9cad9ff02aaed4a48e6aef358cc968065e1b1716e920c1ac5f5c',
            '0a5ee8c35ddd4662d13e9ca46c8499a4c0e7bfd520b164745f5083683e20f0b6'),)
    elif sys.argv[1:]:
        raise ValueError('Only fixed support image selection is supported')
    preflight()
    with (ROOT / 'acquisition.lock').open('a+b') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        preflight()
        store = json.loads(native(['info','--format','json']))
        if store['store']['graphRoot'] != STORE or store['store']['runRoot'] != RUN or store['host']['security']['rootless']:
            raise ValueError('Wrong OCI store or rootless boundary')
        for product, image, source_sha in SOURCES:
            source = OLD / product / 'legacy/stack.runtime.yaml'
            if source.is_symlink() or sha(source.read_bytes()) != source_sha or not re.fullmatch(
                r'[a-z0-9./-]+@sha256:[a-f0-9]{64}', image):
                raise ValueError('OLD provenance or immutable image digest changed')
            intent = ROOT / (product + '.pull.intent.json')
            result = ROOT / (product + '.pull.result.json')
            claim = record({'schemaVersion':1,'product':product,'image':image,'sourceSha256':source_sha,
                            'storeGraph':STORE,'storeRun':RUN,'effect':'pinned-artifact-pull-only'})
            if intent.exists():
                if not result.is_file() or intent.read_bytes()!=claim:
                    raise RuntimeError(product + ' original image pull uncertain; no retry')
                saved = json.loads(result.read_bytes())
                if saved.get('intentSha256')!=sha(claim) or not saved.get('originalPullAcknowledged'):
                    raise RuntimeError(product + ' original image receipt changed')
                actual = json.loads(native(['image','inspect',image]))[0]
                if actual['Id']!=saved['imageId'] or actual['Digest']!=saved['manifestDigest']:
                    raise RuntimeError(product + ' original image identity changed')
                print(product, 'original ACK and native identity preserved',flush=True)
                continue
            preflight()
            save(intent, claim)
            # stdout/stderr are never used as credentials. The result is written
            # only after original pull exits zero AND exact digest/ID readback.
            pull = subprocess.run(CMD+['pull','--platform=linux/amd64',image],
                                  stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=900)
            if pull.returncode: raise RuntimeError(product + ' pull failed; intent retained, no retry')
            actual = json.loads(native(['image','inspect',image]))[0]
            image_id = actual['Id']
            digest = actual['Digest']
            if not re.fullmatch(r'(?:sha256:)?[a-f0-9]{64}',image_id) or digest != image.rsplit('@',1)[1] or \
                    actual['Architecture']!='amd64' or actual['Os']!='linux':
                raise RuntimeError(product + ' native image identity differs; intent retained')
            save(result, record({'schemaVersion':1,'product':product,'image':image,
                                 'intentSha256':sha(claim),'imageId':image_id,'manifestDigest':digest,
                                 'originalPullAcknowledged':True,'applicationStarted':False,
                                 'qualificationEvidence':False}))
            print(product, 'original pinned image pull ACK sealed',flush=True)

if __name__ == '__main__':
    main()
