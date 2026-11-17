#!/usr/bin/env python3
"""Create-only r10 graph revision selecting reviewed Planka r2; preserve sealed r9."""
from pathlib import Path
import hashlib
import os

ROOT = Path(__file__).resolve().parents[1] / 'src/main/resources/fragments/v3'
SRC = ROOT / 'canonical/r9'
DST = ROOT / 'canonical/r10'
PLANKA = ROOT / 'planka/r2/fragment.yaml'

def sha(blob): return hashlib.sha256(blob).hexdigest()
def replace_once(text, before, after):
    if text.count(before) != 1: raise ValueError('Source revision selection drift')
    return text.replace(before, after, 1)

def save(name, data):
    path = DST / name
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'wb') as out:
        out.write(data); out.flush(); os.fsync(out.fileno())
    dirfd = os.open(DST, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(dirfd)
    finally: os.close(dirfd)


def main():
    old_manifest = (SRC / 'manifest.yaml').read_bytes()
    old_index = (SRC / 'index.yaml').read_bytes()
    selected = PLANKA.read_bytes()
    if sha(selected) != '9b9c9fac25ee9037e0ef045f5bd9c024f0e021f65ff595ccfd34339b166117ca':
        raise ValueError('Unreviewed Planka r2 fragment')
    manifest = old_manifest.decode('utf-8')
    manifest = replace_once(manifest, '"revision": 9,\n  "scope": "full-private"',
                            '"revision": 10,\n  "scope": "full-private"')
    manifest = replace_once(manifest, '"id": "planka-postgres",\n      "revision": 1',
                            '"id": "planka-postgres",\n      "revision": 2')
    index = old_index.decode('utf-8')
    index = index.replace('canonical/r9/', 'canonical/r10/')
    index = replace_once(index, 'manifestSha256: ' + sha(old_manifest), 'manifestSha256: ' + sha(manifest.encode()))
    old_recent = sha((ROOT / 'canonical/r8/manifest.yaml').read_bytes())
    index = replace_once(index, 'recentManifestSha256: ' + old_recent,
                         'recentManifestSha256: ' + sha(old_manifest))
    entry = 'id: planka-postgres\n  revision: 1\n  resource: planka/r1/fragment.yaml\n  sha256: 2a9d63897e071aff1e841e5afcd5bbeaf6d9c9fe55710ec87ddb785de516b560'
    next_entry = ('id: planka-postgres\n  revision: 2\n  resource: planka/r2/fragment.yaml\n  sha256: ' + sha(selected))
    index = replace_once(index, entry, next_entry)
    if DST.exists(): raise FileExistsError('r10 graph revision already materialized; do not rewrite')
    DST.mkdir(mode=0o755)
    save('manifest.yaml', manifest.encode())
    save('generated-caddy.json', (SRC / 'generated-caddy.json').read_bytes())
    save('index.yaml', index.encode())
    print('r10 manifestSha256=' + sha(manifest.encode()) + ' indexSha256=' + sha(index.encode()) +
          ' plankaR2Sha256=' + sha(selected) + ' sealedR9ManifestSha256=' + sha(old_manifest))

if __name__ == '__main__': main()
