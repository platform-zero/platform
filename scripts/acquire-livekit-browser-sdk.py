#!/usr/bin/env python3
"""Acquire a fixed upstream browser test dependency; never resolve latest or replace changed bytes."""
import base64
import hashlib
import io
import os
from pathlib import Path
import tarfile
import urllib.request

URL = 'https://registry.npmjs.org/livekit-client/-/livekit-client-2.15.6.tgz'
SRI = 'bLdNXklpMfWofw9pCF2XGyYA3OUddXXG4KY+gTN7dh+YvG7TX+YaP/Kt9ugdZ3KziQLqK2HG1ict4s7uD0JAiQ=='
SHA256 = '71ede404c69bf43c94bf158d979a796a2b546fc8c18256634e75a741b486435f'
WORKER_SHA256 = '6c1aa2363ceb3a7720700c47ebc8d6716ed6ea696306e7a7e0ea24e35b4902fa'
DESTINATION = Path('/mnt/media/p0-v3/cache/livekit-client-2.15.6.umd.js')


def unpack(data, sri=SRI, digest=SHA256, member='package/dist/livekit-client.umd.js'):
    if len(data) > 10000000 or base64.b64encode(hashlib.sha512(data).digest()).decode() != sri:
        raise ValueError('Pinned SDK archive integrity mismatch')
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
        entries = [m for m in archive.getmembers() if m.name == member]
        if len(entries) != 1 or not entries[0].isfile() or entries[0].size > 10000000:
            raise ValueError('Unexpected SDK archive member')
        content = archive.extractfile(entries[0]).read(10000001)
        if hashlib.sha256(content).hexdigest() != digest:
            raise ValueError('Pinned SDK file integrity mismatch')
        return content


def main():
    artifacts = [(DESTINATION, SHA256, 'package/dist/livekit-client.umd.js'),
                 (DESTINATION.with_name('livekit-client-2.15.6.e2ee.worker.js'), WORKER_SHA256, 'package/dist/livekit-client.e2ee.worker.js')]
    for path, digest, _ in artifacts:
        if path.exists() or path.is_symlink():
            if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError('Changed SDK cache retained; refusing replacement')
    missing = [(p, d, m) for p, d, m in artifacts if not p.exists()]
    if missing:
        with urllib.request.urlopen(URL, timeout=60) as response:
            if response.geturl() != URL: raise ValueError('Unexpected SDK redirect')
            data = response.read(10000001)
        verified = [(p, unpack(data, digest=d, member=m)) for p, d, m in missing]
        for path, content in verified:
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644), 'wb') as out:
                out.write(content); out.flush(); os.fsync(out.fileno())
    print('Pinned LiveKit browser SDK and E2EE worker verified')


if __name__ == '__main__':
    if not __debug__: raise SystemExit('Optimized Python disables safety checks; refusing effects')
    main()
