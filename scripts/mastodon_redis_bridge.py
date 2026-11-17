#!/usr/bin/env python3
"""Pinned, thin ENTRY to the single fixed production Mastodon Redis broker resource."""
if not __debug__:
    raise SystemExit('Optimized Python forbidden before broker imports/effects')
import hashlib
import os
import sys

SOURCE = '/run/secrets/mastodon-redis-bridge-runtime.py'
CONFIG = '/run/secrets/mastodon-redis-bridge.json'
SOURCE_SHA256 = 'ba35c8b113a8e4ddafb540e110226100b6db94c0e591b6947b0aa895d7669491'


def main():
    if sys.argv != [sys.argv[0]] or os.path.islink(SOURCE) or os.path.islink(CONFIG):
        raise SystemExit('Fixed immutable bridge mounts required')
    with open(SOURCE, 'rb') as source:
        data = source.read(131073)
    if len(data) > 131072 or hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise SystemExit('Foreign versioned production broker resource')
    os.execve('/usr/bin/python3', ['/usr/bin/python3', '-I', SOURCE, CONFIG],
              {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'})


if __name__ == '__main__':
    main()
