#!/usr/bin/env python3
"""Acquire versioned candidate images into the dedicated v3 store, not a deployment.
Tags are discovery inputs only. Digest references from local inspection are recorded;
compatibility review and a signed release lock are separate required steps.
No services, public ports, systemd units or existing Podman stores are modified.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = '/mnt/media/p0-v3/release-runtime'
RUN = '/run/p0-v3-release-runtime/store'
PODMAN = ['sudo', '-n', 'podman', '--root=' + ROOT + '/graph', '--runroot=' + RUN,
          '--network-config-dir=' + ROOT + '/network-config']

def command(args, timeout=900):
    return subprocess.run(args, check=True, text=True, capture_output=True, timeout=timeout)

def acquire(selection, receipts):
    store = json.loads(command(PODMAN + ['info', '--format', 'json']).stdout)['store']
    if store['graphRoot'] != ROOT + '/graph' or store['runRoot'] != RUN:
        raise RuntimeError('Podman store boundary mismatch')
    if receipts.is_symlink():
        raise RuntimeError('Symlink receipt directory')
    receipts.mkdir(mode=0o700, parents=True, exist_ok=True)
    if receipts.stat().st_mode & 0o077:
        raise RuntimeError('Receipt directory must be private')
    failed = []
    for image in selection:
        product, reference = image['product'], image['reference']
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', product):
            raise ValueError('Invalid product')
        if not re.fullmatch(r'[a-z0-9.-]+/[a-zA-Z0-9/_.-]+:[a-zA-Z0-9_.-]+', reference) or reference.endswith(':latest'):
            raise ValueError('Explicit registry and version tag required')
        target = receipts / (product + '.json')
        try:
            print('Acquiring ' + reference, flush=True)
            result = command(PODMAN + ['pull', '--platform=linux/amd64', reference])
            details = json.loads(command(PODMAN + ['image', 'inspect', reference]).stdout)[0]
            digests = details.get('RepoDigests', [])
            if details['Architecture'] != 'amd64' or details['Os'] != 'linux' or not digests:
                raise RuntimeError('Missing digest or incorrect architecture')
            if not all(re.fullmatch(r'.+@sha256:[a-f0-9]{64}', d) for d in digests):
                raise RuntimeError('Invalid repo digest')
            selected_digest = details.get('Digest', '')
            if not re.fullmatch(r'sha256:[a-f0-9]{64}', selected_digest):
                raise RuntimeError('Missing selected manifest digest')
            if target.exists():
                prior = json.loads(target.read_text())
                if prior['reference'] == reference and prior['imageId'] != details['Id']:
                    raise RuntimeError('Version tag changed image identity; previous receipt retained for review')
            record = {'schemaVersion': 1, 'status': 'downloaded-candidate-not-accepted-release',
                      'product': product, 'source': image['source'], 'reference': reference,
                      'imageId': details['Id'], 'repoDigests': digests, 'selectedManifestDigest': selected_digest,
                      'pinnedImage': reference.rsplit(':', 1)[0] + '@' + selected_digest,
                      'architecture': details['Architecture'], 'os': details['Os'],
                      'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'graphRoot': store['graphRoot'], 'runRoot': store['runRoot']}
            with tempfile.NamedTemporaryFile(mode='w', dir=receipts, delete=False) as out:
                json.dump(record, out, indent=2)
                out.write('\n')
                out.flush()
                os.fsync(out.fileno())
                temporary = out.name
            os.replace(temporary, target)
            print('Downloaded ' + product + ': ' + digests[0], flush=True)
        except (subprocess.SubprocessError, RuntimeError, KeyError) as exc:
            failed.append(product)
            print('FAILED ' + product + ': ' + str(exc), flush=True)
            if isinstance(exc, subprocess.CalledProcessError):
                print(exc.stderr[-3000:], flush=True)
    directory_fd = os.open(receipts, os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    if failed:
        raise SystemExit('Acquisition failed for: ' + ', '.join(failed))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('selection', type=Path)
    parser.add_argument('receipts', type=Path)
    args = parser.parse_args()
    acquire(json.loads(args.selection.read_text()), args.receipts)
