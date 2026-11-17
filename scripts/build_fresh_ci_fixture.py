#!/usr/bin/env python3
"""Build a bounded, locally reviewed Forgejo workflow Git bundle, without action mirrors.

Source-only: accepts an already acquired job-image digest. It never contacts a
remote or starts a container. Outputs must be a new directory under the private
CI repository anchor; consume its sha256/commit in the fresh source plan.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ANCHOR = Path('/mnt/media/p0-v3/release-bootstrap-anchors/forgejo-ci/repository')
IMAGE = re.compile(r'[a-z0-9./_-]+@sha256:([a-f0-9]{64})\Z')

def git(where, *args):
    env = {**os.environ, 'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
           'GIT_ALLOW_PROTOCOL': 'file', 'GIT_AUTHOR_NAME': 'P0V3 reviewed local fixture',
           'GIT_COMMITTER_NAME': 'P0V3 reviewed local fixture',
           'GIT_AUTHOR_EMAIL': 'fixture@localhost.invalid',
           'GIT_COMMITTER_EMAIL': 'fixture@localhost.invalid',
           'GIT_AUTHOR_DATE': '2001-01-01T00:00:00 +0000',
           'GIT_COMMITTER_DATE': '2001-01-01T00:00:00 +0000'}
    return subprocess.run(['/usr/bin/git', *args], cwd=where, env=env, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=90).stdout

def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as source:
        for chunk in iter(lambda: source.read(1048576), b''):
            h.update(chunk)
    return h.hexdigest()

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--name', required=True)
    p.add_argument('--job-image', required=True)
    p.add_argument('--job-image-id', help='OCI config image ID; distinct from OCI manifest digest')
    a = p.parse_args()
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,39}', a.name) or not IMAGE.fullmatch(a.job_image):
        p.error('a bounded fixture name and an acquired immutable job image are required')
    if a.job_image.startswith('localhost/p0v3-ci-job@sha256:'):
        receipt = Path('/mnt/media/p0-v3/image-acquisition-receipts/forgejo-ci-minimal-bound-r2/job.normalize.result.json')
        bound = json.loads(receipt.read_bytes())
        if (not a.job_image_id or not re.fullmatch('[a-f0-9]{64}', a.job_image_id) or
            a.job_image != bound['sourceImageReference'] or a.job_image_id != bound['imageId'] or
            bound['archiveSha256'] != digest(receipt.parent / 'job.oci.tar')):
            p.error('local job image requires an exact bound OCI config ID and archive receipt')
    elif a.job_image_id is not None and (not re.fullmatch('[a-f0-9]{64}', a.job_image_id) or
            a.job_image_id != IMAGE.fullmatch(a.job_image).group(1)):
        p.error('non-local source requires its pinned selected image digest')
    root = ANCHOR / a.name
    if root.exists() or root.is_symlink():
        p.error('fixture already exists; preserve it and never overwrite an acquired source')
    root.mkdir(parents=True, mode=0o700)
    os.chmod(root, 0o700)
    repo = root / 'source'
    repo.mkdir(mode=0o700)
    git(repo, 'init', '-q', '-b', 'main')
    workflow = repo / '.forgejo/workflows/reviewed-fixture.yml'
    workflow.parent.mkdir(parents=True, mode=0o700)
    workflow.write_text('''name: p0v3-reviewed-private-fixture
on: workflow_dispatch
permissions:
  contents: read
jobs:
  reviewed:
    runs-on: p0v3-rootless-oci
    container:
      image: %s
    timeout-minutes: 10
    steps:
      - name: Review local pinned worker tools
        shell: bash
        run: |
          set -euo pipefail
          mkdir -p artifacts
          printf 'p0v3 reviewed local fixture\\n' | tee artifacts/fixture.txt
          test -s artifacts/fixture.txt
''' % a.job_image, encoding='utf-8')
    # Deterministic bounded evidence payload keeps a genuine Git bundle above
    # the minimum archive size without fabricating credentials or action mirrors.
    readme = repo / 'README.md'
    readme.write_text('P0V3 private local fixture; source-only, no public publication.\n' +
                      ''.join(f'{n:03d} {hashlib.sha256(str(n).encode()).hexdigest()}\n'
                              for n in range(96)), encoding='utf-8')
    git(repo, 'add', '--', '.forgejo/workflows/reviewed-fixture.yml', 'README.md')
    git(repo, 'commit', '-q', '-m', 'Pinned local private CI fixture')
    commit = git(repo, 'rev-parse', 'HEAD').decode().strip()
    bundle = root / 'trusted.bundle'
    git(repo, 'bundle', 'create', str(bundle), 'refs/heads/main')
    if not (1024 <= bundle.stat().st_size <= 128 * 1024 * 1024):
        raise RuntimeError('fixture bundle outside source bounds')
    manifest = {'schemaVersion': 1, 'repository': 'private/trusted-repo',
                'trustedCommit': commit, 'workflowSha256': digest(workflow),
                'workflowPath': str(workflow), 'repositoryBundleSha256': digest(bundle),
                'repositoryBundlePath': str(bundle), 'jobImage': a.job_image,
                'jobImageId': a.job_image_id or IMAGE.fullmatch(a.job_image).group(1),
                'actionMirrors': []}
    (root / 'source.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    for item in (workflow, readme, bundle, root / 'source.json'):
        item.chmod(0o600)
    print(json.dumps(manifest, sort_keys=True))

if __name__ == '__main__':
    main()
