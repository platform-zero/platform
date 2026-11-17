#!/usr/bin/env python3
"""Acquire audit-only OLD topology bytes by exact public Git commit (never execute them).

The durable cache contains selected descriptor, ingress and generator source only.
It is not a runtime resource, credential source, release receipt or state migration.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

ROOT = Path('/mnt/media/p0-v3/reference-sources')
RELEASE = Path(__file__).resolve().parents[1] / 'release'
MANIFEST = Path(__file__).resolve().parents[1] / 'src/main/resources/fragments/v3/canonical/r9/manifest.yaml'
OLD_COMMIT = '36b6b74211036df8d425f8c6d6bec276c5f50aae'
GENERATOR_COMMIT = '42bd13939bc95439b3237cd3f53b06d03f6b85d4'
MODULES = 'https://github.com/geraldsummers/p0-modules.git'
GENERATOR = 'https://github.com/geraldsummers/sso-stack-generator.git'
CADDY = 'modules/caddy/legacy/stack.config/caddy/Caddyfile'
MAIN = 'runtime-generator/stack-generator.main.kts'
SCHEMA = 'runtime-generator/stack.runtime.schema.json'
HISTORICAL_AUDIT = Path(__file__).resolve().parents[2] / '.coord/rapid-completion/fresh-r9-old-vs-current-limits-288.json'
PROVENANCE = json.loads((RELEASE / 'fragment-provenance.json').read_text())
REFERENCE = json.loads(MANIFEST.read_text())['integratedReference']
assert PROVENANCE['commit'] == OLD_COMMIT
assert PROVENANCE['repository'] + '.git' == MODULES


def git(*args, cwd=None, input=None):
    env = os.environ.copy()
    env.update(GIT_TERMINAL_PROMPT='0', GIT_ASKPASS='/bin/false')
    # Reuse existing gh authentication in this process only; never alter credentials,
    # print a token, write a credential helper or check out an OLD repository.
    result = subprocess.run(['git', '-c', 'credential.helper=!gh auth git-credential', *args], cwd=cwd,
                            env=env, input=input, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=120)
    if result.returncode:
        raise RuntimeError('Pinned Git read failed with existing gh auth (no token printed): ' +
                           result.stderr.decode(errors='replace')[:400])
    return result.stdout


def acquire(url, commit, name, required_hashes, wanted):
    dest = ROOT / name
    if dest.exists() or dest.is_symlink():
        if dest.is_symlink():
            raise RuntimeError(f'Symlinked original reference cache forbidden: {dest}')
        saved = json.loads((dest / 'reference-provenance.json').read_text())
        if saved['repository'] != url or saved['commit'] != commit or not saved['verifiedGitCommitObject'] or \
                set(saved['files']) != set(required_hashes) | ({SCHEMA} if url == GENERATOR else set()):
            raise RuntimeError(f'Existing selected reference inventory changed: {dest}')
        for path, digest in required_hashes.items():
            verified_reference_file(name, commit, url, path, digest)
        for path in saved['files']:
            verified_reference_file(name, commit, url, path)
        return {'cache': str(dest), 'commit': commit, 'selectedRegularFiles': len(saved['files']),
                'previouslyFetchedExactBytesReverified': True}
    with tempfile.TemporaryDirectory(prefix='.acquire-', dir=ROOT) as folder:
        temp = Path(folder)
        repo = temp / 'objects'
        git('init', '--bare', '--object-format=sha1', str(repo))
        # Exact immutable commit, no branch HEAD substitution or checkout.
        git('fetch', '--depth=1', '--no-tags', url, commit, cwd=repo)
        if git('rev-parse', 'FETCH_HEAD', cwd=repo).decode().strip() != commit:
            raise RuntimeError('Fetched object is not the pinned commit')
        if git('cat-file', '-t', commit, cwd=repo).decode().strip() != 'commit':
            raise RuntimeError('Pinned identity is not a Git commit object')
        tree = git('ls-tree', '-r', '-z', commit, cwd=repo)
        selection = {}
        for row in tree.split(b'\0'):
            if not row:
                continue
            meta, path = row.split(b'\t', 1)
            mode, kind, oid = meta.decode().split()
            name_in_tree = path.decode('utf-8')
            if not wanted(name_in_tree):
                continue
            if mode not in ('100644', '100755') or kind != 'blob':
                raise RuntimeError(f'Non-regular selected reference file: {name_in_tree}')
            selection[name_in_tree] = oid
        if not required_hashes.keys() <= selection.keys():
            raise RuntimeError(f'Missing pinned reference paths: {required_hashes.keys() - selection.keys()}')
        material = temp / 'selected'
        material.mkdir(mode=0o700)
        hashes = {}
        for path, oid in sorted(selection.items()):
            data = git('cat-file', 'blob', oid, cwd=repo)
            actual_oid = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            if actual_oid != oid:
                raise RuntimeError(f'Git blob identity mismatch: {path}')
            sha = hashlib.sha256(data).hexdigest()
            if path in required_hashes and sha != required_hashes[path]:
                raise RuntimeError(f'Known reference SHA-256 mismatch: {path}')
            target = material / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            hashes[path] = {'gitBlobSha1': oid, 'sha256': sha}
        (material / 'reference-provenance.json').write_text(json.dumps({
            'schemaVersion': 1, 'purpose': 'selected-public-source-readonly-topology-reference',
            'repository': url, 'commit': commit, 'verifiedGitCommitObject': True,
            'files': hashes, 'runtimeAuthority': False, 'oldStateImported': False,
            'historicalCapacityTableSha256': hashlib.sha256(HISTORICAL_AUDIT.read_bytes()).hexdigest()
                if url == MODULES else None,
            'access': 'existing-gh-auth-in-process-only-no-auth-configuration-written',
        }, indent=2, sort_keys=True) + '\n')
        os.replace(material, dest)
        return {'cache': str(dest), 'commit': commit, 'selectedRegularFiles': len(hashes)}


def verified_reference_file(name, commit, repository, relative, expected_sha=None):
    """Read only a selected, individually hashed file from a pinned durable source cache."""
    directory = ROOT / name
    receipt = directory / 'reference-provenance.json'
    if not receipt.is_file() or receipt.is_symlink() or directory.is_symlink():
        raise FileNotFoundError(f'Pinned OLD reference cache unavailable: {directory}; run refetch_pinned_old_references.py')
    meta = json.loads(receipt.read_text())
    if (meta['purpose'] != 'selected-public-source-readonly-topology-reference' or
            meta['repository'] != repository or meta['commit'] != commit or
            meta['verifiedGitCommitObject'] is not True or meta['runtimeAuthority'] is not False):
        raise ValueError('Unverified OLD cache provenance')
    if relative not in meta['files'] or Path(relative).is_absolute() or '..' in Path(relative).parts:
        raise ValueError('OLD path is not in the verified selected-source manifest')
    path = directory / relative
    if any(part.is_symlink() for part in (path, *path.parents) if part != ROOT.parent and ROOT in part.parents):
        raise ValueError('Symlinked OLD reference source')
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != meta['files'][relative]['sha256'] or (expected_sha and actual != expected_sha):
        raise ValueError(f'OLD reference bytes differ from pinned source: {relative}')
    return path


def main():
    if ROOT.is_symlink():
        raise RuntimeError('Reference cache root cannot be a symlink')
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptors = re.compile(r'^modules/[^/]+/legacy/stack\.runtime\.yaml$')
    old_hashes = {CADDY: REFERENCE['routeSourceSha256']}
    for item in PROVENANCE['sources']:
        if item['path'] == 'modules/postgres/legacy/stack.runtime.yaml':
            old_hashes[item['path']] = item['sha256']
    historical = json.loads(HISTORICAL_AUDIT.read_bytes())
    for row in historical['oldServiceInventory']:
        name = row['descriptor'].split('/modules/', 1)
        if len(name) != 2 or not descriptors.fullmatch('modules/' + name[1]):
            raise RuntimeError('Historical OLD descriptor table has an unexpected path')
        relative = 'modules/' + name[1]
        prior = old_hashes.get(relative)
        if prior and prior != row['descriptorSha256']:
            raise RuntimeError('Historical descriptor hash conflicts with repository provenance')
        old_hashes[relative] = row['descriptorSha256']
    if len(old_hashes) != 48 or len(historical['oldServiceInventory']) != 94:
        raise RuntimeError('Original 47-descriptor historical hash-bound table incomplete')
    acquired = [acquire(MODULES, OLD_COMMIT, 'p0-modules-' + OLD_COMMIT,
                        old_hashes, lambda p: bool(descriptors.fullmatch(p)) or p == CADDY)]
    acquired.append(acquire(GENERATOR, GENERATOR_COMMIT, 'sso-stack-generator-' + GENERATOR_COMMIT,
                            {MAIN: REFERENCE['generatorSha256']}, lambda p: p in (MAIN, SCHEMA)))
    print(json.dumps({'verifiedReferences': acquired, 'nativeEffects': False}, indent=2))


if __name__ == '__main__':
    main()
