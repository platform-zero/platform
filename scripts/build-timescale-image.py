#!/usr/bin/env python3
"""Fixed private Timescale artifact build, not a deployment or generic command runner.

Source/dependency acquisition precedes a hash-sealed, network-none build. Every native
mutation has a CREATE_NEW/fsynced intent and original result. Missing/failed results
refuse replay; retained containers/networks/build intermediates are never auto-cleaned.
Uses Python consistently with the existing image-acquisition tools; runtime orchestration
and application admission remain in Kotlin.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import urllib.request

JOB = 'timescale-pg17-231-r1'
ROOT = Path('/mnt/media/p0-v3/image-acquisition-receipts') / JOB
BASE = 'docker.io/library/postgres@sha256:2cd2c0f809604aaeff6f0ec8f40aecbd025613107561015c69369a1a7f1d3416'
BASE_ID = '99445113a4a19e82dd3713c65bd9f6fb5bf972065ab043df8d1e1c93e957da9a'
COMMIT = '4fa2a7c6b579171a1a8966fd87a0d4189ebab43b'
SOURCE = 'https://codeload.github.com/timescale/timescaledb/tar.gz/' + COMMIT
TAG = 'localhost/p0-v3/postgres-timescale:2.31.0-pg17.11-r1'
NAME = 'p0v3-build-' + JOB
MODULE = Path('/mnt/media/p0-v3/runtime-stores/canonical-v2/containers.conf')
PODMAN = ['sudo', '-n', '/usr/bin/podman', '--remote=false', '--module=' + str(MODULE),
          '--root=/mnt/media/p0-v3/runtime-stores/canonical-v2/graph',
          '--runroot=/run/p0-v3-canonical-v2/store',
          '--network-config-dir=/mnt/media/p0-v3/runtime-stores/canonical-v2/networks']
RECIPE = Path(__file__).resolve().parent.parent / 'images/postgres-timescale'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def save(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    sync(path.parent)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def private_directory(path):
    info = path.lstat()
    if path.resolve() != path or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('Owned private build directory required')


def original(path, maximum=32 * 1024 * 1024):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > maximum:
        raise ValueError('Original private build record changed')
    with path.open('rb') as source:
        return source.read(maximum + 1)


def headroom():
    mem = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    if int(mem['MemAvailable'].split()[0]) < (16384 + 4096) * 1024 or shutil.disk_usage(ROOT).free < (10240 + 4096) * 1024**2:
        raise RuntimeError('Artifact build would violate reserved headroom')


def effect(key, args, timeout=1800, binding=None):
    headroom()
    intent = {'job': JOB, 'argv': PODMAN + args, 'moduleSha256': sha(MODULE.read_bytes())}
    if binding is not None:
        intent['inputsSha256'] = binding
    path = ROOT / (key + '.intent.json')
    result_path = ROOT / (key + '.result.json')
    if path.exists():
        if original(path) != encode(intent) or not result_path.exists():
            raise RuntimeError('Original artifact operation uncertain or changed; no replay')
        result = json.loads(original(result_path))
        output = original(ROOT / (key + '.stdout'))
        error = original(ROOT / (key + '.stderr'))
        if result != {'exitCode': 0, 'intentSha256': sha(encode(intent)), 'stdoutSha256': sha(output), 'stderrSha256': sha(error)}:
            raise RuntimeError('Failed or changed artifact operation retained; no replay')
        return output
    save(path, encode(intent))
    with os.fdopen(os.open(ROOT / (key + '.stdout'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as out, \
         os.fdopen(os.open(ROOT / (key + '.stderr'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'wb') as err:
        # A timeout leaves the original intent without a result. Never retry or invent cleanup.
        process = subprocess.run(PODMAN + args, stdout=out, stderr=err, timeout=timeout, check=False)
        out.flush(); os.fsync(out.fileno()); err.flush(); os.fsync(err.fileno())
    output = original(ROOT / (key + '.stdout'))
    error = original(ROOT / (key + '.stderr'))
    save(result_path, encode({'exitCode': process.returncode, 'intentSha256': sha(encode(intent)),
                             'stdoutSha256': sha(output), 'stderrSha256': sha(error)}))
    if process.returncode:
        raise RuntimeError('Artifact command failed; original result and resources retained: ' + key)
    return output


def acquire_source():
    save(ROOT / 'source.intent.json', encode({'url': SOURCE, 'commit': COMMIT}))
    with urllib.request.urlopen(SOURCE, timeout=60) as response:
        data = response.read(64 * 1024 * 1024 + 1)
    if len(data) > 64 * 1024 * 1024:
        raise ValueError('Oversized source archive')
    context = ROOT / 'context'
    context.mkdir(mode=0o700)
    save(context / 'timescaledb.tar.gz', data)
    with tarfile.open(context / 'timescaledb.tar.gz', 'r:gz') as archive:
        members = archive.getmembers()
        prefix = 'timescaledb-' + COMMIT + '/'
        if len(members) > 20000 or sum(m.size for m in members) > 512 * 1024**2:
            raise ValueError('Oversized expanded source')
        for entry in members:
            root_entry = entry.name == prefix.rstrip('/') and entry.isdir()
            if (not root_entry and not entry.name.startswith(prefix)) or '..' in Path(entry.name).parts or entry.isdev():
                raise ValueError('Unexpected source archive member')
        license_paths = ['LICENSE', 'LICENSE-APACHE', 'NOTICE', 'tsl/LICENSE-TIMESCALE']
        licenses = {p: sha(archive.extractfile(prefix + p).read()) for p in license_paths}
        cmake = archive.extractfile(prefix + 'CMakeLists.txt').read()
        if sha(cmake) != 'e94108d5899c567697fb6e5add69a3ab6f40df9a882c0b1970cc5dac685a8621':
            raise ValueError('Pinned source compatibility declaration changed')
        if archive.extractfile(prefix + 'version.config').read().splitlines()[0] != b'version = 2.31.0':
            raise ValueError('Source version changed')
    for name in ['Containerfile', 'smoke.sh']:
        save(context / name, (RECIPE / name).read_bytes())
    save(ROOT / 'source.result.json', encode({'archiveSha256': sha(data), 'commit': COMMIT, 'licenses': licenses,
        'purpose': 'internal-private-artifact-build-not-deployment', 'runtimeAdmitted': False}))


def dependencies():
    original(ROOT / 'source.result.json')
    inspected = json.loads(effect('base-inspect', ['image', 'inspect', BASE], 30))[0]
    if inspected['Id'] != BASE_ID or inspected['Architecture'] != 'amd64' or inspected['Os'] != 'linux':
        raise ValueError('Pinned PostgreSQL base changed')
    effect('network', ['network', 'create', '--label', 'io.p0v3.artifact-build=' + JOB, NAME], 30)
    output = ROOT / 'downloads'
    if not output.exists():
        output.mkdir(mode=0o700); sync(ROOT)
    private_directory(output)
    script = '''set -eu
mkdir /out/debs
apt-get -o Acquire::Retries=0 update
apt-get -o Acquire::Retries=0 -o Dir::Cache::archives=/out/debs --download-only --no-install-recommends -y install cmake make gcc libc6-dev libssl-dev postgresql-server-dev-17="$PG_VERSION"
cp -a /var/lib/apt/lists /out/apt-lists
dpkg-query -W > /out/base-packages.tsv
chown -R --no-dereference ''' + str(os.getuid()) + ':' + str(os.getgid()) + ''' /out
chmod -R go-rwx /out
'''
    effect('dependencies', ['run', '--pull=never', '--rm=false', '--replace=false', '--name', NAME,
        '--label', 'io.p0v3.artifact-build=' + JOB, '--network', NAME, '--http-proxy=false',
        '--memory=4g', '--memory-swap=4g', '--cpus=2', '--pids-limit=512', '--security-opt=no-new-privileges',
        '--cap-drop=ALL', '--cap-add=CHOWN,DAC_OVERRIDE,FOWNER,SETUID,SETGID',
        '--volume', str(output) + ':/out:rw', '--entrypoint=/bin/sh', BASE, '-ec', script], 900)
    # The original native result is durable before copying any dependencies to build authority.
    context = ROOT / 'context'
    debs = context / 'debs'
    debs.mkdir(mode=0o700)
    for path in sorted((output / 'debs').glob('*.deb')):
        save(debs / path.name, original(path, 128 * 1024 * 1024))
    lists = context / 'apt-lists'
    lists.mkdir(mode=0o700)
    for path in sorted((output / 'apt-lists').iterdir()):
        if path.is_file() and not path.is_symlink():
            save(lists / path.name, original(path, 128 * 1024 * 1024))
    files = {str(p.relative_to(context)): sha(original(p, 128 * 1024 * 1024))
             for p in sorted(context.rglob('*')) if p.is_file()}
    if not any(name.startswith('debs/') for name in files):
        raise ValueError('No acquired dependencies')
    save(context / 'inputs.sha256', ''.join(digest + '  ' + name + '\n' for name, digest in files.items()
        if name not in ('Containerfile', 'smoke.sh')).encode())
    save(ROOT / 'inputs.json', encode(files))


def build():
    state = json.loads(effect('dependency-state', ['container', 'inspect', NAME], 30))[0]
    if state['State']['Status'] != 'exited' or state['State']['ExitCode'] != 0 or state['State']['Pid'] != 0 or \
            state['Image'].removeprefix('sha256:') != BASE_ID or state['Config']['Labels'].get('io.p0v3.artifact-build') != JOB:
        raise ValueError('Dependency acquisition container is not the original stopped owned fixture')
    context = ROOT / 'context'
    expected = json.loads(original(ROOT / 'inputs.json'))
    actual = {str(p.relative_to(context)): sha(original(p, 128 * 1024 * 1024))
              for p in sorted(context.rglob('*')) if p.is_file() and p.name != 'inputs.sha256'}
    if expected != actual:
        raise ValueError('Build inputs changed after acquisition')
    checksum = ''.join(digest + '  ' + name + '\n' for name, digest in expected.items()
        if name not in ('Containerfile', 'smoke.sh')).encode()
    if original(context / 'inputs.sha256') != checksum:
        raise ValueError('Build checksum manifest changed')
    effect('build', ['build', '--pull=never', '--retry=0', '--network=none', '--http-proxy=false',
        '--rm=false', '--force-rm=false', '--layers=false', '--memory=4g', '--memory-swap=4g',
        '--cpu-period=100000', '--cpu-quota=200000', '--tag', TAG, str(context)], 1800,
        binding=sha(original(ROOT / 'inputs.json')))
    inspected = json.loads(effect('image-inspect', ['image', 'inspect', TAG], 30))[0]
    save(ROOT / 'artifact.result.json', encode({'status': 'built-candidate-not-admitted-not-qualified',
        'sourceCommit': COMMIT, 'inputsSha256': sha(original(ROOT / 'inputs.json')), 'image': inspected,
        'artifactSmokeOnly': True, 'kopiaRecoveryProven': False, 'runtimeAdmitted': False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('phase', choices=['source', 'dependencies', 'build'])
    args = parser.parse_args()
    if os.getuid() == 0:
        raise ValueError('Run as the non-root artifact owner; only fixed Podman operations elevate')
    private_directory(ROOT.parent)
    if args.phase == 'source':
        ROOT.mkdir(mode=0o700); sync(ROOT.parent)
    private_directory(ROOT)
    with os.fdopen(os.open(ROOT / 'build.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600), 'r+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        headroom()
        {'source': acquire_source, 'dependencies': dependencies, 'build': build}[args.phase]()
    print('Completed artifact phase:', args.phase, '; no runtime admission')


if __name__ == '__main__':
    main()
