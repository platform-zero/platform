#!/usr/bin/env python3
"""Explicitly install pinned, v3-only boot/shutdown units. No timers, image updates or pruning."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

if not __debug__:
    raise RuntimeError('Optimized Python would disable supervision safety checks')

ROOT = Path(__file__).resolve().parents[2]
DIST = ROOT / 'platform/build/install/p0-v3-platform'
BASE = Path('/mnt/media/p0-v3/runtime-deployments')
SUPERVISION = Path('/mnt/media/p0-v3/runtime-supervision')
SYSTEMD = Path('/etc/systemd/system')
SLUG = re.compile(r'[a-z][a-z0-9-]{0,39}')


def distribution(source):
    """Snapshot bytes once; identity binds both paths and installed modes, not timestamps."""
    assert source.is_dir() and source.resolve() == source.absolute(), 'Canonical distribution required'
    files = {}
    for path in sorted(source.rglob('*')):
        info = path.lstat()
        assert not stat.S_ISLNK(info.st_mode), 'Distribution symlink rejected'
        if stat.S_ISDIR(info.st_mode):
            assert path.relative_to(source).as_posix() in ('bin', 'lib'), 'Unexpected distribution directory'
            continue
        relative = path.relative_to(source).as_posix()
        assert stat.S_ISREG(info.st_mode) and re.fullmatch(r'(bin|lib)/[A-Za-z0-9_.-]+', relative)
        mode = 0o755 if relative == 'bin/p0-v3-platform' else 0o644
        files[relative] = (mode, path.read_bytes())
    assert 'bin/p0-v3-platform' in files and any(p.startswith('lib/') and p.endswith('.jar') for p in files)
    descriptor = json.dumps({p: {'mode': mode, 'sha256': hashlib.sha256(data).hexdigest()}
        for p, (mode, data) in files.items()}, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(descriptor).hexdigest(), files, descriptor


def same_root_file(path, content, mode):
    if not path.exists() and not path.is_symlink():
        return False
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == mode, 'Unsafe existing supervised file'
    assert path.read_bytes() == content, 'Existing supervised file differs; explicit replacement review required'
    return True


def call(args, **kwargs):
    result = subprocess.run(args, capture_output=True, timeout=900, **kwargs)
    assert result.returncode == 0, 'Supervision command failed: ' + args[0] + '; existing state retained'
    return result.stdout


def root_directory(path):
    if not path.exists() and not path.is_symlink():
        call(['sudo', '-n', 'mkdir', '--mode=0755', '--', str(path)])
    info = path.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o755, 'Unsafe supervision directory'


def install_file(source, destination, content, mode):
    if not same_root_file(destination, content, mode):
        call(['sudo', '-n', 'install', '-m', oct(mode)[2:], '-o', 'root', '-g', 'root', '-T', str(source), str(destination)])
    assert same_root_file(destination, content, mode)


def stage_controller_only(receipts=Path('/mnt/media/p0-v3/image-acquisition-receipts'),
                          supervision=SUPERVISION):
    """Private development controller only; no service unit, enable or daemon-reload."""
    digest, files, descriptor = distribution(DIST)
    release = supervision / 'releases' / digest
    assert receipts.is_dir() and receipts.stat().st_uid == os.getuid() and \
        stat.S_IMODE(receipts.stat().st_mode) == 0o700
    receipt = receipts / ('quadlet-controller-' + digest[:16])
    assert not receipt.exists() and not receipt.is_symlink() and not release.exists() and not release.is_symlink(), \
        'Controller distribution already attempted; reconcile, do not replay'
    receipt.mkdir(mode=0o700)
    with os.fdopen(os.open(receipt / 'stage.intent.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600), 'wb') as output:
        output.write(json.dumps({'schemaVersion': 1, 'controllerSha256': digest,
            'files': {name: hashlib.sha256(data).hexdigest() for name, (_, data) in files.items()},
            'scope': 'pinned-controller-only-no-units'}, sort_keys=True, separators=(',', ':')).encode())
        output.flush(); os.fsync(output.fileno())
    receipt_fd = os.open(receipt, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(receipt_fd)
    finally: os.close(receipt_fd)
    root_directory(supervision)
    root_directory(supervision / 'releases')
    root_directory(release)
    root_directory(release / 'bin')
    root_directory(release / 'lib')
    root_copy = '''import hashlib, os, pathlib, stat, sys
source, target, expected, mode, tree = sys.argv[1:]
root = pathlib.Path('/mnt/media/p0-v3/runtime-supervision/releases') / tree
path = pathlib.Path(target)
assert len(tree) == 64 and all(c in '0123456789abcdef' for c in tree)
assert path.is_absolute() and path == pathlib.Path(os.path.normpath(path)) and path.is_relative_to(root)
assert path.relative_to(root).as_posix() == 'controller.json' or (len(path.relative_to(root).parts) == 2 and path.relative_to(root).parts[0] in ('bin', 'lib'))
assert mode in ('644', '755') and (mode == '755') == (path.relative_to(root).as_posix() == 'bin/p0-v3-platform')
for parent in (root.parent.parent, root.parent, root, path.parent):
    info = parent.lstat()
    assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o755
assert not path.exists() and not path.is_symlink()
src = pathlib.Path(source); info = src.lstat()
assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == int(os.environ['SUDO_UID']) and stat.S_IMODE(info.st_mode) == 0o600
with src.open('rb') as inp:
    data = inp.read(268435457)
assert 0 < len(data) <= 268435456 and hashlib.sha256(data).hexdigest() == expected
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, int(mode, 8))
with os.fdopen(fd, 'wb') as out:
    os.fchmod(out.fileno(), int(mode, 8)); out.write(data); out.flush(); os.fsync(out.fileno())
dirfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try: os.fsync(dirfd)
finally: os.close(dirfd)
'''
    with tempfile.TemporaryDirectory(prefix='quadlet-controller-', dir=receipt) as staging_path:
        staging = Path(staging_path)
        for name, (mode, data) in list(files.items()) + [('controller.json', (0o644, descriptor))]:
            source = staging / name
            source.parent.mkdir(exist_ok=True)
            with os.fdopen(os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as output:
                output.write(data); output.flush(); os.fsync(output.fileno())
            call(['sudo', '-n', '/usr/bin/python3', '-I', '-c', root_copy, str(source),
                str(release / name), hashlib.sha256(data).hexdigest(), format(mode, 'o'), digest])
            assert same_root_file(release / name, data, mode)
    assert set(p.relative_to(release).as_posix() for p in release.rglob('*') if p.is_file()) == set(files) | {'controller.json'}
    with os.fdopen(os.open(receipt / 'stage.result.json', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600), 'wb') as output:
        output.write(json.dumps({'schemaVersion': 1, 'controllerSha256': digest, 'staged': True,
            'unitsInstalled': False, 'unitStarted': False}, sort_keys=True, separators=(',', ':')).encode())
        output.flush(); os.fsync(output.fileno())
    receipt_fd = os.open(receipt, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(receipt_fd)
    finally: os.close(receipt_fd)
    print(json.dumps({'controllerTreeSha256': digest, 'unitsInstalled': False,
        'unitStarted': False, 'fullQualification': False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--activate', action='store_true', help='Enable at boot and start ONLY the explicitly named units')
    parser.add_argument('--controller-only', action='store_true', help='Stage immutable pinned development controller without installing units')
    parser.add_argument('--qualification-publish', type=Path, help='Root-owned original qualification publication request; no boot changes')
    parser.add_argument('names', nargs='*')
    args = parser.parse_args()
    assert 1 <= os.getuid() <= 65534, 'Run as the private runtime owner, not root'
    if args.controller_only:
        assert not args.activate and not args.names and args.qualification_publish is None
        stage_controller_only()
        return
    if args.qualification_publish is not None:
        assert not args.activate and not args.names, 'Publication and boot enrollment are disjoint effects'
        source = args.qualification_publish
        assert source.is_absolute() and source == Path(os.path.normpath(source)) and \
            source.parent == Path('/mnt/media/p0-v3/qualification-publication') and \
            source.name == 'artifacts.request.json', 'Fixed original root request location required'
        # The root-only directory is intentionally inaccessible to this non-root caller.
        # The root-owned platform publisher independently verifies mode/owner/links/bytes.
        digest, files, descriptor = distribution(DIST)
        release = SUPERVISION / 'releases' / digest
        assert same_root_file(release / 'controller.json', descriptor, 0o644)
        for relative, (mode, data) in files.items():
            assert same_root_file(release / relative, data, mode)
        platform = release / 'bin/p0-v3-platform'
        assert call(['sudo', '-n', str(platform), 'qualification', 'publish-artifacts', str(source)])
        return
    assert args.names and len(args.names) == len(set(args.names)) and all(SLUG.fullmatch(n) for n in args.names)
    assert BASE.resolve() == BASE and SYSTEMD.resolve() == SYSTEMD
    env = {**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'}
    # Audit live resources before installing anything; do not adopt incomplete or stopped deployments.
    for name in args.names:
        path = BASE / (name + '.json')
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600
        spec = json.loads(path.read_text())
        assert spec['name'] == name
        status = json.loads(call([str(DIST / 'bin/p0-v3-platform'), 'runtime', 'status-private', str(path)], env=env).splitlines()[0])
        states = {s['id']: s['state'] for s in status}
        assert all(states[p['id']] == 'running' for p in spec['processes'] if not p.get('oneShot', False)), 'Only already-running private deployments may be enrolled'
    digest, files, descriptor = distribution(DIST)
    units = {}
    for name in args.names:
        unit = call([str(DIST / 'bin/p0-v3-platform'), 'runtime', 'boot-unit', name, digest, str(os.getuid())], env=env)
        assert unit.startswith(b'# Managed by p0v3-private-boot-v1;') and len(unit) < 65536
        filename = 'p0v3-private-' + name + '.service'
        same_root_file(SYSTEMD / filename, unit, 0o644)  # Refuse ALL conflicting units before any installs.
        units[filename] = unit
    root_directory(SUPERVISION)
    root_directory(SUPERVISION / 'releases')
    release = SUPERVISION / 'releases' / digest
    root_directory(release)
    for child in ('bin', 'lib'):
        root_directory(release / child)
    with tempfile.TemporaryDirectory(prefix='p0v3-boot-') as temp:
        staging = Path(temp)
        for relative, (mode, data) in files.items():
            source = staging / relative
            source.parent.mkdir(exist_ok=True)
            source.write_bytes(data)
            install_file(source, release / relative, data, mode)
        marker = staging / 'controller.json'
        marker.write_bytes(descriptor)
        install_file(marker, release / marker.name, descriptor, 0o644)
        # Reject undeclared files as well as substitutions in the pinned controller tree.
        actual = set()
        for path in release.rglob('*'):
            info = path.lstat()
            relative = path.relative_to(release).as_posix()
            assert not stat.S_ISLNK(info.st_mode), 'Symlink in pinned controller'
            if stat.S_ISDIR(info.st_mode):
                assert relative in ('bin', 'lib'), 'Unexpected pinned directory'
            else:
                actual.add(relative)
        assert actual == set(files) | {'controller.json'}
        for filename, unit in units.items():
            (staging / filename).write_bytes(unit)
        call(['systemd-analyze', 'verify', *[str(staging / filename) for filename in units]])
        for filename, unit in units.items():
            install_file(staging / filename, SYSTEMD / filename, unit, 0o644)
    call(['sudo', '-n', 'systemctl', 'daemon-reload'])
    if args.activate:
        call(['sudo', '-n', 'systemctl', 'enable', '--now', *units])
        for filename in units:
            assert call(['systemctl', 'is-enabled', filename]).strip() == b'enabled'
            assert call(['systemctl', 'is-active', filename]).strip() == b'active'
    print(json.dumps({'controllerTreeSha256': digest, 'units': list(units), 'activated': args.activate,
        'scope': 'private-boot-shutdown-only', 'hostRebootTest': False, 'crashWatchdog': False,
        'automaticImageUpdates': False, 'fullStackAcceptance': False}, indent=2))


if __name__ == '__main__':
    main()
