#!/usr/bin/env python3
"""Enroll ONE new canonical generation and install its pinned coordinated daily timer. No restore, pruning or publication."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile

PLATFORM = Path(__file__).resolve().parents[1]
BASE = Path('/mnt/media/p0-v3/release-generations')


def boot_helpers():
    spec = importlib.util.spec_from_file_location('p0v3_schedule_install_helpers', Path(__file__).with_name('install-private-boot-units.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--activate', action='store_true')
    parser.add_argument('inventory', type=Path)
    parser.add_argument('generation')
    parser.add_argument('bundle')
    args = parser.parse_args()
    assert re.fullmatch(r'q-[a-f0-9]{12}', args.generation) and re.fullmatch(r'[a-f0-9]{64}', args.bundle)
    assert 1 <= os.getuid() <= 65534
    os.umask(0o077)
    helpers = boot_helpers()
    env = {**os.environ, 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'}
    digest, files, descriptor = helpers.distribution(helpers.DIST)
    cli = helpers.DIST / 'bin/p0-v3-platform'
    enrolled = json.loads(helpers.call([str(cli), 'release', 'backup-schedule-enroll', str(args.inventory), args.generation,
                                       args.bundle, digest, str(os.getuid())], env=env))
    binding = enrolled['bindingSha256']
    units = json.loads(helpers.call([str(cli), 'release', 'backup-schedule-units', args.generation, binding], env=env))
    name = 'p0v3-backup-' + args.generation
    assert set(units) == {name + '.service', name + '-alert.service', name + '.timer'}
    units = {key: value.encode() for key, value in units.items()}
    for filename, content in units.items():
        assert content.startswith(b'# Managed by p0v3-canonical-backup-v1;') and len(content) < 65536
        helpers.same_root_file(helpers.SYSTEMD / filename, content, 0o644)
    root = BASE / args.generation / 'backup-schedule'
    record(root / 'install.intent.json', {'bindingSha256': binding, 'units': {k: hashlib.sha256(v).hexdigest() for k, v in units.items()},
                                         'controllerTreeSha256': digest})
    for path in [helpers.SUPERVISION, helpers.SUPERVISION / 'releases', helpers.SUPERVISION / 'releases' / digest]:
        helpers.root_directory(path)
    release = helpers.SUPERVISION / 'releases' / digest
    for child in ('bin', 'lib'): helpers.root_directory(release / child)
    with tempfile.TemporaryDirectory(prefix='p0v3-schedule-') as temp:
        staging = Path(temp)
        for relative, (mode, data) in files.items():
            source = staging / relative; source.parent.mkdir(exist_ok=True); source.write_bytes(data)
            helpers.install_file(source, release / relative, data, mode)
        marker = staging / 'controller.json'; marker.write_bytes(descriptor)
        helpers.install_file(marker, release / marker.name, descriptor, 0o644)
        # The pinned Kotlin executor also verifies every byte/mode and its own JAR origin before any job effect.
        assert helpers.distribution(helpers.DIST)[0] == digest, 'Controller changed during installation'
        for filename, content in units.items(): (staging / filename).write_bytes(content)
        helpers.call(['systemd-analyze', 'verify', *[str(staging / key) for key in units]])
        for filename, content in units.items(): helpers.install_file(staging / filename, helpers.SYSTEMD / filename, content, 0o644)
    helpers.call(['sudo', '-n', 'systemctl', 'daemon-reload'])
    record(root / 'install.result.json', {'bindingSha256': binding, 'installed': True})
    if args.activate:
        record(root / 'activate.intent.json', {'bindingSha256': binding, 'timer': name + '.timer'})
        helpers.call(['sudo', '-n', 'systemctl', 'enable', '--now', name + '.timer'])
        assert helpers.call(['systemctl', 'is-enabled', name + '.timer']).strip() == b'enabled'
        assert helpers.call(['systemctl', 'is-active', name + '.timer']).strip() == b'active'
        record(root / 'activate.result.json', {'bindingSha256': binding, 'activated': True})
    print(json.dumps({'generation': args.generation, 'bindingSha256': binding, 'controllerTreeSha256': digest,
                      'units': list(units), 'activated': args.activate, 'weeklyRestoreInstalled': False,
                      'retentionDeletion': False, 'fullStackQualification': False}))


if __name__ == '__main__':
    main()
