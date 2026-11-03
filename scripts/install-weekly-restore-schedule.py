#!/usr/bin/env python3
"""Install a fresh pinned Sunday 04:00 UTC functional restore controller; no promotion or retry."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile

BASE = Path('/mnt/media/p0-v3/release-generations')


def helpers():
    spec = importlib.util.spec_from_file_location('weekly_boot_helpers', Path(__file__).with_name('install-private-boot-units.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def require(value, message):
    if not value:
        raise ValueError(message)


def record(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def plan_assertions(data):
    plan = json.loads(data)
    require(plan.get('schemaVersion') == 1 and 1 <= len(plan['cases']) <= 128, 'bounded functional plan required')
    ids = [case['id'] for case in plan['cases']]
    require(len(set(ids)) == len(ids), 'duplicate functional case')
    values = []
    for case in plan['cases']:
        require(re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', case['id']) and case['assertions'] and case['sourceOracle'], 'original fixture oracle required')
        values += [case['id'] + ':' + assertion for assertion in case['assertions']]
    require(len(values) == len(set(values)) and len(values) <= 256, 'duplicate or excessive assertions')
    return sorted(values)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--activate', action='store_true')
    parser.add_argument('inventory', type=Path); parser.add_argument('generation'); parser.add_argument('bundle')
    parser.add_argument('functional_plan', type=Path)
    args = parser.parse_args()
    require(re.fullmatch(r'q-[a-f0-9]{12}', args.generation) and re.fullmatch(r'[a-f0-9]{64}', args.bundle), 'invalid source binding')
    require(1 <= os.getuid() <= 65534, 'non-root private runtime owner required')
    os.umask(0o077)
    helper = helpers()
    tree, files, descriptor = helper.distribution(helper.DIST)
    plan = args.functional_plan.read_bytes(); inventory = args.inventory.read_bytes()
    assertions = plan_assertions(plan)
    release = helper.SUPERVISION / 'releases' / tree
    # Enrollment verifies its own root-owned JAR origin, so pin artifact BEFORE invoking enrollment.
    for path in [helper.SUPERVISION, helper.SUPERVISION / 'releases', release, release / 'bin', release / 'lib']:
        helper.root_directory(path)
    env = {'PATH': '/usr/bin:/bin', 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64', 'LANG': 'C.UTF-8'}
    with tempfile.TemporaryDirectory(prefix='p0v3-weekly-install-') as temp:
        staging = Path(temp)
        for relative, (mode, data) in files.items():
            source = staging / relative; source.parent.mkdir(exist_ok=True); source.write_bytes(data)
            helper.install_file(source, release / relative, data, mode)
        marker = staging / 'controller.json'; marker.write_bytes(descriptor)
        helper.install_file(marker, release / marker.name, descriptor, 0o644)
        require(helper.distribution(helper.DIST)[0] == tree, 'controller changed during pinning')
        binding_file = staging / 'binding.json'
        record(binding_file, {'source': {'schemaVersion': 1, 'generation': args.generation, 'bundleSha256': args.bundle,
            'inventorySha256': hashlib.sha256(inventory).hexdigest(), 'controllerSha256': tree, 'userId': os.getuid(),
            'enrolledAt': datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')},
            'evaluatorSha256': hashlib.sha256(plan).hexdigest(), 'requiredAssertions': assertions})
        cli = release / 'bin/p0-v3-platform'
        expected = json.loads(helper.call([str(cli), 'release', 'weekly-restore-enroll', str(args.inventory), str(binding_file), str(args.functional_plan)], env=env))
        require(re.fullmatch(r'[a-f0-9]{64}', expected), 'invalid enrolled digest')
        units = json.loads(helper.call([str(cli), 'release', 'weekly-restore-units', args.generation, expected], env=env))
        name = 'p0v3-weekly-restore-' + args.generation
        require(set(units) == {name + '.timer', name + '.service', name + '-alert.service'}, 'foreign unit names')
        encoded = {key: value.encode() for key, value in units.items()}
        for filename, content in encoded.items():
            require(content.startswith(b'# Managed by p0v3-weekly-restore-v1;') and len(content) < 65536, 'invalid unit content')
            helper.same_root_file(helper.SYSTEMD / filename, content, 0o644)
        root = BASE / args.generation / 'weekly-restore'
        record(root / 'install.intent.json', {'bindingSha256': expected, 'controllerTreeSha256': tree,
                                             'units': {key: hashlib.sha256(data).hexdigest() for key, data in encoded.items()}})
        for filename, content in encoded.items(): (staging / filename).write_bytes(content)
        helper.call(['systemd-analyze', 'verify', *[str(staging / name) for name in encoded]])
        for filename, content in encoded.items(): helper.install_file(staging / filename, helper.SYSTEMD / filename, content, 0o644)
    helper.call(['sudo', '-n', 'systemctl', 'daemon-reload'])
    record(root / 'install.result.json', {'bindingSha256': expected, 'installed': True})
    if args.activate:
        record(root / 'activate.intent.json', {'bindingSha256': expected, 'timer': name + '.timer'})
        helper.call(['sudo', '-n', 'systemctl', 'enable', '--now', name + '.timer'])
        require(helper.call(['systemctl', 'is-enabled', name + '.timer']).strip() == b'enabled', 'timer enable unknown')
        require(helper.call(['systemctl', 'is-active', name + '.timer']).strip() == b'active', 'timer activation unknown')
        record(root / 'activate.result.json', {'bindingSha256': expected, 'activated': True})
    print(json.dumps({'generation': args.generation, 'bindingSha256': expected, 'controllerTreeSha256': tree,
                      'units': list(encoded), 'activated': args.activate, 'weeklyRestoreInstalled': True,
                      'functionalRestoreExecuted': False, 'publicActivation': False}))


if __name__ == '__main__':
    main()
