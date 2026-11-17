#!/usr/bin/env python3
"""Install an explicitly enrolled release-bound RSS timer. Never enroll, activate, reset or poll RSS here."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import urllib.parse


def private_json(path):
    info = path.lstat()
    assert path.is_absolute() and path.resolve() == path
    assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_uid == os.getuid() and info.st_nlink == 1 and 0 < info.st_size <= 1048576
    return path.read_bytes()


def helpers_module():
    spec = importlib.util.spec_from_file_location('rss_boot_helpers', Path(__file__).with_name('install-private-boot-units.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def install(root, expected, enable_timer=False, helpers=None):
    assert re.fullmatch(r'[a-f0-9]{64}', expected) and 1 <= os.getuid() <= 65534
    assert root.is_absolute() and root.resolve() == root
    info = root.lstat()
    assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid()
    data = private_json(root / 'binding.json')
    assert hashlib.sha256(data).hexdigest() == expected
    assert private_json(root / 'enrolled').decode() == expected
    binding = json.loads(data)
    assert binding['userId'] == os.getuid()
    generation = binding['deployment']['generationId']
    assert re.fullmatch(r'q-[a-f0-9]{12}', generation)
    helpers = helpers or helpers_module()
    digest, files, descriptor = helpers.distribution(helpers.DIST)
    assert digest == binding['controllerSha256'], 'RSS enrollment pins a different controller'
    release = helpers.SUPERVISION / 'releases' / digest
    for path in (helpers.SUPERVISION, release.parent, release, release / 'bin', release / 'lib'):
        helpers.root_directory(path)
    # The running Kotlin controller verifies the installed tree, its origin and enrollment before units are rendered.
    env = {'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64', 'PATH': '/usr/bin:/bin',
           'HOME': str(Path.home()), 'LANG': 'C.UTF-8', 'JAVA_OPTS': '-Xms32m -Xmx256m'}
    with tempfile.TemporaryDirectory(prefix='rss-install-') as temp:
        staging = Path(temp)
        for relative, (mode, content) in files.items():
            path = staging / relative
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(content)
            helpers.install_file(path, release / relative, content, mode)
        marker = staging / 'controller.json'
        marker.write_bytes(descriptor)
        helpers.install_file(marker, release / marker.name, descriptor, 0o644)
        units = json.loads(helpers.call([str(release / 'bin/p0-v3-platform'), 'rss', 'schedule-units', str(root), expected], env=env))
        name = 'p0v3-rss-' + generation
        assert set(units) == {name + '.service', name + '.timer'}
        assert all(isinstance(value, str) and 0 < len(value) < 65536 for value in units.values())
        assert f'ExecStart={release}/bin/p0-v3-platform rss schedule-tick {root} {expected}\n' in units[name + '.service']
        assert f'User={os.getuid()}\n' in units[name + '.service']
        for filename, content in units.items():
            helpers.same_root_file(helpers.SYSTEMD / filename, content.encode(), 0o644)
            (staging / filename).write_text(content)
        helpers.call(['systemd-analyze', 'verify', *[str(staging / key) for key in units]])
        assert helpers.distribution(helpers.DIST)[0] == digest
        assert private_json(root / 'binding.json') == data
        for filename, content in units.items():
            helpers.install_file(staging / filename, helpers.SYSTEMD / filename, content.encode(), 0o644)
    helpers.call(['sudo', '-n', 'systemctl', 'daemon-reload'])
    if enable_timer:
        helpers.call(['sudo', '-n', 'systemctl', 'enable', '--now', name + '.timer'])
        assert helpers.call(['systemctl', 'is-enabled', name + '.timer']).strip() == b'enabled'
        assert helpers.call(['systemctl', 'is-active', name + '.timer']).strip() == b'active'
    return {'generation': generation, 'bindingSha256': expected, 'timerEnabled': enable_timer,
            'publicationAuthorized': False, 'units': list(units)}


def install_fixture(fixture, expected, enable_timer=False, helpers=None):
    """Install only the separately scoped synthetic HTTPS fixture timer, never the real47 worker.

    Timer start is a later explicit user-authorized fixture action. Enrollment, CA custody,
    synthetic bot token and controller pin are independently checked by the Kotlin controller.
    An interrupted install retains its old unit files; no automatic replay or cleanup.
    """
    assert fixture.is_absolute() and fixture.resolve() == fixture and re.fullmatch(r'[a-f0-9]{64}', expected)
    generation_root = fixture.parent.parent
    assert fixture.parent.name == 'rss-qualification' and re.fullmatch(r'q-[a-f0-9]{12}', generation_root.name)
    assert generation_root.parent == Path('/mnt/media/p0-v3/release-generations')
    for path in (generation_root, fixture.parent, fixture):
        info = path.lstat()
        assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and info.st_uid == os.getuid()
    timer_root = generation_root / 'rss' / 'fixture-timers' / fixture.name
    data = private_json(timer_root / 'binding.json')
    assert hashlib.sha256(data).hexdigest() == expected
    assert private_json(timer_root / 'enrolled').decode() == expected
    binding = json.loads(data)
    parsed = urllib.parse.urlsplit(binding['origin'])
    assert parsed.scheme == 'https' and parsed.hostname == '127.0.0.1' and parsed.port in range(49152, 65536)
    assert parsed.path in ('', '/') and not parsed.username and not parsed.password and not parsed.query and not parsed.fragment
    assert binding['generation'] == generation_root.name and binding['userId'] == os.getuid()
    assert re.fullmatch(r'rssq-[a-f0-9]{12}', fixture.name)
    assert binding['tokenFile'] == str(generation_root / 'rss' / 'qualification-custody' / fixture.name / 'bot.token')
    assert binding['syntheticAccount'] == 'rssq_' + fixture.name.removeprefix('rssq-')
    assert binding['mastodonOrigin'] == 'https://social.datamancy.net'
    helpers = helpers or helpers_module()
    digest, files, descriptor = helpers.distribution(helpers.DIST)
    assert digest == binding['controllerSha256']
    release = helpers.SUPERVISION / 'releases' / digest
    for path in (helpers.SUPERVISION, release.parent, release, release / 'bin', release / 'lib'):
        helpers.root_directory(path)
    env = {'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64', 'PATH': '/usr/bin:/bin',
           'HOME': str(Path.home()), 'LANG': 'C.UTF-8', 'JAVA_OPTS': '-Xms32m -Xmx256m'}
    invocation = os.environ.get('P0V3_CASE_INVOCATION_ID')
    claim = os.environ.get('P0V3_RSS_QUALIFICATION_SHA256')
    phase_claim = os.environ.get('P0V3_RSS_PHASE_CLAIM_SHA256')
    assert (invocation is None) == (claim is None) == (phase_claim is None)
    if invocation is not None:
        assert re.fullmatch(r'case-[a-f0-9-]{36}', invocation) and re.fullmatch(r'[a-f0-9]{64}', claim) \
            and re.fullmatch(r'[a-f0-9]{64}', phase_claim)
        env.update({'P0V3_CASE_INVOCATION_ID': invocation, 'P0V3_RSS_QUALIFICATION_SHA256': claim,
                    'P0V3_RSS_PHASE_CLAIM_SHA256': phase_claim})
    with tempfile.TemporaryDirectory(prefix='rss-fixture-install-') as temporary:
        staging = Path(temporary)
        for relative, (mode, content) in files.items():
            path = staging / relative
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(content)
            helpers.install_file(path, release / relative, content, mode)
        marker = staging / 'controller.json'
        marker.write_bytes(descriptor)
        helpers.install_file(marker, release / marker.name, descriptor, 0o644)
        units = json.loads(helpers.call([str(release / 'bin/p0-v3-platform'), 'rss', 'fixture-units',
                                         str(fixture), expected], env=env))
        assert len(units) == 2 and all(name.startswith('p0v3-rss-fixture-' + generation_root.name + '-') for name in units)
        service = next(name for name in units if name.endswith('.service'))
        timer = next(name for name in units if name.endswith('.timer'))
        assert f'ExecStart={release}/bin/p0-v3-platform rss fixture-tick {fixture} {expected}\n' in units[service]
        assert 'OnUnitInactiveSec=900s\n' in units[timer] and 'Unit=' + service + '\n' in units[timer]
        for name, body in units.items():
            assert isinstance(body, str) and 0 < len(body) < 65536
            helpers.same_root_file(helpers.SYSTEMD / name, body.encode(), 0o644)
            (staging / name).write_text(body)
        helpers.call(['systemd-analyze', 'verify', *[str(staging / name) for name in units]])
        assert private_json(timer_root / 'binding.json') == data and helpers.distribution(helpers.DIST)[0] == digest
        for name, body in units.items():
            helpers.install_file(staging / name, helpers.SYSTEMD / name, body.encode(), 0o644)
    helpers.call(['sudo', '-n', 'systemctl', 'daemon-reload'])
    if enable_timer:
        helpers.call(['sudo', '-n', 'systemctl', 'enable', '--now', timer])
        assert helpers.call(['systemctl', 'is-enabled', timer]).strip() == b'enabled'
        assert helpers.call(['systemctl', 'is-active', timer]).strip() == b'active'
    return {'generation': generation_root.name, 'fixtureId': fixture.name, 'bindingSha256': expected,
            'timerEnabled': enable_timer, 'publicationAuthorized': False, 'serviceUnit': service, 'timerUnit': timer}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('binding_sha256')
    parser.add_argument('--enable-timer', action='store_true')
    parser.add_argument('--fixture', action='store_true', help='install only explicitly enrolled loopback synthetic fixture units')
    args = parser.parse_args()
    os.umask(0o077)
    result = install_fixture(args.root, args.binding_sha256, args.enable_timer) if args.fixture else \
        install(args.root, args.binding_sha256, args.enable_timer)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
