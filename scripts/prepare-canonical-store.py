#!/usr/bin/env python3
"""Prepare a fresh, isolated canonical-v2 store with exact existing image pins. Never renumber or prune another store."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import uuid

BASE = Path('/mnt/media/p0-v3')
PLATFORM = Path(__file__).resolve().parents[1]
LEGACY = ['sudo', '-n', 'podman', '--remote=false', '--root=' + str(BASE / 'release-runtime/graph'),
          '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=' + str(BASE / 'release-runtime/network-config')]


def validate_policy(policy):
    assert policy['graph'] == str(BASE / 'runtime-stores/canonical-v2/graph')
    assert policy['run'] == '/run/p0-v3-canonical-v2/store'
    assert policy['network'] == str(BASE / 'runtime-stores/canonical-v2/networks')
    assert policy['module'] == str(BASE / 'runtime-stores/canonical-v2/containers.conf')
    assert policy['objectLimit'] == '4096'
    assert 'lock_type = "file"' in policy['configuration'] and 'num_locks' not in policy['configuration']
    return ['sudo', '-n', 'podman', '--remote=false', '--module=' + policy['module'],
            '--root=' + policy['graph'], '--runroot=' + policy['run'], '--network-config-dir=' + policy['network']]


def reject_overlaps(observed):
    selected = [ipaddress.ip_network('10.203.0.0/16'), ipaddress.ip_network('10.204.0.0/24')]
    for value in observed:
        if value == 'default':
            continue
        net = ipaddress.ip_network(value, strict=False)
        if net.version == 4:
            assert all(not net.overlaps(candidate) for candidate in selected), 'Selected isolated pool overlaps an existing network or route'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source'); parser.add_argument('bundle')
    parser.add_argument('--reconcile', help='Expected original prepare.intent.json SHA; only an unready store without application objects may continue')
    args = parser.parse_args()
    assert re.fullmatch(r'q-[a-f0-9]{12}', args.source) and re.fullmatch(r'[a-f0-9]{64}', args.bundle)
    os.umask(0o077)
    spec = importlib.util.spec_from_file_location('boot_helpers', PLATFORM / 'scripts/install-private-boot-units.py')
    helpers = importlib.util.module_from_spec(spec); spec.loader.exec_module(helpers)
    controller, _, _ = helpers.distribution(helpers.DIST)
    env = {'PATH': '/usr/bin:/bin', 'HOME': os.environ['HOME'], 'LANG': 'C.UTF-8', 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64'}
    policy = json.loads(subprocess.check_output([str(helpers.DIST / 'bin/p0-v3-platform'), 'release', 'runtime-store-v2-policy'], env=env))
    pod = validate_policy(policy)
    root = Path(policy['module']).parent
    if args.reconcile:
        assert re.fullmatch(r'[a-f0-9]{64}', args.reconcile) and root.resolve() == root
        assert not (root / 'ready').exists()
        original_intent = (root / 'prepare.intent.json').read_bytes()
        assert hashlib.sha256(original_intent).hexdigest() == args.reconcile
        prior = json.loads(original_intent)
        assert prior['policy'] == policy and prior['source'] == args.source and prior['sourceBundleSha256'] == args.bundle
        assert helpers.same_root_file(root / 'containers.conf', policy['configuration'].encode(), 0o644)
    else:
        assert not root.exists() and not root.is_symlink(), 'Existing or partial store retained; explicit reconciliation required'
    source = BASE / 'release-generations' / args.source / 'bundle.json'
    info = source.lstat()
    assert source.resolve() == source and stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600
    data = source.read_bytes(); assert hashlib.sha256(data).hexdigest() == args.bundle
    bundle = json.loads(data)
    assert bundle['request']['id'] == args.source
    assert {m['spec']['name'] for m in bundle['members']} == {args.source + '-' + kind for kind in ('canonical-core', 'sql-cache', 'forgejo')}
    images = {p['image']: p['imageId'] for m in bundle['members'] for p in m['spec']['processes']}
    inventory = json.loads((PLATFORM / 'release/downloaded-candidate-inventory.json').read_text())
    kopia, = [image for image in inventory['images'] if image['product'] == 'kopia']
    images[kopia['pinnedImage']] = kopia['imageId']
    if args.reconcile:
        assert prior['images'] == images
    assert len(images) == 8 and all(re.fullmatch(r'[a-z0-9./_-]+@sha256:[a-f0-9]{64}', name) and re.fullmatch(r'[a-f0-9]{64}', value) for name, value in images.items())
    assert shutil.disk_usage(BASE).free >= (10240 + 32768) * 1048576
    available = next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:'))
    assert available >= (16384 + 3072) * 1024
    out = BASE / 'image-acquisition-receipts' / ('p0v3-store-v2-' + uuid.uuid4().hex[:12]); out.mkdir(mode=0o700)
    def record(name, value):
        with (out / name).open('x') as stream:
            json.dump(value, stream, indent=2); stream.flush(); os.fsync(stream.fileno())
    def run(label, command):
        record(label + '.intent.json', {'argvSha256': hashlib.sha256(json.dumps(command).encode()).hexdigest()})
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=1800)
        (out / (label + '.stdout')).write_text(result.stdout); (out / (label + '.stderr')).write_text(result.stderr)
        record(label + '.result.json', {'exitCode': result.returncode})
        assert result.returncode == 0, label + ' failed; preserve partial store and initialization history'
        return result.stdout
    def legacy_state(label):
        return {kind: run(label + '-' + kind, LEGACY + command).splitlines() for kind, command in {
            'containers': ['ps', '-aq', '--no-trunc'], 'volumes': ['volume', 'ls', '-q'], 'networks': ['network', 'ls', '-q']}.items()}
    before = legacy_state('before'); record('legacy-before.json', before)
    old_info = json.loads(run('legacy-info', LEGACY + ['info', '--format', 'json']))
    assert old_info['version']['Version'] == '5.4.2' and old_info['store']['graphRoot'] == str(BASE / 'release-runtime/graph')
    network_ids = before['networks']
    networks = json.loads(run('legacy-networks', LEGACY + ['network', 'inspect', *network_ids]))
    routes = json.loads(run('route-admission', ['ip', '-json', '-4', 'route', 'show', 'table', 'all']))
    reject_overlaps([s['subnet'] for n in networks for s in n.get('subnets', [])] + [r['dst'] for r in routes if 'dst' in r])
    record('prepare.intent.json', {'source': args.source, 'sourceBundleSha256': args.bundle, 'controllerTreeSha256': controller,
                                 'policy': policy, 'images': images, 'legacyFreeLocks': old_info['host']['freeLocks'],
                                 'originalIntentSha256': args.reconcile})
    result = {'id': out.name, 'passed': False, 'source': args.source, 'fullStackQualification': False}
    try:
        helpers.root_directory(root.parent); helpers.root_directory(root)
        for name, content in ([('reconcile-' + out.name + '.intent.json', (out / 'prepare.intent.json').read_bytes())] if args.reconcile else
                              [('containers.conf', policy['configuration'].encode()), ('prepare.intent.json', (out / 'prepare.intent.json').read_bytes())]):
            temporary = out / ('install-' + name); temporary.write_bytes(content)
            helpers.install_file(temporary, root / name, content, 0o644)
        observed = json.loads(run('initialize-store', pod + ['info', '--format', 'json']))
        assert observed['store']['graphRoot'] == policy['graph'] and observed['store']['runRoot'] == policy['run']
        assert observed['host'].get('freeLocks') is None
        for label, command in [('containers', ['ps', '-aq']), ('volumes', ['volume', 'ls', '-q']), ('pods', ['pod', 'ps', '-q'])]:
            assert not run('empty-' + label, pod + command).strip(), 'Store preparation cannot adopt existing runtime objects'
        assert observed['host']['security']['apparmorEnabled'] and observed['host']['security']['seccompEnabled'] and not observed['host']['security']['rootless']
        # Empty, explicitly selected registry auth; never borrow another account's registry credentials.
        auth = out / 'empty-auth.json'; auth.write_text('{"auths":{}}\n')
        for index, (image, expected_id) in enumerate(sorted(images.items())):
            legacy, = json.loads(run('source-image-' + str(index), LEGACY + ['image', 'inspect', image]))
            assert legacy['Id'].removeprefix('sha256:') == expected_id and legacy['Digest'] == image.split('@')[1]
            run('acquire-' + str(index), pod + ['pull', '--authfile=' + str(auth), '--tls-verify=true', '--platform=linux/amd64', image])
            loaded, = json.loads(run('destination-image-' + str(index), pod + ['image', 'inspect', image]))
            assert loaded['Id'].removeprefix('sha256:') == expected_id and loaded['Digest'] == image.split('@')[1]
        after = legacy_state('after'); record('legacy-after.json', after); assert before == after
        assert helpers.distribution(helpers.DIST)[0] == controller
        final_info = json.loads(run('final-legacy-info', LEGACY + ['info', '--format', 'json']))
        assert final_info['host']['freeLocks'] == old_info['host']['freeLocks']
        marker = out / 'ready'; marker.write_text(hashlib.sha256(policy['configuration'].encode()).hexdigest() + '\n')
        helpers.install_file(marker, root / 'ready', marker.read_bytes(), 0o644)
        result.update(passed=True, imagePinsVerified=len(images), independentFileLocks=True, legacyInventoryUnchanged=True,
                      legacyFreeLocksUnchanged=True, controllerTreeSha256=controller, objectPolicyLimit=4096)
    finally:
        record('receipt.json', result)
        print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
