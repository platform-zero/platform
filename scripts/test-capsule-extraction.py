#!/usr/bin/env python3
"""Read-only capsule recovery preparation, not native application restoration."""
if not __debug__:
    raise SystemExit('Optimized execution refused before effects')
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--generation', required=True)
    parser.add_argument('--bundle', required=True)
    parser.add_argument('--capture', required=True)
    args = parser.parse_args()
    import re
    assert re.fullmatch(r'q-[a-f0-9]{12}', args.generation)
    assert re.fullmatch(r'cap-[a-f0-9]{12}', args.capture)
    assert re.fullmatch(r'[a-f0-9]{64}', args.bundle)
    os.umask(0o077)
    base = Path('/mnt/media/p0-v3')
    out = base / 'image-acquisition-receipts' / ('p0v3-extraction-' + uuid.uuid4().hex[:12])
    out.mkdir(mode=0o700)
    for name in ('home', 'tmp'):
        (out / name).mkdir(mode=0o700)
    env = {'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64', 'PATH': '/usr/bin:/bin',
           'HOME': str(out / 'home'), 'TMPDIR': str(out / 'tmp'), 'LANG': 'C.UTF-8'}
    cli = Path(__file__).resolve().parents[1] / 'build/install/p0-v3-platform/bin/p0-v3-platform'

    def digest(path):
        with path.open('rb') as stream:
            return hashlib.file_digest(stream, 'sha256').hexdigest()

    def write(name, value):
        with (out / name).open('x') as stream:
            json.dump(value, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())

    def run(label, argv, expected=0):
        write(label + '.intent.json', {'argvSha256': hashlib.sha256(json.dumps([str(x) for x in argv]).encode()).hexdigest()})
        result = subprocess.run([str(x) for x in argv], capture_output=True, timeout=300, env=env)
        (out / (label + '.stdout')).write_bytes(result.stdout)
        (out / (label + '.stderr')).write_bytes(result.stderr)
        write(label + '.result.json', {'exitCode': result.returncode})
        assert result.returncode == expected, label + ' failed; private logs retained'
        return json.loads(result.stdout) if expected == 0 else None

    receipt = {'id': out.name, 'passed': False, 'runtimeImport': False, 'functionalRestoreVerified': False, 'fullStackCycles': 0}
    source = base / 'release-generations' / args.generation / 'captures' / args.capture / 'state.cap'
    key = base / 'generation-custody' / (args.capture + '.key')
    command = [cli, 'release', 'capsule-extract', source, key, args.capture, args.generation, args.bundle, out / 'recovered']
    write('intent.json', {'capsule': args.capture, 'generation': args.generation, 'bundleSha256': args.bundle})
    write('implementation.json', {str(p.relative_to(cli.parents[1])): digest(p) for p in cli.parents[1].rglob('*') if p.is_file()})
    try:
        manifest = run('extract', command)
        assert all(digest(out / 'recovered' / f['name']) == f['sha256'] for f in manifest['files'])
        trees = {}
        for observation in manifest['members']:
            member = observation['name']
            assert member.startswith(args.generation + '-') and '/' not in member
            spec = json.loads((out / 'recovered' / member / 'spec.json').read_text())
            for volume in spec['volumes']:
                assert re.fullmatch(r'[a-z][a-z0-9-]{0,39}', volume['id'])
                path = out / 'recovered' / member / 'volumes' / (volume['id'] + '.tar')
                entries = run(member + '-' + volume['id'], [cli, 'release', 'volume-tar-inspect', path, str(volume['userId'])])
                trees[member + '/' + volume['id']] = len(entries)
        run('reuse-denied', command, expected=1)
        assert all(digest(out / 'recovered' / f['name']) == f['sha256'] for f in manifest['files'])
        receipt.update(passed=True, payloads=len(manifest['files']), validatedVolumeEntryCounts=trees, reuseDenied=True,
                       archiveSha256=digest(source))
    except BaseException as error:
        receipt['failureType'] = type(error).__name__
        raise
    finally:
        write('receipt.json', receipt)
        print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    main()
