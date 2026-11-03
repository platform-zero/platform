#!/usr/bin/env python3
"""Capture an already retired private generation. No starts, unfencing, initialization or restoration."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import uuid

PLATFORM = Path(__file__).resolve().parents[1]
CLI = PLATFORM / 'build/install/p0-v3-platform/bin/p0-v3-platform'
BASE = Path('/mnt/media/p0-v3')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--generation', required=True)
    parser.add_argument('--bundle', required=True)
    args = parser.parse_args()
    assert re.fullmatch(r'q-[a-f0-9]{12}', args.generation)
    assert re.fullmatch(r'[a-f0-9]{64}', args.bundle)
    os.umask(0o077)
    nonce = uuid.uuid4().hex[:12]
    capture_id = 'cap-' + nonce
    out = BASE / 'image-acquisition-receipts' / ('p0v3-capture-' + nonce)
    out.mkdir(mode=0o700)
    for name in ('home', 'tmp'):
        (out / name).mkdir(mode=0o700)
    env = {'PATH': '/usr/bin:/bin', 'JAVA_HOME': '/usr/lib/jvm/java-21-openjdk-amd64',
           'HOME': str(out / 'home'), 'TMPDIR': str(out / 'tmp'), 'LANG': 'C.UTF-8'}
    receipt = {'id': out.name, 'generation': args.generation, 'bundleSha256': args.bundle, 'captureId': capture_id,
               'passed': False, 'functionalRestoreVerified': False, 'fullStackQualification': False,
               'sourceStarted': False, 'sourceUnfenced': False, 'publicActivation': False}

    def write(name, value):
        with (out / name).open('x') as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.flush()
            os.fsync(stream.fileno())

    def run(label, argv, expected=0):
        write(label + '.intent.json', {'argvSha256': hashlib.sha256(json.dumps([str(x) for x in argv]).encode()).hexdigest(),
                                      'captureId': capture_id, 'replayPermitted': False})
        result = subprocess.run([str(x) for x in argv], capture_output=True, env=env, timeout=1200)
        (out / (label + '.stdout')).write_bytes(result.stdout)
        (out / (label + '.stderr')).write_bytes(result.stderr)
        write(label + '.result.json', {'exitCode': result.returncode})
        assert result.returncode == expected, 'Capture phase failed: ' + label
        return result.stdout.decode()

    def census(label):
        summary = json.loads(run(label, ['python3', PLATFORM / 'scripts/inspect-private-fleet.py']))
        value = json.loads((BASE / 'image-acquisition-receipts' / summary['id'] / 'receipt.json').read_text())
        assert value['passed']
        write(label + '.json', value)
        return value

    generation_root = BASE / 'release-generations' / args.generation
    bundle_bytes = (generation_root / 'bundle.json').read_bytes()
    assert hashlib.sha256(bundle_bytes).hexdigest() == args.bundle
    bundle = json.loads(bundle_bytes)
    names = [m['member']['name'] for m in bundle['members']]
    assert all(name.startswith(args.generation + '-') for name in names)

    def source_hashes():
        files = []
        for name in names:
            root = BASE / 'runtime-deployments' / name
            files += [BASE / 'runtime-deployments' / (name + '.json')]
            files += list(root.iterdir())
        assert all(p.is_file() and not p.is_symlink() for p in files)
        return {str(p.relative_to(BASE)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}

    before = None
    failure = None
    try:
        before = census('fleet-before')
        original = source_hashes()
        write('source-before.json', original)
        result = json.loads(run('capture', [CLI, 'release', 'generation-capture', args.generation, args.bundle, capture_id]).splitlines()[0])
        assert result['passed'] and result['verification']['authenticated'] and not result['verification']['functionalRestoreVerified']
        verified = json.loads(run('verify', [CLI, 'release', 'generation-verify-capture', args.generation, args.bundle, capture_id]).splitlines()[0])
        assert result['verification'] == verified
        root = generation_root / 'captures' / capture_id
        archive = root / 'state.cap'
        key = BASE / 'generation-custody' / (capture_id + '.key')
        assert key.stat().st_mode & 0o077 == 0 and key.stat().st_uid == os.getuid()
        standalone = json.loads(run('standalone-verify', [CLI, 'release', 'capsule-verify', archive, key,
                                                       capture_id, args.generation, args.bundle]))
        assert standalone == verified
        wrong = out / 'wrong.key'
        wrong.write_bytes(secrets.token_bytes(64))
        run('wrong-key-denied', [CLI, 'release', 'capsule-verify', archive, wrong, capture_id, args.generation, args.bundle], expected=1)
        tampered = out / 'tampered.cap'
        shutil.copyfile(archive, tampered)
        with tampered.open('r+b') as stream:
            stream.seek(100)
            value = stream.read(1)
            assert len(value) == 1
            stream.seek(100)
            stream.write(bytes([value[0] ^ 1]))
        run('tampering-denied', [CLI, 'release', 'capsule-verify', tampered, key, capture_id, args.generation, args.bundle], expected=1)
        assert not list(root.glob('*.tar')), 'Verified capture must remove only its own scratch exports'
        assert original == source_hashes(), 'Source inputs, ledgers or fences changed'
        receipt.update(authenticatedCapture=True, completeCiphertextAndPayloadVerification=True,
                       wrongKeyDenied=True, tamperingDenied=True, scratchExportsRemoved=True,
                       sourceMetadataUnchanged=True, archiveSha256=verified['archiveSha256'],
                       manifestSha256=verified['manifestSha256'], payloadFiles=verified['files'],
                       plaintextBytes=verified['plaintextBytes'])
    except BaseException as error:
        failure = error
        receipt['failureType'] = type(error).__name__
    finally:
        try:
            after = census('fleet-after')
            if before:
                assert before['deployments'] == after['deployments']
                assert before['retainedFenceHashes'] == after['retainedFenceHashes']
                receipt['protectedFleetAndAllFencesUnchanged'] = True
            receipt['passed'] = failure is None and receipt.get('authenticatedCapture', False)
        except BaseException as error:
            failure = failure or error
            receipt['finalCheckFailureType'] = type(error).__name__
        write('receipt.json', receipt)
    print(json.dumps(receipt, indent=2))
    if failure:
        raise SystemExit('Capture failed; retain partial capture and custody records, never replay source initialization')


if __name__ == '__main__':
    main()
