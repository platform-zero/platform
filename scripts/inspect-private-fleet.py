#!/usr/bin/env python3
"""Read-only declared-runtime census; not a restart or application availability test."""
if not __debug__:
    raise SystemExit('Optimized Python refused before imports or effects')
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid
from probe_receipt import private_receipt


def main():
    os.umask(0o077)
    base = Path('/mnt/media/p0-v3/runtime-deployments')
    out = Path('/mnt/media/p0-v3/image-acquisition-receipts') / ('p0v3-fleet-' + uuid.uuid4().hex[:12]); out.mkdir(mode=0o700)
    p = ['sudo', '-n', 'podman', '--remote=false', '--root=/mnt/media/p0-v3/release-runtime/graph', '--runroot=/run/p0-v3-release-runtime/store', '--network-config-dir=/mnt/media/p0-v3/release-runtime/network-config']
    receipt = {'id': out.name, 'passed': False, 'scope': 'read-only-runtime-census', 'hostReboot': False, 'fullFleetRestart': False, 'applicationAvailability': False, 'fullStackAcceptance': False}
    with private_receipt(receipt, lambda r: (out / 'receipt.json').write_text(json.dumps(r, indent=2))):
        rows = []
        for unit in sorted(Path('/etc/systemd/system').glob('p0v3-private-*.service')):
            if subprocess.run(['systemctl', 'is-enabled', unit.name], capture_output=True, timeout=15).returncode:
                continue
            assert subprocess.run(['systemctl', 'is-active', unit.name], capture_output=True, timeout=15).returncode == 0
            name = unit.name[len('p0v3-private-'):-len('.service')]; manifest = base / (name + '.json'); spec = json.loads(manifest.read_text())
            processes = [x for x in spec['processes'] if not x.get('oneShot', False)]
            names = ['p0v3-live-' + name + '-' + x['id'] for x in processes]
            result = subprocess.run(p + ['inspect'] + names, capture_output=True, check=True, timeout=30)
            inspected = json.loads(result.stdout); proofs = []
            for expected, actual in zip(processes, inspected, strict=True):
                h = actual['HostConfig']; assert actual['State']['Running'] and not h['PortBindings'] and h['ReadonlyRootfs'] and 'no-new-privileges' in h['SecurityOpt']
                assert actual['Config']['User'] == str(expected['userId']) + ':' + str(expected.get('groupId', expected['userId'])) and expected['userId'] > 0
                caps = {'CAP_' + c.removeprefix('CAP_') for c in expected.get('capabilities', [])}
                assert set(actual['EffectiveCaps'] or []) == caps and set(actual['BoundingCaps'] or []) == caps
                assert actual['Image'].removeprefix('sha256:') == expected['imageId'] and h['Memory'] == expected.get('memoryMiB', 512) * 1024 * 1024
                proofs.append({'role': expected['id'], 'id': actual['Id'], 'startedAt': actual['State']['StartedAt']})
            rows.append({'deployment': name, 'manifestSha256': hashlib.sha256(manifest.read_bytes()).hexdigest(), 'processes': proofs})
        assert rows
        for name in ('huly-r8', 'huly-r9', 'jupyterhub-r7', 'mail-r4', 'mail-r7', 'sogo-mail-r1', 'smrestore-0609bbce6070'):
            assert (base / name / 'runtime.maintenance').is_file()
        fences = {}
        for file in sorted(base.glob('*/runtime.maintenance')):
            assert not file.is_symlink() and file.stat().st_uid == os.getuid() and file.stat().st_mode & 0o777 == 0o600
            fences[file.parent.name] = hashlib.sha256(file.read_bytes()).hexdigest()
        receipt.update(passed=True, enabledActiveUnits=len(rows), runningDeclaredDaemons=sum(len(row['processes']) for row in rows), deployments=rows, retainedFenceHashes=fences)
    print(json.dumps({k: v for k, v in receipt.items() if k not in ('deployments', 'retainedFenceHashes')}))


if __name__ == '__main__':
    main()
