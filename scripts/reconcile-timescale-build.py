#!/usr/bin/env python3
"""Read-only reconciliation of the original failed Timescale build; never rerun or clean it.

The sidecar is an independent observation, NOT the missing original command result or
permission to reuse its operation ID. Retained files and build resources are left intact.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path('/mnt/media/p0-v3/image-acquisition-receipts/timescale-pg17-231-r1')
STORE = '/mnt/media/p0-v3/runtime-stores/canonical-v2/graph'
RUN = '/run/p0-v3-canonical-v2/store'
MODULE = '/mnt/media/p0-v3/runtime-stores/canonical-v2/containers.conf'
NETWORK = '/mnt/media/p0-v3/runtime-stores/canonical-v2/networks'
ENGINE = ['sudo', '-n', '/usr/bin/podman', '--remote=false', '--module=' + MODULE,
          '--root=' + STORE, '--runroot=' + RUN, '--network-config-dir=' + NETWORK]
IMAGE = 'localhost/p0-v3/postgres-timescale:2.31.0-pg17.11-r1'
FAILURE = b'Error: building at STEP "RUN sha256sum -c inputs.sha256 && dpkg -i /build/debs/*.deb"'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def private_file(path, maximum=128 * 1024):
    info = path.lstat()
    if not path.is_file() or path.is_symlink() or info.st_nlink != 1 or info.st_uid != os.getuid() or \
            info.st_mode & 0o077 or info.st_size > maximum:
        raise ValueError('Changed original build record')
    data = path.read_bytes()
    if len(data) > maximum:
        raise ValueError('Oversized original build record')
    return data


def observe(command):
    result = subprocess.run(command, capture_output=True, timeout=30, check=False)
    if result.returncode or len(result.stdout) > 2_000_000 or result.stderr:
        raise RuntimeError('Build observation uncertain; retain original')
    return result.stdout


def reconcile():
    if os.getuid() == 0 or ROOT.is_symlink() or ROOT.stat().st_uid != os.getuid() or ROOT.stat().st_mode & 0o077:
        raise ValueError('Original owner and private build directory required')
    with (ROOT / 'build.lock').open('rb') as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt = ROOT / 'build.reconciliation-v1.json'
        if receipt.exists():
            raise ValueError('Original build already reconciled; preserve receipt')
        if (ROOT / 'build.result.json').exists():
            raise ValueError('Original result exists; do not substitute a reconciliation')
        intent = private_file(ROOT / 'build.intent.json')
        record = json.loads(intent)
        if record['job'] != 'timescale-pg17-231-r1' or record['argv'] != ENGINE + [
            'build', '--pull=never', '--retry=0', '--network=none', '--http-proxy=false',
            '--rm=false', '--force-rm=false', '--layers=false', '--memory=4g', '--memory-swap=4g',
            '--cpu-period=100000', '--cpu-quota=200000', '--tag', IMAGE, str(ROOT / 'context')]:
            raise ValueError('Foreign original build operation')
        stdout = private_file(ROOT / 'build.stdout', 2_000_000)
        stderr = private_file(ROOT / 'build.stderr', 2_000_000)
        if FAILURE not in stderr or b'while running runtime: exit status 1' not in stderr or \
                b'pre-dependency problem' not in stderr or b'COPY' not in stdout:
            raise ValueError('Original failed-build terminal evidence missing')
        containers = json.loads(observe(ENGINE + ['ps', '-a', '--format', 'json']))
        images = json.loads(observe(ENGINE + ['images', '--all', '--format', 'json']))
        build_containers = json.loads(observe(['sudo', '-n', 'buildah', '--root', STORE,
            '--runroot', RUN, 'containers', '--json'])) or []
        if any(IMAGE in str(image.get('Names', [])) for image in images) or \
                any('timescale' in str(item).lower() for item in build_containers):
            raise ValueError('Build image or intermediate identity still present; retain uncertainty')
        owned = [item for item in containers if item.get('Labels', {}).get('io.p0v3.artifact-build') == record['job']]
        if len(owned) != 1 or owned[0]['ImageID'] != '99445113a4a19e82dd3713c65bd9f6fb5bf972065ab043df8d1e1c93e957da9a' or \
                owned[0]['Exited'] is not True or owned[0]['Pid'] != 0 or owned[0]['ExitCode'] != 0:
            raise ValueError('Unexpected original acquisition container or active build')
        process_matches = []
        for process in Path('/proc').iterdir():
            if not process.name.isdecimal() or process.name == str(os.getpid()):
                continue
            try:
                argv = (process / 'cmdline').read_bytes()
            except (OSError, PermissionError):
                continue
            if b'timescale-pg17-231-r1' in argv and (b'buildah' in argv or b'podman' in argv):
                process_matches.append(process.name)
        if process_matches:
            raise ValueError('Possible active original builder; retain uncertainty')
        # This observation is neither an original ACK nor permission for an automatic retry.
        observation = {
            'schemaVersion': 1, 'operation': 'timescale-pg17-231-r1',
            'status': 'terminal-build-error-observed-original-result-absent',
            'originalIntentSha256': digest(intent), 'originalStdoutSha256': digest(stdout),
            'originalStderrSha256': digest(stderr), 'originalResultPresent': False,
            'builtTaggedImagePresent': False, 'matchingBuildahIntermediatesPresent': False,
            'retainedAcquisitionContainerId': owned[0]['Id'], 'retainedAcquisitionContainerState': 'exited-0',
            'originalOperationReplayAuthorized': False, 'cleanupAuthorized': False,
            'releaseArtifactAdmitted': False,
        }
        data = (json.dumps(observation, sort_keys=True, indent=2) + '\n').encode()
        fd = os.open(receipt, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        fd = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return observation


if __name__ == '__main__':
    print(json.dumps(reconcile(), sort_keys=True))
