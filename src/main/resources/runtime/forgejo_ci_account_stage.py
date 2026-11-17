"""One-use rootless-account source handoff. Invoked by Platform with -c, not as an OLD script.

Only the pinned control files cross stdin. No registration token, image archive,
Kopia key or site secret is present. A pre-existing staged file is never adopted.
"""
import base64
import hashlib
import json
import os
import stat
import sys


def owned(directory, name):
    if not name or '/' in name or name in ('.', '..'):
        raise ValueError('invalid CI directory name')
    try:
        os.mkdir(name, 0o700, dir_fd=directory)
    except FileExistsError:
        pass
    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
    mode = os.fstat(child)
    if mode.st_uid != 784 or stat.S_IMODE(mode.st_mode) != 0o700:
        raise ValueError('foreign or shared CI directory')
    return child


def save(directory, name, contents, allowed):
    if name not in allowed:
        raise ValueError('unreviewed CI source file')
    # The public trust anchor is the sole world-readable *file*. Its parent is
    # still 0700 and the job receives only this one read-only bind mount.
    mode = 0o644 if name == 'transport-ca.pem' else 0o600
    fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, mode, dir_fd=directory)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.fsync(directory)
    return hashlib.sha256(contents).hexdigest()


def main():
    if len(sys.argv) != 2 or os.geteuid() != 784 or os.getegid() != 784:
        raise ValueError('wrong dedicated rootless CI account')
    generation = sys.argv[1]
    import re
    if not re.fullmatch(r'q-[a-f0-9]{12}', generation):
        raise ValueError('foreign CI generation')
    payload = sys.stdin.buffer.read(262145)
    if len(payload) > 262144:
        raise ValueError('oversized CI source handoff')
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate handoff field')
            result[key] = value
        return result
    source = json.loads(payload, object_pairs_hook=unique)
    unit_prefix = 'p0v3-ci-' + generation
    units = {f'unit-{unit_prefix}-internal.network', f'unit-{unit_prefix}-egress.network',
             f'unit-{unit_prefix}-transport.container', f'unit-{unit_prefix}-runner.container',
             f'unit-{unit_prefix}-guard.service'}
    control = {'runner-config.yaml', 'guard-config.json', 'guard.py',
               'transport-ca.pem', 'transport-leaf.pem', 'transport-leaf-key.pem',
               'transport-upstream-ca.pem', 'transport-Caddyfile'}
    allowed = control | units
    if (set(source) != {'generation', 'files'} or source['generation'] != generation or
            set(source['files']) != allowed):
        raise ValueError('foreign CI source handoff')
    home = os.open('/home/webservices-lab-ci-runner', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if os.fstat(home).st_uid != 784:
            raise ValueError('wrong dedicated CI home')
        current = home
        for part in ('.local', 'share', 'p0v3-ci', generation):
            next_dir = owned(current, part)
            if current != home:
                os.close(current)
            current = next_dir
        try:
            if os.listdir(current):
                raise ValueError('previous CI source staging may not be replayed')
            decoded = {}
            for entry_name, encoded in source['files'].items():
                if not isinstance(encoded, str) or len(encoded) > 180000:
                    raise ValueError('invalid CI source encoding')
                body = base64.b64decode(encoded, validate=True)
                if len(body) not in range(1, 100001):
                    raise ValueError('oversized CI source')
                decoded[entry_name] = body
            result = {entry: save(current, entry, decoded[entry], allowed) for entry in sorted(allowed)}
            os.close(owned(current, 'guard-state'))
            os.fsync(current)
            config = owned(home, '.config')
            try:
                containers = owned(config, 'containers')
                try:
                    quadlets = owned(containers, 'systemd')
                    try:
                        for entry in sorted(units - {f'unit-{unit_prefix}-guard.service'}):
                            save(quadlets, entry.removeprefix('unit-'), decoded[entry],
                                 {entry.removeprefix('unit-')})
                    finally:
                        os.close(quadlets)
                finally:
                    os.close(containers)
                systemd = owned(config, 'systemd')
                try:
                    user = owned(systemd, 'user')
                    try:
                        entry = f'unit-{unit_prefix}-guard.service'
                        save(user, entry.removeprefix('unit-'), decoded[entry],
                             {entry.removeprefix('unit-')})
                    finally:
                        os.close(user)
                finally:
                    os.close(systemd)
            finally:
                os.close(config)
            print(json.dumps(result, sort_keys=True, separators=(',', ':')))
        finally:
            os.close(current)
    finally:
        os.close(home)


if __name__ == '__main__':
    main()
