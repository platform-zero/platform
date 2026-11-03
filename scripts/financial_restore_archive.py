"""Fail-closed regular-file tar inventory for the confined financial-volume restore harness."""
import hashlib
from pathlib import PurePosixPath
import tarfile


def inventory(path, max_entries=100000, max_bytes=8 * 1024**3, expected_owner=None):
    result, total = {}, 0
    with tarfile.open(path, 'r:') as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or '\\' in member.name:
                raise ValueError('Unsafe archive path')
            key = str(name)
            if key in result or not (member.isdir() or member.isfile()) or member.mode & 0o7000:
                raise ValueError('Duplicate, linked, special or privileged archive entry')
            if key == '.' and not member.isdir():
                raise ValueError('Archive root is not a directory')
            if expected_owner is not None and (member.uid, member.gid) != expected_owner:
                raise ValueError('Archive ownership differs from declared volume owner')
            total += member.size
            if len(result) >= max_entries or total > max_bytes:
                raise ValueError('Archive budget exceeded')
            digest = None
            if member.isfile():
                stream = archive.extractfile(member)
                digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                stream.close()
            result[key] = {'directory': member.isdir(), 'mode': member.mode, 'size': member.size, 'sha256': digest}
    for key, entry in result.items():
        if any(str(parent) in result and not result[str(parent)]['directory'] for parent in PurePosixPath(key).parents):
            raise ValueError('Non-directory archive parent')
    return result


def extraction_command(tree):
    """Fixed destination; explicitly clear pre-existing directory sticky bits after extraction."""
    if any(name in tree for name in ('.restore-in-progress', '.p0v3-restore-complete', 'foreign-marker')):
        raise ValueError('Archive collides with restore control markers')
    root = tree.get('.')
    if not root or root.get('directory') is not True or type(root.get('mode')) is not int or not 0 <= root['mode'] <= 0o777:
        raise ValueError('Invalid archive root mode')
    return 'tar --no-same-owner -xf - -C /state; chmod ' + format(root['mode'], 'o') + ' /state; sync'
