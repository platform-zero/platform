"""Read-only oracle binding for a cold SOGo/mail restore; never authorizes fixture creation."""
import hashlib
import json
import re


def fixture_hash(base, name, restored_from=None, mutating=False):
    if mutating and name.startswith('smrestore-'):
        raise ValueError('Restored history cannot be replaced by newly created probe fixtures')
    target_path = base / (name + '.json')
    fingerprint = hashlib.sha256(target_path.read_bytes()).hexdigest()
    if restored_from is None:
        return fingerprint
    if mutating or not re.fullmatch('smrestore-[a-z0-9-]+', name) or not re.fullmatch('[a-z][a-z0-9-]{0,39}', restored_from) or name == restored_from:
        raise ValueError('Restore fixture bindings authorize readback only')
    source_path = base / (restored_from + '.json')
    source_hash = hashlib.sha256(source_path.read_bytes()).hexdigest()
    source = json.loads(source_path.read_text()); target = json.loads(target_path.read_text())
    if source['volumes'] != target['volumes']:
        raise ValueError('Restore volumes differ')
    roles = {p['id']: p for p in target['processes']}
    if set(roles) != {p['id'] for p in source['processes']} | {'home-restore-check'}:
        raise ValueError('Unexpected restore roles')
    for process in source['processes']:
        if not process.get('oneShot', False):
            expected = dict(process)
            if process['id'] == 'sogod':
                expected['dependencies'] = process.get('dependencies', []) + ['home-restore-check']
            if roles[process['id']] != expected:
                raise ValueError('Restored serving recipe differs')
    for role in ('database-init', 'mail-init', 'home-restore-check'):
        guard = roles[role]
        if not guard.get('oneShot') or source_hash not in guard['command'][-1] or '.p0v3-restore-complete' not in guard['command'][-1]:
            raise ValueError('Missing source-bound restore guard')
    names = {p['environmentFile'] for p in source['processes'] if p.get('environmentFile')} | {f['file'] for p in source['processes'] for f in p.get('files', [])}
    for file in names:
        if not re.fullmatch('[a-zA-Z0-9_.-]+', file):
            raise ValueError('Invalid input name')
        original, recovered = base / restored_from / file, base / name / file
        if original.is_symlink() or recovered.is_symlink() or original.read_bytes() != recovered.read_bytes():
            raise ValueError('Recovered inputs differ; no fixture substitution')
    return source_hash
