import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'src/main/resources/runtime/homeassistant-recovery-guard.py'
spec = importlib.util.spec_from_file_location('ha_recovery_guard', SCRIPT)
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class RecoveryGuardTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ha-recovery-unit-')
        self.root = Path(self.temp.name).resolve()
        (self.root / '.storage').mkdir(mode=0o700)
        (self.root / 'configuration.yaml').write_text('homeassistant:\nrecorder:\n')
        (self.root / 'configuration.yaml').chmod(0o600)
        self.save('auth', 1, {'users': [{'id': 'original-owner', 'is_owner': True, 'is_active': True,
                                      'system_generated': False}],
                             'credentials': [{'user_id': 'original-owner', 'auth_provider_type': 'homeassistant',
                                              'auth_provider_id': None, 'data': {'username': 'original-user'}}]})
        self.save('auth_provider.homeassistant', 1, {'users': [{'username': 'original-user', 'password': 'synthetic-hash'}]})
        self.save('onboarding', 4, {'done': ['user', 'core_config', 'integration', 'analytics']})
        self.db = self.root / 'home-assistant_v2.db'
        with sqlite3.connect(self.db) as db:
            for table in guard.TABLES:
                db.execute(f'CREATE TABLE {table} (schema_version INTEGER)')
            db.execute('INSERT INTO schema_changes VALUES (53)')
        self.db.chmod(0o600)

    def tearDown(self):
        self.temp.cleanup()

    def save(self, key, version, data):
        path = self.root / '.storage' / key
        path.write_text(json.dumps({'key': key, 'version': version, 'data': data}))
        path.chmod(0o600)

    def test_admission_is_read_only_and_accepts_empty_closed_sidecar(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        guard.verify(self.root)
        self.assertEqual(before, {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
        (self.root / 'home-assistant_v2.db-journal').touch(mode=0o600)
        guard.verify(self.root)

    def test_missing_corrupt_old_schema_and_missing_table_do_not_initialize(self):
        for mode in ['missing', 'corrupt', 'old', 'table']:
            with self.subTest(mode=mode):
                original = self.db.read_bytes()
                if mode == 'missing':
                    self.db.unlink()
                elif mode == 'corrupt':
                    self.db.write_bytes(b'not a database')
                else:
                    with sqlite3.connect(self.db) as db:
                        db.execute('UPDATE schema_changes SET schema_version=52' if mode == 'old' else 'DROP TABLE states')
                with self.assertRaises((ValueError, OSError, sqlite3.DatabaseError)):
                    guard.verify(self.root)
                if mode == 'missing':
                    self.assertFalse(self.db.exists())
                self.db.write_bytes(original)

    def test_original_owner_provider_and_completed_onboarding_are_required(self):
        changes = [('auth', lambda d: d['data']['users'][0].update(is_active=False)),
                   ('auth', lambda d: d['data']['credentials'][0].update(user_id='foreign')),
                   ('auth_provider.homeassistant', lambda d: d['data']['users'].clear()),
                   ('onboarding', lambda d: d['data'].update(done=['user'])),
                   ('onboarding', lambda d: d.update(version=3)),
                   ('auth', lambda d: d.update(key='foreign')),
                   ('auth', lambda d: d.update(version=True))]
        for key, change in changes:
            path = self.root / '.storage' / key
            original = path.read_bytes()
            with self.subTest(key=key):
                value = json.loads(original); change(value); path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):
                    guard.verify(self.root)
            path.write_bytes(original)
        self.assertRaises(ValueError, guard.unique, [('same', 1), ('same', 2)])

    def test_links_fifo_permissions_and_empty_config_refuse(self):
        for mode in ['symlink', 'hardlink', 'fifo', 'permissions', 'empty']:
            config = self.root / 'configuration.yaml'; original = config.read_bytes()
            with self.subTest(mode=mode):
                config.unlink()
                if mode == 'symlink':
                    config.symlink_to(self.db)
                elif mode == 'hardlink':
                    os.link(self.db, config)
                elif mode == 'fifo':
                    os.mkfifo(config)
                else:
                    config.write_bytes(b' ' if mode == 'empty' else original)
                    config.chmod(0o600)
                    if mode == 'permissions':
                        config.chmod(0o666)
                with self.assertRaises((ValueError, OSError)):
                    guard.verify(self.root)
                config.unlink(); config.write_bytes(original); config.chmod(0o600)
        (self.root / '.storage').chmod(0o777)
        self.assertRaises(ValueError, guard.verify, self.root)
        (self.root / '.storage').chmod(0o700)
        auth = self.root / '.storage/auth'; auth.chmod(0o644)
        self.assertRaises(ValueError, guard.verify, self.root)
        auth.chmod(0o600)
        (self.root / 'alias').symlink_to(self.root, target_is_directory=True)
        self.assertRaises(ValueError, guard.verify, self.root / 'alias')
        self.assertRaises(ValueError, guard.verify, Path('.'))
        self.db.with_name(self.db.name + '-wal').symlink_to(self.db)
        self.assertRaises(OSError, guard.verify, self.root)

    def test_main_executes_only_after_admission_and_errors_are_private(self):
        with patch.object(guard, 'verify') as check, patch.object(guard.os, 'execve') as execute:
            guard.main()
            check.assert_called_once_with(Path('/config'))
            execute.assert_called_once_with('/usr/local/bin/python3', ['/usr/local/bin/python3', '-m', 'homeassistant', '--config', '/config'],
                                            {**os.environ, 'HOME': '/config'})
        with patch.object(guard, 'verify', side_effect=ValueError('unit-private-secret')), patch.object(guard.os, 'execve') as execute:
            with self.assertRaises(SystemExit) as caught:
                guard.main()
            self.assertNotIn('unit-private-secret', str(caught.exception)); execute.assert_not_called()

    def test_optimized_interpreter_refuses_before_imports(self):
        sentinel = self.root / 'imported'
        (self.root / 'json.py').write_text(f'open({str(sentinel)!r}, "w").write("bad")\n')
        result = subprocess.run([sys.executable, '-O', str(SCRIPT)], env={**os.environ, 'PYTHONPATH': str(self.root)},
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('before imports or effects', result.stderr)
        self.assertFalse(sentinel.exists())


if __name__ == '__main__':
    unittest.main()
