import importlib.util
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('private_boot', Path(__file__).with_name('install-private-boot-units.py'))
boot = importlib.util.module_from_spec(spec)
spec.loader.exec_module(boot)


class PrivateBootUnitsTest(unittest.TestCase):
    def fixture(self, root):
        (root / 'bin').mkdir()
        (root / 'lib').mkdir()
        (root / 'bin/p0-v3-platform').write_bytes(b'unit-only-controller')
        (root / 'lib/unit.jar').write_bytes(b'unit-only-jar')

    def test_distribution_identity_binds_paths_bytes_and_installed_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            digest, files, descriptor = boot.distribution(root)
            self.assertEqual(len(digest), 64)
            self.assertEqual(files['bin/p0-v3-platform'][0], 0o755)
            self.assertEqual(files['lib/unit.jar'][0], 0o644)
            self.assertEqual(boot.distribution(root), (digest, files, descriptor))
            (root / 'lib/unit.jar').write_bytes(b'different')
            self.assertNotEqual(boot.distribution(root)[0], digest)
            (root / 'lib/unit.jar').rename(root / 'lib/other.jar')
            self.assertNotEqual(boot.distribution(root)[0], digest)

    def test_distribution_rejects_symlinks_extra_directories_and_missing_launcher(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root)
            link = root / 'lib/link.jar'
            link.symlink_to(root / 'lib/unit.jar')
            with self.assertRaises(AssertionError):
                boot.distribution(root)
            link.unlink()
            (root / 'extra').mkdir()
            with self.assertRaises(AssertionError):
                boot.distribution(root)
            (root / 'extra').rmdir()
            (root / 'bin/p0-v3-platform').unlink()
            with self.assertRaises(AssertionError):
                boot.distribution(root)

    def test_existing_unit_never_silently_changes_content_owner_or_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'unit'
            self.assertFalse(boot.same_root_file(path, b'unit', 0o644))
            path.write_bytes(b'unit')
            with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0)):
                self.assertTrue(boot.same_root_file(path, b'unit', 0o644))
                with self.assertRaises(AssertionError):
                    boot.same_root_file(path, b'changed', 0o644)
            for mode, uid in [(stat.S_IFREG | 0o666, 0), (stat.S_IFREG | 0o644, 1000), (stat.S_IFLNK | 0o777, 0)]:
                with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=mode, st_uid=uid)):
                    with self.assertRaises(AssertionError):
                        boot.same_root_file(path, b'unit', 0o644)

    def test_commands_and_root_install_fail_closed(self):
        with patch.object(boot.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'ok')):
            self.assertEqual(boot.call(['unit-only']), b'ok')
        with patch.object(boot.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout=b'')):
            with self.assertRaises(AssertionError):
                boot.call(['unit-only'])
        with patch.object(boot, 'same_root_file', side_effect=[False, True]), patch.object(boot, 'call') as command:
            boot.install_file(Path('/unit-source'), Path('/unit-destination'), b'unit', 0o644)
            self.assertIn('root', command.call_args.args[0])
        with patch.object(boot, 'same_root_file', return_value=True), patch.object(boot, 'call') as command:
            boot.install_file(Path('/unit-source'), Path('/unit-destination'), b'unit', 0o644)
            command.assert_not_called()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'root-directory'
            with patch.object(boot, 'call') as command, patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)):
                boot.root_directory(path)
                self.assertIn('--mode=0755', command.call_args.args[0])
            path.mkdir()
            with patch.object(boot, 'call') as command, patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o777, st_uid=0)):
                with self.assertRaises(AssertionError):
                    boot.root_directory(path)
                command.assert_not_called()

    def test_optimized_interpreter_is_rejected_before_effects(self):
        result = subprocess.run([sys.executable, '-O', str(Path(boot.__file__)), '--help'], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Optimized Python', result.stderr)

    def test_main_with_fake_effects_stages_verifies_and_activates_only_named_unit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist = root / 'distribution'
            dist.mkdir()
            self.fixture(dist)
            base = root / 'manifests'
            base.mkdir(mode=0o700)
            manifest = base / 'unit.json'
            manifest.write_text('{"name":"unit","processes":[{"id":"app"}]}')
            manifest.chmod(0o600)
            systemd = root / 'systemd'
            systemd.mkdir()
            calls = []
            unit = b'# Managed by p0v3-private-boot-v1; unit-only\n'
            def command(args, **kwargs):
                calls.append(args)
                if 'status-private' in args:
                    return b'[{"id":"app","state":"running"}]\n'
                if 'boot-unit' in args:
                    return unit
                if 'is-active' in args:
                    return b'active\n'
                if 'is-enabled' in args:
                    return b'enabled\n'
                return b''
            def install(source, destination, content, mode):
                destination.write_bytes(content)
                destination.chmod(mode)
            with patch.object(boot, 'DIST', dist), patch.object(boot, 'BASE', base), patch.object(boot, 'SYSTEMD', systemd), \
                 patch.object(boot, 'SUPERVISION', root / 'supervision'), patch.object(boot, 'call', side_effect=command), \
                 patch.object(boot, 'root_directory', side_effect=lambda p: p.mkdir(mode=0o755, exist_ok=True)), \
                 patch.object(boot, 'same_root_file', return_value=False), patch.object(boot, 'install_file', side_effect=install), \
                 patch.object(sys, 'argv', ['unit-only', '--activate', 'unit']), patch('builtins.print'):
                boot.main()
            self.assertEqual((systemd / 'p0v3-private-unit.service').read_bytes(), unit)
            self.assertTrue(any(c[0] == 'systemd-analyze' for c in calls))
            self.assertIn(['sudo', '-n', 'systemctl', 'enable', '--now', 'p0v3-private-unit.service'], calls)


if __name__ == '__main__':
    unittest.main()
