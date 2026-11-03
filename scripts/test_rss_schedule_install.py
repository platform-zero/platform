import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('rss_installer', Path(__file__).with_name('install-rss-schedule.py'))
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class RssInstallerTest(unittest.TestCase):
    def fixture(self, root):
        digest = 'a' * 64
        binding = {'userId': os.getuid(), 'deployment': {'generationId': 'q-123456789abc'}, 'controllerSha256': digest}
        data = json.dumps(binding).encode()
        expected = hashlib.sha256(data).hexdigest()
        for name, content in [('binding.json', data), ('enrolled', expected.encode())]:
            (root / name).write_bytes(content)
            (root / name).chmod(0o600)
        calls = []
        release = Path('/mnt/media/p0-v3/runtime-supervision/releases') / digest
        name = 'p0v3-rss-q-123456789abc'
        units = {name + '.service': f'[Service]\nUser={os.getuid()}\nExecStart={release}/bin/p0-v3-platform rss schedule-tick {root} {expected}\n',
                 name + '.timer': '[Timer]\nOnUnitInactiveSec=900s\n'}
        def call(args, **kwargs):
            calls.append(args)
            if 'schedule-units' in args:
                self.assertNotIn('JAVA_TOOL_OPTIONS', kwargs['env'])
                return json.dumps(units).encode()
            if 'is-enabled' in args:
                return b'enabled\n'
            if 'is-active' in args:
                return b'active\n'
            return b''
        helpers = SimpleNamespace(DIST=root / 'dist', SUPERVISION=release.parent.parent, SYSTEMD=Path('/etc/systemd/system'),
            distribution=lambda _: (digest, {'bin/p0-v3-platform': (0o755, b'unit'), 'lib/unit.jar': (0o644, b'unit')}, b'{}'),
            root_directory=lambda _: None, install_file=lambda *args: None, same_root_file=lambda *args: False, call=call)
        return expected, helpers, calls

    def test_install_and_explicit_enable_do_not_release_or_poll(self):
        for enabled in (False, True):
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                expected, helpers, calls = self.fixture(root)
                result = installer.install(root, expected, enabled, helpers)
                self.assertFalse(result['publicationAuthorized'])
                self.assertEqual(enabled, result['timerEnabled'])
                self.assertEqual(enabled, any('enable' in args for args in calls))
                self.assertFalse(any('schedule-tick' in args or 'release' in args or 'poll' in args for args in calls))

    def test_changed_binding_or_controller_rejected_before_privileged_calls(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            expected, helpers, calls = self.fixture(root)
            with self.assertRaises(AssertionError):
                installer.install(root, 'b' * 64, helpers=helpers)
            helpers.distribution = lambda _: ('b' * 64, {}, b'{}')
            with self.assertRaises(AssertionError):
                installer.install(root, expected, helpers=helpers)
            self.assertEqual([], calls)

    def test_linked_and_public_inputs_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            expected, helpers, _ = self.fixture(root)
            (root / 'binding.json').chmod(0o644)
            with self.assertRaises(AssertionError):
                installer.install(root, expected, helpers=helpers)
            (root / 'binding.json').chmod(0o600)
            (root / 'link').symlink_to(root / 'binding.json')
            with self.assertRaises(AssertionError):
                installer.private_json(root / 'link')


if __name__ == '__main__':
    unittest.main()
