import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

PATH = Path(__file__).with_name('test-private-backup.py')
spec = importlib.util.spec_from_file_location('backup_probe', PATH)
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class BackupSafetyTests(unittest.TestCase):
    def test_optimized_refusal_before_imports(self):
        result = subprocess.run([sys.executable, '-O', str(PATH)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Optimized Python disables safety checks; refusing effects', result.stderr)
        self.assertNotIn(b'Traceback', result.stderr)

    def test_intent_is_private_exclusive_and_never_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / 'state'; filename = 'backup-upload-' + 'a' * 64 + '.intent'
            path = M.write_intent(state, filename, {'snapshot': 'old'})
            self.assertEqual(json.loads(path.read_text()), {'snapshot': 'old'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(state.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(FileExistsError): M.write_intent(state, filename, {'snapshot': 'new'})
            with self.assertRaises(AssertionError): M.write_intent(state, '../escape', {})
            with self.assertRaises(AssertionError): M.write_intent(state, 'backup-file-' + 'b' * 64 + '.intent', {'large': 'x' * 8192})
            link = Path(directory) / 'link'; link.symlink_to(state)
            with self.assertRaises(AssertionError): M.write_intent(link, filename, {})
            another = state / ('backup-file-' + 'c' * 64 + '.intent'); another.symlink_to('absent')
            with self.assertRaises(FileExistsError): M.write_intent(state, another.name, {})
            self.assertFalse((state / 'absent').exists())

    def test_uncertain_durability_leaves_intent_blocking_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); filename = 'backup-file-' + 'a' * 64 + '.intent'
            with patch.object(M.os, 'fsync', side_effect=OSError('injected')):
                with self.assertRaises(OSError): M.write_intent(root, filename, {})
            self.assertTrue((root / filename).exists())
            with self.assertRaises(FileExistsError): M.write_intent(root, filename, {})
