import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PATH = Path(__file__).with_name('test-node-metrics-encrypted-restore.py')
spec = importlib.util.spec_from_file_location('metrics_recovery', PATH)
M = importlib.util.module_from_spec(spec); spec.loader.exec_module(M)


class RecoverySafetyTests(unittest.TestCase):
    def test_optimized_refusal_precedes_imports_and_argument_parsing(self):
        result = subprocess.run([sys.executable, '-O', str(PATH)], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Optimized Python disables safety checks; refusing effects', result.stderr)
        self.assertNotIn(b'Traceback', result.stderr)

    def test_fixture_identity_rejects_failed_foreign_invalidated_or_ambiguous_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            receipt = {'passed': True, 'phase': 'complete', 'deployment': 'node-metrics-r2',
                       'manifestSha256': 'a' * 64, 'nativeTsdbHistorySurvivedRestart': True}
            (root / 'receipt.json').write_text(json.dumps(receipt))
            (root / 'probe-one-intent.json').write_text(json.dumps({'file': 'probe-' + 'b' * 32 + '.prom'}))
            self.assertEqual(M.fixture_identity(root, 'a' * 64), (receipt, 'b' * 32))
            with self.assertRaises(AssertionError): M.fixture_identity(root, 'c' * 64)
            receipt['passed'] = False; (root / 'receipt.json').write_text(json.dumps(receipt))
            with self.assertRaises(AssertionError): M.fixture_identity(root, 'a' * 64)
            receipt['passed'] = True; (root / 'receipt.json').write_text(json.dumps(receipt))
            (root / 'receipt.invalidated.json').touch()
            with self.assertRaises(AssertionError): M.fixture_identity(root, 'a' * 64)
            (root / 'receipt.invalidated.json').unlink()
            (root / 'probe-two-intent.json').write_text(json.dumps({'file': 'probe-' + 'c' * 32 + '.prom'}))
            with self.assertRaises(AssertionError): M.fixture_identity(root, 'a' * 64)

    def test_private_artifacts_are_exclusive_and_hashed_streaming(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'artifact'
            M.private(path, b'test')
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(M.digest(path), '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08')
            with self.assertRaises(FileExistsError): M.private(path, b'replacement')
            self.assertEqual(path.read_bytes(), b'test')
