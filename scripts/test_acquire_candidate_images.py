import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('acquire', Path(__file__).with_name('acquire-candidate-images.py'))
acquire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(acquire)

class AcquisitionTest(unittest.TestCase):
    def fake(self, args, timeout=900):
        if 'info' in args:
            body = {'store': {'graphRoot': acquire.ROOT + '/graph', 'runRoot': acquire.RUN}}
        elif 'inspect' in args:
            body = [{'Id': 'a' * 64, 'Digest': 'sha256:' + 'b' * 64, 'Architecture': 'amd64', 'Os': 'linux',
                     'RepoDigests': ['example.org/app@sha256:' + 'b' * 64]}]
        else:
            return subprocess.CompletedProcess(args, 0, '', '')
        return subprocess.CompletedProcess(args, 0, json.dumps(body), '')

    def test_acquisition_records_content_identity_and_reuses_receipt(self):
        with tempfile.TemporaryDirectory() as root, patch.object(acquire, 'command', self.fake):
            selection = [{'product': 'example', 'reference': 'example.org/app:1.0', 'source': 'https://example.org/release'}]
            receipts = Path(root) / 'receipts'
            acquire.acquire(selection, receipts)
            acquire.acquire(selection, receipts)
            record = json.loads((receipts / 'example.json').read_text())
            self.assertEqual(record['selectedManifestDigest'], 'sha256:' + 'b' * 64)
            self.assertEqual(record['status'], 'downloaded-candidate-not-accepted-release')
            self.assertEqual((receipts / 'example.json').stat().st_mode & 0o777, 0o600)

    def test_shared_store_denied_before_pull(self):
        with tempfile.TemporaryDirectory() as root, patch.object(acquire, 'command', return_value=
            subprocess.CompletedProcess([], 0, json.dumps({'store': {'graphRoot': '/var/lib/containers/storage', 'runRoot': '/run/containers'}}), '')):
            with self.assertRaises(RuntimeError):
                acquire.acquire([], Path(root) / 'receipts')

    def test_mutable_tag_and_path_injection_denied(self):
        with tempfile.TemporaryDirectory() as root, patch.object(acquire, 'command', self.fake):
            for product, ref in [('example', 'example.org/app:latest'), ('../escape', 'example.org/app:1.0')]:
                with self.assertRaises(ValueError):
                    acquire.acquire([{'product': product, 'reference': ref}], Path(root) / 'receipts')

    def test_changed_tag_does_not_overwrite_previous_identity(self):
        with tempfile.TemporaryDirectory() as root, patch.object(acquire, 'command', self.fake):
            receipts = Path(root) / 'receipts'
            receipts.mkdir(mode=0o700)
            old = {'reference': 'example.org/app:1.0', 'imageId': 'old-image'}
            (receipts / 'example.json').write_text(json.dumps(old))
            with self.assertRaises(SystemExit):
                acquire.acquire([{'product': 'example', 'reference': old['reference'], 'source': 'https://example.org'}], receipts)
            self.assertEqual(json.loads((receipts / 'example.json').read_text()), old)

if __name__ == '__main__':
    unittest.main()
