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
    def test_native_completion_receipt_binds_original_journals_and_isolation(self):
        import hashlib
        adapter = Path(__file__).parents[2] / 'acceptance/runners/backup-restore-native.py'
        spec = importlib.util.spec_from_file_location('backup_restore_native', adapter)
        native = importlib.util.module_from_spec(spec); spec.loader.exec_module(native)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory); generation = 'q-abcdef123456'; target = 'q-111111111111'
            operation = 'cap-111111111111'; bundle = 'a' * 64; target_bundle = 'b' * 64
            source = base / generation / 'backups' / operation; source.mkdir(parents=True)
            isolated = base / target / 'isolate.result.json'; isolated.parent.mkdir()
            def original(path, data):
                path.write_bytes(data); path.chmod(0o600)
                return hashlib.sha256(data).hexdigest()
            snapshot_id = 'c' * 32; fences = {target + '-core': '22222222-2222-2222-2222-222222222222'}
            snapshot = {'generation': generation, 'bundleSha256': bundle, 'id': operation, 'snapshotId': snapshot_id}
            access = {'generation': generation, 'operation': operation, 'bundleSha256': bundle}
            held_sha = original(source / 'held.json', b'held source')
            result_sha = original(source / 'result.json', json.dumps({'access': access, 'snapshot': snapshot,
                'passed': True, 'sourceResumed': True, 'failureType': None}).encode())
            authority_sha = original(source / 'resume.authority.json', b'authorized target')
            original(source / 'resume.verified.json', json.dumps({
                'generation': generation, 'operation': operation, 'bundleSha256': bundle}).encode())
            isolation_sha = original(isolated, b'target isolated')
            proof = {'access': access,
                     'heldSha256': held_sha, 'sourceResultSha256': result_sha,
                     'resumeAuthoritySha256': authority_sha, 'snapshotId': snapshot_id,
                     'target': target, 'targetBundleSha256': target_bundle, 'targetFences': fences,
                     'sourceObservations': [{'name': generation + '-core'}],
                     'targetObservations': [{'name': target + '-core'}]}
            proof_path = source / 'completion.proof.json'
            proof_sha = original(proof_path, json.dumps(proof).encode())
            weekly = {'operation': operation, 'target': target, 'targetBundleSha256': target_bundle,
                      'snapshot': snapshot,
                      'sourceResumed': True, 'requiredAssertions': ['fixture:original'],
                      'functional': {'operation': operation, 'target': target, 'targetBundleSha256': target_bundle,
                                     'snapshotId': snapshot_id, 'assertions': ['fixture:original'], 'passed': True},
                      'targetIsolation': {'action': 'isolate', 'passed': True, 'failureType': None,
                                          'bundleSha256': target_bundle, 'fences': fences},
                      'nativeCompletion': {'record': {'path': str(proof_path), 'sha256': proof_sha}, 'proof': proof},
                      'completionProof': {'heldSha256': held_sha, 'sourceResumeResultSha256': result_sha,
                                          'sourceResumeAuthoritySha256': authority_sha, 'targetIsolationSha256': isolation_sha}}
            native.checked_weekly(weekly, generation, bundle, base)
            original(source / 'resume.authority.json', b'changed authority')
            with self.assertRaises(ValueError): native.checked_weekly(weekly, generation, bundle, base)

    def test_qualified_backup_adapter_refuses_optimized_python_before_effects(self):
        adapter = Path(__file__).parents[2] / 'acceptance/runners/backup-restore-native.py'
        result = subprocess.run([sys.executable, '-O', str(adapter)], capture_output=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'optimized Python is refused before imports or effects', result.stderr)
        self.assertNotIn(b'Traceback', result.stderr)

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
