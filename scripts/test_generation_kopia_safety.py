import ast
from pathlib import Path
import subprocess
import sys
import unittest


class KopiaGenerationSafetyTest(unittest.TestCase):
    def test_capture_refuses_optimized_execution_before_imports_or_effects(self):
        script = Path(__file__).with_name('test-generation-kopia.py')
        result = subprocess.run([sys.executable, '-O', str(script)], capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Optimized Python refused before imports or effects', result.stderr)
        nodes = ast.parse(script.read_text()).body
        first_import = next(i for i, node in enumerate(nodes) if isinstance(node, (ast.Import, ast.ImportFrom)))
        self.assertIsInstance(nodes[first_import - 1], ast.If)

    def test_backup_fault_rejects_optimized_execution_and_foreign_scope(self):
        script = Path(__file__).with_name('routine_backup_fault.py')
        result = subprocess.run([sys.executable, '-O', str(script)], capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Optimized Python refused before imports or effects', result.stderr)
        from routine_backup_fault import exercise
        with self.assertRaises(AssertionError):
            exercise('foundation-r3', 'a' * 64, None, None, None, None, None, None, None)
        text = script.read_text()
        self.assertNotIn('killpg', text)
        self.assertNotIn('pkill', text)
        self.assertIn('startTicks', text)
        self.assertIn('SIGSTOP', text)
        self.assertIn('generation-backup-reconcile', text)

    def test_capture_does_not_start_source_or_reuse_historical_kopia_fixture(self):
        source = Path(__file__).with_name('test-generation-kopia.py').read_text()
        for forbidden in ('maintenance-leave', 'apply-private', 'systemctl', 'p0v3-live-backup-volume-repository'):
            self.assertNotIn(forbidden, source)
        for required in ('--network=none', '--pull=never', 'wrong-password-denied', 'snapshot.pending.json', 'existingRepositoryAndCustodyReusedWithoutInitialization'):
            self.assertIn(required, source)


if __name__ == '__main__': unittest.main()
