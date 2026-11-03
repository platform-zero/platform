import ast
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest


class GenerationScheduleSafetyTest(unittest.TestCase):
    def test_optimized_execution_refused_before_imports(self):
        for name in ('install-generation-backup-schedule.py', 'generation_schedule_probe.py'):
            path = Path(__file__).with_name(name)
            result = subprocess.run([sys.executable, '-O', str(path)], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(0, result.returncode)
            self.assertIn('Optimized Python refused before imports or effects', result.stderr)
            tree = ast.parse(path.read_text())
            self.assertIsInstance(tree.body[1], ast.If)
            self.assertTrue(all(not isinstance(n, (ast.Import, ast.ImportFrom)) for n in tree.body[:2]))

    def test_installer_rejects_foreign_scope_before_enrollment(self):
        path = Path(__file__).with_name('install-generation-backup-schedule.py')
        result = subprocess.run([sys.executable, str(path), '/does/not/exist', 'foundation-r3', 'a' * 64], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('AssertionError', result.stderr)
        self.assertNotIn('sudo', result.stderr)

    def test_probe_rejects_foreign_scope_and_never_starts_first_backup_manually(self):
        from generation_schedule_probe import exercise
        with self.assertRaises(AssertionError):
            exercise(None, 'foundation-r3', 'a' * 64, None, None, None, None)
        text = Path(__file__).with_name('generation_schedule_probe.py').read_text()
        self.assertNotIn('killpg', text)
        self.assertNotIn('snapshot create', text)
        self.assertIn('schedule-suspend', text)
        self.assertIn('schedule-inventory-fault.intent.json', text)
        self.assertLess(text.index("run('schedule-native-invocation'"), text.index("run('schedule-disable-after-fire'"))
        self.assertLess(text.index("run('schedule-disable-after-fire'"), text.index("run('schedule-bound-inventory-denied'"))

    def test_installer_import_has_no_root_effects(self):
        path = Path(__file__).with_name('install-generation-backup-schedule.py')
        spec = importlib.util.spec_from_file_location('schedule_installer_unit', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        helpers = module.boot_helpers()
        self.assertTrue(callable(helpers.distribution))
        text = path.read_text()
        self.assertNotIn("'restart'", text)
        self.assertNotIn("'rm'", text)
        self.assertNotIn('reset-failed', text)


if __name__ == '__main__':
    unittest.main()
