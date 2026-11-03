import ast
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


class SogoProbeSafetyTest(unittest.TestCase):
    script = Path(__file__).with_name('test-private-sogo.py')

    def test_optimized_python_refused_before_imports(self):
        tree = ast.parse(self.script.read_text())
        guard = next(n for n in tree.body if isinstance(n, ast.If))
        self.assertLess(guard.lineno, min(n.lineno for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))))
        result = subprocess.run(['python3', '-O', str(self.script), '--help'], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Optimized Python refused', result.stderr)

    def test_exclusive_durable_intents_cannot_be_replayed(self):
        spec = importlib.util.spec_from_file_location('sogo_probe_unit', self.script)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'intent'
            module.durable(path, {'state': 'uncertain'}, exclusive=True)
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                module.durable(path, {'state': 'replay'}, exclusive=True)
            self.assertEqual(original, path.read_bytes())
            receipt = Path(directory) / 'receipt'
            module.durable(receipt, {'passed': False})
            self.assertFalse(json.loads(receipt.read_text())['passed'])

    def test_write_intent_precedes_http_and_browser_has_no_business_writes(self):
        tree = ast.parse(self.script.read_text())
        method = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'write_once')
        calls = [n for n in ast.walk(method) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
        intent = next(n for n in calls if n.func.id == 'durable')
        http = next(n for n in calls if n.func.id == 'request')
        self.assertLess(intent.lineno, http.lineno)
        self.assertTrue(next(k.value.value for k in intent.keywords if k.arg == 'exclusive'))
        browser = (self.script.resolve().parents[2] / 'acceptance/scripts/SogoBrowserProbe.java').read_text()
        self.assertNotIn('fetch(', browser)
        self.assertNotIn('setIgnoreHTTPSErrors', browser)
        self.assertIn('0xHIGHFLYxSOGo', browser)
        self.assertIn('calendar/week/', browser)
        self.assertIn('--clear-groups', self.script.read_text())


if __name__ == '__main__':
    unittest.main()
