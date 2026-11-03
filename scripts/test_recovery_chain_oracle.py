import ast
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
import unittest


class RecoveryChainOracleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).with_name('test-generation-restore.py')
        spec = importlib.util.spec_from_file_location('recovery_chain_client_unit', path)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_lock_probe_refuses_optimized_execution_before_imports(self):
        script = Path(__file__).with_name('test-runtime-lock-admission.py')
        result = subprocess.run([sys.executable, '-O', str(script)], capture_output=True, text=True, timeout=10)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Optimized Python refused before imports or effects', result.stderr)

    def test_lock_probe_refuses_foreign_scope_without_resource_mutation(self):
        script = Path(__file__).with_name('test-runtime-lock-admission.py')
        result = subprocess.run([sys.executable, str(script), 'foundation-r3', 'a' * 64, 'cap-abcdef123456'],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('AssertionError', result.stderr)
        text = script.read_text()
        self.assertNotIn("['volume', 'rm'", text)
        self.assertNotIn("['system', 'renumber'", text)
        self.assertIn("before['freeLocks'] == 0", text)

    def test_exact_bounded_synthetic_rows(self):
        rows = [{'id': 'post-abcdef123456', 'value': None},
                {'id': 'chain-before-abcdef123456', 'value': 'chain-value-abcdef123456'},
                {'id': 'chain-after-abcdef123456', 'value': None}]
        self.assertEqual(rows, self.module.validate_rows(rows))
        self.assertEqual([], self.module.validate_rows([]))

    def test_duplicate_extra_unbounded_and_sql_shaped_inputs_refused(self):
        good = {'id': 'post-abcdef123456', 'value': None}
        for rows in ([good, good], [good] * 9, {}, [{'id': "post-'; DROP TABLE x;--", 'value': None}],
                     [{'id': good['id'], 'value': 'not-a-synthetic-oracle'}], [{'id': 123, 'value': None}],
                     [{'id': good['id'], 'value': 12}], [dict(good, ignored=True)], [None]):
            with self.subTest(rows=rows):
                with self.assertRaises(AssertionError):
                    self.module.validate_rows(rows)

    def test_readback_keeps_snapshot_expectations_separate_from_notification_rows(self):
        tree = ast.parse(Path(__file__).with_name('test-generation-restore.py').read_text())
        function = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == 'readback')
        marker = 'a' * 32
        historical = {'mid': 'unit-mid', 'message': marker, 'time': 1, 'expires': 2}
        rows = [{'id': 'post-abcdef123456', 'value': None},
                {'id': 'chain-before-abcdef123456', 'value': 'chain-value-abcdef123456'}]
        def pg(label, statement):
            if '-excluded-' in label: return '0'
            if '-preserved-' in label: return rows[1]['value']
            return marker
        def run(label, argv):
            if label.endswith('-valkey'): return marker
            return json.dumps(dict(historical, id=historical['mid']))
        def maria(label, statement, password=True):
            if label.endswith('-maria'): return 'committed-abcdef123456'
            return '1' if label.endswith('-rollback') else '0'
        scope = {'snapshot_rows': rows, 'receipt': {}, 'pg': pg, 'run': run, 'maria': maria, 're': re, 'json': json,
                 'POD': [], 'container': lambda *a: 'unit', 'original': 'unit-original', 'sql_nonce': 'abcdef123456'}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<unit-readback>', 'exec'), scope)
        scope['readback']('before', historical)
        scope['readback']('after', historical)
        self.assertEqual(rows, scope['receipt']['snapshotRowsVerified'])

    def test_recovered_source_uses_real_parent_receipt_not_a_clean_install_alias(self):
        text = Path(__file__).with_name('test-generation-restore.py').read_text()
        self.assertIn("'p0v3-generation-restore-' + args.generation[2:]", text)
        self.assertIn("oracle_hash == parent['oracleSourceReceiptSha256']", text)
        self.assertIn("parent['rebackup']['capture'] == args.capture", text)
        self.assertIn('originalImportMarkersUnchanged', text)
        self.assertIn('clean-stage-still-denied', text)
        self.assertNotIn('write_text(json.dumps(source_receipt', text)


if __name__ == '__main__':
    unittest.main()
