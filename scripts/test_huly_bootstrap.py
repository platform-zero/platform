#!/usr/bin/env python3
if not __debug__:
    raise SystemExit('Unit checks require assertions enabled')

from pathlib import Path
import ast
import subprocess
import sys
import unittest


class HulyBootstrapSafety(unittest.TestCase):
    def test_native_bootstrap_boundaries_without_network_or_native_processes(self):
        result = subprocess.run(
            ['node', '--test', '--experimental-test-coverage', '--test-coverage-include=**/runtime/huly*', '--test-coverage-lines=90', str(Path(__file__).with_name('huly-bootstrap-unit.cjs')), str(Path(__file__).with_name('huly-kvs-unit.cjs')), str(Path(__file__).with_name('huly-supervisor-unit.cjs'))],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_effectful_probes_refuse_optimization_before_imports(self):
        for name in ('inspect-private-huly.py', 'test-private-huly.py'):
            with self.subTest(script=name):
                script = Path(__file__).with_name(name)
                nodes = ast.parse(script.read_text()).body
                first = 1 if isinstance(nodes[0], ast.Expr) and isinstance(nodes[0].value, ast.Constant) else 0
                self.assertIsInstance(nodes[first], ast.If)
                self.assertEqual(ast.dump(nodes[first].test), ast.dump(ast.parse('not __debug__', mode='eval').body))
                result = subprocess.run([sys.executable, '-O', str(script), '--help'], capture_output=True, text=True, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Optimized Python refused', result.stderr)


if __name__ == '__main__':
    unittest.main()
