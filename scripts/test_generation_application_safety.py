"""Effectful generation clients must reject -O before parsing arguments or touching native fixtures."""
from pathlib import Path
import subprocess
import sys
import unittest


class GenerationApplicationSafetyTest(unittest.TestCase):
    def test_optimized_execution_denied_before_argument_parsing(self):
        scripts = ('test-private-generation.py', 'test-persistent-foundation.py', 'test-persistent-sql-cache.py',
                   'test-persistent-forgejo.py', 'test-persistent-planka.py')
        for name in scripts:
            with self.subTest(script=name):
                result = subprocess.run([sys.executable, '-O', str(Path(__file__).with_name(name)), '--invalid-argument'],
                                        capture_output=True, timeout=10)
                self.assertEqual(1, result.returncode)
                self.assertEqual(b'', result.stdout)
                self.assertIn(b'Optimized Python refused before imports or effects', result.stderr)


if __name__ == '__main__':
    unittest.main()
