import subprocess
import sys
from pathlib import Path
import unittest


class HubCoverageGate(unittest.TestCase):
    def test_only_mocked_helpers_satisfy_line_coverage_floor(self):
        result = subprocess.run([sys.executable, str(Path(__file__).with_name('check-hub-unit-coverage.py'))], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('hub-agent.py:', result.stdout)
        self.assertIn('hub-config.py:', result.stdout)

    def test_effectful_probes_refuse_optimized_python(self):
        for name in ('inspect-private-hub.py', 'test-private-hub.py'):
            result = subprocess.run([sys.executable, '-O', str(Path(__file__).with_name(name)), '--help'], capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Optimized Python refused before imports or effects', result.stderr)


if __name__ == '__main__':
    unittest.main()
