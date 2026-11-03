"""Unit-only process-observation bounds; native fault executions are separate evidence."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('test-import-interruption.py')
SPEC = importlib.util.spec_from_file_location('import_interruption_probe', SCRIPT)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class ImportInterruptionTest(unittest.TestCase):
    def test_process_identity_and_missing_process(self):
        text = '123 (fixture name) S ' + ' '.join(['0'] * 18 + ['777'])
        with patch.object(Path, 'read_text', return_value=text):
            self.assertEqual({'pid': 123, 'state': 'S', 'startTicks': '777'}, probe.process_state(123))
        with patch.object(Path, 'read_text', side_effect=FileNotFoundError):
            self.assertIsNone(probe.process_state(123))

    def test_only_reachable_descendants_and_exit_race(self):
        def children(path):
            return {'1': '2 3', '2': '4'}.get(path.parent.name, '')
        def state(pid):
            return None if pid == 3 else {'pid': pid, 'state': 'Z', 'startTicks': str(pid)}
        with patch.object(Path, 'read_text', autospec=True, side_effect=children), patch.object(probe, 'process_state', side_effect=state):
            self.assertEqual([2, 4], [p['pid'] for p in probe.descendants(1)])
        with patch.object(Path, 'read_text', side_effect=FileNotFoundError):
            self.assertEqual([], probe.descendants(1))

    def test_unexpected_population_is_not_silently_truncated(self):
        with patch.object(Path, 'read_text', return_value=' '.join(str(n) for n in range(2, 35))), patch.object(probe, 'process_state', side_effect=lambda pid: {'pid': pid, 'state': 'S', 'startTicks': '1'}):
            with self.assertRaisesRegex(AssertionError, 'Unexpected controller descendant population'):
                probe.descendants(1)

    def test_optimized_execution_refuses_before_argument_processing_or_effects(self):
        result = subprocess.run([sys.executable, '-O', str(SCRIPT), '--invalid-argument'], capture_output=True, timeout=10)
        self.assertEqual(1, result.returncode)
        self.assertEqual(b'', result.stdout)
        self.assertIn(b'Optimized execution refused before effects', result.stderr)


if __name__ == '__main__':
    unittest.main()
