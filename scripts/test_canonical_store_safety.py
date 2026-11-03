import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest

PATH = Path(__file__).with_name('prepare-canonical-store.py')
spec = importlib.util.spec_from_file_location('store_prepare', PATH)
store = importlib.util.module_from_spec(spec); spec.loader.exec_module(store)


class StoreSafetyTest(unittest.TestCase):
    def test_overlap_checks_fail_closed_without_changing_routes(self):
        store.reject_overlaps(['default', '10.89.0.0/16', '192.168.1.0/24', '::1/128'])
        for value in ['10.0.0.0/8', '10.203.1.0/24', '10.204.0.12/32', '0.0.0.0/0', 'not-a-route']:
            with self.assertRaises((AssertionError, ValueError)):
                store.reject_overlaps([value])

    def test_fixed_store_prefix_never_uses_default_or_legacy_store(self):
        policy = {'graph': '/mnt/media/p0-v3/runtime-stores/canonical-v2/graph', 'run': '/run/p0-v3-canonical-v2/store',
                  'network': '/mnt/media/p0-v3/runtime-stores/canonical-v2/networks',
                  'module': '/mnt/media/p0-v3/runtime-stores/canonical-v2/containers.conf', 'objectLimit': '4096',
                  'configuration': '[engine]\nlock_type = "file"\n'}
        prefix = store.validate_policy(policy)
        self.assertIn('--root=' + policy['graph'], prefix)
        self.assertIn('--module=' + policy['module'], prefix)
        for field in policy:
            with self.assertRaises(AssertionError):
                store.validate_policy({**policy, field: 'foreign'})
        self.assertNotIn('renumber', PATH.read_text().split('import argparse', 1)[1])
        self.assertNotIn("['system', 'prune'", PATH.read_text())
        self.assertNotIn("['pod', 'ps', '-aq']", PATH.read_text())
        self.assertNotIn('--policy=missing', PATH.read_text())
        self.assertIn("['pod', 'ps', '-q']", PATH.read_text())
        self.assertIn("observed['host'].get('freeLocks') is None", PATH.read_text())

    def test_optimized_execution_refuses_before_imports_or_effects(self):
        result = subprocess.run([sys.executable, '-O', str(PATH)], text=True, capture_output=True, timeout=10)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Optimized Python refused before imports or effects', result.stderr)

    def test_store_selection_is_explicit_in_restore_probe(self):
        text = PATH.with_name('test-generation-restore.py').read_text()
        self.assertIn("parser.add_argument('--isolated-store'", text)
        self.assertIn('or args.isolated_store) or args.kopia', text)
        self.assertIn('generation-kopia-restore-canonical-core-v2', text)


if __name__ == '__main__':
    unittest.main()
