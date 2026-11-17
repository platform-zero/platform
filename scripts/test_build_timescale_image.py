"""No native Podman calls: pin safety and uncertainty behavior of the artifact builder."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('build-timescale-image.py')
spec = importlib.util.spec_from_file_location('timescale_build', SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class TimescaleBuilderTest(unittest.TestCase):
    def test_pending_original_refuses_without_subprocess(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = module.ROOT
            module.ROOT = root
            try:
                key = 'build'
                argv = ['build', '--network=none', '--pull=never', 'unchanged-context']
                intent = {'job': module.JOB, 'argv': module.PODMAN + argv,
                          'moduleSha256': module.sha(module.MODULE.read_bytes())}
                module.save(root / (key + '.intent.json'), module.encode(intent))
                with patch.object(module, 'headroom'), patch.object(module.subprocess, 'run') as native:
                    with self.assertRaisesRegex(RuntimeError, 'uncertain or changed; no replay'):
                        module.effect(key, argv)
                    native.assert_not_called()
                    with self.assertRaisesRegex(RuntimeError, 'uncertain or changed; no replay'):
                        module.effect(key, argv + ['another-id'])
                    native.assert_not_called()
                self.assertFalse((root / (key + '.result.json')).exists())
            finally:
                module.ROOT = old

    def test_native_smoke_never_grants_database_create_to_runtime(self):
        script = (SCRIPT.parent.parent / 'images/postgres-timescale/smoke.sh').read_text()
        self.assertIn('REVOKE CREATE ON DATABASE ordinary FROM p0_artifact_runtime;', script)
        self.assertNotIn('GRANT CREATE ON DATABASE ordinary TO p0_artifact_runtime;', script)
        self.assertIn('timescaledb.restoring=on', script)
        self.assertIn("SELECT value FROM hourly", script)

    def test_changed_build_inputs_cannot_be_assumed_admitted(self):
        text = SCRIPT.read_text()
        self.assertIn("'runtimeAdmitted': False", text)
        self.assertIn("'kopiaRecoveryProven': False", text)
        self.assertIn("'status': 'built-candidate-not-admitted-not-qualified'", text)
        self.assertIn("'--network=none'", text)
        self.assertIn("'--pull=never'", text)
        self.assertIn('--no-download', (SCRIPT.parent.parent / 'images/postgres-timescale/Containerfile').read_text())
        self.assertTrue((SCRIPT.parent.parent / 'images/postgres-timescale/smoke.sh').exists())


if __name__ == '__main__':
    unittest.main()
