import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class NodeMetricsSafetyTest(unittest.TestCase):
    def test_optimized_entrypoint_refuses_before_imports(self):
        script = Path(__file__).with_name('test-private-node-metrics.py').resolve()
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'imported'
            (Path(directory) / 'argparse.py').write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\nraise RuntimeError("must not import")\n')
            result = subprocess.run([sys.executable, '-O', str(script), '--help'], capture_output=True, text=True, env={**os.environ, 'PYTHONPATH': directory})
            self.assertNotEqual(0, result.returncode)
            self.assertIn('Optimized Python', result.stderr)
            self.assertFalse(marker.exists())

    def test_observability_effectful_entrypoint_refuses_optimized_import(self):
        script = Path(__file__).with_name('test-persistent-observability.py').resolve()
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'imported'
            (Path(directory) / 'argparse.py').write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\nraise RuntimeError("must not import")\n')
            result = subprocess.run([sys.executable, '-O', str(script), '--help'], capture_output=True, text=True,
                                    env={**os.environ, 'PYTHONPATH': directory})
            self.assertNotEqual(0, result.returncode)
            self.assertIn('Optimized Python', result.stderr)
            self.assertFalse(marker.exists())

    def test_grafana_browser_denies_foreign_origin_and_private_input_symlink_before_launch(self):
        path = Path(__file__).resolve().parents[2] / 'acceptance/runners/grafana-browser.py'
        spec = importlib.util.spec_from_file_location('a11_grafana_browser_unit', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / 'private.json'
            original.write_text('{}')
            original.chmod(0o600)
            link = root / 'foreign.json'
            link.symlink_to(original)
            with self.assertRaises(ValueError):
                module.private(link)
            with self.assertRaises((KeyError, ValueError)):
                module.execute({'schemaVersion': 1, 'invocation': {'serviceId': 'grafana', 'surface': 'WEB',
                    'variant': 'BROWSER', 'binding': {'phase': 'INSTALL'}},
                    'context': {'origin': 'https://foreign.example/'}, 'url': 'https://foreign.example/'},
                    browser_factory=lambda: self.fail('foreign web case must never launch Chromium'))

    def test_alertmanager_restored_original_is_read_only_and_rejects_foreign_auth(self):
        path = Path(__file__).resolve().parents[2] / 'acceptance/runners/alertmanager-native.py'
        spec = importlib.util.spec_from_file_location('a11_alertmanager_native_unit', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        import hashlib
        config = 'route:\n  receiver: private-no-outbound\nreceivers:\n- name: private-no-outbound\n'
        labels = {'alertname': 'P0SyntheticAcceptance', 'scope': 'synthetic-only', 'case': 'a' * 16}
        source = {'kind': 'alertmanager-original-synthetic', 'sourceGenerationId': 'q-' + 'a' * 12,
                  'labels': labels, 'fingerprint': 'a' * 16, 'configSha256': hashlib.sha256(config.encode()).hexdigest(),
                  'startedAt': '2026-11-09T00:00:00+00:00', 'resolvedAt': '2026-11-09T00:01:00Z',
                  'receiver': 'private-no-outbound'}
        class Client:
            def __init__(self): self.calls = []
            def request(self, service, operation, method, path, body=None, unauthorized=False):
                self.calls.append((service, operation, method, unauthorized))
                if unauthorized: return 403, {}
                if operation == 'private-config': return 200, {'config': {'original': config}}
                return 200, [{'labels': labels, 'fingerprint': 'a' * 16, 'endsAt': source['resolvedAt']}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); root.chmod(0o700)
            request = {'schemaVersion': 1, 'artifactDirectory': str(root), 'context': {
                'targetIsolationProofSha256': 'b' * 64, 'bootstrapReplayed': False},
                'invocation': {'serviceId': 'alertmanager', 'surface': 'HEADLESS', 'variant': 'NATIVE',
                    'invocationId': 'alertmanager-original-readback', 'binding': {'phase': 'RESTORE',
                    'generationId': 'q-' + 'b' * 12}, 'requiredAssertions': [
                    'alert-delivery', 'alert-resolution', 'authorization-denial', 'source-oracle-readback',
                    'restore-isolation', 'bootstrap-not-replayed']}, 'sourceOracle': source}
            client = Client()
            result = module.workflow(request, client)
            self.assertEqual(source, result['oracle'])
            self.assertTrue(all(method == 'GET' for _, _, method, _ in client.calls))
            self.assertEqual(client.calls[-1][-1], True)
            request['context']['bootstrapReplayed'] = True
            with self.assertRaises(ValueError): module.workflow(request, Client())

    def test_offline_image_recipe_pins_base_helper_and_reaps_without_restart(self):
        recipe = (Path(__file__).resolve().parents[1] / 'images/node-exporter/Containerfile').read_text()
        self.assertIn('FROM quay.io/prometheus/node-exporter@sha256:da83fae85603c4e47e6c68369a7d746e2dda683dc35ea2e234b4f171e0d92798', recipe)
        self.assertIn('84e9bde9a352e11949c9a09abe64b81e83d5dc345a9d99c62eefdfdfc359bb96', recipe)
        self.assertIn('USER 65534:65534', recipe)
        self.assertIn('ENTRYPOINT ["/sbin/catatonit", "--", "/bin/node_exporter"]', recipe)
        self.assertNotIn('restart', recipe)
        self.assertNotIn('apt-get', recipe)


if __name__ == '__main__': unittest.main()
