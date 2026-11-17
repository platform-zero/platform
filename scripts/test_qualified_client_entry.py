"""Source-only bounded client-policy tests. Never execute in implementation run."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('qualified_client_entry',
    Path(__file__).resolve().parents[1] / 'src/main/resources/runtime/qualified-client-entry.py')
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)


class QualifiedClientEntrypointSourceTests(unittest.TestCase):
    def test_private_native_never_starts_a_second_runner_and_denial_is_probe_only(self):
        for service in ('opensearch', 'crowdsec', 'alloy', 'loki', 'onlyoffice', 'node-exporter'):
            self.assertFalse(client.allowed_qualified_client(
                {'serviceId': service, 'surface': 'HEADLESS', 'variant': 'NATIVE'}, 'NORMAL'))
        self.assertTrue(client.allowed_qualified_client(
            {'serviceId': 'alloy', 'surface': 'HEADLESS', 'variant': 'NATIVE'}, 'NATIVE_NETWORK_DENIAL'))
        self.assertFalse(client.allowed_qualified_client(
            {'serviceId': 'opensearch', 'surface': 'HEADLESS', 'variant': 'NATIVE'}, 'NATIVE_NETWORK_DENIAL'))
        for service in ('mastodon', 'sogo', 'seafile', 'homeassistant', 'jellyfin',
                        'qbittorrent', 'searxng', 'grafana', 'prometheus', 'alertmanager'):
            with self.subTest(public_native=service):
                self.assertTrue(client.allowed_qualified_client(
                    {'serviceId': service, 'surface': 'HEADLESS', 'variant': 'NATIVE'}, 'NORMAL'))
                self.assertFalse(client.allowed_qualified_client(
                    {'serviceId': service, 'surface': 'HEADLESS', 'variant': 'NATIVE'}, 'NATIVE_NETWORK_DENIAL'))
        self.assertFalse(client.allowed_qualified_client(
            {'serviceId': 'loki', 'surface': 'HEADLESS', 'variant': 'NATIVE'}, 'NORMAL'))
        self.assertTrue(client.allowed_qualified_client(
            {'serviceId': 'loki', 'surface': 'HEADLESS', 'variant': 'NATIVE'}, 'NATIVE_NETWORK_DENIAL'))
        self.assertTrue(client.allowed_qualified_client(
            {'serviceId': 'element', 'surface': 'ANDROID', 'variant': 'API34'}, 'NORMAL'))

    def test_seafile_tool_requires_reviewed_root_owned_immutable_bounded_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / 'seaf-cli'
            source.write_bytes(b'original owned Seafile tool bytes')
            digest = client.digest(source.read_bytes())
            # A writable acceptance file is NOT an immutable original image tool.
            source.chmod(0o666)
            with self.assertRaises(ValueError):
                client._producer_file(source, digest, 1024)
            with self.assertRaises(ValueError):
                client._producer_file(source, digest, source.stat().st_size - 1)
            with self.assertRaises(ValueError):
                client._producer_file(source, '0' * 64, 1024)
            shadow = Path(temporary) / 'symlink'
            shadow.symlink_to(source)
            with self.assertRaises(ValueError):
                client._producer_file(shadow, digest, 1024)

    def test_seafile_browser_and_android_do_not_require_seaf_cli_tool_closure(self):
        for surface, variant in (('WEB', 'BROWSER'), ('ANDROID', 'API34'), ('ANDROID', 'API36')):
            with self.subTest(surface=surface, variant=variant):
                client.seafile_official_tools({'serviceId': 'seafile', 'surface': surface,
                    'variant': variant}, {}, {}, '10.42.0.2')

    def test_seafile_unreviewed_gate_cannot_mint_fake_native_receipt(self):
        invocation = {'serviceId': 'seafile', 'surface': 'HEADLESS', 'variant': 'NATIVE',
                      'binding': {'generationId': 'q-0123456789ab'}}
        gate = {'generationId': 'q-0123456789ab', 'originalHost': 'foreign.datamancy.net',
                'caseIntentSha256': 'f' * 64}
        with self.assertRaises((ValueError, KeyError, FileNotFoundError)):
            client.seafile_official_tools(invocation, gate, {
                'P0V3_CLIENT_CERTIFICATE_SHA256': 'a' * 64,
                'P0V3_CLIENT_LEAF_SHA256': 'b' * 64}, '10.42.0.2')


if __name__ == '__main__':
    unittest.main()
