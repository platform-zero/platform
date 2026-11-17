import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from canonical_provider_readback import verify_provider


class CanonicalProviderReadbackTest(unittest.TestCase):
    name = 'q-abcdef123456-canonical-core'

    def observed(self):
        def member(networks):
            return {'NetworkSettings': {'Networks': {'p0v3-live-' + self.name + '-' + n: {'IPAddress': '10.89.0.2'} for n in networks}}}
        return [member(['planka-web', 'planka-data']), member(['net', 'db-admin', 'planka-data']), member(['net'])]

    def test_checks_are_native_and_do_not_provision(self):
        results = [subprocess.CompletedProcess([], 0, json.dumps(self.observed()), ''),
                   subprocess.CompletedProcess([], 0, '{"unitFixture": true}', '')]
        with patch('canonical_provider_readback.subprocess.run', side_effect=results) as run:
            self.assertEqual({'unitFixture': True}, verify_provider(self.name, ['dedicated-podman'], {}))
            script = run.call_args.kwargs['input']
            for required in ('pg_stat_ssl', 'rolcanlogin', 'rejectUnauthorized: true', "['42501']", "['28000']", 'net.connect'):
                self.assertIn(required, script)
            self.assertNotIn('PASSWORD', script)
            self.assertEqual(['exec', '-i', 'p0v3-live-' + self.name + '-planka', 'node'], run.call_args.args[0][1:])

    def test_foreign_names_rejected_before_command(self):
        with patch('canonical_provider_readback.subprocess.run') as run:
            for name in ('foundation-r3', '../foreign', 'q-abcdef123456-planka'):
                with self.assertRaises(AssertionError): verify_provider(name, [], {})
            run.assert_not_called()

    def test_unexpected_network_stops_before_client(self):
        observed = self.observed()
        observed[0]['NetworkSettings']['Networks']['foreign'] = {'IPAddress': '10.89.0.3'}
        with patch('canonical_provider_readback.subprocess.run', return_value=subprocess.CompletedProcess([], 0, json.dumps(observed), '')) as run:
            with self.assertRaises(AssertionError): verify_provider(self.name, [], {})
            self.assertEqual(1, run.call_count)

    def test_failed_inspect_or_native_client_cannot_pass(self):
        for results in ([subprocess.CompletedProcess([], 1, '', '')], [subprocess.CompletedProcess([], 0, json.dumps(self.observed()), ''), subprocess.CompletedProcess([], 1, '', '')]):
            with patch('canonical_provider_readback.subprocess.run', side_effect=results):
                with self.assertRaises(AssertionError): verify_provider(self.name, [], {})

    def test_optimized_execution_refused(self):
        module = Path(__file__).with_name('canonical_provider_readback.py')
        result = subprocess.run([sys.executable, '-O', str(module)], capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Optimized Python refused before imports or effects', result.stderr)


class CanonicalProviderAdapterSourceTest(unittest.TestCase):
    """No live provider calls: test the invocation/oracle and authorization branches by injection."""

    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[2] / 'acceptance/runners/provider_native.py'
        loader = importlib.util.spec_from_file_location('provider_native_source_unit', path)
        cls.adapter = importlib.util.module_from_spec(loader)
        loader.loader.exec_module(cls.adapter)
        sys.modules['provider_native'] = cls.adapter
        cls.surface_adapters = {}
        for surface in ('browser', 'android'):
            source = path.with_name('ntfy-' + surface + '.py')
            extension = importlib.util.spec_from_file_location('ntfy_' + surface + '_source_unit', source)
            module = importlib.util.module_from_spec(extension)
            extension.loader.exec_module(module)
            cls.surface_adapters[surface] = module

    def test_exact_native_assertions_and_source_oracle_denials(self):
        adapter = self.adapter
        expected = {
            'postgres': {'cross-database-denial', 'transaction-commit', 'transaction-rollback', 'authorization-denial'},
            'mariadb': {'cross-schema-denial', 'transaction-commit', 'transaction-rollback', 'authorization-denial'},
            'valkey': {'acl-denial', 'queue-lifecycle', 'durable-data', 'authorization-denial'},
            'memcached': {'ephemeral-restart-contract', 'native-cache', 'authorization-denial'},
            'ntfy': {'authenticated-delivery', 'historical-message', 'expiry-semantics', 'authorization-denial'},
        }
        self.assertEqual(expected, adapter.ASSERTIONS)
        for target in expected:
            with self.assertRaises(ValueError):
                adapter.journey(target, 'install-original', 'RESTORE', None, None)
            with self.assertRaises(ValueError):
                adapter.journey(target, 'install-original', 'INSTALL', {'provider': target}, None)
        with self.assertRaises(ValueError):
            adapter.journey('unapproved', 'install-original', 'INSTALL', None, None)
        self.assertTrue(adapter.RESTORE_ASSERTIONS.issuperset({'source-oracle-readback', 'restore-isolation',
                                                                'bootstrap-not-replayed'}))

    def test_native_invocation_rejects_wrong_phase_assertions_and_surface_before_backend(self):
        a = self.adapter
        invocation = {'serviceId': 'postgres', 'surface': 'HEADLESS', 'variant': 'NATIVE',
                      'invocationId': 'original-1', 'binding': {'phase': 'INSTALL'},
                      'requiredAssertions': sorted(a.ASSERTIONS['postgres'])}
        request = {'schemaVersion': 1, 'invocation': invocation, 'context': {},
                   'artifactDirectory': '/unreachable', 'sourceOracle': None}
        with self.assertRaisesRegex(AssertionError, 'backend must not run'):
            a.execute(request, 'postgres', backend_factory=lambda *_: self.fail('backend must not run'))
        for wrong in (dict(invocation, surface='ANDROID'), dict(invocation, variant='API34'),
                      dict(invocation, requiredAssertions=['transaction-commit']),
                      dict(invocation, binding={'phase': 'UPDATE'})):
            with self.assertRaises(ValueError):
                a.execute(dict(request, invocation=wrong), 'postgres',
                          backend_factory=lambda *_: self.fail('backend must not run'))

    def test_postgres_restore_reads_original_oracle_and_never_recreates_fixture(self):
        adapter = self.adapter
        original = 'original-invocation'
        source = {'provider': 'postgres', 'fixture': 'q_' + adapter.digest(original.encode())[:24],
                  'value': adapter.digest(('synthetic:' + original).encode())}
        seen = []
        class ReadOnlyBackend:
            context = {'deniedDatabase': 'postgres', 'database': 'qualification'}
            def sql(self, statement, database=None, allow_failure=False):
                seen.append((statement, database))
                if statement.startswith('SELECT value'):
                    return subprocess.CompletedProcess([], 0, source['value'] + '\n1\n', '')
                if database == 'postgres' or statement.startswith('CREATE ROLE'):
                    return subprocess.CompletedProcess([], 1, '', 'ERROR: 42501')
                raise AssertionError('restore attempted an unexpected SQL effect')
        self.assertEqual(source, adapter.journey('postgres', 'different-restored-invocation',
                                                 'RESTORE', source, ReadOnlyBackend()))
        self.assertEqual(3, len(seen))
        self.assertFalse(any('CREATE TABLE' in text or 'INSERT INTO' in text for text, _ in seen))
        with self.assertRaises(ValueError):
            adapter.journey('postgres', 'different-restored-invocation', 'RESTORE',
                            dict(source, fixture='q_unknown'), ReadOnlyBackend())

    def test_lost_ack_never_retries_a_provider_write(self):
        count = []
        class LostAcknowledgement:
            context = {'deniedDatabase': 'postgres', 'database': 'qualification'}
            def sql(self, statement, *args, **kwargs):
                count.append(statement)
                raise TimeoutError('commit uncertain')
        with self.assertRaises(TimeoutError):
            self.adapter.journey('postgres', 'original-1', 'INSTALL', None, LostAcknowledgement())
        self.assertEqual(1, len(count))
        self.assertIn('CREATE TABLE', count[0])

    def test_ntfy_web_and_official_android_reject_improper_phases_and_assertions_before_effects(self):
        root = {'schemaVersion': 1, 'context': {}, 'url': 'https://notify.datamancy.net/',
                'artifactDirectory': '/unreachable', 'sourceOracle': None}
        for surface, variant, adapter in (
            ('WEB', 'BROWSER', self.surface_adapters['browser']),
            ('ANDROID', 'API34', self.surface_adapters['android']),
            ('ANDROID', 'API36', self.surface_adapters['android'])):
            correct = {'serviceId': 'ntfy', 'surface': surface, 'variant': variant,
                       'binding': {'phase': 'INSTALL'}, 'requiredAssertions': sorted(adapter.ASSERTIONS)}
            wrong = [dict(correct, surface='HEADLESS'), dict(correct, serviceId='foreign'),
                     dict(correct, requiredAssertions=['browser-workflow']),
                     dict(correct, binding={'phase': 'UPDATE'})]
            for invocation in wrong:
                with self.subTest(surface=surface, variant=variant, invocation=invocation):
                    with self.assertRaises(ValueError):
                        adapter.execute(dict(root, invocation=invocation),
                                        backend_factory=lambda *_: self.fail('backend called on invalid request'))

    def test_browser_install_and_restore_use_original_ntfy_message_identity(self):
        import tempfile
        import time
        browser = self.surface_adapters['browser']
        messages = {}
        class Backend:
            def __init__(self, context, invocation):
                self.context = context
            def observe(self):
                return None
            def notification(self, topic, payload=None, anonymous=False, subscriber=False):
                if anonymous or subscriber:
                    return 403, ''
                if payload is not None:
                    message = {'topic': topic, 'message': payload, 'id': 'originalmessage',
                               'expires': int(time.time()) + 86400}
                    messages[topic] = message
                    return 200, json.dumps(message)
                return 200, json.dumps(messages[topic]) + '\n'
        class Location:
            def __init__(self, page):
                self.page = page
                self.first = self.last = self
            def click(self, **kwargs):
                return None
            def fill(self, text):
                self.page.topic = text
            def wait_for(self, **kwargs):
                self.page.value = messages[self.page.topic]['message']
            def inner_text(self):
                return (self.page.topic + ' ' + getattr(self.page, 'value', '')) if self.page.authorized else ''
        class Page:
            url = 'https://notify.datamancy.net/'
            def __init__(self, authorized):
                self.authorized = authorized
                self.topic = ''
            def goto(self, *args, **kwargs):
                return None
            def get_by_role(self, *args, **kwargs):
                return Location(self)
            def get_by_text(self, *args, **kwargs):
                return Location(self)
            def locator(self, *args, **kwargs):
                return Location(self)
            def screenshot(self, **kwargs):
                return b'\x89PNG\r\n\x1a\n' + b'original UI fixture'
            def route(self, *args, **kwargs):
                return None
        class Browser:
            def new_context(self, http_credentials=None, **kwargs):
                authorized = http_credentials is not None
                class Context:
                    def new_page(self):
                        return Page(authorized)
                return Context()
            def close(self):
                return None
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            binary = root / 'chromium'
            binary.write_bytes(b'owned browser binary')
            subscriber = root / 'subscriber'
            subscriber.write_text('a' * 64)
            subscriber.chmod(0o600)
            context = {'origin': 'https://notify.datamancy.net/', 'browserExecutable': str(binary),
                       'browserSha256': browser.digest(binary.read_bytes()),
                       'subscriberUsername': 'subscriber', 'subscriberCredentialFile': str(subscriber)}
            intent = {'serviceId': 'ntfy', 'surface': 'WEB', 'variant': 'BROWSER',
                      'invocationId': 'original-browser', 'binding': {'phase': 'INSTALL'},
                      'requiredAssertions': sorted(browser.ASSERTIONS)}
            request = {'schemaVersion': 1, 'invocation': intent, 'context': context, 'url': context['origin'],
                       'artifactDirectory': str(root), 'sourceOracle': None}
            installed = browser.execute(request, backend_factory=Backend, browser_factory=Browser)
            original = installed['oracle']
            self.assertEqual('originalmessage', original['messageId'])
            self.assertEqual(original['expires'], messages[original['fixture']]['expires'])
            (root / 'ntfy-browser.png').unlink()
            (root / 'ntfy-browser-proof.json').unlink()
            restored_intent = dict(intent, invocationId='restored-browser', binding={'phase': 'RESTORE'},
                                   requiredAssertions=sorted(browser.ASSERTIONS | browser.RESTORE_ASSERTIONS))
            context['caFile'] = '/private/approved-ca'
            context['bridge'] = {'originalHost': 'notify.datamancy.net', 'address': '10.203.4.10',
                                 'port': 443, 'caFile': context['caFile']}
            request = dict(request, invocation=restored_intent, sourceOracle=original)
            self.assertEqual(original, browser.execute(request, backend_factory=Backend,
                                                       browser_factory=Browser)['oracle'])
            with self.assertRaises(ValueError):
                browser.execute(dict(request, sourceOracle=dict(original, messageId='forged')),
                                backend_factory=Backend, browser_factory=Browser)

    def test_android_official_client_secret_uses_stdin_only_not_shell_argv(self):
        android = self.surface_adapters['android']
        context = {'subscriberCredentialFile': '/private/subscriber',
                   'android': {'adb': '/owned/adb', 'serial': 'emulator-5554'}}
        password = 'abcdef0123456789' * 4
        completed = subprocess.CompletedProcess([], 0, '', '')
        with patch.object(android, 'private', return_value=password.encode()), \
                patch.object(android.subprocess, 'run', return_value=completed) as run:
            android.type_subscriber_secret(context)
        self.assertEqual(password + '\n', run.call_args.kwargs['input'])
        self.assertNotIn(password, ' '.join(run.call_args.args[0]))
        self.assertEqual(['shell', 'sh', '-c'], run.call_args.args[0][3:6])

    def test_restored_notification_requires_scoped_original_sni_bridge_before_network(self):
        adapter = self.adapter
        backend = object.__new__(adapter.ProviderBackend)
        backend.context = {'origin': 'https://notify.datamancy.net/', 'caFile': '/private/ca.pem'}
        backend.invocation = {'binding': {'phase': 'RESTORE'}}
        backend.target = 'ntfy'
        with patch.object(adapter, 'private', return_value=b'fake-ca'), \
                patch.object(adapter.ssl, 'create_default_context', return_value=object()), \
                patch.object(adapter.urllib.request, 'build_opener') as opener:
            with self.assertRaises(ValueError):
                backend.notification('events-test', anonymous=True)
            backend.context['bridge'] = {'originalHost': 'notify.datamancy.net', 'address': '127.0.0.1',
                                         'port': 443, 'caFile': '/private/ca.pem', 'clientNetwork': 'ntfy-web',
                                         'sourceStoppedProofSha256': '1' * 64,
                                         'targetIsolationProofSha256': '2' * 64}
            with self.assertRaises(ValueError):
                backend.notification('events-test', anonymous=True)
            opener.assert_not_called()

    def test_optimized_provider_and_client_entrypoints_refuse_before_effects(self):
        runners = Path(__file__).resolve().parents[2] / 'acceptance/runners'
        for name in ('provider_native.py', 'postgres-native.py', 'mariadb-native.py',
                     'valkey-native.py', 'memcached-native.py', 'ntfy-native.py',
                     'ntfy-browser.py', 'ntfy-android.py'):
            with self.subTest(name=name):
                result = subprocess.run([sys.executable, '-O', str(runners / name)],
                                        capture_output=True, text=True, timeout=10)
                self.assertNotEqual(0, result.returncode)
                self.assertIn('Optimized Python refused before imports or effects', result.stderr)

    def test_private_inputs_reject_symlink_mode_or_truncated_data(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_bytes(b'original-state')
            path.chmod(0o600)
            self.assertEqual(b'original-state', self.adapter.private(path))
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                self.adapter.private(path)
            path.chmod(0o600)
            alias = Path(directory) / 'alias'
            alias.symlink_to(path)
            with self.assertRaises(ValueError):
                self.adapter.private(alias)


if __name__ == '__main__':
    unittest.main()
