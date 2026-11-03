import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / 'src/main/resources/runtime/mail-bootstrap.py'


class MailBootstrapTest(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('mail_bootstrap_under_test', SOURCE)
        self.m = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.m)
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'data'; self.root.mkdir()
        self.config = Path(self.temp.name) / 'config'; self.config.mkdir()
        self.seed = [
            {'method': 'x:Domain/set', 'arguments': {'create': {'domain': {'name': 'p0v3.example.org'}}}},
            {'method': 'x:Application/get', 'arguments': {}, 'bindBuiltinApplication': 'builtin'},
            {'method': 'x:Application/set', 'arguments': {'update': {'#builtin': {'enable': False}}}},
            {'method': 'x:Account/set', 'arguments': {'create': {'alice': {'domainId': '#domain', 'secret': '@password:alice'}}}},
        ]
        self.save_seed()
        (self.config / 'users.json').write_text(json.dumps({'alice': 'a' * 64}))
        (self.config / 'generation').write_bytes(b'fixture-generation\n')
        self.child = Mock(); self.child.poll.return_value = None; self.child.wait.return_value = 0
        self.calls = []

    def save_seed(self):
        (self.config / 'mail-seed.json').write_text(json.dumps(self.seed))

    def start(self, *args, **kwargs):
        (self.root / 'store').mkdir(); (self.root / 'store/CURRENT').write_text('MANIFEST-fixture')
        return self.child

    def api(self, method, arguments, credential):
        self.calls.append((method, arguments))
        if method == 'x:Application/get':
            return {'list': [{'id': 'builtin-id', 'resourceUrl': 'https://github.com/stalwartlabs/webui/releases/download/v2/webui.zip'}]}
        return {'created': {k: {'id': k + '-id'} for k in arguments.get('create', {})}, 'updated': {k: None for k in arguments.get('update', {})}}

    def run_init(self, api=None, start=None, clock=None, signal_handler=None):
        with patch.object(self.m.os, 'getpid', return_value=1), patch.object(self.m.os, 'umask'), patch.dict(os.environ, {'STALWART_RECOVERY_ADMIN': 'admin:fixture'}), patch.object(self.m.subprocess, 'run', return_value=Mock(stdout=b'$6$fixture\n')), patch.object(self.m.subprocess, 'Popen', side_effect=start or self.start), patch.object(self.m.signal, 'signal', side_effect=signal_handler), patch.object(self.m, 'api', side_effect=api or self.api), patch.object(self.m.time, 'sleep'), patch.object(self.m.time, 'monotonic', side_effect=clock or [0] * 20):
            self.m.initialize(self.root, self.config)

    def test_success_and_exclusive_no_replay(self):
        self.run_init()
        self.assertEqual((self.root / 'ready').read_bytes(), b'fixture-generation\n')
        self.assertEqual(self.calls[-1][1]['create']['alice'], {'domainId': 'domain-id', 'secret': '$6$fixture'})
        self.assertEqual(self.calls[3][1], {'update': {'builtin-id': {'enable': False}}})
        self.assertEqual(len(list(self.root.glob('step-*.intent'))), 4)
        self.child.terminate.assert_called_once(); self.child.wait.assert_called_once_with(timeout=25)
        with self.assertRaisesRegex(RuntimeError, 'no replay'):
            self.run_init()

    def test_pid_and_intent_guard(self):
        with patch.object(self.m.os, 'getpid', return_value=2), patch.object(self.m.os, 'umask'):
            with self.assertRaisesRegex(RuntimeError, 'dedicated'):
                self.m.initialize(self.root, self.config)
        self.m.durable(self.root / 'bootstrap.intent', b'uncertain')
        with self.assertRaises(FileExistsError):
            self.run_init()
        self.assertEqual((self.root / 'bootstrap.intent').read_bytes(), b'uncertain')

    def test_resolve_lists_and_missing_references(self):
        self.assertEqual(self.m.resolve(['#x', '@password:alice', 42, None], {'x': 'id'}, {'alice': 'hash'}), ['id', 'hash', 42, None])
        with self.assertRaises(KeyError):
            self.m.resolve('#unknown', {}, {})

    def test_invalid_fixture_and_hash(self):
        (self.config / 'users.json').write_text('{"unexpected":"bad"}')
        with self.assertRaisesRegex(RuntimeError, 'credential'):
            self.run_init()
        # Separate fresh directory, never remove an intent to exercise a retry.
        other = Path(self.temp.name) / 'other'; other.mkdir()
        (self.config / 'users.json').write_text(json.dumps({'alice': 'a' * 64}))
        with patch.object(self.m.os, 'getpid', return_value=1), patch.object(self.m.os, 'umask'), patch.object(self.m.subprocess, 'run', return_value=Mock(stdout=b'bad')):
            with self.assertRaisesRegex(RuntimeError, 'hashing'):
                self.m.initialize(other, self.config)

    def test_rejected_write_retains_response_and_no_ready(self):
        def api(method, args, credential):
            if method.endswith('/set'):
                return {'notCreated': {'domain': {'type': 'invalidPatch'}}}
            return self.api(method, args, credential)
        with self.assertRaisesRegex(RuntimeError, 'no replay'):
            self.run_init(api=api)
        self.assertTrue((self.root / 'step-00.response').exists()); self.assertFalse((self.root / 'ready').exists())
        self.child.terminate.assert_called_once()

    def test_missing_write_acknowledgement(self):
        with self.assertRaisesRegex(RuntimeError, 'incomplete'):
            self.run_init(api=lambda *args: {})
        self.assertFalse((self.root / 'ready').exists())

    def test_foreign_builtin_is_never_disabled(self):
        def api(method, args, credential):
            return {'list': [{'id': 'foreign', 'resourceUrl': 'https://example.net/'}]} if method == 'x:Application/get' else self.api(method, args, credential)
        with self.assertRaisesRegex(RuntimeError, 'no mutation authorized'):
            self.run_init(api=api)
        self.assertFalse((self.root / 'step-02.intent').exists())

    def test_listener_deadline(self):
        with self.assertRaisesRegex(RuntimeError, 'deadline'):
            self.run_init(api=OSError('not ready'), clock=[0, 61])
        self.assertFalse((self.root / 'ready').exists())

    def test_listener_retry_only_reads(self):
        failed = [False]
        def api(method, args, credential):
            if not failed[0]:
                failed[0] = True; raise OSError('not ready')
            return self.api(method, args, credential)
        self.run_init(api=api)
        self.assertEqual(sum(m == 'x:Domain/set' for m, _ in self.calls), 1)

    def test_premature_exit(self):
        self.child.poll.side_effect = [1, None]
        with self.assertRaisesRegex(RuntimeError, 'listener exited'):
            self.run_init()

    def test_missing_store_blocks_ready(self):
        with self.assertRaisesRegex(RuntimeError, 'store missing'):
            self.run_init(start=lambda *args, **kwargs: self.child)
        self.assertFalse((self.root / 'ready').exists())

    def test_interruption_stops_child(self):
        handlers = {}
        def api(*args):
            handlers[self.m.signal.SIGTERM](self.m.signal.SIGTERM, None)
        with self.assertRaises(InterruptedError):
            self.run_init(api=api, signal_handler=lambda sig, handler: handlers.update({sig: handler}))
        self.child.terminate.assert_called_once(); self.assertFalse((self.root / 'ready').exists())

    def test_shutdown_rejections(self):
        self.child.poll.return_value = 1
        with self.assertRaisesRegex(RuntimeError, 'unexpectedly'):
            self.m.stop(self.child)
        self.child.poll.return_value = None; self.child.wait.return_value = 1
        with self.assertRaisesRegex(RuntimeError, 'shutdown failed'):
            self.m.stop(self.child)
        self.child.wait.side_effect = [subprocess.TimeoutExpired('fixture', 25), 0]
        with self.assertRaisesRegex(RuntimeError, 'forced'):
            self.m.stop(self.child)
        self.child.kill.assert_called_once()

    def test_api_bounds_and_correlations(self):
        for status, body, valid in [(200, {'methodResponses': [['x:Account/get', {'list': []}, 'p0']]}, True), (401, {}, False), (200, {'methodResponses': []}, False), (200, {'methodResponses': [['error', {}, 'p0']]}, False), (200, {'methodResponses': [['x:Account/get', {}, 'wrong']]}, False), (200, b'x' * 1048577, False)]:
            with self.subTest(status=status, valid=valid):
                connection = Mock(); response = connection.getresponse.return_value; response.status = status; response.read.return_value = body if isinstance(body, bytes) else json.dumps(body).encode()
                with patch.object(self.m.http.client, 'HTTPConnection', return_value=connection):
                    if valid:
                        self.assertEqual(self.m.api('x:Account/get', {}, 'fixture'), {'list': []})
                    else:
                        with self.assertRaises(RuntimeError):
                            self.m.api('x:Account/get', {}, 'fixture')
                connection.close.assert_called_once()

    def test_optimized_python_refused(self):
        for source in (SOURCE, SOURCE.parents[4] / 'scripts/test-private-mail.py'):
            result = subprocess.run([sys.executable, '-O', str(source)], capture_output=True)
            self.assertNotEqual(result.returncode, 0); self.assertIn(b'Optimized Python refused', result.stderr)


if __name__ == '__main__':
    unittest.main()
