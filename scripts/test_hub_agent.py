#!/usr/bin/env python3
"""Unit-only notebook lifecycle checks; no container, HTTP listener or real child processes."""
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

spec = importlib.util.spec_from_file_location('hub_agent', Path(__file__).parents[1] / 'src/main/resources/runtime/hub-agent.py')
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class HubAgentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.journal = Path(self.temporary.name) / 'journal'
        self.child = Mock()
        self.child.poll.return_value = None
        self.child.wait.return_value = 0
        self.spawn = Mock(return_value=self.child)
        self.retire = Mock(return_value=True)
        self.notebook = agent.Notebook(self.journal, ['fixed-program', 'fixed-config'], self.spawn, self.retire)

    def test_start_is_exclusive_and_clean_shutdown_is_durable(self):
        self.assertEqual(self.notebook.status(), 'stopped')
        self.assertEqual(self.notebook.start(), 201)
        self.assertEqual(self.notebook.status(), 'running')
        self.assertEqual(self.notebook.start(), 409)
        self.spawn.assert_called_once_with(('fixed-program', 'fixed-config'), stdin=subprocess.DEVNULL, start_new_session=True)
        self.assertEqual(self.notebook.stop(), 204)
        self.assertEqual(self.notebook.stop(), 204)
        self.retire.assert_called_once_with()
        self.assertEqual(self.journal.read_text(), 'stopped\n')
        self.assertEqual(self.journal.stat().st_mode & 0o777, 0o600)
        self.assertEqual(agent.Notebook(self.journal, []).status(), 'stopped')

    def test_partial_or_unclean_journal_cannot_be_replayed(self):
        self.journal.write_text('running\n')
        other = agent.Notebook(self.journal, [], self.spawn)
        self.assertEqual(other.status(), 'blocked')
        self.assertEqual(other.start(), 409)
        self.assertEqual(other.stop(), 409)
        self.journal.write_text('stopped\n')
        self.journal.with_suffix('.pending').write_text('starting\n')
        self.assertEqual(self.notebook.start(), 409)
        self.spawn.assert_not_called()

    def test_spawn_uncertainty_and_failed_children_are_not_success(self):
        self.spawn.side_effect = OSError('unit-only')
        with self.assertRaises(OSError):
            self.notebook.start()
        self.assertEqual(self.notebook.start(), 409)
        self.assertEqual(self.notebook.status(), 'blocked')
        self.spawn.assert_called_once()

    def test_unexpected_exit_force_kill_and_surviving_descendants_fail_closed(self):
        self.notebook.start()
        self.child.poll.return_value = 7
        self.assertEqual(self.notebook.status(), 'failed')
        self.assertEqual(self.notebook.stop(), 409)
        self.child.poll.return_value = None
        self.child.wait.side_effect = [subprocess.TimeoutExpired('fixed-program', 30), 0]
        self.assertEqual(self.notebook.stop(), 500)
        self.child.kill.assert_called_once_with()
        self.assertEqual(self.notebook.status(), 'blocked')

    def test_bad_exit_and_descendant_failure_never_mark_stopped(self):
        for code, retired in [(2, True), (0, False)]:
            with self.subTest(code=code, retired=retired):
                self.journal.unlink(missing_ok=True)
                item = agent.Notebook(self.journal, [], self.spawn, self.retire)
                self.child.wait.return_value = code
                self.retire.return_value = retired
                item.start()
                self.assertEqual(item.stop(), 500)
                self.assertEqual(item.status(), 'blocked')

    def request(self, method, path, authorization=None, length='0', transfer=None):
        cls = agent.handler(self.notebook, '1' * 64)
        request = cls.__new__(cls)
        request.path = path
        request.headers = {}
        if authorization is not None:
            request.headers['Authorization'] = authorization
        if length is not None:
            request.headers['Content-Length'] = length
        if transfer is not None:
            request.headers['Transfer-Encoding'] = transfer
        request.respond = Mock()
        getattr(request, 'do_' + method)()
        return request.respond.call_args.args

    def test_http_actions_have_no_body_or_argv_and_authenticate_before_effects(self):
        self.assertEqual(self.request('POST', '/start')[0], 403)
        self.assertEqual(self.request('POST', '/start', 'Bearer ' + '2' * 64)[0], 403)
        for length, transfer in [('1', None), (None, None), ('0', 'chunked')]:
            self.assertEqual(self.request('POST', '/start', 'Bearer ' + '1' * 64, length, transfer)[0], 400)
        self.spawn.assert_not_called()
        self.assertEqual(self.request('POST', '/unknown', 'Bearer ' + '1' * 64)[0], 404)
        self.assertEqual(self.request('POST', '/start', 'Bearer ' + '1' * 64)[0], 201)
        self.assertEqual(self.request('POST', '/stop', 'Bearer ' + '1' * 64)[0], 204)
        self.spawn.side_effect = OSError('private error must not reach response')
        self.assertEqual(self.request('POST', '/start', 'Bearer ' + '1' * 64), (500,))
        self.assertEqual(self.notebook.status(), 'blocked')

    def test_state_is_authenticated_and_health_does_not_hide_failure(self):
        self.assertEqual(self.request('GET', '/health')[0], 200)
        self.assertEqual(self.request('GET', '/state')[0], 403)
        self.assertEqual(self.request('GET', '/state', 'Bearer ' + '1' * 64)[1], b'{"state": "stopped"}')
        self.notebook.blocked = True
        self.assertEqual(self.request('GET', '/health')[0], 503)

    def test_response_framing_does_not_log_private_headers(self):
        cls = agent.handler(self.notebook, '1'*64); request = cls.__new__(cls)
        request.send_response = Mock(); request.send_header = Mock(); request.end_headers = Mock(); request.wfile = io.BytesIO()
        request.respond(200, b'{}'); request.send_response.assert_called_once_with(200)
        request.send_header.assert_any_call('Content-Length', '2'); self.assertEqual(request.wfile.getvalue(), b'{}')
        request.log_message('private-header')

    def test_pid_namespace_descendant_retirement_reaps_and_bounds_escalation(self):
        pid = Mock(); pid.name = '22'
        proc = Mock(); proc.iterdir.side_effect = [[pid], [pid], [], []]
        with patch.object(agent.os, 'getpid', return_value=1), patch.object(agent.os, 'waitpid', side_effect=[(22, 0), (0, 0), ChildProcessError(), ChildProcessError(), ChildProcessError()]), patch.object(agent, 'Path', return_value=proc), patch.object(agent.os, 'kill') as kill, patch.object(agent.time, 'monotonic', side_effect=[0, 1]), patch.object(agent.time, 'sleep') as sleep:
            self.assertTrue(agent.retire_descendants()); kill.assert_called_once_with(22, agent.signal.SIGTERM); sleep.assert_called_once_with(0.05)
        proc.iterdir.side_effect = None; proc.iterdir.return_value = [pid]
        with patch.object(agent.os, 'getpid', return_value=1), patch.object(agent.os, 'waitpid', return_value=(0, 0)), patch.object(agent, 'Path', return_value=proc), patch.object(agent.os, 'kill', side_effect=ProcessLookupError()) as kill, patch.object(agent.time, 'monotonic', side_effect=[0, 6]):
            self.assertFalse(agent.retire_descendants()); self.assertEqual([call.args[1] for call in kill.call_args_list], [agent.signal.SIGTERM, agent.signal.SIGKILL])

    def test_main_wires_fixed_tls_command_and_denies_peer_before_handshake(self):
        for peer, tls_failure, stop_code in [('127.0.0.1', False, 204), ('10.0.0.7', False, 204), ('10.0.0.8', False, 204), ('127.0.0.1', True, 500)]:
            with self.subTest(peer=peer, tls_failure=tls_failure):
                signals = {}; client = Mock(); client.getsockname.return_value = ('10.0.0.5', 8444)
                keypath = MagicMock(); keypath.read_text.return_value = '1'*64
                state = Mock(); state.stop.return_value = stop_code
                context = Mock(); context.wrap_socket.return_value = client
                if tls_failure: context.wrap_socket.side_effect = agent.ssl.SSLError('unit-only')
                case = self
                class Server:
                    def __init__(self, address, handler):
                        case.assertEqual(address, ('0.0.0.0', 8444)); self.socket = Mock(); self.socket.accept.return_value = (client, (peer, 12345))
                    def serve_forever(self, poll_interval):
                        if peer == '10.0.0.8' or tls_failure:
                            with case.assertRaises(OSError): self.get_request()
                            client.close.assert_called_once()
                        else:
                            self.get_request(); client.settimeout.assert_called_once_with(5)
                        signals[agent.signal.SIGTERM](None, None)
                    def shutdown(self): pass
                    def server_close(self): pass
                with patch.object(agent.os, 'getpid', return_value=1), patch.object(agent.os, 'umask'), patch.object(agent, 'Path', return_value=keypath), patch.object(agent, 'Notebook', return_value=state) as constructor, patch.object(agent.ssl, 'SSLContext', return_value=context), patch.object(agent, 'ThreadingHTTPServer', Server), patch.object(agent.socket, 'gethostbyname', return_value='10.0.0.7'), patch.object(agent.signal, 'signal', side_effect=lambda name, callback: signals.update({name: callback})), patch.object(agent.threading, 'Thread'):
                    if stop_code == 500:
                        with self.assertRaises(SystemExit): agent.main()
                    else: agent.main()
                    command = constructor.call_args.args[1]
                    self.assertIn('--ServerApp.certfile=/run/secrets/web.pem', command)
                    self.assertIn('--ServerApp.keyfile=/run/secrets/web-key.pem', command)
                    context.load_cert_chain.assert_called_once_with('/run/secrets/web.pem', '/run/secrets/web-key.pem')
                    if peer == '10.0.0.8': context.wrap_socket.assert_not_called()

    def test_bad_control_secret_stops_before_listener_creation(self):
        keypath = Mock(); keypath.read_text.return_value = 'wrong'
        with patch.object(agent.os, 'getpid', return_value=1), patch.object(agent.os, 'umask'), patch.object(agent, 'Path', return_value=keypath), patch.object(agent, 'ThreadingHTTPServer') as server:
            with self.assertRaises(ValueError): agent.main()
            server.assert_not_called()

    def test_cleanup_and_main_refuse_host_pid_namespace_before_effects(self):
        with patch.object(agent.os, 'getpid', return_value=1234), patch.object(agent.os, 'kill') as kill:
            with self.assertRaises(RuntimeError):
                agent.retire_descendants()
            with self.assertRaises(RuntimeError):
                agent.main()
            kill.assert_not_called()


if __name__ == '__main__':
    unittest.main()
