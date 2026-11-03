import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch
from keykeeper_probe_client import Client


class KeykeeperClientTest(unittest.TestCase):
    def setUp(self):
        self.client = object.__new__(Client)
        self.client.host, self.client.port, self.client.address = 'keeper', 8443, '192.0.2.10'
        self.client.leaf = b'unit-leaf'
        self.raw = MagicMock(); self.raw.__enter__.return_value = self.raw
        self.tls = MagicMock(); self.tls.__enter__.return_value = self.tls
        self.tls.getpeercert.return_value = self.client.leaf
        self.client.context = MagicMock(); self.client.context.wrap_socket.return_value = self.tls
        self.response = MagicMock(); self.response.__enter__.return_value = self.response
        self.response.status = 200; self.response.read.return_value = b'{"value":"unit-only"}'

    def test_optimized_entrypoint_and_library_refuse_before_effects(self):
        scripts = Path(__file__).parent
        for command in ([sys.executable, '-O', str(scripts / 'test-private-keykeeper.py'), '--help'], [sys.executable, '-O', '-c', 'import keykeeper_probe_client']):
            result = subprocess.run(command, capture_output=True, text=True, env={**os.environ, 'PYTHONPATH': str(scripts)})
            self.assertNotEqual(0, result.returncode)
            self.assertIn('Optimized Python', result.stderr)

    def test_bad_method_path_header_and_oversize_body_never_connect(self):
        with patch('keykeeper_probe_client.socket.create_connection') as connect:
            for args in [('PATCH', '/api/items', None, None), ('GET', '/\r\nX:1', None, None), ('GET', '/api/items', None, 'token\nleak'), ('POST', '/api/items', {'value': 'x' * 65536}, None)]:
                with self.assertRaises(AssertionError): self.client.request(*args)
            connect.assert_not_called()

    def test_wrong_leaf_and_failed_tls_close_without_sending_token(self):
        with patch('keykeeper_probe_client.socket.create_connection', return_value=self.raw):
            self.tls.getpeercert.return_value = b'wrong'
            with self.assertRaises(AssertionError): self.client.request('GET', '/api/items', token='unit-token')
            self.tls.sendall.assert_not_called(); self.tls.__exit__.assert_called_once(); self.raw.__exit__.assert_called_once()
            self.raw.reset_mock(); self.client.context.wrap_socket.side_effect = ssl.SSLError('unit-only')
            with self.assertRaises(ssl.SSLError): self.client.request('GET', '/api/items', token='unit-token')
            self.raw.__exit__.assert_called_once(); self.tls.sendall.assert_not_called()

    def test_bounded_response_native_error_redaction_and_no_write_retry(self):
        with patch('keykeeper_probe_client.socket.create_connection', return_value=self.raw) as connect, patch('keykeeper_probe_client.http.client.HTTPResponse', return_value=self.response):
            self.assertEqual({'value': 'unit-only'}, self.client.request('POST', '/api/items', {'value': 'unit'}, 'unit-token'))
            self.response.read.assert_called_once_with(1048577); self.response.__exit__.assert_called_once()
            wire = self.tls.sendall.call_args.args[0]
            self.assertIn(b'Host: keeper:8443\r\n', wire); self.assertIn(b'Authorization: Bearer unit-token\r\n', wire)
            self.response.status = 500; self.response.read.return_value = b'private-error-must-not-be-printed'
            with self.assertRaises(AssertionError) as failure: self.client.request('POST', '/api/items', {'value': 'unit'}, 'unit-token')
            self.assertNotIn('private-error', str(failure.exception)); self.assertEqual(2, connect.call_count)
            self.response.status = 200; self.response.read.return_value = b'x' * 1048577
            with self.assertRaises(AssertionError): self.client.request('GET', '/api/items')

    def test_form_encoding_and_uncertain_upload_are_not_replayed(self):
        with patch('keykeeper_probe_client.socket.create_connection', return_value=self.raw) as connect, patch('keykeeper_probe_client.http.client.HTTPResponse', return_value=self.response):
            self.client.request('POST', '/token', {'client_secret': 'unit&value'}, form=True)
            self.assertIn(b'client_secret=unit%26value', self.tls.sendall.call_args.args[0])
            self.tls.sendall.side_effect = OSError('uncertain')
            with self.assertRaises(OSError): self.client.request('POST', '/api/items', {'value': 'unit'})
            self.assertEqual(2, connect.call_count)


if __name__ == '__main__': unittest.main()
