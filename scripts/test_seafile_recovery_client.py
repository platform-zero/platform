import unittest
from unittest.mock import Mock, patch
import ssl
import subprocess
import sys
from pathlib import Path
from seafile_recovery_client import Client


class RecoveryClientTest(unittest.TestCase):
    def setUp(self):
        self.client=object.__new__(Client)
        self.client.address=Mock(return_value='10.20.30.40')
        self.client.leaf=b'fixture-certificate';self.client.ctx=Mock()
        self.client.ctx.wrap_socket.return_value.getpeercert.return_value=self.client.leaf
        self.client.tokens={'owner':'a'*40}

    def test_optimized_entrypoints_refuse_before_imports_or_argument_processing(self):
        for name in ('seafile_recovery_client.py','test-seafile-encrypted-restore.py'):
            result=subprocess.run([sys.executable,'-O','-B',str(Path(__file__).with_name(name))],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0);self.assertIn('Optimized Python',result.stderr);self.assertEqual(result.stdout,'')

    def test_foreign_urls_and_header_injection_are_denied_before_connect(self):
        with patch('seafile_recovery_client.socket.create_connection') as connect:
            for path in ('https://evil.invalid/file','http://files:8443/file','https://files:8443@evil.invalid/file','https://files:8443/path#fragment','/path\r\nHost: evil.invalid'):
                with self.subTest(path=path),self.assertRaises(AssertionError):self.client.request(path,'owner')
            connect.assert_not_called()

    def test_exact_leaf_and_tls_failure_close_connection_without_request(self):
        with patch('seafile_recovery_client.http.client.HTTPConnection') as factory,patch('seafile_recovery_client.socket.create_connection'):
            connection=factory.return_value
            self.client.ctx.wrap_socket.return_value.getpeercert.return_value=b'changed'
            with self.assertRaises(AssertionError):self.client.request('/file','owner')
            connection.request.assert_not_called();connection.close.assert_called_once()
            connection.reset_mock();self.client.ctx.wrap_socket.side_effect=ssl.SSLError('fixture rejection')
            with self.assertRaises(ssl.SSLError):self.client.request('/file','owner')
            connection.request.assert_not_called();connection.close.assert_called_once()

    def test_bounded_body_exact_origin_and_encoded_form(self):
        with patch('seafile_recovery_client.http.client.HTTPConnection') as factory,patch('seafile_recovery_client.socket.create_connection'):
            connection=factory.return_value;response=connection.getresponse.return_value
            response.status=200;response.read.return_value=b'{}'
            self.assertEqual((200,b'{}'),self.client.request('https://files:8443/api?x=1','owner','POST',form={'field':'a&b'}))
            connection.request.assert_called_once_with('POST','/api?x=1',body='field=a%26b',headers={'Authorization':'Token '+'a'*40,'Content-Type':'application/x-www-form-urlencoded'})
            response.read.assert_called_once_with(16*1024*1024+1);connection.close.assert_called_once()
            connection.reset_mock();response.read.return_value=b'x'*(16*1024*1024+1)
            with self.assertRaises(AssertionError):self.client.request('/file')
            connection.close.assert_called_once()

    def test_failed_upload_is_not_retried_and_response_body_is_not_reported(self):
        self.client.api=Mock(return_value='https://files:8443/upload-fixture')
        self.client.request=Mock(return_value=(500,b'fixture-private-error'))
        with self.assertRaises(AssertionError) as failure:self.client.upload('repo','synthetic.txt',b'synthetic')
        self.assertNotIn('fixture-private-error',str(failure.exception));self.client.request.assert_called_once()
        self.client.request.reset_mock()
        with self.assertRaises(AssertionError):self.client.upload('repo','../foreign',b'synthetic')
        self.client.request.assert_not_called()

    def test_uncertain_share_cleanup_reads_before_compensation(self):
        self.client.api=Mock(return_value=[{'id':'other'}]);self.client.share=Mock()
        self.assertFalse(self.client.revoke_if_shared('fixture'));self.client.share.assert_not_called()
        self.client.api.return_value=[{'id':'fixture','permission':'r'}]
        self.assertTrue(self.client.revoke_if_shared('fixture'));self.client.share.assert_called_once_with('fixture',False)
        self.client.share.reset_mock()
        with self.assertRaisesRegex(RuntimeError,'manual reconciliation'):self.client.revoke_if_shared('fixture',allow_revoke=False)
        self.client.share.assert_not_called()
        self.client.api.side_effect=RuntimeError('read unavailable')
        with self.assertRaises(RuntimeError):self.client.revoke_if_shared('fixture')
        self.client.share.assert_not_called()

    def test_login_rejects_non_native_token_and_api_errors_do_not_disclose_body(self):
        self.client.passwords={'owner':'fixture-password'};self.client.request=Mock(return_value=(403,b'fixture-private-error'))
        with self.assertRaisesRegex(AssertionError,'returned 403') as failure:self.client.api('/api2/repos/')
        self.assertNotIn('fixture-private-error',str(failure.exception))
        self.client.api=Mock(return_value={'token':'not-a-native-token'})
        with self.assertRaises(AssertionError):self.client.login()


if __name__=='__main__':unittest.main()
