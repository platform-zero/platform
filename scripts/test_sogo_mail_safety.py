import subprocess
import sys
import unittest
from pathlib import Path
from sogo_mail_safety import redact_diagnostics


class SogoMailSafetyTest(unittest.TestCase):
    def test_headers_and_passwords_redacted_but_failure_preserved(self):
        for header in ('cookie: secret', 'Cookie: secret', 'set-cookie: secret', 'AUTHORIZATION: secret', '"cookie":"secret"', "'authorization'=secret"):
            result = redact_diagnostics(('getaddrinfo EAI_AGAIN groupware\n - ' + header + '\nfill(fixture-password)\n').encode(), ['fixture-password'])
            self.assertNotIn('secret', result); self.assertNotIn('fixture-password', result)
            self.assertIn('getaddrinfo EAI_AGAIN groupware', result)
            self.assertIn('[redacted credential header]', result)
        self.assertEqual(redact_diagnostics(b'bounded error\xff', ['', 'missing']), 'bounded error\ufffd')

    def test_effectful_probes_refuse_optimized_python(self):
        for name in ('test-private-sogo-mail.py', 'inspect-private-sogo-mail.py', 'sogo_native_tls_probe.py', 'inspect-private-fleet.py'):
            result = subprocess.run([sys.executable, '-O', str(Path(__file__).parent / name)], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'Optimized Python refused', result.stderr)

    def test_native_actions_are_guarded_and_tls_never_disabled(self):
        source = (Path(__file__).resolve().parents[2] / 'acceptance/scripts/SogoMailBrowserProbe.java').read_text()
        self.assertLess(source.index('.send.intent'), source.index("method:'POST'"))
        self.assertLess(source.index('.compose.intent'), source.index('Response composed'))
        self.assertIn('StandardOpenOption.CREATE_NEW', source)
        self.assertIn('channel.force(true)', source)
        self.assertNotIn('context.request()', source)
        self.assertNotIn('setIgnoreHTTPSErrors', source)
        self.assertNotIn('ignore-certificate-errors"', source)


if __name__ == '__main__':
    unittest.main()
