"""Pure tests only: no containers, network requests or integration acceptance credit."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('identity_probe', Path(__file__).with_name('identity-browser-probe.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class IdentityProbeTest(unittest.TestCase):
    def test_rfc6238_sha1_vectors_truncated_to_six_digits(self):
        for timestamp, expected in [(59, '287082'), (1111111109, '081804'),
                                    (1111111111, '050471'), (1234567890, '005924'),
                                    (2000000000, '279037'), (20000000000, '353130')]:
            self.assertEqual(expected, probe.totp('12345678901234567890', timestamp))

    def test_form_parser_retains_hidden_fields_without_following_links(self):
        parser = probe.FormParser()
        parser.feed('''<input name="outside" value="ignored"><form action="/login?a=1&amp;b=2">
            <input name="csrf" value="opaque&amp;value"><input name="password" type="password">
            <button name="login" value="yes">Log in</button></form>
            <form action="/another"><input name="otp"></form>''')
        self.assertEqual([
            {'action': '/login?a=1&b=2', 'fields': {'csrf': 'opaque&value', 'password': ''}},
            {'action': '/another', 'fields': {'otp': ''}}], parser.forms)


if __name__ == '__main__':
    unittest.main()
