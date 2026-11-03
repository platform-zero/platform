import subprocess
import sys
import unittest
from pathlib import Path
from application_restore_readback import fixture_id, NoRedirect


class ApplicationRestoreReadbackTest(unittest.TestCase):
    def test_source_fixture_namespace_is_exact(self):
        value = 'p0v3-forgejo-0123456789ab'
        self.assertEqual(value, fixture_id(value, 'p0v3-forgejo-'))
        for bad in [None, 1, '../'+value, value+'\n', value+'/user.json', value.upper(), 'p0v3-planka-0123456789ab']:
            with self.subTest(value=bad), self.assertRaises(ValueError):
                fixture_id(bad, 'p0v3-forgejo-')

    def test_redirects_never_forward_credentials(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, '', {}, 'https://example.org'))

    def test_optimized_execution_refused_before_imports(self):
        result = subprocess.run([sys.executable, '-O', str(Path(__file__).with_name('application_restore_readback.py'))], capture_output=True, timeout=10)
        self.assertEqual(1, result.returncode)
        self.assertIn(b'Optimized Python refused before imports or effects', result.stderr)


if __name__ == '__main__':
    unittest.main()
