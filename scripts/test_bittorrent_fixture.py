import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('bittorrent_fixture', Path(__file__).with_name('test-private-bittorrent-transfer.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class TorrentFixtureTest(unittest.TestCase):
    def test_canonical_binary_metadata(self):
        self.assertEqual(b'd1:ai1e1:b2:\x00\xffe', fixture.encode({b'b': b'\x00\xff', b'a': 1}))
        self.assertEqual(b'0:', fixture.encode(b''))
        self.assertEqual(b'i-1e', fixture.encode(-1))

    def test_session_and_persistent_accounting_are_not_double_counted(self):
        self.assertEqual(131072, fixture.downloaded_bytes({'downloaded': 0, 'downloaded_session': 131072}))
        self.assertEqual(131072, fixture.downloaded_bytes({'downloaded': 131072, 'downloaded_session': 131072}))
        self.assertEqual(0, fixture.downloaded_bytes({'downloaded': 0, 'downloaded_session': 0}))

    def test_unsupported_types_are_not_silently_encoded(self):
        for value in (True, None, 'text', [], 1.5):
            with self.assertRaises(TypeError):
                fixture.encode(value)


if __name__ == '__main__':
    unittest.main()
