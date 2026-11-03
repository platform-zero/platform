import base64
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch, MagicMock

spec = importlib.util.spec_from_file_location('livekit_sdk', Path(__file__).with_name('acquire-livekit-browser-sdk.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


class LiveKitSdkTest(unittest.TestCase):
    def archive(self, duplicate=False, link=False):
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w:gz') as archive:
            for _ in range(2 if duplicate else 1):
                entry = tarfile.TarInfo('package/dist/livekit-client.umd.js')
                if link:
                    entry.type = tarfile.SYMTYPE; entry.linkname = '/outside'
                    archive.addfile(entry)
                else:
                    entry.size = 7; archive.addfile(entry, io.BytesIO(b'fixture'))
        data = out.getvalue()
        return data, base64.b64encode(hashlib.sha512(data).digest()).decode()

    def test_exact_member_and_integrity(self):
        data, sri = self.archive()
        digest = hashlib.sha256(b'fixture').hexdigest()
        self.assertEqual(b'fixture', m.unpack(data, sri, digest))
        with self.assertRaises(ValueError): m.unpack(data, 'incorrect', digest)
        with self.assertRaises(ValueError): m.unpack(data, sri, 'incorrect')
        for flags in ({'duplicate': True}, {'link': True}):
            data, sri = self.archive(**flags)
            with self.assertRaises(ValueError): m.unpack(data, sri, digest)

    def test_acquire_repeat_changed_bytes_symlink_and_redirect(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sdk.js'
            response = MagicMock(); response.__enter__.return_value = response
            response.geturl.return_value = m.URL; response.read.return_value = b'archive'
            with patch.object(m, 'DESTINATION', path), patch.object(m, 'SHA256', hashlib.sha256(b'fixture').hexdigest()), patch.object(m, 'WORKER_SHA256', hashlib.sha256(b'fixture').hexdigest()), patch.object(m.urllib.request, 'urlopen', return_value=response) as fetch, patch.object(m, 'unpack', return_value=b'fixture'):
                m.main(); self.assertEqual(path.read_bytes(), b'fixture')
                m.main(); self.assertEqual(fetch.call_count, 1)
                path.write_bytes(b'changed')
                with self.assertRaises(ValueError): m.main()
                self.assertEqual(path.read_bytes(), b'changed')
                path.unlink(); path.symlink_to(Path(directory) / 'missing')
                with self.assertRaises(ValueError): m.main()
                path.unlink(); response.geturl.return_value = 'https://unapproved.invalid'
                with self.assertRaises(ValueError): m.main()
                self.assertFalse(path.exists())
