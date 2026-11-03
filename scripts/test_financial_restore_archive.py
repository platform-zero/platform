import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from financial_restore_archive import inventory, extraction_command


class FinancialArchiveTest(unittest.TestCase):
    def make(self, entries):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / 'data.tar'
        with tarfile.open(path, 'w') as archive:
            for name, kind, mode in entries:
                entry = tarfile.TarInfo(name)
                entry.type, entry.mode = kind, mode
                if kind == tarfile.REGTYPE:
                    entry.size = 3
                    archive.addfile(entry, io.BytesIO(b'abc'))
                else:
                    archive.addfile(entry)
        return path

    def test_regular_inventory(self):
        path = self.make([('.', tarfile.DIRTYPE, 0o700), ('./key', tarfile.REGTYPE, 0o600)])
        data = inventory(path)
        self.assertEqual(data['key']['size'], 3)
        self.assertEqual(data['key']['sha256'], 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
        self.assertTrue(data['.']['directory'])
        for budget in ({'max_entries': 1}, {'max_bytes': 2}):
            with self.assertRaises(ValueError):
                inventory(path, **budget)

    def test_expected_owner_and_explicit_root_mode(self):
        path = self.make([('.', tarfile.DIRTYPE, 0o700), ('data', tarfile.REGTYPE, 0o600)])
        tree = inventory(path, expected_owner=(0, 0))
        with self.assertRaises(ValueError):
            inventory(path, expected_owner=(999, 999))
        self.assertEqual(extraction_command(tree), 'tar --no-same-owner -xf - -C /state; chmod 700 /state; sync')
        for name in ('.restore-in-progress', '.p0v3-restore-complete', 'foreign-marker'):
            with self.assertRaises(ValueError):
                extraction_command({**tree, name: {}})
        for tree in ({}, {'.': {'directory': False, 'mode': 0o700}}, {'.': {'directory': True, 'mode': '700'}}, {'.': {'directory': True, 'mode': True}}, {'.': {'directory': True, 'mode': -1}}, {'.': {'directory': True, 'mode': 0o1700}}):
            with self.assertRaises(ValueError):
                extraction_command(tree)

    def test_reject_unsafe_members(self):
        for name, kind, mode in [('/absolute', tarfile.REGTYPE, 0o600), ('../escape', tarfile.REGTYPE, 0o600),
                ('a\\b', tarfile.REGTYPE, 0o600), ('link', tarfile.SYMTYPE, 0o600), ('hard', tarfile.LNKTYPE, 0o600),
                ('fifo', tarfile.FIFOTYPE, 0o600), ('setuid', tarfile.REGTYPE, 0o4600), ('.', tarfile.REGTYPE, 0o600)]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                inventory(self.make([(name, kind, mode)]))
        for entries in [[('a', tarfile.REGTYPE, 0o600), ('./a', tarfile.REGTYPE, 0o600)],
                        [('a', tarfile.REGTYPE, 0o600), ('a/b', tarfile.REGTYPE, 0o600)]]:
            with self.assertRaises(ValueError):
                inventory(self.make(entries))


if __name__ == '__main__':
    unittest.main()
