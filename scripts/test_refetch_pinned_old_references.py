#!/usr/bin/env python3
"""Offline cache-custody tests; never fetch or execute an OLD repository."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import refetch_pinned_old_references as source


class PinnedOldReferenceCacheTest(unittest.TestCase):
    def test_verified_bytes_and_tamper_and_symlink_rejection(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            name = 'p0-modules-' + source.OLD_COMMIT
            relative = source.CADDY
            directory = root / name
            target = directory / relative
            target.parent.mkdir(parents=True)
            target.write_bytes(b'offline source fixture')
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            (directory / 'reference-provenance.json').write_text(json.dumps({
                'purpose': 'selected-public-source-readonly-topology-reference',
                'repository': source.MODULES, 'commit': source.OLD_COMMIT,
                'verifiedGitCommitObject': True, 'runtimeAuthority': False,
                'files': {relative: {'sha256': digest}},
            }))
            with patch.object(source, 'ROOT', root):
                self.assertEqual(target, source.verified_reference_file(
                    name, source.OLD_COMMIT, source.MODULES, relative, digest))
                with self.assertRaises(ValueError):
                    source.verified_reference_file(name, source.OLD_COMMIT, source.MODULES,
                                                   relative, '0' * 64)
                with self.assertRaises(ValueError):
                    source.verified_reference_file(name, '0' * 40, source.MODULES, relative)
                target.write_bytes(b'tampered')
                with self.assertRaises(ValueError):
                    source.verified_reference_file(name, source.OLD_COMMIT, source.MODULES, relative)
                target.unlink()
                other = root / 'other'
                other.write_bytes(b'offline source fixture')
                target.symlink_to(other)
                with self.assertRaises(ValueError):
                    source.verified_reference_file(name, source.OLD_COMMIT, source.MODULES, relative)


if __name__ == '__main__':
    unittest.main()
