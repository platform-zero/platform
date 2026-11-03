import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from restored_sogo_fixture import fixture_hash


class RestoreOracleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.base = Path(self.temp.name)
        self.source = {'volumes': [{'id': 'home', 'userId': 994}], 'processes': [
            {'id': 'database-init', 'oneShot': True, 'environmentFile': 'fixture.env'},
            {'id': 'mail-init', 'oneShot': True},
            {'id': 'sogod', 'image': 'pinned', 'dependencies': [], 'files': [{'file': 'ca.pem'}]}]}
        self.store('source', self.source); self.hash = hashlib.sha256((self.base / 'source.json').read_bytes()).hexdigest()
        command = ['-ec', self.hash + ' .p0v3-restore-complete']
        self.target = {'volumes': self.source['volumes'], 'processes': [
            {'id': 'database-init', 'oneShot': True, 'command': command},
            {'id': 'mail-init', 'oneShot': True, 'command': command},
            dict(self.source['processes'][2], dependencies=['home-restore-check']),
            {'id': 'home-restore-check', 'oneShot': True, 'command': command}]}
        self.store('smrestore-unit', self.target)
        for name in ('source', 'smrestore-unit'):
            (self.base / name).mkdir()
            for file in ('fixture.env', 'ca.pem'):
                (self.base / name / file).write_text('synthetic-unit-' + file)
    def store(self, name, value):
        (self.base / (name + '.json')).write_text(json.dumps(value))
    def test_exact_read_only_binding(self):
        self.assertEqual(self.hash, fixture_hash(self.base, 'source'))
        self.assertEqual(self.hash, fixture_hash(self.base, 'smrestore-unit', 'source'))
        with self.assertRaises(ValueError):
            fixture_hash(self.base, 'smrestore-unit', 'source', mutating=True)
        with self.assertRaises(ValueError):
            fixture_hash(self.base, 'smrestore-unit', mutating=True)
        with self.assertRaises(ValueError):
            fixture_hash(self.base, 'source', 'source')
        with self.assertRaises(ValueError):
            fixture_hash(self.base, 'smrestore-unit', '../escape')
    def test_missing_guards_foreign_recipe_and_volume_rejected(self):
        for mutate in (
            lambda x: x['volumes'].append({'id': 'unexpected'}),
            lambda x: x['processes'].pop(),
            lambda x: x['processes'][0].update(command=['foreign']),
            lambda x: x['processes'][1].update(oneShot=False),
            lambda x: x['processes'][2].update(image='unexpected'),
        ):
            changed = json.loads(json.dumps(self.target)); mutate(changed); self.store('smrestore-unit', changed)
            with self.assertRaises(ValueError):
                fixture_hash(self.base, 'smrestore-unit', 'source')
    def test_input_change_symlink_and_unsafe_name_rejected(self):
        path = self.base / 'smrestore-unit/ca.pem'; path.write_text('changed')
        with self.assertRaises(ValueError):
            fixture_hash(self.base, 'smrestore-unit', 'source')
        path.unlink(); path.symlink_to(self.base / 'source/ca.pem')
        with self.assertRaises(ValueError):
            fixture_hash(self.base, 'smrestore-unit', 'source')
        path.unlink(); path.write_text('synthetic-unit-ca.pem')
        self.source['processes'][0]['environmentFile'] = '../escape'; self.store('source', self.source)
        fingerprint = hashlib.sha256((self.base / 'source.json').read_bytes()).hexdigest()
        for p in self.target['processes']:
            if p.get('oneShot'):
                p['command'] = [fingerprint + ' .p0v3-restore-complete']
        self.store('smrestore-unit', self.target)
        with self.assertRaises(ValueError):
            fixture_hash(self.base, 'smrestore-unit', 'source')


if __name__ == '__main__':
    unittest.main()
