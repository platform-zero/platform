"""Focused installer units; helper transport is always mocked."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('weekly_installer', Path(__file__).with_name('install-weekly-restore-schedule.py'))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class WeeklyInstallerTest(unittest.TestCase):
    def plan(self):
        return {'schemaVersion': 1, 'cases': [{'id': 'fixture', 'assertions': ['readback'], 'sourceOracle': {'object': 'original'}}]}

    def test_requires_original_oracle_and_exact_bounded_cases(self):
        self.assertEqual(['fixture:readback'], MODULE.plan_assertions(json.dumps(self.plan())))
        for fault in ('empty', 'duplicate', 'oracle'):
            plan = self.plan()
            if fault == 'empty': plan['cases'] = []
            if fault == 'duplicate': plan['cases'] += plan['cases']
            if fault == 'oracle': plan['cases'][0]['sourceOracle'] = {}
            with self.subTest(fault=fault), self.assertRaises(ValueError): MODULE.plan_assertions(json.dumps(plan))

    def test_installs_artifact_before_pinned_enrollment_and_activates_only_explicitly(self):
        for activate in (False, True):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp); generation = 'q-abcdef123456'; digest = 'a' * 64; binding = 'b' * 64
                inventory = root / 'inventory.json'; inventory.write_text('{}')
                plan = root / 'plan.json'; plan.write_text(json.dumps(self.plan()))
                namespace = root / generation / 'weekly-restore'; namespace.mkdir(parents=True)
                name = 'p0v3-weekly-restore-' + generation
                units = {name + suffix: '# Managed by p0v3-weekly-restore-v1; unit-only\n' for suffix in ('.service', '-alert.service', '.timer')}
                helper = mock.Mock(); helper.DIST = root / 'dist'; helper.SUPERVISION = root / 'supervision'; helper.SYSTEMD = root / 'systemd'
                helper.distribution.return_value = (digest, {'bin/p0-v3-platform': (0o755, b'unit-script')}, b'unit-descriptor')
                calls = []
                def call(args, **kwargs):
                    calls.append(args)
                    if 'weekly-restore-enroll' in args:
                        self.assertGreaterEqual(helper.install_file.call_count, 2)
                        self.assertTrue(str(args[0]).startswith(str(helper.SUPERVISION)))
                        return json.dumps(binding).encode()
                    if 'weekly-restore-units' in args: return json.dumps(units).encode()
                    if 'is-enabled' in args: return b'enabled\n'
                    if 'is-active' in args: return b'active\n'
                    return b''
                helper.call.side_effect = call
                argv = ['install-weekly-restore-schedule.py'] + (['--activate'] if activate else []) + [str(inventory), generation, digest, str(plan)]
                with mock.patch.object(MODULE, 'helpers', return_value=helper), mock.patch.object(MODULE, 'BASE', root), \
                        mock.patch.object(MODULE.os, 'getuid', return_value=1000), mock.patch('sys.argv', argv), mock.patch('builtins.print'):
                    MODULE.main()
                self.assertTrue((namespace / 'install.intent.json').exists())
                self.assertTrue((namespace / 'install.result.json').exists())
                self.assertEqual(activate, any('enable' in args for args in calls))
                self.assertFalse(any('weekly-restore-tick' in args for args in calls))


if __name__ == '__main__':
    unittest.main()
