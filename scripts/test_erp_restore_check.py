import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('erp_restore_check', Path(__file__).resolve().parents[1] / 'src/main/resources/runtime/erp-restore-check.py')
erp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(erp)


class ErpRestoreCheckTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sites, self.config, self.logs = [self.root / x for x in ('sites', 'config', 'logs')]
        self.digest = 'a' * 64
        for directory in (self.sites, self.config, self.logs):
            directory.mkdir()
            (directory / '.p0v3-restore-complete').write_text(self.digest + '\n')
        site = self.sites / erp.SITE
        site.mkdir()
        self.site_config = site / 'site_config.json'
        self.site_config.write_text(json.dumps({'db_name': 'p0_erp', 'db_type': 'mariadb', 'db_password': 'synthetic'}))
        (self.sites / 'common_site_config.json').write_text(json.dumps({'db_host': 'mariadb', 'db_port': 3306,
            'default_site': erp.SITE, 'pause_scheduler': 1, 'server_script_enabled': False, 'disable_telemetry': 1}))
        (self.sites / 'apps.txt').write_text('frappe\nerpnext\n')
        (self.sites / 'assets').symlink_to(erp.ASSETS)

    def check(self):
        return erp.check(self.digest, self.sites, self.config, self.logs)

    def test_valid_state_is_unchanged_and_bound_to_all_three_volumes(self):
        before = self.site_config.read_bytes()
        self.assertTrue(self.check())
        self.assertEqual(before, self.site_config.read_bytes())
        for root in (self.sites, self.config, self.logs):
            marker = root / '.p0v3-restore-complete'
            marker.write_text('b' * 64 + '\n')
            with self.assertRaises(ValueError): self.check()
            marker.write_text(self.digest + '\n')
        with self.assertRaises(ValueError): erp.check('invalid', self.sites, self.config, self.logs)

    def test_uncertainty_and_linked_completion_are_not_accepted(self):
        progress = self.config / '.restore-in-progress'
        progress.symlink_to(self.root / 'missing')
        with self.assertRaises(ValueError): self.check()
        progress.unlink()
        marker = self.logs / '.p0v3-restore-complete'
        marker.unlink()
        marker.symlink_to(self.sites / '.p0v3-restore-complete')
        with self.assertRaises(ValueError): self.check()

    def test_only_compiled_asset_link_is_allowed(self):
        asset = self.sites / 'assets'
        asset.unlink()
        asset.symlink_to('/etc')
        with self.assertRaises(ValueError): self.check()
        asset.unlink()
        asset.symlink_to(erp.ASSETS)
        link = self.logs / 'foreign'
        link.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError): self.check()

    def test_site_overrides_duplicate_keys_and_missing_password_are_rejected(self):
        original = json.loads(self.site_config.read_text())
        for changes in ({'db_name': 'mysql'}, {'db_user': 'root'}, {'db_password': ''}, {'pause_scheduler': 0}, {'server_script_enabled': True}):
            self.site_config.write_text(json.dumps(original | changes))
            with self.assertRaises(ValueError): self.check()
        self.site_config.write_text('{"db_name":"p0_erp","db_name":"mysql"}')
        with self.assertRaises(ValueError): self.check()
        self.site_config.write_text('[]')
        with self.assertRaises(ValueError): self.check()

    def test_hardlinks_special_files_unexpected_apps_and_missing_files_fail(self):
        linked = self.logs / 'linked'
        linked.hardlink_to(self.site_config)
        with self.assertRaises(ValueError): self.check()
        linked.unlink()
        import os
        os.mkfifo(self.logs / 'pipe')
        with self.assertRaises(ValueError): self.check()
        (self.logs / 'pipe').unlink()
        (self.sites / 'apps.txt').write_text('frappe\nerpnext\nforeign\n')
        with self.assertRaises(ValueError): self.check()
        (self.sites / 'apps.txt').unlink()
        with self.assertRaises(FileNotFoundError): self.check()


if __name__ == '__main__':
    unittest.main()
