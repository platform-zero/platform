#!/usr/bin/env python3
"""Read-only cold ERP state admission. No Frappe import, repair, install or migration."""
import json
import os
from pathlib import Path
import re
import stat
import sys

SITE = "erp.private.invalid"
ASSETS = "/home/frappe/frappe-bench/assets"


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("Expected unlinked regular ERP state")
    return path


def directory(path):
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise ValueError("Expected real ERP state directory")
    return path


def marker(root, source_hash):
    directory(root)
    if os.path.lexists(root / ".restore-in-progress"):
        raise ValueError("Uncertain ERP import retained")
    if regular(root / ".p0v3-restore-complete").read_bytes() != (source_hash + "\n").encode("ascii"):
        raise ValueError("Foreign ERP import marker")


def document(path):
    regular(path)
    if path.stat().st_size > 1048576:
        raise ValueError("Oversized ERP configuration")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate ERP configuration key")
            result[key] = value
        return result
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise ValueError("Expected ERP configuration object")
    return value


def check(source_hash, sites=Path('/site-state'), config=Path('/bench-config'), logs=Path('/bench-logs')):
    if not re.fullmatch(r"[a-f0-9]{64}", source_hash):
        raise ValueError("Invalid ERP source binding")
    for root in (sites, config, logs):
        marker(root, source_hash)
    site = directory(sites / SITE)
    settings = document(site / 'site_config.json')
    if settings.get('db_name') != 'p0_erp' or settings.get('db_type', 'mariadb') != 'mariadb':
        raise ValueError("Unexpected ERP database identity")
    if not isinstance(settings.get('db_password'), str) or not settings['db_password']:
        raise ValueError("Missing recovered ERP database credential")
    if settings.get('db_user', 'p0_erp') != 'p0_erp':
        raise ValueError("Unexpected ERP database principal")
    common = document(sites / 'common_site_config.json')
    expected = {'db_host': 'mariadb', 'db_port': 3306, 'default_site': SITE,
                'pause_scheduler': 1, 'server_script_enabled': False, 'disable_telemetry': 1}
    if any(common.get(key) != value for key, value in expected.items()):
        raise ValueError("Recovered ERP safety configuration changed")
    # Site-local keys override common configuration in Frappe: reject a bypass there too.
    if any(key in settings and settings[key] != value for key, value in expected.items()):
        raise ValueError("Site-local ERP safety override")
    apps = regular(sites / 'apps.txt').read_text().splitlines()
    if sorted(apps) != ['erpnext', 'frappe']:
        raise ValueError("Unexpected recovered ERP applications")
    assets = sites / 'assets'
    if not assets.is_symlink() or os.readlink(assets) != ASSETS:
        raise ValueError("Unexpected ERP asset link")
    # This is the one compiled absolute image link, not permission for arbitrary archive links.
    for root in (sites, config, logs):
        for base, directories, files in os.walk(root, followlinks=False):
            for name in directories + files:
                path = Path(base) / name
                if path == assets:
                    continue
                info = path.lstat()
                if not (stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1)):
                    raise ValueError("Unsupported recovered ERP state entry")
    return True


if __name__ == '__main__':
    if not __debug__ or len(sys.argv) != 2:
        raise SystemExit('Expected non-optimized ERP restore check and source digest')
    check(sys.argv[1])
