#!/usr/bin/env python3
"""One original native ERP privilege cutover. Never retry an existing intent.

This one-shot is launched only by the exclusive owner after the native site install.
Its cutover-only Maria principal has CREATE USER globally but is isolated from all
Frappe service environments and networks and is dropped before success. The Frappe
installer itself has no global grant. Every unknown outcome retains its intent.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import pymysql

SITES = Path('/home/frappe/frappe-bench/sites')
CA = '/run/secrets/mariadb-ca.pem'
NATIVE = SITES / '.erp-native-site-install-receipt.json'
INTENT = SITES / '.erp-maria-cutover-intent.json'
RESULT = SITES / '.erp-maria-cutover-result.json'


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def exclusive(path, record):
    payload = (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        require(out.write(payload) == len(payload), 'Short ERP native cutover receipt write')
        out.flush()
        os.fsync(out.fileno())
    sync_dir(path.parent)


def connect(user, password):
    return pymysql.connect(host='mariadb', port=3306, user=user, password=password,
                           database='p0_erp', ssl={'ca': CA, 'check_hostname': True},
                           connect_timeout=5, read_timeout=5, write_timeout=5)


def main():
    require(__debug__ and SITES.is_dir() and not SITES.is_symlink() and
            NATIVE.is_file() and not NATIVE.is_symlink() and
            not INTENT.exists() and not RESULT.exists(),
            'Missing native ERP site or uncertain prior privilege cutover')
    migration = os.environ['ERP_MIGRATION_PASSWORD']
    runtime = os.environ['ERP_RUNTIME_PASSWORD']
    cutover = os.environ['ERP_CUTOVER_PASSWORD']
    generation = os.environ['ERP_GENERATION']
    require(all(re.fullmatch(r'[a-f0-9]{64}', s) for s in (migration, runtime, cutover)) and
            len({migration, runtime, cutover}) == 3 and re.fullmatch(r'q-[a-f0-9]{12}', generation),
            'Invalid sealed ERP cutover credentials or generation')
    source = NATIVE.read_bytes()
    receipt = json.loads(source)
    require(receipt.get('generation') == generation and receipt.get('database') == 'p0_erp' and
            receipt.get('site') == 'erp.private.invalid' and receipt.get('cutoverPending') is True,
            'Wrong original ERP native site receipt')
    with connect('p0_erp', migration) as original:
        with original.cursor() as cursor:
            cursor.execute('SELECT CURRENT_USER(), DATABASE()')
            require(cursor.fetchone() == ('p0_erp@%', 'p0_erp'), 'Original Frappe login changed')
            cursor.execute('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=%s', ('p0_erp',))
            require(cursor.fetchone()[0] > 0, 'Original native ERP tables absent')
            cursor.execute('SHOW GRANTS')
            grants = [row[0] for row in cursor.fetchall()]
            require(any('ALL PRIVILEGES ON `p0_erp`.*' in row for row in grants) and
                    not any('WITH GRANT OPTION' in row or 'CREATE USER ON *.*' in row for row in grants),
                    'Installer has foreign or overprivileged grant')
    with connect('erp_cutover', cutover) as control:
        with control.cursor() as cursor:
            cursor.execute('SELECT CURRENT_USER()')
            require(cursor.fetchone()[0] == 'erp_cutover@%', 'Wrong cutover identity')
            cursor.execute('SHOW GRANTS')
            grants = [row[0] for row in cursor.fetchall()]
            require(any('CREATE USER ON *.*' in row for row in grants) and
                    any('`p0_erp`.*' in row and 'WITH GRANT OPTION' in row for row in grants),
                    'No bounded, one-use cutover authority')
    os.umask(0o077)
    # Persist exclusive intent BEFORE first SQL effect. No retry on missing result.
    exclusive(INTENT, {'generation': generation, 'database': 'p0_erp', 'attempted': True,
                       'sourceReceiptSha256': hashlib.sha256(source).hexdigest(),
                       'migrationSha256': hashlib.sha256(migration.encode()).hexdigest(),
                       'runtimeSha256': hashlib.sha256(runtime.encode()).hexdigest()})
    with connect('erp_cutover', cutover) as control:
        with control.cursor() as cursor:
            cursor.execute("REVOKE ALL PRIVILEGES ON `p0_erp`.* FROM 'p0_erp'@'%' ")
            cursor.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON `p0_erp`.* TO 'p0_erp'@'%'")
            cursor.execute("ALTER USER 'p0_erp'@'%' IDENTIFIED BY %s", (runtime,))
            # A successful owner cutover cannot leave a permanent global principal.
            cursor.execute("DROP USER 'erp_cutover'@'%'")
        control.commit()
    with connect('p0_erp', runtime) as current:
        with current.cursor() as cursor:
            cursor.execute('SELECT CURRENT_USER(), DATABASE()')
            require(cursor.fetchone() == ('p0_erp@%', 'p0_erp'), 'ERP runtime identity changed')
            cursor.execute('SHOW GRANTS')
            grants = [row[0] for row in cursor.fetchall()]
            require(any('SELECT, INSERT, UPDATE, DELETE' in row and '`p0_erp`.*' in row
                        for row in grants) and not any('ALL PRIVILEGES' in row or 'WITH GRANT OPTION' in row
                                                      for row in grants), 'ERP runtime grant not bounded')
    for user, password in [('p0_erp', migration), ('erp_cutover', cutover)]:
        try:
            with connect(user, password):
                pass
        except pymysql.err.OperationalError as error:
            require(error.args[0] == 1045, 'Old ERP login failed unexpectedly')
        else:
            raise RuntimeError('Original privileged ERP or cutover credential still authenticates')
    exclusive(RESULT, {'generation': generation, 'database': 'p0_erp',
                       'nativeSourceReceiptSha256': hashlib.sha256(source).hexdigest(),
                       'runtimeReadback': True, 'oldMigrationDenied': True, 'cutoverAuthorityRetired': True})


if __name__ == '__main__':
    main()
