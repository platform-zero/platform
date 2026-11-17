package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.*

/** Only fresh site-local password grants; never the Frappe administrator, Maria or issuer secret. */
internal data class FreshErpActorGrant(val ownerPassword: String, val outsiderPassword: String) {
    init {
        require(ownerPassword.matches(Regex("[a-f0-9]{64}")) &&
            outsiderPassword.matches(Regex("[a-f0-9]{64}")) && ownerPassword != outsiderPassword)
    }
}

/** Private ERPNext with native journalled site installation, isolated queues and no configured mail transport. */
internal object ErpNextRuntime {
    const val SITE = "erp.private.invalid"
    const val FRESH_OWNER = "owner"
    const val FRESH_OUTSIDER = "outsider"
    const val FRESH_OWNER_EMAIL = "p0v3-erp-owner@localhost.invalid"
    const val FRESH_OUTSIDER_EMAIL = "p0v3-erp-outsider@localhost.invalid"
    const val FRESH_LEDGER_ROLE = "P0v3 Ledger Operator"

    /** Read-only original-site probe: core runs this only after the real INSTALL journey
     * using the sealed actor passwords. Recheck native Frappe hashes and permission
     * engine, not the site-install receipt. It emits only actor names/native IDs.
     */
    fun nativeIssuanceReadbackSource(): String = """
        import json, os
        import frappe
        from frappe.utils.password import check_password

        owner = '$FRESH_OWNER_EMAIL'
        outsider = '$FRESH_OUTSIDER_EMAIL'
        owner_password = os.environ['ERP_OWNER_PASSWORD']
        outsider_password = os.environ['ERP_OUTSIDER_PASSWORD']
        assert len(owner_password) == len(outsider_password) == 64
        assert owner_password != outsider_password
        assert all(c in '0123456789abcdef' for c in owner_password + outsider_password)
        frappe.init(site='$SITE', sites_path='/home/frappe/frappe-bench/sites')
        frappe.connect()
        try:
            owner_user = frappe.get_doc('User', owner)
            outsider_user = frappe.get_doc('User', outsider)
            assert owner_user.enabled and outsider_user.enabled
            assert owner_user.username == '$FRESH_OWNER' and outsider_user.username == '$FRESH_OUTSIDER'
            assert owner_user.user_type == 'System User' and outsider_user.user_type == 'Website User'
            assert check_password(owner, owner_password) == owner
            assert check_password(outsider, outsider_password) == outsider
            assert '$FRESH_LEDGER_ROLE' in frappe.get_roles(owner)
            assert '$FRESH_LEDGER_ROLE' not in frappe.get_roles(outsider)
            assert not {'System Manager', 'Accounts Manager'} & set(frappe.get_roles(owner))
            for doctype, allowed in {
                'Customer': ('read', 'create'),
                'Journal Entry': ('read', 'create', 'write', 'submit'),
                'GL Entry': ('read',), 'Company': ('read',), 'Account': ('read',),
                'Scheduled Job Log': ('read',), 'Customer Group': ('read',),
                'Territory': ('read',)
            }.items():
                for permission in allowed:
                    assert frappe.has_permission(doctype, permission, user=owner, raise_exception=False)
            for doctype in ('Customer', 'Journal Entry'):
                for permission in ('read', 'create'):
                    assert not frappe.has_permission(doctype, permission, user=outsider, raise_exception=False)
            for doctype in ('GL Entry', 'Company', 'Account', 'Scheduled Job Log'):
                for permission in ('create', 'write', 'submit', 'delete'):
                    assert not frappe.has_permission(doctype, permission, user=owner, raise_exception=False)
            print(json.dumps({'owner': '$FRESH_OWNER', 'outsider': '$FRESH_OUTSIDER',
                'ownerNativeId': owner_user.name, 'outsiderNativeId': outsider_user.name},
                sort_keys=True, separators=(',', ':')))
        finally:
            frappe.destroy()
    """.trimIndent() + "\n"
    fun spec(inventory: AcquiredInventory, name: String = "erpnext"): PrivateDeploymentSpec {
        fun image(id: String) = inventory.images.single { it.product == id }.also { require(it.os == "linux" && it.architecture == "amd64") }
        val app = image("erpnext"); val maria = image("mariadb"); val redis = image("valkey")
        val database = RuntimeProcess("mariadb", maria.pinnedImage, maria.imageId, 999,
            environmentFile = "mariadb.env", volumes = listOf(RuntimeMount("mariadb", "/var/lib/mysql")),
            memoryMiB = 1024, apparmorProfile = "p0v3-private-v1")
        fun queue(id: String) = RuntimeProcess(id, redis.pinnedImage, redis.imageId, 999,
            entrypoint = "/usr/local/bin/valkey-server", command = listOf("/run/secrets/$id.conf"),
            volumes = listOf(RuntimeMount(id, "/data")), files = listOf(RuntimeFile("$id.conf", "/run/secrets/$id.conf")),
            apparmorProfile = "p0v3-private-v1", readiness = listOf("/bin/sh", "-ec",
                "export REDISCLI_AUTH=\"${'$'}(sed -n 's/^requirepass //p' /run/secrets/$id.conf)\"; test \"${'$'}(valkey-cli ping)\" = PONG"))
        val mounts = listOf(RuntimeMount("sites", "/home/frappe/frappe-bench/sites"), RuntimeMount("logs", "/home/frappe/frappe-bench/logs"), RuntimeMount("config", "/home/frappe/frappe-bench/config"))
        val base = RuntimeProcess("backend", app.pinnedImage, app.imageId, 1000, dependencies = listOf("installer-retire"),
            entrypoint = "/bin/sh", environmentFile = "erp.env", volumes = mounts, apparmorProfile = "p0v3-private-v1", memoryMiB = 1024)
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("mariadb", 999), RuntimeVolume("cache", 999),
            RuntimeVolume("queue", 999), RuntimeVolume("sites", 1000), RuntimeVolume("logs", 1000), RuntimeVolume("config", 1000)), processes = listOf(
            database.copy(id = "mariadb-init", entrypoint = "/bin/sh", oneShot = true, command = listOf("-ec", """
                mariadb-install-db --no-defaults --datadir=/var/lib/mysql --auth-root-authentication-method=normal --skip-test-db
                mariadbd --no-defaults --datadir=/var/lib/mysql --bootstrap --skip-networking <<SQL
                DELETE FROM mysql.global_priv WHERE User = '' OR (User = 'root' AND Host <> 'localhost');
                FLUSH PRIVILEGES;
                ALTER USER 'root'@'localhost' IDENTIFIED BY '${'$'}MARIADB_ROOT_PASSWORD';
                CREATE USER 'frappe_installer'@'%' IDENTIFIED BY '${'$'}INSTALLER_PASSWORD';
                GRANT ALL PRIVILEGES ON *.* TO 'frappe_installer'@'%' WITH GRANT OPTION;
                SQL
            """.trimIndent())),
            database.copy(dependencies = listOf("mariadb-init"), entrypoint = "/usr/sbin/mariadbd", command = listOf(
                "--no-defaults", "--datadir=/var/lib/mysql", "--socket=/tmp/mysql.sock", "--pid-file=/tmp/mysql.pid", "--bind-address=0.0.0.0",
                "--skip-name-resolve", "--max-connections=96", "--innodb-buffer-pool-size=256M", "--character-set-server=utf8mb4", "--collation-server=utf8mb4_unicode_ci"),
                readiness = listOf("/bin/sh", "-ec", "MYSQL_PWD=\"${'$'}MARIADB_ROOT_PASSWORD\" mariadb --socket=/tmp/mysql.sock -u root -Nse 'SELECT 1' | grep -qx 1")),
            queue("cache"), queue("queue"),
            base.copy(id = "site-config-init", dependencies = listOf("mariadb", "cache", "queue"), oneShot = true,
                environmentFile = null, entrypoint = "/home/frappe/frappe-bench/env/bin/python", command = listOf("/run/secrets/site-config.py"),
                volumes = listOf(RuntimeMount("sites", "/site-state")),
                files = listOf("site-config.py", "common-site.json").map { RuntimeFile(it, "/run/secrets/$it") }),
            base.copy(id = "site-init", dependencies = listOf("site-config-init"), oneShot = true, memoryMiB = 2048,
                environmentFile = "bootstrap.env", entrypoint = "/home/frappe/frappe-bench/env/bin/python", command = listOf("/run/secrets/site-init.py"),
                files = listOf(RuntimeFile("site-init.py", "/run/secrets/site-init.py"))),
            database.copy(id = "installer-retire", dependencies = listOf("site-init"), oneShot = true, entrypoint = "/bin/sh", volumes = emptyList(), environmentFile = "installer.env",
                command = listOf("-ec", "MYSQL_PWD=\"${'$'}INSTALLER_PASSWORD\" mariadb -h mariadb -u frappe_installer -e \"DROP USER 'frappe_installer'@'%';\"")),
            base.copy(command = listOf("-ec", "exec /home/frappe/frappe-bench/env/bin/gunicorn --chdir=/home/frappe/frappe-bench/sites --bind=0.0.0.0:8000 --threads=2 --workers=2 --worker-class=gthread --worker-tmp-dir=/tmp --timeout=120 --preload frappe.app:application"),
                readiness = listOf("/home/frappe/frappe-bench/env/bin/python", "-c", "import urllib.request,json; r=urllib.request.Request('http://127.0.0.1:8000/api/method/ping',headers={'X-Frappe-Site-Name':'$SITE'}); assert json.load(urllib.request.urlopen(r,timeout=5))['message']=='pong'")),
            base.copy(id = "websocket", entrypoint = "/home/frappe/frappe-bench/env/bin/python",
                files = listOf(RuntimeFile("process-init.py", "/run/secrets/process-init.py")),
                command = listOf("/run/secrets/process-init.py", "node", "/home/frappe/frappe-bench/apps/frappe/socketio.js"),
                readiness = listOf("/home/frappe/frappe-bench/env/bin/python", "-c", "import urllib.request; r=urllib.request.urlopen('http://127.0.0.1:9000/socket.io/?EIO=4&transport=polling',timeout=5); assert r.status==200")),
            base.copy(id = "worker", entrypoint = "/home/frappe/frappe-bench/env/bin/python",
                files = listOf(RuntimeFile("process-init.py", "/run/secrets/process-init.py")),
                command = listOf("/run/secrets/process-init.py", "bench", "worker", "--queue", "short,default,long"), readiness = listOf("/bin/sh", "-ec", "kill -0 1")),
            base.copy(id = "scheduler", entrypoint = "/home/frappe/frappe-bench/env/bin/python",
                files = listOf(RuntimeFile("process-init.py", "/run/secrets/process-init.py")),
                command = listOf("/run/secrets/process-init.py", "bench", "schedule"), readiness = listOf("/bin/sh", "-ec", "kill -0 1")),
            base.copy(id = "erp", dependencies = listOf("backend", "websocket", "worker", "scheduler"), entrypoint = "/usr/sbin/nginx",
                command = listOf("-c", "/run/secrets/nginx.conf", "-g", "daemon off;"),
                files = listOf("nginx.conf", "ca.pem", "web.pem", "web-key.pem").map { RuntimeFile(it, "/run/secrets/$it") },
                readinessHttpPort = 8080, readinessHttpPath = "/healthz")
        )).also { PrivateDeployment.validate(it) }
    }
    /** Exact upstream immutable source bytes. Three previously read-only local files
     * independently matched these v15.125.0 hashes; the other pinned files and RQ
     * 1.15.1 were read via bounded official raw source GET. EVERY ERP effectful
     * process attests the mounted image source before opening the first connection.
     */
    private val sourceHashes = mapOf(
        "frappe/installer.py" to "004050d4143a386af7ce9e27d2235428a0b1df9b2dee386ac25a08438aab59ca",
        "frappe/permissions.py" to "efe6de57546d7c59a4c2ebe44fde123bdcdbfd83bbd7ec4bb889c562ecedc73a",
        "frappe/core/doctype/user/user.py" to "d170f286d0748ae3494cb9a1ab35726564357dc0f40649f1ae6b31c34bf13b5c",
        "frappe/utils/password.py" to "ec004bb42df48bd8180fe3ae73af6a668fbc13664081a7a9b5490f16832bb7f0",
        "frappe/core/doctype/system_settings/system_settings.json" to "d97b6adb9ac63c21b864abff9c1fb71129befefb34188eefae6b4ce540f5c27a",
        "frappe/commands/site.py" to "e8dc45c06d6c4789d36fae150175c418e900efc6a30346c3d3c79cc275b6b1df",
        "frappe/utils/redis_wrapper.py" to "6791bdd625428883c128214c71fc575562862ad15fb28ed72aebc540efba3455",
        "frappe/utils/redis_queue.py" to "194f49453bc4f12656fb4355b9fb03a001974d0e03d31f1d4c6b0c5e4aedd8db",
        "frappe/utils/background_jobs.py" to "50d3a3a2f94b81d5688c351f8e4579bc484c45e835f95767c14115685392d43b",
        "frappe/database/__init__.py" to "91781e557776bd811099f87a054ecdc0f9ae099f86cf34a92511e8e4dc775594",
        "frappe/database/mariadb/database.py" to "c5ae910555d440351eacd681bb6e2933958863698f625837e8becf7f811eae46",
        "frappe/database/db_manager.py" to "7b0726019816a32945cd899a765b60b5951d0ee6e0be07dbcf27bd30dc5944a1",
        "frappe/realtime.py" to "f08977cf2d6be9fff4ad4707fed826c969839e5c0f6e867af6ffa693c996fc05",
        "realtime/index.js" to "821c1d26404b02fae63fa8c6676c6c10188fdf3fd0c85a149c454e0934ab11a0",
        "node_utils.js" to "c08d86349370fa51b030c93e31b1395caed3813c3a6c68c2e3aff38986b110e2",
        "rq/queue.py" to "54084ae2590304aa0ff9a499fdb1d0ab7bc9463bc2148105aea2a59acaf775b7",
        "rq/worker.py" to "168c5af94401366fffe39b6a465848fd1c73bd59d7cec25c3dc9b4eba193a4bf",
        "rq/command.py" to "2ef8a4c847b9bf62415f54d700608588a273d18d0ebbf5851097126ec8fc92d9")

    private fun releaseSourceAttestationInput(): String = buildJsonObject {
        put("frappeVersion", "15.125.0"); put("rqVersion", "1.15.1"); put("redisVersion", "4.5.5")
        put("hashes", buildJsonObject { sourceHashes.toSortedMap().forEach { (file, hash) -> put(file, hash) } })
    }.toString() + "\n"

    /** No daemon or replica database is composed here. A01/A09 pure whole-graph validation
     * must precede this one-shot's credentials; COORD holds application startup until its
     * journalled local-Maria erpMariaCutover native GRANTS/old-password rejection proof.
     * Pinned Frappe 15.125.0 ALWAYS uses db_name as Maria username, ignoring db_user.
     */
    fun releaseNativeSiteInstall(inventory: AcquiredInventory, name: String): RuntimeProcess {
        val legacy = spec(inventory, name).processes.single { it.id == "site-init" }
        return legacy.copy(id = "erp-native-site-install", dependencies = listOf("mariadb", "erp-redis-bridge"),
            networks = listOf("erp-data", "erp-cache"), environmentFile = "erp-site-bootstrap.env",
            files = listOf(RuntimeFile("erp-native-site-install.py", "/run/secrets/erp-native-site-install.py"),
                RuntimeFile("erp-common-site.json", "/run/secrets/erp-common-site.json"),
                RuntimeFile("erp-source-attestation.json", "/run/secrets/erp-source-attestation.json"),
                RuntimeFile("erp-maria-client.cnf", "/run/secrets/erp-maria-client.cnf"),
                RuntimeFile("mariadb-ca.pem", "/run/secrets/mariadb-ca.pem")),
            oneShot = true, command = listOf("/run/secrets/erp-native-site-install.py"))
    }

    /** Call only after canonical complete-graph validation and selection of the SAME
     * provider Maria pair. The native Maria CLI import consumes a sealed option file,
     * not its original password-on-argv or unverified plaintext connection.
     */
    fun releaseNativeSiteInputs(pair: CanonicalMariaCredentialPair, adminPassword: String,
        bridgeClientPassword: String, generation: String,
        actors: FreshErpActorGrant? = null): Map<String, String> {
        val grant = requireNotNull(actors) { "Fresh ERP site requires two original, distinct native actors" }
        require(adminPassword.matches(Regex("[a-f0-9]{64}")) &&
            bridgeClientPassword.matches(Regex("[a-f0-9]{64}")) &&
            setOf(pair.migrationPassword, pair.runtimePassword, adminPassword, bridgeClientPassword,
                grant.ownerPassword, grant.outsiderPassword).size == 6 &&
            generation.matches(Regex("q-[a-f0-9]{12}")))
        val common = buildJsonObject {
            put("db_host", "mariadb"); put("db_port", 3306)
            put("redis_cache", "redis://erp-app:$bridgeClientPassword@erp-redis-bridge:6379/0")
            put("redis_queue", "redis://erp-app:$bridgeClientPassword@erp-redis-bridge:6379/0")
            put("redis_socketio", "redis://erp-app:$bridgeClientPassword@erp-redis-bridge:6379/0")
            put("bench_id", "p0v3-erp"); put("socketio_port", 9000)
            put("webserver_host", "backend"); put("webserver_port", 8000)
            put("default_site", SITE); put("serve_default_site", true)
            put("host_name", "https://erp.datamancy.net")
            put("disable_telemetry", 1); put("developer_mode", 0); put("server_script_enabled", false)
            // No scheduler daemon exists before the journalled Maria cutover. Once
            // it starts, native scheduled jobs must actually execute, not stay paused.
            put("pause_scheduler", 0)
        }
        return mapOf("erp-common-site.json" to "$common\n",
            "erp-source-attestation.json" to releaseSourceAttestationInput(),
            "erp-site-bootstrap.env" to "ERP_MIGRATION_PASSWORD=${pair.migrationPassword}\n" +
                "ERP_RUNTIME_PASSWORD=${pair.runtimePassword}\nERP_ADMIN_PASSWORD=$adminPassword\nERP_GENERATION=$generation\n" +
                "ERP_OWNER_PASSWORD=${grant.ownerPassword}\nERP_OUTSIDER_PASSWORD=${grant.outsiderPassword}\n" +
                "PYTHONDONTWRITEBYTECODE=1\n",
            "erp-maria-client.cnf" to "[client]\nuser=p0_erp\npassword=${pair.migrationPassword}\n" +
                "host=mariadb\nport=3306\nssl-ca=/run/secrets/mariadb-ca.pem\nssl-verify-server-cert\n",
            "erp-native-site-install.py" to releaseNativeSiteSource())
    }

    fun releaseNativeSiteSource(): String = """
        #!/usr/bin/env python3
        if not __debug__:
            raise SystemExit('Optimized Python refused before imports or effects')
        import hashlib
        import importlib.metadata
        import json
        import os
        from pathlib import Path
        import re
        import pymysql

        SITE = '$SITE'
        DB = 'p0_erp'
        SITES = Path('/home/frappe/frappe-bench/sites')
        CA = '/run/secrets/mariadb-ca.pem'
        MYSQL_CNF = '/run/secrets/erp-maria-client.cnf'
        INTENT = SITES / '.erp-native-site-install-intent.json'
        RECEIPT = SITES / '.erp-native-site-install-receipt.json'
        os.umask(0o077)

        def require(condition, reason):
            if not condition:
                raise RuntimeError(reason)

        def sync_directory(path):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)

        def exclusive(path, payload):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(payload); stream.flush(); os.fsync(stream.fileno())
            finally:
                sync_directory(path.parent)

        def canonical(value):
            return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()

        def pinned_image():
            source = json.loads(Path('/run/secrets/erp-source-attestation.json').read_text())
            require(set(source) == {'frappeVersion', 'rqVersion', 'redisVersion', 'hashes'} and
                source['frappeVersion'] == '15.125.0' and source['rqVersion'] == '1.15.1' and
                source['redisVersion'] == '4.5.5' and len(source['hashes']) == 18,
                'Foreign pinned ERP source manifest')
            for package, version in (('frappe', '15.125.0'), ('rq', '1.15.1'), ('redis', '4.5.5')):
                require(importlib.metadata.version(package) == version,
                    'ERP dependency version changed before native installer')
            root = Path('/home/frappe/frappe-bench/apps/frappe')
            rq = Path(importlib.metadata.distribution('rq').locate_file('rq'))
            for name, expected in source['hashes'].items():
                require(re.fullmatch(r'[a-f0-9]{64}', expected) and
                    name in {'frappe/installer.py', 'frappe/permissions.py', 'frappe/core/doctype/user/user.py',
                        'frappe/utils/password.py', 'frappe/core/doctype/system_settings/system_settings.json',
                        'frappe/commands/site.py', 'frappe/utils/redis_wrapper.py',
                        'frappe/utils/redis_queue.py', 'frappe/utils/background_jobs.py',
                        'frappe/database/__init__.py', 'frappe/database/mariadb/database.py',
                        'frappe/database/db_manager.py', 'frappe/realtime.py', 'realtime/index.js',
                        'node_utils.js', 'rq/queue.py', 'rq/worker.py', 'rq/command.py'},
                    'Foreign source path in ERP sealed manifest')
                file = rq / name.removeprefix('rq/') if name.startswith('rq/') else root / name
                require(file.is_file() and not file.is_symlink() and file.stat().st_size < 1048576 and
                    hashlib.sha256(file.read_bytes()).hexdigest() == expected,
                    'ERP image source changed before native installer')

        def main():
            pinned_image()  # Reads only; before Maria connection, site writes or intent.
            migration = os.environ['ERP_MIGRATION_PASSWORD']
            runtime = os.environ['ERP_RUNTIME_PASSWORD']
            admin = os.environ['ERP_ADMIN_PASSWORD']
            owner_password = os.environ['ERP_OWNER_PASSWORD']
            outsider_password = os.environ['ERP_OUTSIDER_PASSWORD']
            generation = os.environ['ERP_GENERATION']
            require(all(re.fullmatch(r'[a-f0-9]{64}', s) for s in
                (migration, runtime, admin, owner_password, outsider_password)) and
                len({migration, runtime, admin, owner_password, outsider_password}) == 5 and
                re.fullmatch(r'q-[a-f0-9]{12}', generation),
                'Foreign sealed ERP site credential or generation')
            require(SITES.is_dir() and not SITES.is_symlink() and not any(SITES.iterdir()) and
                not INTENT.exists() and not RECEIPT.exists(), 'Existing or uncertain ERP site retained')
            # Native, TLS-verifying Maria authentication and full visible table count precede effects.
            conn = pymysql.connect(host='mariadb', port=3306, user=DB, password=migration,
                database=DB, ssl={'ca': CA, 'check_hostname': True}, connect_timeout=5)
            try:
                with conn.cursor() as cursor:
                    cursor.execute('SELECT CURRENT_USER(), DATABASE()')
                    require(cursor.fetchone() == ('p0_erp@%', DB), 'Wrong native migration login')
                    cursor.execute('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=%s', (DB,))
                    require(cursor.fetchone()[0] == 0, 'Maria original tables or interrupted bootstrap exist')
                    cursor.execute('SHOW GRANTS')
                    grants = [row[0] for row in cursor.fetchall()]
                    require(any('ALL PRIVILEGES ON `p0_erp`.*' in grant for grant in grants) and
                        not any('WITH GRANT OPTION' in grant or 'CREATE USER ON *.*' in grant for grant in grants),
                        'Native fixed DB-only migration privilege absent or global grant present')
            finally:
                conn.close()
            # Exclusive durable intent BEFORE the first write; failure or lost ACK retains it forever.
            exclusive(INTENT, canonical({'generation': generation, 'database': DB, 'site': SITE,
                'migrationSha256': hashlib.sha256(migration.encode()).hexdigest(),
                'runtimeSha256': hashlib.sha256(runtime.encode()).hexdigest(),
                'ownerSha256': hashlib.sha256(owner_password.encode()).hexdigest(),
                'outsiderSha256': hashlib.sha256(outsider_password.encode()).hexdigest(), 'attempted': True}))
            exclusive(SITES / 'apps.txt', b'frappe\nerpnext\n')
            common = Path('/run/secrets/erp-common-site.json').read_bytes()
            conf = json.loads(common)
            require(conf['bench_id'] == 'p0v3-erp' and conf['default_site'] == SITE and
                conf['db_host'] == 'mariadb' and conf.get('pause_scheduler') == 0 and
                not conf.get('disable_scheduler'), 'Foreign sealed ERP bench profile')
            exclusive(SITES / 'common_site_config.json', common)
            (SITES / 'assets').symlink_to('/home/frappe/frappe-bench/assets', target_is_directory=True)
            sync_directory(SITES)
            site_dir = SITES / SITE
            site_dir.mkdir(mode=0o700)
            original = {'db_name': DB, 'db_password': migration, 'db_type': 'mariadb',
                'db_host': 'mariadb', 'db_port': 3306, 'db_ssl_ca': CA,
                'db_ssl_check_hostname': True}
            exclusive(site_dir / 'site_config.json', canonical(original))
            os.chdir(SITES)
            import frappe.database as database
            actual_get_command = database.get_command
            def safe_native_import(*args, **kwargs):
                require(kwargs.get('user') == DB and kwargs.get('db_name') == DB and
                    kwargs.get('password') == migration and not kwargs.get('dump') and
                    kwargs.get('host') == 'mariadb' and kwargs.get('port') == 3306,
                    'Foreign native Maria import refused')
                binary, argv, binary_name = actual_get_command(*args, **kwargs)
                require(Path(binary).name in ('mysql', 'mariadb') and
                    argv.count('--password=' + migration) == 1 and '--user=p0_erp' in argv and
                    argv[-1] == DB and all('--password=' not in arg or arg == '--password=' + migration for arg in argv),
                    'Pinned native import command changed')
                return (binary, ['--defaults-extra-file=' + MYSQL_CNF] +
                    [arg for arg in argv if arg != '--password=' + migration], binary_name)
            database.get_command = safe_native_import
            from frappe.commands.site import new_site
            new_site.callback(site=SITE, admin_password=admin, db_name=DB, db_password=migration,
                db_type='mariadb', db_host='mariadb', db_port=3306,
                install_app=('erpnext',), set_default=True, force=True, setup_db=False)
            import frappe
            frappe.destroy(); frappe.init(site=SITE); frappe.connect()
            require({'frappe', 'erpnext'}.issubset(set(frappe.get_installed_apps())) and
                frappe.get_doc('User', 'Administrator').name == 'Administrator',
                'Native ERP apps/admin user were not installed')
            from frappe.utils.password import get_encryption_key
            require(bool(get_encryption_key()), 'Native Frappe encryption key was not generated')
            # Same original site-install intent: no second bootstrap or retryable
            # mutation. The site administrator remains installer-only; only these
            # two non-admin users are released for original APP-host workflows.
            frappe.set_user('Administrator')
            from frappe.permissions import add_permission, update_permission_property
            from frappe.utils.password import check_password, update_password
            role = '$FRESH_LEDGER_ROLE'
            owner_email = '$FRESH_OWNER_EMAIL'
            outsider_email = '$FRESH_OUTSIDER_EMAIL'
            assert_owner = '$FRESH_OWNER'
            assert_outsider = '$FRESH_OUTSIDER'
            require(not frappe.db.exists('Role', role) and
                not any(frappe.db.exists('User', email) for email in (owner_email, outsider_email)) and
                not any(frappe.db.exists('User', {'username': name}) for name in
                    (assert_owner, assert_outsider)) and frappe.get_meta('Journal Entry').is_submittable,
                'Foreign ERP actor, role or ledger DocType')
            created_role = frappe.get_doc({'doctype': 'Role', 'role_name': role,
                'desk_access': 1}).insert(ignore_permissions=True)
            require(created_role.name == role, 'ERP scoped ledger role not created')
            # Native Custom DocPerm rules govern both REST and Desk. No broad
            # Accounts Manager or System Manager role is assigned to either user.
            rights = {'Customer': ('read', 'create'),
                'Journal Entry': ('read', 'create', 'write', 'submit'),
                'GL Entry': ('read',), 'Company': ('read',), 'Account': ('read',),
                'Scheduled Job Log': ('read',), 'Customer Group': ('read',),
                'Territory': ('read',)}
            for doctype, allowed in rights.items():
                require(frappe.db.exists('DocType', doctype), 'ERP scoped DocType absent')
                add_permission(doctype, role)
                for permission in allowed:
                    update_permission_property(doctype, role, 0, permission, 1)
            # Keycloak's selected username is owner/outsider, while Frappe stores
            # User.name as email. Enable Frappe's native, scoped username login.
            frappe.db.set_single_value('System Settings', 'allow_login_using_user_name', 1)
            # The real bench scheduler/worker start only after Maria cutover.
            # Frappe also consults System Settings, not just pause_scheduler.
            frappe.db.set_single_value('System Settings', 'enable_scheduler', 1)
            for username, email, password, user_type in (
                (assert_owner, owner_email, owner_password, 'System User'),
                (assert_outsider, outsider_email, outsider_password, 'Website User')):
                user = frappe.get_doc({'doctype': 'User', 'email': email,
                    'username': username, 'first_name': 'Fresh ERP ' + username,
                    'enabled': 1, 'user_type': user_type, 'send_welcome_email': 0})
                user.flags.no_welcome_mail = True
                if username == assert_owner:
                    user.append('roles', {'role': role})
                user.insert(ignore_permissions=True)
                update_password(email, password)
            frappe.db.commit()  # Native role, hashes and user rows before receipt.
            frappe.clear_cache()
            native_jobs = frappe.get_all('Scheduled Job Type', filters={'stopped': 0},
                fields=['method'], limit_page_length=1000)
            require(native_jobs and any(str(job.method).startswith('frappe.') for job in native_jobs) and
                frappe.db.get_single_value('System Settings', 'enable_scheduler') in (1, '1'),
                'Fresh ERP has no enabled native Frappe scheduler source')
            require(frappe.db.get_single_value('System Settings', 'allow_login_using_user_name') in (1, '1') and
                check_password(owner_email, owner_password) == owner_email and
                check_password(outsider_email, outsider_password) == outsider_email and
                frappe.get_doc('User', owner_email).username == assert_owner and
                frappe.get_doc('User', outsider_email).username == assert_outsider and
                role in frappe.get_roles(owner_email) and role not in frappe.get_roles(outsider_email),
                'ERP native actor login/readback refused')
            for doctype, allowed in rights.items():
                for permission in allowed:
                    require(frappe.has_permission(doctype, permission, user=owner_email,
                        raise_exception=False), 'ERP scoped owner permission absent')
            for doctype in ('Customer', 'Journal Entry'):
                for permission in ('read', 'create'):
                    require(not frappe.has_permission(doctype, permission, user=outsider_email,
                        raise_exception=False), 'ERP outsider reached original business scope')
            for doctype in ('GL Entry', 'Company', 'Account', 'Scheduled Job Log'):
                for permission in ('create', 'write', 'submit', 'delete'):
                    require(not frappe.has_permission(doctype, permission, user=owner_email,
                        raise_exception=False), 'ERP ledger reader gained write authority')
            frappe.destroy()
            # One-shot switch on ORIGINAL site config; COORD journals local-socket
            # REVOKE/GRANT/ALTER USER and proves new password succeeds + old fails
            # BEFORE starting any daemon. Never rewrite a restored site here.
            generated = json.loads((site_dir / 'site_config.json').read_text())
            require(generated.get('db_name') == DB and generated.get('db_password') == migration and
                generated.get('db_ssl_ca') == CA and generated.get('db_ssl_check_hostname') is True and
                all(generated.get(key) == value for key, value in original.items()) and
                generated.get('encryption_key'), 'Native generated original site keys or migration identity changed')
            target = dict(generated, db_password=runtime)  # Preserve EVERY original native key.
            temp = site_dir / 'site_config.json.pending-runtime'
            exclusive(temp, canonical(target))
            os.replace(temp, site_dir / 'site_config.json')
            sync_directory(site_dir)
            exclusive(RECEIPT, canonical({'generation': generation, 'database': DB, 'site': SITE,
                'originalAdminId': 'Administrator', 'runtimeConfigSha256': hashlib.sha256(canonical(target)).hexdigest(),
                'nativeApps': ['erpnext', 'frappe'], 'cutoverPending': True,
                'ownerUser': '$FRESH_OWNER', 'ownerEmail': '$FRESH_OWNER_EMAIL',
                'outsiderUser': '$FRESH_OUTSIDER', 'outsiderEmail': '$FRESH_OUTSIDER_EMAIL',
                'ledgerRole': '$FRESH_LEDGER_ROLE', 'schedulerEnabled': True}))
        main()
    """.trimIndent() + "\n"

    /** The one shared Valkey speaks Frappe v15.125.0 / RQ v1.15.1 native keys, not
     * fabricated app:erpnext:* keys. Only this fixed authenticated bridge may join
     * both erp-cache and the provider's cache-data networks. The application never
     * receives the native provider password or a direct cache-data network edge.
     */
    /** Exact owner-launched one-shot cutover, with an exclusive durable intent
     * before privileged Maria SQL and a separately durable native readback result.
     * Its cutover-only CREATE USER principal is never exposed to Frappe daemons,
     * is confined to the provider's admin network, and removes itself on success. */
    fun releaseMariaCutover(inventory: AcquiredInventory, name: String): RuntimeProcess {
        val image = inventory.images.single { it.product == "erpnext" }
        require(name.matches(Regex("[a-z][a-z0-9-]{1,47}")))
        return RuntimeProcess("erp-maria-cutover", image.pinnedImage, image.imageId, 1000,
            dependencies = listOf("erp-native-site-install"), oneShot = true,
            entrypoint = "/home/frappe/frappe-bench/env/bin/python",
            command = listOf("/run/secrets/erp-maria-cutover.py"), environmentFile = "erp-maria-cutover.env",
            files = listOf(RuntimeFile("erp-maria-cutover.py", "/run/secrets/erp-maria-cutover.py"),
                RuntimeFile("mariadb-ca.pem", "/run/secrets/mariadb-ca.pem")),
            volumes = listOf(RuntimeMount("erp-sites", "/home/frappe/frappe-bench/sites")),
            networks = listOf("maria-admin"), memoryMiB = 256, apparmorProfile = "p0v3-private-v1")
    }

    fun releaseMariaCutoverInputs(pair: CanonicalMariaCredentialPair, cutoverPassword: String,
        generation: String): Map<String, String> {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
            cutoverPassword.matches(Regex("[a-f0-9]{64}")) &&
            cutoverPassword !in setOf(pair.migrationPassword, pair.runtimePassword))
        return mapOf("erp-maria-cutover.env" to
            "ERP_MIGRATION_PASSWORD=${pair.migrationPassword}\nERP_RUNTIME_PASSWORD=${pair.runtimePassword}\n" +
                "ERP_CUTOVER_PASSWORD=$cutoverPassword\nERP_GENERATION=$generation\nPYTHONDONTWRITEBYTECODE=1\n",
            "erp-maria-cutover.py" to requireNotNull(javaClass.getResource("/runtime/erpnext_maria_cutover.py"))
                .readText())
    }

    fun releaseRedisBridge(inventory: AcquiredInventory, name: String): RuntimeProcess {
        val image = inventory.images.single { it.product == "erpnext" }
        require(name.matches(Regex("[a-z][a-z0-9-]{1,47}")))
        return RuntimeProcess("erp-redis-bridge", image.pinnedImage, image.imageId, 1000,
            dependencies = listOf("valkey"), entrypoint = "/home/frappe/frappe-bench/env/bin/python",
            command = listOf("/run/secrets/erp-redis-bridge.py"), environmentFile = "erp-bridge.env",
            files = listOf(RuntimeFile("erp-redis-bridge.py", "/run/secrets/erp-redis-bridge.py"),
                RuntimeFile("erp-source-attestation.json", "/run/secrets/erp-source-attestation.json")),
            networks = listOf("cache-data", "erp-cache"), memoryMiB = 128,
            apparmorProfile = "p0v3-private-v1", readiness = listOf("/home/frappe/frappe-bench/env/bin/python", "-c",
                "import socket; s=socket.create_connection(('127.0.0.1',6379),3); s.close()"))
    }

    /** Fixed bridge protocol: authenticated local-only RESP2/RESP3 transport, and the
     * pinned Frappe cache KEYS pattern is checked BEFORE reaching the shared provider.
     * Valkey 7.2.15 marks KEYS DANGEROUS and has no ACL key_spec; key ACLs alone do
     * not constrain KEYS */
    fun releaseRedisBridgeInputs(clientPassword: String, providerPassword: String): Map<String, String> {
        require(clientPassword.matches(Regex("[a-f0-9]{64}")) &&
            providerPassword.matches(Regex("[a-f0-9]{64}")) && clientPassword != providerPassword)
        return mapOf("erp-bridge.env" to "ERP_CLIENT_PASSWORD=$clientPassword\nERP_PROVIDER_PASSWORD=$providerPassword\n",
            "erp-redis-bridge.py" to releaseRedisBridgeSource())
    }

    /** Packaged ONE reviewed production implementation. The developer-facing
     * platform/scripts entrypoint delegates to this same resource, never a copy.
     * Gradle's ordinary main resources include this fixed A09-owned path.
     */
    fun releaseRedisBridgeSource(): String = ErpNextRuntime::class.java
        .getResource("/runtime/erpnext_redis_bridge.py")?.readText()
        ?: error("Missing fixed packaged ERP Redis bridge")

    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "erpnext", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }
    fun inputs(pki: () -> Map<String, String> = { PrivateWebPki.generate("erp") }): Map<String, String> {
        val installer = RuntimePreparation.password(); val cache = RuntimePreparation.password(); val queue = RuntimePreparation.password()
        fun redis(password: String, persistent: Boolean) = "bind 0.0.0.0\nprotected-mode yes\nport 6379\ndir /data\nrequirepass $password\nsave \"\"\nappendonly ${if (persistent) "yes" else "no"}\nappendfsync everysec\n"
        val common = buildJsonObject {
            put("db_host", "mariadb"); put("db_port", 3306); put("redis_cache", "redis://:$cache@cache:6379")
            put("redis_queue", "redis://:$queue@queue:6379"); put("redis_socketio", "redis://:$queue@queue:6379")
            put("socketio_port", 9000); put("webserver_host", "backend"); put("webserver_port", 8000); put("default_site", SITE); put("serve_default_site", true)
            put("host_name", "https://erp:8443"); put("disable_telemetry", 1); put("developer_mode", 0)
            put("server_script_enabled", false); put("pause_scheduler", 1)
        }
        return pki() + mapOf("process-init.py" to ErpNextRuntime::class.java.getResource("/runtime/process-init.py")!!.readText(),
            "mariadb.env" to "MARIADB_ROOT_PASSWORD=${RuntimePreparation.password()}\nINSTALLER_PASSWORD=$installer\n",
            "installer.env" to "INSTALLER_PASSWORD=$installer\n",
            "bootstrap.env" to "INSTALLER_PASSWORD=$installer\nADMIN_PASSWORD=${RuntimePreparation.password()}\nSITE_DB_PASSWORD=${RuntimePreparation.password()}\nPYTHONDONTWRITEBYTECODE=1\n",
            "erp.env" to "PYTHONDONTWRITEBYTECODE=1\nHOME=/home/frappe\n",
            "cache.conf" to redis(cache, false), "queue.conf" to redis(queue, true), "common-site.json" to "$common\n",
            "site-config.py" to """
                import os, json
                from pathlib import Path
                if not __debug__:
                    raise SystemExit('Optimized Python refused')
                os.umask(0o077)
                sites = Path('/site-state')
                if list(sites.iterdir()):
                    raise SystemExit('Existing or interrupted site retained')
                (sites / 'apps.txt').write_text('frappe\nerpnext\n')
                (sites / 'common_site_config.json').write_text(Path('/run/secrets/common-site.json').read_text())
                (sites / 'assets').symlink_to('/home/frappe/frappe-bench/assets', target_is_directory=True)
            """.trimIndent() + "\n", "site-init.py" to """
                import os
                from pathlib import Path
                if not __debug__:
                    raise SystemExit('Optimized Python refused')
                os.umask(0o077)
                sites = Path('/home/frappe/frappe-bench/sites')
                if (sites / '$SITE').exists() or not (sites / 'common_site_config.json').is_file():
                    raise SystemExit('Existing or interrupted site retained')
                os.chdir(sites)
                from frappe.commands.site import new_site
                new_site.callback(site='$SITE', db_root_username='frappe_installer', db_root_password=os.environ['INSTALLER_PASSWORD'],
                    admin_password=os.environ['ADMIN_PASSWORD'], db_name='p0_erp', db_password=os.environ['SITE_DB_PASSWORD'],
                    db_type='mariadb', db_host='mariadb', db_port=3306, mariadb_user_host_login_scope='%',
                    install_app=('erpnext',), set_default=True, force=False)
                import frappe
                frappe.destroy()
            """.trimIndent() + "\n", "nginx.conf" to """
                worker_processes 1;
                pid /tmp/nginx.pid;
                error_log /tmp/nginx-error.log warn;
                events { worker_connections 512; }
                http {
                    include /etc/nginx/mime.types;
                    access_log off;
                    client_body_temp_path /tmp/body;
                    proxy_temp_path /tmp/proxy;
                    fastcgi_temp_path /tmp/fastcgi;
                    uwsgi_temp_path /tmp/uwsgi;
                    scgi_temp_path /tmp/scgi;
                    map ${'$'}http_upgrade ${'$'}connection_upgrade { default upgrade; '' close; }
                    map ${'$'}http_origin ${'$'}erp_origin { default ${'$'}http_origin; '' https://erp:8443; }
                    server { listen 8080; location = /healthz { return 200 'ready'; } location / { return 404; } }
                    server {
                        listen 8443 ssl;
                        server_name erp;
                        ssl_certificate /run/secrets/web.pem;
                        ssl_certificate_key /run/secrets/web-key.pem;
                        ssl_protocols TLSv1.2 TLSv1.3;
                        client_max_body_size 10m;
                        location /assets/ { alias /home/frappe/frappe-bench/assets/; }
                        location /files/ { alias /home/frappe/frappe-bench/sites/$SITE/public/files/; }
                        location /socket.io/ {
                            proxy_pass http://websocket:9000;
                            proxy_http_version 1.1;
                            proxy_set_header Upgrade ${'$'}http_upgrade;
                            proxy_set_header Connection ${'$'}connection_upgrade;
                            proxy_set_header Origin ${'$'}erp_origin;
                            proxy_set_header Host ${'$'}http_host;
                            proxy_set_header X-Frappe-Site-Name $SITE;
                        }
                        location / {
                            proxy_pass http://backend:8000;
                            proxy_set_header Host ${'$'}http_host;
                            proxy_set_header X-Forwarded-Proto https;
                            proxy_set_header X-Frappe-Site-Name $SITE;
                        }
                    }
                }
            """.trimIndent() + "\n")
    }
}
