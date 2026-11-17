package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.add
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** A provider-less application contribution, compiled into the one fixed canonical member.
 * Its spec is a partial graph: external provider edges are resolved by composeProviders, not
 * by creating another SQL/cache daemon or copying a provider volume into an application member.
 */
internal enum class CanonicalIdentityWebConsumer(val product: String, val process: String) {
    MAS("matrix-authentication-service", "mas"), BOOKSTACK_PHP("bookstack", "bookstack-php")
}
internal data class CanonicalProviderFragment(val product: String, val spec: PrivateDeploymentSpec,
    val providerNetworks: Map<String, Set<String>> = emptyMap(),
    val webNetworks: Set<String> = emptySet(),
    /** Only fixed, reviewed process IDs on the existing private Caddy/Keycloak identity-web. */
    val identityWebConsumers: Set<CanonicalIdentityWebConsumer> = emptySet())
/** A selected application's unique Valkey principal; only its exact key/channel namespace is granted. */
internal data class CanonicalCachePrincipal(val product: String, val password: String) {
    val username: String get() = product.replace('-', '_')
    val namespace: String get() = if (product == "erpnext") "p0_erp|" else "app:$product:"
    /** Frappe v15.125.0 uses a DB-qualified cache namespace, RQ v1.15.1 uses
     * separate queue/worker keys, and realtime publishes fixed channels. This
     * principal is ONLY injected into the A09 authenticated fixed bridge; ERP
     * daemons never obtain this password or a direct cache-data edge. The bridge
     * restricts KEYS (Valkey 7.2.15 has no key spec) and rejects arbitrary SCAN,
     * scripting, key enumeration and non-ERP channels before this ACL is reached.
     */
    fun aclRule(): String {
        require(product != "mastodon") {
            "Original Mastodon Redis/Sidekiq keys and channels have no authenticated namespace projection; " +
                "a shared Valkey ACL would either expose peer keys or reject live work"
        }
        return if (product == "erpnext") {
        "user $username on >$password ~p0_erp|* ~rq:[^q]* ~rq:queues ~rq:queue:p0v3-erp:* " +
            "&events &open_in_editor &rq:pubsub:* -@all +@read +@write +@pubsub +@connection " +
            "+@scripting +@transaction -@admin -@dangerous +keys +ping\n"
    } else "user $username on >$password ~${namespace}* &${namespace}* -@all +get +set +del +exists +expire +ttl +lpush +rpush +lpop +rpop +llen +ping\n"
    }
}

/** Reviewed fixed bootstrap adapter, never an arbitrary SQL string or a remote root grant. */
internal enum class CanonicalMariaGrant { SEAFILE, ERPNEXT, BOOKSTACK }

/** One fixed, reviewed account-lock operation, never caller SQL or a generic shell hook.
 * COORD journals the attempted local-only MariaDB action and requires native lock readback.
 */
internal data class CanonicalMariaRetirement(val grant: CanonicalMariaGrant, val migrationAccount: String,
    val databases: Set<String>, val lockStatement: String, val readbackStatement: String)

/** Pinned Frappe 15.125.0 hardcodes its Maria login to db_name (`p0_erp`), ignoring db_user.
 * Thus ERP's single original native login must have DDL removed and its password rotated
 * under a journalled local-only provider action before any application daemon starts.
 * The literal `$ERP_RUNTIME_PASSWORD` comes from sealed one-shot custody, never argv.
 */
internal data class CanonicalErpMariaCutover(val account: String, val database: String,
    val beforeSessionCensus: String, val killSessionsStatement: String, val afterSessionCensus: String,
    val revokeStatement: String, val runtimeGrantStatement: String,
    val rotateStatement: String, val readbackStatement: String)

/** Generated only after the complete graph passes pure validation, then shared by A08's sealed
 * native migration/runtime envs and the original, one-shot-only MariaDB bootstrap input.
 */
internal data class CanonicalMariaCredentialPair(val migrationPassword: String, val runtimePassword: String) {
    init {
        require(migrationPassword.matches(Regex("[a-f0-9]{64}")) &&
            runtimePassword.matches(Regex("[a-f0-9]{64}")) && migrationPassword != runtimePassword)
    }
}

/** First canonical provider cohort: one PostgreSQL, distinct administration/data/frontend networks,
 * TLS-verified Planka connections and a retired migration principal. No public routes or boot enrollment. */
internal object CanonicalCoreRuntime {
    private val ca = RuntimeFile("postgres-ca.pem", "/run/secrets/postgres-ca.pem")
    /** Fixed shared Maria provider local-socket bootstrap once; no global CREATE USER grant
     * reaches Frappe's installer or application, and no second MariaDB is created. */
    private val erpMariaBootstrapSql = """
        CREATE DATABASE p0_erp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
        CREATE USER 'p0_erp'@'%' IDENTIFIED BY '${'$'}ERP_MIGRATION_PASSWORD';
        GRANT ALL PRIVILEGES ON p0_erp.* TO 'p0_erp'@'%';
    """.trimIndent().replace("\n", "\n                    ")
    private val bookstackMariaBootstrapSql = """
        CREATE DATABASE bookstack CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
        CREATE USER 'bookstack_migrate'@'%' IDENTIFIED BY '${'$'}BOOKSTACK_MIGRATION_PASSWORD';
        CREATE USER 'bookstack_runtime'@'%' IDENTIFIED BY '${'$'}BOOKSTACK_RUNTIME_PASSWORD';
        GRANT CREATE, ALTER, DROP, INDEX, REFERENCES, SELECT, INSERT, UPDATE, DELETE ON bookstack.* TO 'bookstack_migrate'@'%';
        GRANT SELECT, INSERT, UPDATE, DELETE ON bookstack.* TO 'bookstack_runtime'@'%';
    """.trimIndent().replace("\n", "\n                    ")
    private val seafileMariaBootstrapSql = """
        CREATE DATABASE ccnet_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
        CREATE DATABASE seafile_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
        CREATE DATABASE seahub_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
        CREATE USER 'seafile_migrate'@'%' IDENTIFIED BY '${'$'}SEAFILE_MIGRATION_PASSWORD';
        CREATE USER 'seafile_runtime'@'%' IDENTIFIED BY '${'$'}SEAFILE_RUNTIME_PASSWORD';
        GRANT CREATE, ALTER, DROP, INDEX, REFERENCES, SELECT, INSERT, UPDATE, DELETE ON ccnet_db.* TO 'seafile_migrate'@'%';
        GRANT CREATE, ALTER, DROP, INDEX, REFERENCES, SELECT, INSERT, UPDATE, DELETE ON seafile_db.* TO 'seafile_migrate'@'%';
        GRANT CREATE, ALTER, DROP, INDEX, REFERENCES, SELECT, INSERT, UPDATE, DELETE ON seahub_db.* TO 'seafile_migrate'@'%';
        GRANT SELECT, INSERT, UPDATE, DELETE ON ccnet_db.* TO 'seafile_runtime'@'%';
        GRANT SELECT, INSERT, UPDATE, DELETE ON seafile_db.* TO 'seafile_runtime'@'%';
        GRANT SELECT, INSERT, UPDATE, DELETE ON seahub_db.* TO 'seafile_runtime'@'%';
    """.trimIndent().replace("\n", "\n                    ")
    /** Execute only through COORD's journalled local Maria socket; uncertain attempt is not retried. */
    fun mariaMigrationRetirement(grant: CanonicalMariaGrant): CanonicalMariaRetirement {
        require(grant != CanonicalMariaGrant.ERPNEXT) { "Pinned Frappe uses one DB-named login; it cannot be ACCOUNT LOCKed" }
        val (account, databases) = when (grant) {
            CanonicalMariaGrant.SEAFILE -> "seafile_migrate" to setOf("ccnet_db", "seafile_db", "seahub_db")
            CanonicalMariaGrant.BOOKSTACK -> "bookstack_migrate" to setOf("bookstack")
            CanonicalMariaGrant.ERPNEXT -> error("ERP uses native role cutover, not migration login retirement")
        }
        return CanonicalMariaRetirement(grant, account, databases,
            "ALTER USER '$account'@'%' ACCOUNT LOCK;",
            "SHOW CREATE USER '$account'@'%';")
    }

    fun erpMariaCutover(): CanonicalErpMariaCutover = CanonicalErpMariaCutover(
        account = "p0_erp", database = "p0_erp",
        beforeSessionCensus = "SELECT ID FROM information_schema.PROCESSLIST WHERE USER = 'p0_erp';",
        killSessionsStatement = "KILL USER p0_erp;",
        afterSessionCensus = "SELECT ID FROM information_schema.PROCESSLIST WHERE USER = 'p0_erp';",
        revokeStatement = "REVOKE ALL PRIVILEGES ON p0_erp.* FROM 'p0_erp'@'%';",
        runtimeGrantStatement = "GRANT SELECT, INSERT, UPDATE, DELETE ON p0_erp.* TO 'p0_erp'@'%';",
        rotateStatement = "ALTER USER 'p0_erp'@'%' IDENTIFIED BY '${'$'}ERP_RUNTIME_PASSWORD';",
        readbackStatement = "SHOW GRANTS FOR 'p0_erp'@'%';")

    fun spec(inventory: AcquiredInventory, name: String = "canonical-core"): PrivateDeploymentSpec {
        val foundation = FoundationRuntime.spec(inventory, name)
        val planka = PlankaRuntime.spec(inventory, name)
        val pg = foundation.processes.single { it.id == "postgres" }
        val clientFiles = listOf(ca)
        fun admin(id: String, dependencies: List<String>, sql: String) = RuntimeProcess(id, pg.image, pg.imageId, 999,
            dependencies = dependencies, entrypoint = "/bin/sh", environmentFile = "postgres-admin.env",
            files = clientFiles, networks = listOf("db-admin"), oneShot = true, apparmorProfile = "p0v3-private-v1",
            command = listOf("-ec", sql))
        val processes = foundation.processes.map { process -> when (process.id) {
            "postgres-init" -> process.copy(networks = listOf("db-admin"))
            "postgres" -> process.copy(networks = listOf("net", "db-admin", "planka-data"), files = listOf(
                RuntimeFile("postgres.pem", "/run/secrets/postgres.pem"), RuntimeFile("postgres-key.pem", "/run/secrets/postgres-key.pem"),
                RuntimeFile("postgres-hba.conf", "/run/secrets/postgres-hba.conf")), command = process.command + listOf(
                "-c", "ssl=on", "-c", "ssl_cert_file=/run/secrets/postgres.pem", "-c", "ssl_key_file=/run/secrets/postgres-key.pem",
                "-c", "hba_file=/run/secrets/postgres-hba.conf"))
            else -> process
        } } + listOf(
            admin("planka-db-init", listOf("postgres"), """
                psql -X -v ON_ERROR_STOP=1 <<SQL
                REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
                REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
                CREATE ROLE planka_migrate LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '${'$'}PLANKA_MIGRATION_PASSWORD';
                CREATE ROLE planka LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '${'$'}PLANKA_PASSWORD';
                CREATE DATABASE planka OWNER planka_migrate;
                REVOKE ALL ON DATABASE planka FROM PUBLIC;
                GRANT CONNECT ON DATABASE planka TO planka;
                SQL
            """.trimIndent()),
            planka.processes.single { it.id == "planka-init" }.copy(environmentFile = "planka-bootstrap.env",
                networks = listOf("planka-data"), files = planka.processes.single { it.id == "planka-init" }.files + ca),
            admin("postgres-finalize", listOf("planka-init"), """
                psql -X -d planka -v ON_ERROR_STOP=1 <<'SQL'
                REVOKE CREATE ON SCHEMA public FROM PUBLIC;
                GRANT USAGE ON SCHEMA public TO planka;
                GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO planka;
                GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO planka;
                ALTER ROLE planka_migrate NOLOGIN;
                SQL
            """.trimIndent()),
            planka.processes.single { it.id == "planka" }.copy(dependencies = listOf("postgres-finalize"),
                networks = listOf("planka-web", "planka-data"), files = planka.processes.single { it.id == "planka" }.files + ca + RuntimeFile("planka-database.js", "/app/config/local.js"))
        )
        return foundation.copy(volumes = foundation.volumes + planka.volumes.filter { it.id != "postgres" }, processes = processes,
            networks = listOf("net", "db-admin", "planka-data", "planka-web"), databaseAccess = listOf(
                RuntimeDatabaseAccess("planka-init", "postgres", "postgres", "planka", "planka_migrate", "planka-bootstrap.env", "planka-data"),
                RuntimeDatabaseAccess("planka", "postgres", "postgres", "planka", "planka", "planka.env", "planka-data")
            )).also { PrivateDeployment.validate(it) }
    }

    fun inputs(pki: () -> Map<String, String> = { PrivateWebPki.generate("postgres") },
        password: () -> String = RuntimePreparation::password): Map<String, String> {
        val secrets = List(6) { password() }
        require(secrets.distinct().size == secrets.size && secrets.all { it.matches(Regex("[a-f0-9]{64}")) })
        val (postgres, application, migration, key, admin) = secrets
        val cache = secrets[5]
        val tls = pki()
        require(tls.keys == setOf("ca.pem", "web.pem", "web-key.pem"))
        val common = "NODE_ENV=production\nLOG_FILE=/tmp/planka.log\nBASE_URL=http://planka:1337\nSECRET_KEY=$key\nNODE_EXTRA_CA_CERTS=/run/secrets/postgres-ca.pem\nOUTGOING_PROXY=http://127.0.0.1:9\n"
        fun app(role: String, secret: String) = common + "DATABASE_URL=postgresql://$role:$secret@postgres:5432/planka?sslmode=verify-full\n"
        return mapOf(
            "postgres.env" to "POSTGRES_PASSWORD=$postgres\n",
            "postgres-admin.env" to "PGPASSWORD=$postgres\nPGHOST=postgres\nPGUSER=postgres\nPGDATABASE=postgres\nPGSSLMODE=verify-full\nPGSSLROOTCERT=/run/secrets/postgres-ca.pem\nPLANKA_PASSWORD=$application\nPLANKA_MIGRATION_PASSWORD=$migration\n",
            "postgres-ca.pem" to tls.getValue("ca.pem"), "postgres.pem" to tls.getValue("web.pem"), "postgres-key.pem" to tls.getValue("web-key.pem"),
            "postgres-hba.conf" to "local all postgres trust\nlocal all all reject\nhostnossl all all 0.0.0.0/0 reject\nhostssl all all 0.0.0.0/0 scram-sha-256\nhostnossl all all ::/0 reject\nhostssl all all ::/0 scram-sha-256\n",
            // Sails' adapter does not preserve URL sslmode. Configure verified TLS explicitly as well.
            "planka-database.js" to "module.exports = { datastores: { default: { ssl: { rejectUnauthorized: true, ca: require('fs').readFileSync('/run/secrets/postgres-ca.pem') } } } };\n",
            "planka.env" to app("planka", application),
            "planka-bootstrap.env" to app("planka_migrate", migration) + "DEFAULT_ADMIN_EMAIL=bootstrap@localhost.invalid\nDEFAULT_ADMIN_USERNAME=p0v3_bootstrap\nDEFAULT_ADMIN_NAME=Private bootstrap\nDEFAULT_ADMIN_PASSWORD=$admin\n",
            "fixture-terms.md" to PlankaRuntime.FIXTURE_TERMS,
            "valkey.conf" to "bind 0.0.0.0\nprotected-mode yes\nport 6379\ndir /data\nappendonly yes\nappendfsync everysec\nrequirepass $cache\n"
        )
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "canonical-core", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }

    /** Historical e51e8dc canonical-providers compiler. Explicitly retain the V1 catalog API. */
    fun providersSpec(inventory: AcquiredInventory, name: String = "canonical-providers"): PrivateDeploymentSpec =
        legacyProvidersSpec(inventory, name)

    fun legacyProvidersSpec(inventory: AcquiredInventory, name: String = "canonical-providers"): PrivateDeploymentSpec =
        providerSpecVersion(inventory, name, release = false)

    /** Versioned new full-release cohort. Never use for historical canonical-providers reconstruction. */
    fun releaseProvidersSpec(inventory: AcquiredInventory, name: String = "canonical-release-v2",
        mariaGrants: Set<CanonicalMariaGrant> = emptySet()): PrivateDeploymentSpec =
        providerSpecVersion(inventory, name, release = true, mariaGrants)

    private fun providerSpecVersion(inventory: AcquiredInventory, name: String, release: Boolean,
        mariaGrants: Set<CanonicalMariaGrant> = emptySet()): PrivateDeploymentSpec {
        require(release || mariaGrants.isEmpty()) { "Historical V1 cannot acquire a MariaDB grant" }
        val core = spec(inventory, name)
        val sql = SqlCacheRuntime.spec(inventory, name)
        val ntfy = core.processes.single { it.id == "ntfy" }
        val processes = core.processes.map { process -> when (process.id) {
            "postgres" -> process.copy(networks = process.networks - "net", files = process.files + ca)
            "planka-db-init" -> if (!release) process else process.copy(files = process.files + RuntimeFile("postgres-qualification.env", "/run/secrets/postgres-qualification.env"),
                command = listOf("-ec", ". /run/secrets/postgres-qualification.env\n" + process.command.last() + "\n" + """
                    psql -X -v ON_ERROR_STOP=1 <<SQL
                    CREATE ROLE qualification LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '${'$'}POSTGRES_QUALIFICATION_PASSWORD';
                    CREATE DATABASE qualification OWNER qualification;
                    REVOKE ALL ON DATABASE qualification FROM PUBLIC;
                    SQL
                """.trimIndent()))
            "valkey" -> process.copy(networks = listOf("cache-data"), environmentFile = "valkey-health.env",
                files = process.files + RuntimeFile("valkey.acl", "/etc/valkey/users.acl"),
                readiness = listOf("/bin/sh", "-ec", "export REDISCLI_AUTH=\"${'$'}VALKEY_HEALTH_PASSWORD\"; test \"${'$'}(valkey-cli --user health ping)\" = PONG"))
            "ntfy" -> process.copy(dependencies = listOf("ntfy-auth-init"), networks = listOf("ntfy-web"),
                command = listOf("serve", "--config=/run/secrets/ntfy.yml"),
                files = listOf(RuntimeFile("ntfy.yml", "/run/secrets/ntfy.yml")))
            else -> process
        } } + ntfy.copy(id = "ntfy-auth-init", oneShot = true, readiness = emptyList(),
            networks = listOf("ntfy-web"), entrypoint = "/bin/sh", environmentFile = "ntfy-bootstrap.env",
            files = listOf(RuntimeFile("ntfy.yml", "/run/secrets/ntfy.yml")), command = listOf("-ec", if (release) """
                test ! -e /var/cache/ntfy/auth.db
                ntfy serve --config=/run/secrets/ntfy.yml --listen-http=127.0.0.1:8080 &
                pid=${'$'}!
                trap 'kill -TERM "${'$'}pid" 2>/dev/null || true; wait "${'$'}pid" 2>/dev/null || true' EXIT HUP INT TERM
                ready=false
                for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
                    if wget -q -O - http://127.0.0.1:8080/v1/health | grep -q '"healthy":true'; then ready=true; break; fi
                    sleep 1
                done
                test "${'$'}ready" = true
                kill -TERM "${'$'}pid"
                wait "${'$'}pid"
                trap - EXIT HUP INT TERM
                test -s /var/cache/ntfy/auth.db
                ntfy tier --config=/run/secrets/ntfy.yml add --message-expiry-duration=840h p0history
                ntfy tier --config=/run/secrets/ntfy.yml add --message-expiry-duration=60s p0expiry
                ntfy user --config=/run/secrets/ntfy.yml add publisher
                ntfy user --config=/run/secrets/ntfy.yml change-tier publisher p0history
                ntfy access --config=/run/secrets/ntfy.yml publisher 'events-*' rw
                export NTFY_PASSWORD="${'$'}NTFY_SUBSCRIBER_PASSWORD"
                ntfy user --config=/run/secrets/ntfy.yml add subscriber
                ntfy user --config=/run/secrets/ntfy.yml change-tier subscriber p0history
                ntfy access --config=/run/secrets/ntfy.yml subscriber 'events-*' ro
                export NTFY_PASSWORD="${'$'}NTFY_EXPIRY_PASSWORD"
                ntfy user --config=/run/secrets/ntfy.yml add expiry
                ntfy user --config=/run/secrets/ntfy.yml change-tier expiry p0expiry
                ntfy access --config=/run/secrets/ntfy.yml expiry 'events-*' rw
            """.trimIndent() else """
                test ! -e /var/cache/ntfy/auth.db
                ntfy serve --config=/run/secrets/ntfy.yml --listen-http=127.0.0.1:8080 &
                pid=${'$'}!
                trap 'kill -TERM "${'$'}pid" 2>/dev/null || true; wait "${'$'}pid" 2>/dev/null || true' EXIT HUP INT TERM
                ready=false
                for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
                    if wget -q -O - http://127.0.0.1:8080/v1/health | grep -q '"healthy":true'; then ready=true; break; fi
                    sleep 1
                done
                test "${'$'}ready" = true
                kill -TERM "${'$'}pid"
                wait "${'$'}pid"
                trap - EXIT HUP INT TERM
                test -s /var/cache/ntfy/auth.db
                ntfy user --config=/run/secrets/ntfy.yml add publisher
                ntfy access --config=/run/secrets/ntfy.yml publisher 'events-*' rw
            """.trimIndent())) + sql.processes.map { process -> when (process.id) {
            "mariadb-init" -> process.copy(networks = listOf("maria-data"), environmentFile = "mariadb-bootstrap.env",
                files = if (release) listOf(RuntimeFile("mariadb-qualification.env", "/run/secrets/mariadb-qualification.env")) +
                    (if (CanonicalMariaGrant.SEAFILE in mariaGrants) listOf(RuntimeFile("mariadb-seafile-grants.env", "/run/secrets/mariadb-seafile-grants.env")) else emptyList()) +
                    (if (CanonicalMariaGrant.ERPNEXT in mariaGrants) listOf(RuntimeFile("mariadb-erp-grants.env", "/run/secrets/mariadb-erp-grants.env")) else emptyList()) +
                    (if (CanonicalMariaGrant.BOOKSTACK in mariaGrants) listOf(RuntimeFile("mariadb-bookstack-grants.env", "/run/secrets/mariadb-bookstack-grants.env")) else emptyList())
                    else process.files,
                command = listOf("-ec", if (release) """
                    . /run/secrets/mariadb-qualification.env
                    ${if (CanonicalMariaGrant.SEAFILE in mariaGrants) ". /run/secrets/mariadb-seafile-grants.env" else ""}
                    ${if (CanonicalMariaGrant.ERPNEXT in mariaGrants) ". /run/secrets/mariadb-erp-grants.env" else ""}
                    ${if (CanonicalMariaGrant.BOOKSTACK in mariaGrants) ". /run/secrets/mariadb-bookstack-grants.env" else ""}
                    mariadb-install-db --no-defaults --datadir=/var/lib/mysql --auth-root-authentication-method=normal --skip-test-db
                    mariadbd --no-defaults --datadir=/var/lib/mysql --bootstrap --skip-networking <<SQL
                    DELETE FROM mysql.global_priv WHERE User = '' OR (User = 'root' AND Host <> 'localhost');
                    FLUSH PRIVILEGES;
                    ALTER USER 'root'@'localhost' IDENTIFIED BY '${'$'}MARIADB_ROOT_PASSWORD';
                    CREATE USER 'health'@'localhost' IDENTIFIED BY '${'$'}MARIADB_HEALTH_PASSWORD';
                    CREATE DATABASE qualification;
                    CREATE USER 'qualification'@'%' IDENTIFIED BY '${'$'}MARIADB_QUALIFICATION_PASSWORD';
                    GRANT ALL PRIVILEGES ON qualification.* TO 'qualification'@'%';
                    ${if (CanonicalMariaGrant.SEAFILE in mariaGrants) seafileMariaBootstrapSql else ""}
                    ${if (CanonicalMariaGrant.ERPNEXT in mariaGrants) erpMariaBootstrapSql else ""}
                    ${if (CanonicalMariaGrant.BOOKSTACK in mariaGrants) bookstackMariaBootstrapSql else ""}
                    SQL
                """.trimIndent() else """
                    mariadb-install-db --no-defaults --datadir=/var/lib/mysql --auth-root-authentication-method=normal --skip-test-db
                    mariadbd --no-defaults --datadir=/var/lib/mysql --bootstrap --skip-networking <<SQL
                    DELETE FROM mysql.global_priv WHERE User = '' OR (User = 'root' AND Host <> 'localhost');
                    FLUSH PRIVILEGES;
                    ALTER USER 'root'@'localhost' IDENTIFIED BY '${'$'}MARIADB_ROOT_PASSWORD';
                    CREATE USER 'health'@'localhost' IDENTIFIED BY '${'$'}MARIADB_HEALTH_PASSWORD';
                    SQL
                """.trimIndent()))
            "mariadb" -> process.copy(networks = listOf("maria-data"), environmentFile = "mariadb-health.env",
                files = listOf(RuntimeFile("mariadb-ca.pem", "/run/secrets/mariadb-ca.pem"),
                    RuntimeFile("mariadb.pem", "/run/secrets/mariadb.pem"), RuntimeFile("mariadb-key.pem", "/run/secrets/mariadb-key.pem")),
                command = process.command + listOf("--require-secure-transport=ON", "--ssl-ca=/run/secrets/mariadb-ca.pem",
                    "--ssl-cert=/run/secrets/mariadb.pem", "--ssl-key=/run/secrets/mariadb-key.pem"),
                readiness = listOf("/bin/sh", "-ec", "MYSQL_PWD=\"${'$'}MARIADB_HEALTH_PASSWORD\" mariadb --no-defaults --socket=/tmp/mysql.sock -u health -Nse 'SELECT 1' | grep -qx 1"))
            else -> process.copy(networks = listOf("memcache-data"))
        } }
        val identity = if (release) IdentityRuntime.canonicalProcesses(processes.single { it.id == "postgres" })
            else legacyIdentityProcesses(processes.single { it.id == "postgres" })
        val pg = processes.single { it.id == "postgres" }
        val finance = FireflyCanonical.projection(inventory, "postgres", includeNativeOnboarding = release)
        val ingress = CaddyRuntime.spec(inventory, name)
        fun financeSql(id: String, dependencies: List<String>, sqlText: String) = RuntimeProcess(id, pg.image, pg.imageId, pg.userId,
            dependencies = dependencies, entrypoint = "/bin/sh", environmentFile = "firefly-db-admin.env", oneShot = true,
            files = listOf(ca), networks = listOf("db-admin"), apparmorProfile = "p0v3-private-v1", command = listOf("-ec", sqlText))
        val financeJobs = listOf(financeSql("firefly-db-init", listOf("postgres"), """
            psql -X -v ON_ERROR_STOP=1 <<SQL
            CREATE ROLE firefly_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '${'$'}FIREFLY_MIGRATION_PASSWORD';
            CREATE ROLE firefly_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '${'$'}FIREFLY_RUNTIME_PASSWORD';
            CREATE DATABASE firefly OWNER firefly_migration;
            REVOKE ALL ON DATABASE firefly FROM PUBLIC;
            GRANT CONNECT ON DATABASE firefly TO firefly_runtime;
            SQL
            psql -X -d firefly -v ON_ERROR_STOP=1 <<'SQL'
            REVOKE CREATE ON SCHEMA public FROM PUBLIC;
            GRANT USAGE ON SCHEMA public TO firefly_runtime;
            ALTER DEFAULT PRIVILEGES FOR ROLE firefly_migration IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO firefly_runtime;
            ALTER DEFAULT PRIVILEGES FOR ROLE firefly_migration IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO firefly_runtime;
            SQL
        """.trimIndent()), financeSql("firefly-db-finalize", listOf("firefly-runtime-config"), """
            psql -X -d firefly -v ON_ERROR_STOP=1 <<'SQL'
            GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO firefly_runtime;
            GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO firefly_runtime;
            ALTER ROLE firefly_migration NOLOGIN;
            SQL
        """.trimIndent()))
        val financeProcesses = finance.processes.map { process -> process.copy(
            networks = when (process.id) { "firefly" -> listOf("firefly-web"); "firefly-php" -> listOf("firefly-data", "firefly-web"); else -> listOf("firefly-data") },
            dependencies = when (process.id) {
                "firefly-migrate" -> process.dependencies.map { if (it == "postgres") "firefly-db-init" else it }
                "firefly-php" -> listOf("postgres", "firefly-db-finalize")
                else -> process.dependencies
            }) }
        return core.copy(volumes = core.volumes + sql.volumes + finance.volumes + ingress.volumes,
            processes = processes.map { if (it.id == "postgres") it.copy(networks = it.networks + listOf("keycloak-data", "firefly-data")) else it } + identity + financeJobs + financeProcesses + ingress.processes.map {
                it.copy(networks = listOf("ingress-control", "planka-web", "ntfy-web", "identity-web", "firefly-web"))
            },
            networks = (core.networks - "net") + listOf("cache-data", "ntfy-web", "maria-data", "memcache-data", "keycloak-data", "identity-web", "firefly-data", "firefly-web", "ingress-control"),
            databaseAccess = core.databaseAccess + listOf(
                RuntimeDatabaseAccess("identity-realm-init", "postgres", "postgres", "keycloak", "keycloak_migrate", "identity-migration.env", "keycloak-data"),
                RuntimeDatabaseAccess("keycloak", "postgres", "postgres", "keycloak", "keycloak", "identity-runtime.env", "keycloak-data")) +
                financeProcesses.filter { it.environmentFile != null }.map { process ->
                    RuntimeDatabaseAccess(process.id, "postgres", "postgres", "firefly",
                        if (process.id in setOf("firefly-migrate", "firefly-users-init")) "firefly_migration" else "firefly_runtime",
                        process.environmentFile!!, "firefly-data")
                })
            .also { PrivateDeployment.validate(it) }
    }

    /** Pure graph merge. Resolve all fragment references before any credential generation. Process
     * names and state are globally owned; an application cannot silently duplicate a canonical
     * provider, take over ingress control, or borrow the database administration network.
     */
    fun composeProviders(base: PrivateDeploymentSpec, fragments: List<CanonicalProviderFragment>): PrivateDeploymentSpec {
        PrivateDeployment.validate(base)
        // A11's immutable internal observability network has NO generic provider edge.
        // Even another fragment introducing a network not in base.networks must not
        // borrow the exact private monitoring names to reach Alloy/Loki/node.
        val observabilityInternal = "observability-net"
        val observabilityWeb = "observability-web"
        val observabilityIds = setOf("metrics-init", "node", "prometheus", "alertmanager", "alloy", "loki", "grafana")
        val observabilityFrontends = setOf("prometheus", "alertmanager", "grafana")
        require(base.networks.none { it in setOf(observabilityInternal, observabilityWeb) } &&
            base.processes.none { it.id in observabilityIds ||
                it.networks.any { network -> network in setOf(observabilityInternal, observabilityWeb) } }) {
            "Only exact original prometheus fragment may own the two monitoring networks" }
        require(fragments.map { it.product }.distinct().size == fragments.size) { "Repeated application projection" }
        val mariaInit = base.processes.singleOrNull { it.id == "mariadb-init" }
        if (mariaInit != null) {
            val selected = mapOf(
                "seafile" to "mariadb-seafile-grants.env",
                "erpnext" to "mariadb-erp-grants.env",
                "bookstack" to "mariadb-bookstack-grants.env")
            val actual = mariaInit.files.map { it.file }.filter { it.startsWith("mariadb-") && it.endsWith("-grants.env") }.toSet()
            require(actual == selected.filterKeys { product -> fragments.any { it.product == product } }.values.toSet() &&
                selected.all { (product, input) ->
                    (input in mariaInit.files.map { it.file }) == fragments.any { it.product == product }
                }) { "Fixed MariaDB grant must match exactly its selected application before credentials" }
        } else require(base.processes.none { it.oneShot } && fragments.all { it.spec.processes.none(RuntimeProcess::oneShot) }) {
            "Only a genuinely retired canonical MariaDB bootstrap may omit original grant inputs"
        }
        val fixed = setOf("postgres", "mariadb", "valkey", "memcached", "ntfy")
        val baseProcesses = base.processes.associateBy { it.id }
        require(fixed.all { id -> baseProcesses[id]?.oneShot == false }) { "Canonical provider cohort required" }
        val processes = fragments.flatMap { fragment ->
            require(fragment.product in GenerationAssembly.requiredCapabilities && fragment.product !in fixed &&
                fragment.spec.schemaVersion == base.schemaVersion && fragment.spec.name == base.name &&
                fragment.spec.store == base.store && fragment.spec.ingress == null && fragment.spec.processes.isNotEmpty()) {
                "Invalid provider-less application projection"
            }
            require(fragment.spec.processes.none { it.id in baseProcesses || it.id in fixed || it.id == "caddy" } &&
                fragment.spec.volumes.none { it.id in base.volumes.map(RuntimeVolume::id) }) {
                "Application duplicated canonical authority or state"
            }
            if (fragment.product == "prometheus") {
                require(fragment.spec.networks.toSet() == setOf(observabilityInternal, observabilityWeb) &&
                    fragment.spec.processes.map { it.id }.toSet() == observabilityIds &&
                    fragment.spec.processes.size == observabilityIds.size &&
                    fragment.spec.processes.all { process -> process.networks.toSet() ==
                        (if (process.id in observabilityFrontends)
                            setOf(observabilityInternal, observabilityWeb) else setOf(observabilityInternal)) } &&
                    fragment.webNetworks == setOf(observabilityWeb) && fragment.providerNetworks.isEmpty()) {
                    "Original prometheus monitoring contribution must be exact and isolated" }
            } else {
                require(fragment.spec.networks.none { it in setOf(observabilityInternal, observabilityWeb) } &&
                    fragment.spec.processes.none { process -> process.id in observabilityIds ||
                        process.networks.any { it in setOf(observabilityInternal, observabilityWeb) } } &&
                    fragment.webNetworks.none { it in setOf(observabilityInternal, observabilityWeb) } &&
                    fragment.providerNetworks.values.none { names ->
                        names.any { it in setOf(observabilityInternal, observabilityWeb) } }) {
                    "Foreign fragment joined private observability network or impersonated fixed process" }
            }
            val providerImages = baseProcesses.filterKeys { it in fixed }.values.map { it.imageId }.toSet()
            val approvedIdentity = CanonicalIdentityWebConsumer.entries
                .filter { it.product == fragment.product }.toSet()
            val approvedProcesses = approvedIdentity.map { it.process }.toSet()
            require(fragment.identityWebConsumers == approvedIdentity &&
                fragment.spec.processes.filter { "identity-web" in it.networks }.map { it.id }.toSet() == approvedProcesses &&
                fragment.spec.processes.filter { it.id in approvedProcesses }.all { !it.oneShot } &&
                ("identity-web" in fragment.spec.networks) == approvedIdentity.isNotEmpty() &&
                "identity-web" in base.processes.single { it.id == "keycloak" }.networks &&
                "identity-web" in base.processes.single { it.id == "caddy" }.networks) {
                "Only exact reviewed native OIDC daemon consumers may join existing identity-web"
            }
            val sharedNetworks = fragment.providerNetworks.values.flatten().toSet() +
                if (approvedIdentity.isNotEmpty()) setOf("identity-web") else emptySet()
            require(fragment.spec.processes.all { process -> process.networks.all { network ->
                network !in base.networks || network in sharedNetworks ||
                    (network == "db-admin" && process.oneShot && process.id.endsWith("-db-init"))
            } }) { "Application joined a shared provider/site network without an explicit edge" }
            require(fragment.spec.processes.none { process ->
                "ingress-control" in process.networks || "ingress-egress" in process.networks ||
                (!process.oneShot && (process.imageId in providerImages ||
                    process.environmentFile?.contains("bootstrap") == true || process.environmentFile?.contains("admin") == true)) ||
                ("db-admin" in process.networks && !(process.oneShot && process.id.endsWith("-db-init") &&
                    process.environmentFile?.endsWith("-db-admin.env") == true && process.imageId in providerImages))
            }) { "Application inherited provider/bootstrap authority or disguised a provider daemon" }
            fragment.spec.processes
        }
        val ownerNames = (base.processes + processes).map { it.id }
        require(ownerNames.distinct().size == ownerNames.size) { "Conflicting canonical process owners" }
        val networks = (base.networks + fragments.flatMap { it.spec.networks }).distinct()
        val webNetworks = fragments.flatMap { fragment ->
            require(fragment.webNetworks.all { it in fragment.spec.networks && it.endsWith("-web") && it !in base.networks &&
                fragment.spec.processes.any { process -> !process.oneShot && it in process.networks } }) {
                "Public frontend requires an explicit owned app-only web network"
            }
            fragment.webNetworks
        }.toSet()
        val providerNetworks = fragments.flatMap { fragment -> fragment.providerNetworks.entries.flatMap { (provider, names) ->
            require(provider in fixed && provider in baseProcesses && names.isNotEmpty() &&
                (provider != "memcached" || fragment.product == "sogo") &&
                names.all { it in networks && it != "db-admin" && it != "ingress-control" &&
                    it != "ingress-egress" && (it in fragment.spec.networks ||
                        provider == "valkey" && it == "cache-data" ||
                        provider == "ntfy" && it == "ntfy-web") &&
                    (provider != "memcached" || it !in base.networks) &&
                    (provider !in setOf("postgres", "mariadb") || it !in base.networks) }) {
                "Foreign provider network extension"
            }
            names.map { provider to it }
        } }.groupBy({ it.first }, { it.second })
        val joined = base.copy(volumes = base.volumes + fragments.flatMap { it.spec.volumes },
            processes = base.processes.map { provider ->
                when (provider.id) {
                    in fixed -> provider.copy(networks = (provider.networks + providerNetworks[provider.id].orEmpty()).distinct())
                    else -> provider
                }
            } + processes,
            networks = networks,
            unmountedRecoveryVolumes = base.unmountedRecoveryVolumes + fragments.flatMap { it.spec.unmountedRecoveryVolumes },
            databaseAccess = base.databaseAccess + fragments.flatMap { it.spec.databaseAccess })
        // A13 owns the typed frontend guard; no generic Caddy route is published by graph merge.
        val fronted = CaddyRuntime.withFrontendNetworks(joined, webNetworks)
        // Exact provider/consumer membership and credential ownership are checked by the full graph.
        PrivateDeployment.validate(fronted)
        require(fragments.flatMap { it.spec.databaseAccess }.all { access ->
            access.provider in setOf("postgres", "mariadb") &&
                access.consumer in processes.map { it.id } &&
                access.network in providerNetworks[access.provider].orEmpty()
        }) { "Application database edge not admitted to its shared provider" }
        return fronted
    }

    /** Caller-supplied, feature-owned cold projections. An initializer is retired only by the
     * feature's explicit fresh/cold pair; no generic routine silently filters boot authority.
     * The exact original fresh spec must be matched before the restored graph is compiled.
     */
    fun coldRestoreComposedSpec(original: PrivateDeploymentSpec, baseFresh: PrivateDeploymentSpec,
        freshFragments: List<CanonicalProviderFragment>, coldFragments: List<CanonicalProviderFragment>): PrivateDeploymentSpec {
        require(original == composeProviders(baseFresh, freshFragments)) { "Original canonical source graph changed" }
        require(freshFragments.map { it.product } == coldFragments.map { it.product }) {
            "Missing or reordered feature-owned cold projection"
        }
        freshFragments.zip(coldFragments).forEach { (fresh, cold) ->
            val f = fresh.spec; val c = cold.spec
            require(f.name == c.name && f.store == c.store && f.volumes == c.volumes &&
                f.networks == c.networks && fresh.providerNetworks == cold.providerNetworks &&
                fresh.webNetworks == cold.webNetworks && fresh.identityWebConsumers == cold.identityWebConsumers &&
                c.processes.none { it.oneShot } &&
                c.processes.map { it.id }.toSet() == f.processes.filterNot { it.oneShot }.map { it.id }.toSet() &&
                c.databaseAccess == f.databaseAccess.filter { access -> f.processes.single { it.id == access.consumer }.oneShot.not() }) {
                "Feature cold projection changed state or retained initializer authority"
            }
            c.processes.forEach { restored ->
                val initial = f.processes.single { it.id == restored.id }
                require(restored.image == initial.image && restored.imageId == initial.imageId &&
                    restored.userId == initial.userId && restored.groupId == initial.groupId &&
                    restored.volumes == initial.volumes && restored.files == initial.files &&
                    restored.networks == initial.networks && restored.environmentFile == initial.environmentFile) {
                    "Cold projection cannot substitute process image, state or principal"
                }
            }
        }
        val restored = composeProviders(releaseColdRestoreProvidersSpec(baseFresh), coldFragments)
        require(restored.volumes == original.volumes && restored.networks == original.networks &&
            restored.processes.none { it.oneShot }) { "Canonical restore changed physical state or retained initializer" }
        return restored
    }

    /** Merge only generated, disjoint private inputs after composeProviders has validated the
     * entire graph. Shared CA references are intentionally supplied by the base input map once.
     */
    fun mergeProviderInputs(expected: PrivateDeploymentSpec, baseInputs: Map<String, String>,
        fragmentInputs: List<Map<String, String>>): Map<String, String> {
        val result = baseInputs.toMutableMap()
        for (part in fragmentInputs) for ((name, content) in part) {
            require(name !in result && content.isNotEmpty()) { "Overlapping or empty canonical input" }
            result[name] = content
        }
        require(result.keys == PrivateDeployment.inputNames(expected).toSet()) { "Incomplete canonical credential graph" }
        return result
    }

    fun providersInputs(inventory: AcquiredInventory, pki: (String) -> Map<String, String> = { PrivateWebPki.generate(it) },
        password: () -> String = RuntimePreparation::password): Map<String, String> =
        legacyInputs(inventory, pki, password)

    fun legacyInputs(inventory: AcquiredInventory, pki: (String) -> Map<String, String> = { PrivateWebPki.generate(it) },
        password: () -> String = RuntimePreparation::password): Map<String, String> =
        providerInputsVersion(inventory, pki, password, release = false, emptyList(), emptySet(), null)

    fun releaseProvidersInputs(inventory: AcquiredInventory, pki: (String) -> Map<String, String> = { PrivateWebPki.generate(it) },
        password: () -> String = RuntimePreparation::password,
        cachePrincipals: List<CanonicalCachePrincipal> = emptyList(),
        mariaGrants: Set<CanonicalMariaGrant> = emptySet(),
        mariaCredentials: CanonicalMariaCredentialPair? = null,
        mariaFeatureCredentials: Map<CanonicalMariaGrant, CanonicalMariaCredentialPair> = emptyMap(),
        fireflyOriginalSubjects: FireflyOriginalSubjects? = null): Map<String, String> =
        providerInputsVersion(inventory, pki, password, release = true, cachePrincipals, mariaGrants, mariaCredentials,
            mariaFeatureCredentials, fireflyOriginalSubjects)

    /** Byte-frozen e51e8dc Keycloak process projection. Never use an evolving identity helper
     * when reconstructing the original v1 canonical-provider member or its one-shot authority.
     */
    private fun legacyIdentityProcesses(postgres: RuntimeProcess): List<RuntimeProcess> {
        val image = "localhost/p0v3-keycloak@sha256:ff264e6231948cf3b879dc3d08f89cbdd0dbef24c044ef1c4dcd71f571b77c1e"
        val imageId = "345177fdf5102c9a0b017e1ef0eb409a0020c74ee4feaca82b1389758de041e1"
        fun sql(id: String, dependencies: List<String>, command: String) = RuntimeProcess(id, postgres.image, postgres.imageId,
            postgres.userId, groupId = postgres.groupId, dependencies = dependencies, entrypoint = "/bin/sh",
            command = listOf("-ec", command), environmentFile = "identity-db-admin.env", oneShot = true,
            files = listOf(RuntimeFile("postgres-ca.pem", "/run/secrets/postgres-ca.pem")),
            networks = listOf("db-admin"), apparmorProfile = "p0v3-private-v1")
        return listOf(
            sql("identity-db-init", listOf(postgres.id), """
                psql -X -v ON_ERROR_STOP=1 <<SQL
                CREATE ROLE keycloak_migrate LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '${'$'}KEYCLOAK_MIGRATION_PASSWORD';
                CREATE ROLE keycloak LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '${'$'}KEYCLOAK_PASSWORD';
                CREATE DATABASE keycloak OWNER keycloak_migrate;
                REVOKE ALL ON DATABASE keycloak FROM PUBLIC;
                GRANT CONNECT ON DATABASE keycloak TO keycloak;
                SQL
            """.trimIndent()),
            RuntimeProcess("identity-realm-init", image, imageId, 1000, groupId = 0, dependencies = listOf("identity-db-init"),
                command = listOf("import", "--optimized", "--file=/run/secrets/identity-realm.json"), oneShot = true,
                environmentFile = "identity-migration.env", memoryMiB = 1024, networks = listOf("keycloak-data"),
                files = listOf(RuntimeFile("identity-realm.json", "/run/secrets/identity-realm.json"),
                    RuntimeFile("postgres-ca.pem", "/run/secrets/postgres-ca.pem")),
                tmpfs = listOf("/tmp", "/opt/keycloak/data"), apparmorProfile = "p0v3-private-v1"),
            sql("identity-db-finalize", listOf("identity-realm-init"), """
                psql -X -d keycloak -v ON_ERROR_STOP=1 <<'SQL'
                REVOKE CREATE ON SCHEMA public FROM PUBLIC;
                GRANT USAGE ON SCHEMA public TO keycloak;
                GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO keycloak;
                GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO keycloak;
                ALTER ROLE keycloak_migrate NOLOGIN;
                SQL
            """.trimIndent()),
            RuntimeProcess("keycloak", image, imageId, 1000, groupId = 0, dependencies = listOf("identity-db-finalize"),
                command = listOf("start", "--optimized", "--spi-connections-jpa--quarkus--migration-strategy=validate"),
                environmentFile = "identity-runtime.env", memoryMiB = 1024, networks = listOf("keycloak-data", "identity-web"),
                files = listOf("identity-web.pem", "identity-web-key.pem", "identity-ca.pem", "postgres-ca.pem").map { RuntimeFile(it, "/run/secrets/$it") },
                tmpfs = listOf("/tmp", "/opt/keycloak/data"), apparmorProfile = "p0v3-private-v1",
                readiness = listOf("/bin/bash", "-ec", "exec 3<>/dev/tcp/127.0.0.1/9000; printf 'GET /health/ready HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' >&3; read -r -t 3 line <&3; [[ \"${'$'}line\" == *' 200 '* ]]"))
        )
    }

    /** Byte-frozen e51e8dc canonical Keycloak contribution. Current identity policy/issuer
     * changes cannot rewrite the inputs or original serialized realm of historical bundles.
     */
    private fun legacyIdentityInputs(postgresAdminPassword: String, pki: () -> Map<String, String>,
        password: () -> String): Map<String, String> {
        val migration = password(); val runtime = password(); val initial = password()
        require((listOf(postgresAdminPassword, migration, runtime, initial)).all { it.matches(Regex("[a-f0-9]{64}")) })
        require(setOf(postgresAdminPassword, migration, runtime, initial).size == 4)
        val tls = pki()
        require(tls.keys == setOf("ca.pem", "web.pem", "web-key.pem"))
        val realm = buildJsonObject {
            put("realm", "p0v3"); put("enabled", true); put("sslRequired", "all"); put("registrationAllowed", false)
            put("resetPasswordAllowed", false); put("bruteForceProtected", true); put("accessTokenLifespan", 300)
            put("clients", JsonArray(emptyList()))
            put("users", buildJsonArray { add(buildJsonObject {
                put("id", java.util.UUID.randomUUID().toString()); put("username", "owner"); put("enabled", true)
                put("clientRoles", buildJsonObject { put("realm-management", buildJsonArray {
                    add("manage-users"); add("view-users"); add("query-users"); add("manage-clients"); add("view-clients")
                }) })
                put("requiredActions", buildJsonArray { add("UPDATE_PASSWORD"); add("CONFIGURE_TOTP") })
                put("credentials", buildJsonArray { add(buildJsonObject {
                    put("type", "password"); put("temporary", true); put("value", initial)
                }) })
            }) })
        }
        val database = "KC_DB=postgres\nKC_DB_URL=jdbc:postgresql://postgres:5432/keycloak?sslmode=verify-full&sslrootcert=/run/secrets/postgres-ca.pem\n"
        return mapOf(
            "identity-db-admin.env" to "PGHOST=postgres\nPGUSER=postgres\nPGDATABASE=postgres\nPGPASSWORD=$postgresAdminPassword\nPGSSLMODE=verify-full\nPGSSLROOTCERT=/run/secrets/postgres-ca.pem\nKEYCLOAK_MIGRATION_PASSWORD=$migration\nKEYCLOAK_PASSWORD=$runtime\n",
            "identity-migration.env" to database + "KC_DB_USERNAME=keycloak_migrate\nKC_DB_PASSWORD=$migration\n",
            "identity-runtime.env" to database + "KC_DB_USERNAME=keycloak\nKC_DB_PASSWORD=$runtime\nKC_HTTP_ENABLED=false\nKC_HOSTNAME=https://keycloak:8443\nKC_HTTPS_PORT=8443\nKC_HTTPS_CERTIFICATE_FILE=/run/secrets/identity-web.pem\nKC_HTTPS_CERTIFICATE_KEY_FILE=/run/secrets/identity-web-key.pem\nKC_HTTP_MANAGEMENT_SCHEME=http\n",
            "identity-realm.json" to realm.toString(), "identity-ca.pem" to tls.getValue("ca.pem"),
            "identity-web.pem" to tls.getValue("web.pem"), "identity-web-key.pem" to tls.getValue("web-key.pem")
        )
    }

    private fun providerInputsVersion(inventory: AcquiredInventory, pki: (String) -> Map<String, String>,
        password: () -> String, release: Boolean, cachePrincipals: List<CanonicalCachePrincipal>,
        mariaGrants: Set<CanonicalMariaGrant>, mariaCredentials: CanonicalMariaCredentialPair?,
        mariaFeatureCredentials: Map<CanonicalMariaGrant, CanonicalMariaCredentialPair> = emptyMap(),
        fireflyOriginalSubjects: FireflyOriginalSubjects? = null): Map<String, String> {
        require((release || mariaGrants.isEmpty() && mariaFeatureCredentials.isEmpty()) &&
            (CanonicalMariaGrant.SEAFILE in mariaGrants) == (mariaCredentials != null) &&
            mariaFeatureCredentials.keys == mariaGrants - CanonicalMariaGrant.SEAFILE &&
            mariaFeatureCredentials.keys.all { it in setOf(CanonicalMariaGrant.ERPNEXT, CanonicalMariaGrant.BOOKSTACK) }) {
            "Every selected fixed MariaDB grant requires its own sealed migration/runtime pair"
        }
        require(!release || fireflyOriginalSubjects != null) {
            "Complete graph must bind original Firefly owner and outsider before any credential preparation" }
        require((release || cachePrincipals.isEmpty()) &&
            cachePrincipals.map { it.product }.distinct().size == cachePrincipals.size &&
            cachePrincipals.map { it.password }.distinct().size == cachePrincipals.size &&
            cachePrincipals.all { it.product.matches(Regex("[a-z][a-z0-9-]{0,23}")) &&
                it.product in GenerationAssembly.requiredCapabilities && it.product !in setOf("postgres", "mariadb", "valkey", "memcached", "ntfy") &&
                it.password.matches(Regex("[a-f0-9]{64}")) }) {
            "Shared Valkey requires distinct selected-product principals before credential preparation"
        }
        // Validate all generated secrets, including those produced by inputs(), as one unique set.
        val seen = mutableSetOf<String>()
        fun fresh(): String = password().also {
            require(it.matches(Regex("[a-f0-9]{64}")) && seen.add(it)) { "Invalid or reused provider credential" }
        }
        val core = inputs({ pki("postgres") }, ::fresh).toMutableMap()
        val cacheHealth = fresh(); val cacheClient = fresh(); val ntfyClient = fresh()
        val ntfySubscriber = if (release) fresh() else null; val ntfyExpiry = if (release) fresh() else null
        val mariaRoot = fresh(); val mariaHealth = fresh()
        val mariaQualification = if (release) fresh() else null; val postgresQualification = if (release) fresh() else null
        val mariaTls = pki("mariadb")
        require(mariaTls.keys == setOf("ca.pem", "web.pem", "web-key.pem"))
        core["valkey.conf"] = "bind 0.0.0.0\nprotected-mode yes\nport 6379\ndir /data\nappendonly yes\nappendfsync everysec\naclfile /etc/valkey/users.acl\n"
        core["valkey.acl"] = "user default off\nuser health on >$cacheHealth -@all +ping\n" +
            "user application on >$cacheClient ${if (release) "~app:q_* &app:q_*" else "~app:* &app:*"} -@all +get +set +del +exists +expire +ttl +lpush +rpush +lpop +rpop +llen +ping\n"
        core["valkey-health.env"] = "VALKEY_HEALTH_PASSWORD=$cacheHealth\n"
        core["ntfy-bootstrap.env"] = "NTFY_PASSWORD=$ntfyClient\n" +
            if (release) "NTFY_SUBSCRIBER_PASSWORD=$ntfySubscriber\nNTFY_EXPIRY_PASSWORD=$ntfyExpiry\n" else ""
        core["ntfy.yml"] = "base-url: ${if (release) "https://notify.datamancy.net" else "http://ntfy:8080"}\nlisten-http: :8080\ncache-file: /var/cache/ntfy/cache.db\nattachment-cache-dir: /var/cache/ntfy/attachments\nauth-file: /var/cache/ntfy/auth.db\nauth-default-access: deny-all\nenable-signup: false\n"
        core["mariadb-bootstrap.env"] = "MARIADB_ROOT_PASSWORD=$mariaRoot\nMARIADB_HEALTH_PASSWORD=$mariaHealth\n"
        if (release) {
            core["mariadb-qualification.env"] = "MARIADB_QUALIFICATION_PASSWORD=$mariaQualification\n"
            core["postgres-qualification.env"] = "POSTGRES_QUALIFICATION_PASSWORD=$postgresQualification\n"
        }
        if (mariaCredentials != null) {
            require(seen.add(mariaCredentials.migrationPassword) && seen.add(mariaCredentials.runtimePassword)) {
                "Seafile principal collided with generated provider credentials"
            }
            core["mariadb-seafile-grants.env"] = "SEAFILE_MIGRATION_PASSWORD=${mariaCredentials.migrationPassword}\n" +
                "SEAFILE_RUNTIME_PASSWORD=${mariaCredentials.runtimePassword}\n"
        }
        for ((grant, pair) in mariaFeatureCredentials.toSortedMap()) {
            require(seen.add(pair.migrationPassword) && seen.add(pair.runtimePassword)) {
                "Business MariaDB principal collided with another generated credential"
            }
            when (grant) {
                CanonicalMariaGrant.ERPNEXT -> core["mariadb-erp-grants.env"] =
                    "ERP_MIGRATION_PASSWORD=${pair.migrationPassword}\nERP_RUNTIME_PASSWORD=${pair.runtimePassword}\n"
                CanonicalMariaGrant.BOOKSTACK -> core["mariadb-bookstack-grants.env"] =
                    "BOOKSTACK_MIGRATION_PASSWORD=${pair.migrationPassword}\nBOOKSTACK_RUNTIME_PASSWORD=${pair.runtimePassword}\n"
                CanonicalMariaGrant.SEAFILE -> error("Seafile must use its historically separate fixed input slot")
            }
        }
        core["mariadb-health.env"] = "MARIADB_HEALTH_PASSWORD=$mariaHealth\n"
        core["mariadb-ca.pem"] = mariaTls.getValue("ca.pem")
        core["mariadb.pem"] = mariaTls.getValue("web.pem")
        core["mariadb-key.pem"] = mariaTls.getValue("web-key.pem")
        val postgresAdmin = core.getValue("postgres.env").removePrefix("POSTGRES_PASSWORD=").trimEnd()
        core.putAll(if (release) IdentityRuntime.canonicalInputs(postgresAdmin, { pki("keycloak") }, ::fresh,
            originalOwnerId = fireflyOriginalSubjects!!.ownerUuid,
            originalOutsiderId = fireflyOriginalSubjects.outsiderUuid)
            else legacyIdentityInputs(postgresAdmin, { pki("keycloak") }, ::fresh))
        val financeRuntime = fresh(); val financeMigration = fresh()
        val appKey = "base64:" + java.util.Base64.getEncoder().encodeToString(java.util.HexFormat.of().parseHex(fresh()))
        core.putAll(FireflyCanonical.fragment(inventory, "postgres", "postgres", financeRuntime, financeMigration,
            core.getValue("postgres-ca.pem"), appKey, "https://finance.datamancy.net",
            if (release) fireflyOriginalSubjects else null).inputs)
        core["firefly-db-admin.env"] = "PGHOST=postgres\nPGUSER=postgres\nPGDATABASE=postgres\nPGPASSWORD=$postgresAdmin\nPGSSLMODE=verify-full\nPGSSLROOTCERT=/run/secrets/postgres-ca.pem\nFIREFLY_RUNTIME_PASSWORD=$financeRuntime\nFIREFLY_MIGRATION_PASSWORD=$financeMigration\n"
        core.putAll(CaddyRuntime.inputs())
        require(cachePrincipals.all { seen.add(it.password) }) {
            "Shared Valkey principal collided with generated generation credentials"
        }
        if (cachePrincipals.isNotEmpty()) core["valkey.acl"] = core.getValue("valkey.acl") +
            cachePrincipals.sortedBy { it.product }.joinToString("") { it.aclRule() }
        return core
    }

    /** Historical v1 projection; only original e51e8dc initializer set and inputs are retired. */
    fun coldRestoreProvidersSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec =
        legacyColdProjection(compiled)

    fun legacyColdProjection(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec =
        coldProviderProjection(compiled, release = false)

    /** New versioned full-release projection; never apply it to a historical v1 bundle. */
    fun releaseColdRestoreProvidersSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec =
        coldProviderProjection(compiled, release = true)

    private fun legacyColdIdentityProcesses(processes: List<RuntimeProcess>): List<RuntimeProcess> {
        val retired = setOf("identity-db-init", "identity-realm-init", "identity-db-finalize")
        require(processes.filter { it.id in retired }.map { it.id }.toSet() == retired &&
            processes.filter { it.id in retired }.all { it.oneShot })
        val daemon = processes.single { it.id == "keycloak" }
        require(!daemon.oneShot && daemon.environmentFile == "identity-runtime.env" &&
            daemon.command == listOf("start", "--optimized", "--spi-connections-jpa--quarkus--migration-strategy=validate") &&
            daemon.files.map { it.file }.toSet() == setOf("identity-web.pem", "identity-web-key.pem", "identity-ca.pem", "postgres-ca.pem"))
        return processes.filterNot { it.id in retired }.map { process ->
            if (process.id == "keycloak") process.copy(dependencies = listOf("postgres"))
            else process.copy(dependencies = process.dependencies.filterNot { it in retired })
        }
    }

    /** Source compiler and expected one-shot set must be checked before importing any volume.
     * A callback must not infer authority from a changed v2 input name or a missing initializer.
     */
    private fun coldProviderProjection(compiled: PrivateDeploymentSpec, release: Boolean): PrivateDeploymentSpec {
        val qualified = compiled.processes.single { it.id == "planka-db-init" }
        val mariaInit = compiled.processes.single { it.id == "mariadb-init" }
        val ntfyInit = compiled.processes.single { it.id == "ntfy-auth-init" }
        require(("postgres-qualification.env" in qualified.files.map { it.file }) == release &&
            ("mariadb-qualification.env" in mariaInit.files.map { it.file }) == release &&
            (release || mariaInit.files.none { it.file in setOf("mariadb-seafile-grants.env",
                "mariadb-erp-grants.env", "mariadb-bookstack-grants.env") }) &&
            ntfyInit.command.last().contains("ntfy tier --config=/run/secrets/ntfy.yml add") == release) {
            "Wrong canonical-provider version for cold projection"
        }
        val identityJobs = setOf("identity-db-init", "identity-realm-init", "identity-db-finalize")
        val financeJobs = setOf("firefly-files-init", "firefly-migrate", "firefly-runtime-config") +
            (if (release) setOf("firefly-users-init") else emptySet())
        val providerJobs = setOf("postgres-init", "planka-db-init", "planka-init", "postgres-finalize", "ntfy-auth-init",
            "mariadb-init", "firefly-db-init", "firefly-db-finalize")
        require(compiled.processes.filter { it.oneShot }.map { it.id }.toSet() == identityJobs + financeJobs + providerJobs) {
            "Unreviewed canonical initializer retirement"
        }
        require(compiled.processes.single { it.id == "caddy" }.command == listOf("run", "--resume", "--config", "/run/secrets/caddy.json")) {
            "Unreviewed Caddy restore command"
        }
        val identity = compiled.copy(processes = if (release) IdentityRuntime.canonicalColdRestoreProcesses(compiled.processes)
            else legacyColdIdentityProcesses(compiled.processes),
            databaseAccess = compiled.databaseAccess.filterNot { it.consumer in identityJobs })
        val finance = FireflyCanonical.coldRestoreSpec(identity)
        val retired = identityJobs + financeJobs + providerJobs
        return finance.copy(processes = finance.processes.filterNot { it.id in providerJobs }.map { process ->
            process.copy(entrypoint = if (process.id in setOf("valkey", "ntfy")) "/bin/sh" else process.entrypoint,
                command = when (process.id) {
                    "caddy" -> process.command - "--resume"
                    "valkey" -> listOf("-ec", "test -s /data/appendonlydir/appendonly.aof.manifest; exec /usr/local/bin/valkey-server /etc/valkey/valkey.conf")
                    "ntfy" -> listOf("-ec", "test -s /var/cache/ntfy/auth.db; test -s /var/cache/ntfy/cache.db; exec ntfy serve --config=/run/secrets/ntfy.yml")
                    else -> process.command
                }, dependencies = when (process.id) {
                "planka", "firefly-php" -> listOf("postgres")
                else -> process.dependencies.filterNot { it in retired }
            })
        }, databaseAccess = finance.databaseAccess.filterNot { it.consumer in retired }).also { restored ->
            require(restored.processes.none { it.oneShot })
            require(PrivateDeployment.inputNames(restored).none { it in setOf("postgres.env", "postgres-admin.env", "planka-bootstrap.env",
                "mariadb-bootstrap.env", "mariadb-qualification.env", "mariadb-seafile-grants.env",
                "mariadb-erp-grants.env", "mariadb-bookstack-grants.env", "postgres-qualification.env", "ntfy-bootstrap.env", "identity-db-admin.env", "identity-migration.env", "identity-realm.json",
                "firefly-db-admin.env", "firefly-migration.env", "firefly-onboarding.env") }) { "Bootstrap authority survived provider restore" }
            PrivateDeployment.validate(restored)
        }
    }

    fun prepareProviders(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE,
        name: String = "canonical-providers", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(providersSpec(inventory, name).copy(store = store), base) { providersInputs(inventory) }

    fun prepareReleaseProviders(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE,
        name: String = "canonical-release-v2", store: RuntimeStore = RuntimeStore.CANONICAL_V2): Path =
        error("Direct provider-only preparation cannot bind original Firefly subjects or validate the complete release graph")
}
