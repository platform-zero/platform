package net.datamancy.platform

import java.nio.file.Path

/** First canonical provider cohort: one PostgreSQL, distinct administration/data/frontend networks,
 * TLS-verified Planka connections and a retired migration principal. No public routes or boot enrollment. */
internal object CanonicalCoreRuntime {
    private val ca = RuntimeFile("postgres-ca.pem", "/run/secrets/postgres-ca.pem")
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

    /** Fresh canonical providers, not a rewrite of historical canonical-core manifests. Each protocol
     * owns its network; no unrelated cache/notification client can reach a database administration port.
     * PostgreSQL/Planka retain the verified-TLS split-principal implementation above. */
    fun providersSpec(inventory: AcquiredInventory, name: String = "canonical-providers"): PrivateDeploymentSpec {
        val core = spec(inventory, name)
        val sql = SqlCacheRuntime.spec(inventory, name)
        val ntfy = core.processes.single { it.id == "ntfy" }
        val processes = core.processes.map { process -> when (process.id) {
            "postgres" -> process.copy(networks = process.networks - "net", files = process.files + ca)
            "valkey" -> process.copy(networks = listOf("cache-data"), environmentFile = "valkey-health.env",
                files = process.files + RuntimeFile("valkey.acl", "/etc/valkey/users.acl"),
                readiness = listOf("/bin/sh", "-ec", "export REDISCLI_AUTH=\"${'$'}VALKEY_HEALTH_PASSWORD\"; test \"${'$'}(valkey-cli --user health ping)\" = PONG"))
            "ntfy" -> process.copy(dependencies = listOf("ntfy-auth-init"), networks = listOf("ntfy-web"),
                command = listOf("serve", "--config=/run/secrets/ntfy.yml"),
                files = listOf(RuntimeFile("ntfy.yml", "/run/secrets/ntfy.yml")))
            else -> process
        } } + ntfy.copy(id = "ntfy-auth-init", oneShot = true, readiness = emptyList(),
            networks = listOf("ntfy-web"), entrypoint = "/bin/sh", environmentFile = "ntfy-bootstrap.env",
            files = listOf(RuntimeFile("ntfy.yml", "/run/secrets/ntfy.yml")), command = listOf("-ec", """
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
                command = listOf("-ec", """
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
        val identity = IdentityRuntime.canonicalProcesses(processes.single { it.id == "postgres" })
        val pg = processes.single { it.id == "postgres" }
        val finance = FireflyCanonical.projection(inventory, "postgres")
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
                        if (process.id == "firefly-migrate") "firefly_migration" else "firefly_runtime", process.environmentFile!!, "firefly-data")
                })
            .also { PrivateDeployment.validate(it) }
    }

    fun providersInputs(inventory: AcquiredInventory, pki: (String) -> Map<String, String> = { PrivateWebPki.generate(it) },
        password: () -> String = RuntimePreparation::password): Map<String, String> {
        // Validate all generated secrets, including those produced by inputs(), as one unique set.
        val seen = mutableSetOf<String>()
        fun fresh(): String = password().also {
            require(it.matches(Regex("[a-f0-9]{64}")) && seen.add(it)) { "Invalid or reused provider credential" }
        }
        val core = inputs({ pki("postgres") }, ::fresh).toMutableMap()
        val cacheHealth = fresh(); val cacheClient = fresh(); val ntfyClient = fresh()
        val mariaRoot = fresh(); val mariaHealth = fresh()
        val mariaTls = pki("mariadb")
        require(mariaTls.keys == setOf("ca.pem", "web.pem", "web-key.pem"))
        core["valkey.conf"] = "bind 0.0.0.0\nprotected-mode yes\nport 6379\ndir /data\nappendonly yes\nappendfsync everysec\naclfile /etc/valkey/users.acl\n"
        core["valkey.acl"] = "user default off\nuser health on >$cacheHealth -@all +ping\n" +
            "user application on >$cacheClient ~app:* &app:* -@all +get +set +del +exists +expire +ttl +lpush +rpush +lpop +rpop +llen +ping\n"
        core["valkey-health.env"] = "VALKEY_HEALTH_PASSWORD=$cacheHealth\n"
        core["ntfy-bootstrap.env"] = "NTFY_PASSWORD=$ntfyClient\n"
        core["ntfy.yml"] = "base-url: http://ntfy:8080\nlisten-http: :8080\ncache-file: /var/cache/ntfy/cache.db\nattachment-cache-dir: /var/cache/ntfy/attachments\nauth-file: /var/cache/ntfy/auth.db\nauth-default-access: deny-all\nenable-signup: false\n"
        core["mariadb-bootstrap.env"] = "MARIADB_ROOT_PASSWORD=$mariaRoot\nMARIADB_HEALTH_PASSWORD=$mariaHealth\n"
        core["mariadb-health.env"] = "MARIADB_HEALTH_PASSWORD=$mariaHealth\n"
        core["mariadb-ca.pem"] = mariaTls.getValue("ca.pem")
        core["mariadb.pem"] = mariaTls.getValue("web.pem")
        core["mariadb-key.pem"] = mariaTls.getValue("web-key.pem")
        val postgresAdmin = core.getValue("postgres.env").removePrefix("POSTGRES_PASSWORD=").trimEnd()
        core.putAll(IdentityRuntime.canonicalInputs(postgresAdmin, { pki("keycloak") }, ::fresh))
        val financeRuntime = fresh(); val financeMigration = fresh()
        val appKey = "base64:" + java.util.Base64.getEncoder().encodeToString(java.util.HexFormat.of().parseHex(fresh()))
        core.putAll(FireflyCanonical.fragment(inventory, "postgres", "postgres", financeRuntime, financeMigration,
            core.getValue("postgres-ca.pem"), appKey, "https://finance.datamancy.net").inputs)
        core["firefly-db-admin.env"] = "PGHOST=postgres\nPGUSER=postgres\nPGDATABASE=postgres\nPGPASSWORD=$postgresAdmin\nPGSSLMODE=verify-full\nPGSSLROOTCERT=/run/secrets/postgres-ca.pem\nFIREFLY_RUNTIME_PASSWORD=$financeRuntime\nFIREFLY_MIGRATION_PASSWORD=$financeMigration\n"
        core.putAll(CaddyRuntime.inputs())
        return core
    }

    /** D03 verifies exact fresh/continued compiler equality before invoking this projection. No
     * generic one-shot filtering: newly introduced jobs must be reviewed by their owner first. */
    fun coldRestoreProvidersSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec {
        val identityJobs = setOf("identity-db-init", "identity-realm-init", "identity-db-finalize")
        val financeJobs = setOf("firefly-files-init", "firefly-migrate", "firefly-runtime-config")
        val providerJobs = setOf("postgres-init", "planka-db-init", "planka-init", "postgres-finalize", "ntfy-auth-init",
            "mariadb-init", "firefly-db-init", "firefly-db-finalize")
        require(compiled.processes.filter { it.oneShot }.map { it.id }.toSet() == identityJobs + financeJobs + providerJobs) {
            "Unreviewed canonical initializer retirement"
        }
        require(compiled.processes.single { it.id == "caddy" }.command == listOf("run", "--resume", "--config", "/run/secrets/caddy.json")) {
            "Unreviewed Caddy restore command"
        }
        val identity = compiled.copy(processes = IdentityRuntime.canonicalColdRestoreProcesses(compiled.processes),
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
                "mariadb-bootstrap.env", "ntfy-bootstrap.env", "identity-db-admin.env", "identity-migration.env", "identity-realm.json",
                "firefly-db-admin.env", "firefly-migration.env") }) { "Bootstrap authority survived provider restore" }
            PrivateDeployment.validate(restored)
        }
    }

    fun prepareProviders(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE,
        name: String = "canonical-providers", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(providersSpec(inventory, name).copy(store = store), base) { providersInputs(inventory) }
}
