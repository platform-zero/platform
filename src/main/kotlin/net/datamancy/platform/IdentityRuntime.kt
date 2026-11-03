package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.*

/** Persistent private Keycloak deployment, not public identity activation. */
internal object IdentityRuntime {
    private const val IMAGE = "localhost/p0v3-keycloak@sha256:ff264e6231948cf3b879dc3d08f89cbdd0dbef24c044ef1c4dcd71f571b77c1e"
    private const val IMAGE_ID = "345177fdf5102c9a0b017e1ef0eb409a0020c74ee4feaca82b1389758de041e1"
    fun spec(inventory: AcquiredInventory, name: String = "identity"): PrivateDeploymentSpec {
        val foundation = FoundationRuntime.spec(inventory, name)
        val pg = foundation.processes.single { it.id == "postgres" }
        return PrivateDeploymentSpec(name = name, volumes = foundation.volumes.filter { it.id == "postgres" },
            processes = foundation.processes.filter { it.id in setOf("postgres-init", "postgres") } + listOf(
                RuntimeProcess("identity-db-init", pg.image, pg.imageId, 999, dependencies = listOf("postgres"),
                    entrypoint = "/bin/sh", environmentFile = "database-init.env", oneShot = true,
                    apparmorProfile = "p0v3-private-v1", command = listOf("-ec", """
                        export PGPASSWORD="${'$'}POSTGRES_PASSWORD"
                        psql -X -h postgres -U postgres -v ON_ERROR_STOP=1 <<SQL
                        CREATE ROLE keycloak LOGIN PASSWORD '${'$'}KEYCLOAK_PASSWORD';
                        CREATE DATABASE keycloak OWNER keycloak;
                        SQL
                    """.trimIndent())),
                RuntimeProcess("keycloak", IMAGE, IMAGE_ID, 1000, groupId = 0, dependencies = listOf("identity-db-init"),
                    command = listOf("start", "--optimized", "--import-realm"), environmentFile = "keycloak.env",
                    files = listOf(RuntimeFile("realm.json", "/opt/keycloak/data/import/realm.json")),
                    tmpfs = listOf("/tmp", "/opt/keycloak/data"), memoryMiB = 1024, apparmorProfile = "p0v3-private-v1",
                    readiness = listOf("/bin/bash", "-ec", "exec 3<>/dev/tcp/127.0.0.1/9000; printf 'GET /health/ready HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' >&3; read -r -t 3 line <&3; [[ \"${'$'}line\" == *' 200 '* ]]"))
            )).also { PrivateDeployment.validate(it) }
    }
    fun inputs(): Map<String, String> {
            val postgresPassword = RuntimePreparation.password()
            val applicationPassword = RuntimePreparation.password()
            val bootstrapPassword = RuntimePreparation.password()
            val initialPassword = RuntimePreparation.password()
            val realm = buildJsonObject {
                put("realm", "p0v3"); put("enabled", true); put("sslRequired", "none"); put("registrationAllowed", false)
                put("users", buildJsonArray { add(buildJsonObject {
                    put("username", "owner"); put("enabled", true)
                    put("requiredActions", buildJsonArray { add("UPDATE_PASSWORD"); add("CONFIGURE_TOTP") })
                    put("credentials", buildJsonArray { add(buildJsonObject {
                        put("type", "password"); put("value", initialPassword); put("temporary", true)
                    }) })
                }) })
            }
            return mapOf(
                "postgres.env" to "POSTGRES_PASSWORD=$postgresPassword\n",
                "database-init.env" to "POSTGRES_PASSWORD=$postgresPassword\nKEYCLOAK_PASSWORD=$applicationPassword\n",
                "keycloak.env" to "KC_DB=postgres\nKC_DB_URL=jdbc:postgresql://postgres:5432/keycloak\nKC_DB_USERNAME=keycloak\nKC_DB_PASSWORD=$applicationPassword\nKC_HTTP_ENABLED=true\nKC_HOSTNAME=http://keycloak:8080\nKC_BOOTSTRAP_ADMIN_USERNAME=p0v3-bootstrap\nKC_BOOTSTRAP_ADMIN_PASSWORD=$bootstrapPassword\n",
                "realm.json" to realm.toString())
    }
    /** Provider-less canonical projection. Caller owns postgres and the three named networks.
     * Offline realm import owns migrations; serving Keycloak cannot run DDL or regain bootstrap inputs. */
    fun canonicalProcesses(postgres: RuntimeProcess): List<RuntimeProcess> {
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
            RuntimeProcess("identity-realm-init", IMAGE, IMAGE_ID, 1000, groupId = 0, dependencies = listOf("identity-db-init"),
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
            RuntimeProcess("keycloak", IMAGE, IMAGE_ID, 1000, groupId = 0, dependencies = listOf("identity-db-finalize"),
                command = listOf("start", "--optimized", "--spi-connections-jpa--quarkus--migration-strategy=validate"),
                environmentFile = "identity-runtime.env", memoryMiB = 1024, networks = listOf("keycloak-data", "identity-web"),
                files = listOf("identity-web.pem", "identity-web-key.pem", "identity-ca.pem", "postgres-ca.pem").map { RuntimeFile(it, "/run/secrets/$it") },
                tmpfs = listOf("/tmp", "/opt/keycloak/data"), apparmorProfile = "p0v3-private-v1",
                readiness = listOf("/bin/bash", "-ec", "exec 3<>/dev/tcp/127.0.0.1/9000; printf 'GET /health/ready HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' >&3; read -r -t 3 line <&3; [[ \"${'$'}line\" == *' 200 '* ]]"))
        )
    }

    /** Composable projection; other products' jobs are intentionally left for their owning projections. */
    fun canonicalColdRestoreProcesses(processes: List<RuntimeProcess>): List<RuntimeProcess> {
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

    fun canonicalInputs(postgresAdminPassword: String, pki: () -> Map<String, String> = { PrivateWebPki.generate("keycloak") },
        password: () -> String = RuntimePreparation::password, clients: JsonArray = JsonArray(emptyList())): Map<String, String> {
        val migration = password(); val runtime = password(); val initial = password()
        require((listOf(postgresAdminPassword, migration, runtime, initial)).all { it.matches(Regex("[a-f0-9]{64}")) })
        require(setOf(postgresAdminPassword, migration, runtime, initial).size == 4)
        val tls = pki()
        require(tls.keys == setOf("ca.pem", "web.pem", "web-key.pem"))
        val realm = buildJsonObject {
            put("realm", "p0v3"); put("enabled", true); put("sslRequired", "all"); put("registrationAllowed", false)
            put("resetPasswordAllowed", false); put("bruteForceProtected", true); put("accessTokenLifespan", 300)
            put("clients", clients)
            put("users", buildJsonArray { add(buildJsonObject {
                put("id", java.util.UUID.randomUUID().toString()); put("username", "owner"); put("enabled", true)
                // Realm-scoped administration, never master-realm/root authority. Required actions precede token issuance.
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

    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "identity", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base, ::inputs)
}
