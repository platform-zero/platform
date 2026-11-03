package net.datamancy.platform

/** Provider-less Firefly fragment. The canonical compiler owns PostgreSQL, role creation and networks. */
internal data class FireflyCanonicalFragment(
    val processes: List<RuntimeProcess>, val volumes: List<RuntimeVolume>,
    val inputs: Map<String, String>, val processOwners: Map<String, String>,
    val database: String = "firefly", val runtimeRole: String = "firefly_runtime", val migrationRole: String = "firefly_migration"
)

internal data class FireflyCanonicalProjection(val processes: List<RuntimeProcess>, val volumes: List<RuntimeVolume>,
    val processOwners: Map<String, String>)

internal object FireflyCanonical {
    /** Pure planning: no entropy, PKI, credentials or files are generated or returned. */
    fun projection(inventory: AcquiredInventory, postgresProcessId: String): FireflyCanonicalProjection {
        val shape = fragment(inventory, postgresProcessId, "postgres", "1".repeat(64), "2".repeat(64),
            "-----BEGIN CERTIFICATE-----\nplanning-only\n-----END CERTIFICATE-----\n",
            "base64:" + "A".repeat(43) + "=", "https://firefly.datamancy.net")
        return FireflyCanonicalProjection(shape.processes, shape.volumes, shape.processOwners)
    }

    /** Both roles/database must already exist; migration role owns schema, runtime role never owns it. */
    fun fragment(inventory: AcquiredInventory, postgresProcessId: String, databaseHost: String,
                 runtimePassword: String, migrationPassword: String, caPem: String, appKey: String,
                 publicOrigin: String): FireflyCanonicalFragment {
        require(postgresProcessId.matches(Regex("[a-z][a-z0-9-]{0,47}")))
        require(databaseHost.matches(Regex("[a-z][a-z0-9.-]{0,252}")) && !databaseHost.contains(".."))
        require(runtimePassword.matches(Regex("[a-f0-9]{64}")) && migrationPassword.matches(Regex("[a-f0-9]{64}")) && runtimePassword != migrationPassword)
        require(appKey.matches(Regex("base64:[A-Za-z0-9+/]{43}=")))
        require(caPem.startsWith("-----BEGIN CERTIFICATE-----\n") && caPem.trimEnd().endsWith("-----END CERTIFICATE-----"))
        val origin = java.net.URI(publicOrigin)
        require(origin.scheme == "https" && origin.host?.endsWith(".datamancy.net") == true && origin.userInfo == null &&
            origin.port == -1 && origin.rawPath.isNullOrEmpty() && origin.query == null && origin.fragment == null)
        // The caller must additionally bind this exact host to its approved site-ownership document.
        val legacy = FireflyRuntime.spec(inventory)
        // Legacy template filler is deterministic here. Every actual key/credential is supplied by
        // the canonical owner below; unused provider/fixture inputs are never returned.
        val generated = FireflyRuntime.inputs { "0".repeat(64) }
        fun env(user: String, password: String): String = generated.getValue("firefly.env").lineSequence()
            .filter { it.isNotBlank() && !it.startsWith("P0V3_FIXTURE_PASSWORD=") }
            .joinToString("\n", postfix = "\n") { line -> when (line.substringBefore('=')) {
                "APP_KEY" -> "APP_KEY=$appKey"
                "DB_HOST" -> "DB_HOST=$databaseHost"
                "DB_USERNAME" -> "DB_USERNAME=$user"
                "DB_PASSWORD" -> "DB_PASSWORD=$password"
                "PGSQL_SSL_MODE" -> "PGSQL_SSL_MODE=verify-full"
                "APP_URL" -> "APP_URL=$publicOrigin"
                "COOKIE_SECURE" -> "COOKIE_SECURE=true"
                else -> line
            } } + "PGSSLROOTCERT=/run/secrets/firefly-db-ca.pem\nPGSSLMODE=verify-full\n"
        val names = mapOf("php" to "firefly-php", "firefly" to "firefly", "firefly-files-init" to "firefly-files-init", "firefly-migrate" to "firefly-migrate")
        val inputs = mapOf(
            "firefly-runtime.env" to env("firefly_runtime", runtimePassword),
            "firefly-migration.env" to env("firefly_migration", migrationPassword),
            "firefly-db-ca.pem" to caPem,
            "firefly-fpm.conf" to generated.getValue("fpm.conf"), "firefly-health.php" to generated.getValue("health.php"),
            "firefly-nginx.conf" to generated.getValue("nginx.conf").replace("php:9000", "firefly-php:9000")
        )
        val processes = legacy.processes.filter { it.id in names }.map { p ->
            val base = p.copy(id = names.getValue(p.id),
                volumes = p.volumes.map { it.copy(volume = "firefly-${it.volume}") },
                environmentFile = if (p.environmentFile == null) null else "firefly-runtime.env",
                files = p.files.map { it.copy(file = "firefly-${it.file}") } +
                    if (p.environmentFile != null) listOf(RuntimeFile("firefly-db-ca.pem", "/run/secrets/firefly-db-ca.pem")) else emptyList(),
                dependencies = p.dependencies.map { names[it] ?: postgresProcessId })
            when (p.id) {
                "firefly-migrate" -> base.copy(environmentFile = "firefly-migration.env", command = listOf("-ec", """
                    php artisan config:clear --no-interaction
                    php artisan migrate --seed --force --no-interaction
                    php artisan firefly-iii:upgrade-database --no-interaction
                    php artisan firefly-iii:laravel-passport-keys --no-interaction
                    test -s storage/oauth-private.key; test -s storage/oauth-public.key
                    chmod 600 storage/oauth-private.key storage/oauth-public.key
                    php artisan config:clear --no-interaction
                """.trimIndent()))
                "php" -> base.copy(dependencies = listOf(postgresProcessId, "firefly-runtime-config"))
                else -> base
            }
        }
        val configure = processes.single { it.id == "firefly-php" }.copy(id = "firefly-runtime-config", oneShot = true,
            dependencies = listOf("firefly-migrate"), entrypoint = "/bin/sh", readiness = emptyList(),
            command = listOf("-ec", "php artisan config:cache --no-interaction"))
        return FireflyCanonicalFragment(processes + configure,
            legacy.volumes.filter { it.id != "postgres" }.map { it.copy(id = "firefly-${it.id}") }, inputs,
            (processes + configure).associate { it.id to "firefly-iii" })
    }

    /** Called only after whole-cohort authenticated cold import, never instead of import validation. */
    fun coldRestoreSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec {
        val ids = setOf("firefly-files-init", "firefly-migrate", "firefly-runtime-config", "firefly-php", "firefly")
        require(compiled.processes.map { it.id }.toSet().containsAll(ids)) { "Missing compiled canonical Firefly processes" }
        val retired = ids - setOf("firefly-php", "firefly")
        return compiled.copy(processes = compiled.processes.filterNot { it.id in retired }.map { p ->
            p.copy(dependencies = p.dependencies.filterNot { it in retired })
        }, databaseAccess = compiled.databaseAccess.filterNot { it.consumer in retired })
    }
}
