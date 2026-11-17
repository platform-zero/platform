package net.datamancy.platform

import java.nio.file.Path
import java.util.Base64
import kotlinx.serialization.json.put
import kotlinx.serialization.json.add

/** Private BookStack with an isolated MariaDB and native initial-admin replacement before web startup. */
internal object BookStackRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "bookstack"): PrivateDeploymentSpec {
        val sql = SqlCacheRuntime.spec(inventory, name)
        val image = inventory.images.single { it.product == "bookstack" }
        require(image.os == "linux" && image.architecture == "amd64")
        val database = sql.processes.filter { it.id != "memcached" }.map { p ->
            if (p.id != "mariadb-init") p else p.copy(environmentFile = "database-init.env", command = p.command.map {
                it.replace("ALTER USER", """
                    CREATE DATABASE bookstack CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
                    CREATE USER 'bookstack'@'%' IDENTIFIED BY '${'$'}BOOKSTACK_DB_PASSWORD';
                    GRANT ALL PRIVILEGES ON bookstack.* TO 'bookstack'@'%';
                    ALTER USER
                """.trimIndent())
            })
        }
        val app = RuntimeProcess("php", image.pinnedImage, image.imageId, 911, environmentFile = "bookstack.env",
            apparmorProfile = "p0v3-private-v1", memoryMiB = 1024,
            volumes = listOf(RuntimeMount("config", "/config"), RuntimeMount("storage", "/app/www/storage"),
                RuntimeMount("cache", "/app/www/bootstrap/cache"), RuntimeMount("uploads", "/config/www/uploads")))
        return PrivateDeploymentSpec(name = name,
            volumes = sql.volumes + listOf("config", "storage", "cache", "uploads").map { RuntimeVolume(it, 911) },
            processes = database + listOf(
                app.copy(id = "bookstack-files-init", oneShot = true, entrypoint = "/bin/sh",
                    volumes = listOf(RuntimeMount("config", "/config"), RuntimeMount("storage", "/seed/storage"),
                        RuntimeMount("cache", "/seed/cache"), RuntimeMount("uploads", "/seed/uploads")),
                    command = listOf("-ec", """
                        cp -R /app/www/storage/. /seed/storage/
                        cp -R /app/www/bootstrap/cache/. /seed/cache/
                        mkdir -p /config/backups /config/log/bookstack /config/www/files /config/www/images /config/www/uploads
                        for folder in cache/data purifier sessions views; do mkdir -p /config/www/framework/${'$'}folder; done
                    """.trimIndent())),
                app.copy(id = "bookstack-migrate", oneShot = true, dependencies = listOf("mariadb", "bookstack-files-init"),
                    entrypoint = "/bin/sh", environmentFile = "admin.env",
                    files = listOf(RuntimeFile("admin.php", "/run/secrets/admin.php")),
                    command = listOf("-ec", "cd /app/www; php artisan migrate --force --no-interaction; php /run/secrets/admin.php; php artisan config:cache --no-interaction")),
                app.copy(dependencies = listOf("bookstack-migrate"), entrypoint = "/usr/sbin/php-fpm85",
                    command = listOf("--nodaemonize", "--fpm-config", "/run/secrets/fpm.conf"),
                    files = listOf(RuntimeFile("fpm.conf", "/run/secrets/fpm.conf"), RuntimeFile("health.php", "/run/secrets/health.php")),
                    readiness = listOf("/usr/bin/php", "-r", "${'$'}s=fsockopen('127.0.0.1',9000,${'$'}e,${'$'}m,3); if(!${'$'}s)exit(1); fclose(${'$'}s);")),
                RuntimeProcess("bookstack", image.pinnedImage, image.imageId, 911, dependencies = listOf("php"),
                    entrypoint = "/usr/sbin/nginx", command = listOf("-e", "/tmp/nginx-error.log", "-c", "/run/secrets/nginx.conf", "-g", "daemon off;"),
                    files = listOf(RuntimeFile("nginx.conf", "/run/secrets/nginx.conf")),
                    volumes = listOf(RuntimeMount("uploads", "/config/www/uploads")),
                    apparmorProfile = "p0v3-private-v1", memoryMiB = 256, readinessHttpPort = 8080, readinessHttpPath = "/login")
            )).also { PrivateDeployment.validate(it) }
    }

    /** Provider-less V2 partial graph. Maria bootstrap must create DB-scoped migration/runtime roles first. */
    fun releaseFragment(inventory: AcquiredInventory, member: String): CanonicalProviderFragment {
        val legacy = spec(inventory, member)
        val owners = legacy.processes.filter { it.id in setOf("bookstack-files-init", "bookstack-migrate", "php", "bookstack") }
        require(owners.size == 4)
        val names = mapOf("php" to "bookstack-php")
        val processes = owners.map { p ->
            val mapped = p.copy(id = names[p.id] ?: p.id,
                volumes = p.volumes.map { it.copy(volume = "bookstack-${it.volume}") },
                dependencies = p.dependencies.map { names[it] ?: it },
                networks = if (p.id == "bookstack") listOf("bookstack-web") else if (p.id == "php")
                    listOf("bookstack-data", "bookstack-web", "identity-web") else listOf("bookstack-data"),
                environmentFile = when (p.id) {
                    "bookstack-migrate" -> "bookstack-migration.env"
                    "php" -> "bookstack-runtime.env"
                    else -> null
                }, files = p.files.map { file -> if (p.id == "bookstack" && file.file == "nginx.conf")
                    file.copy(file = "bookstack-nginx.conf") else if (file.file == "admin.php")
                    file.copy(file = "bookstack-admin.php") else file.copy(file = "bookstack-${file.file}") } +
                    if (p.id in setOf("php", "bookstack-migrate")) listOf(
                        RuntimeFile("mariadb-ca.pem", "/run/secrets/mariadb-ca.pem"),
                        RuntimeFile("bookstack-closed-registration.php", "/config/www/themes/p0v3-closed/functions.php")) else emptyList())
            when (p.id) {
                "bookstack-files-init" -> mapped.copy(command = p.command.map { it + "\nmkdir -p /config/www/themes/p0v3-closed" })
                "bookstack-migrate" -> mapped.copy(dependencies = listOf("mariadb", "bookstack-files-init"))
                "php" -> mapped.copy(dependencies = listOf("mariadb", "bookstack-migrate"))
                "bookstack" -> mapped.copy(dependencies = listOf("bookstack-php"), readinessHttpPath = "/healthz")
                else -> mapped
            }
        }
        return CanonicalProviderFragment("bookstack", PrivateDeploymentSpec(name = member,
            store = RuntimeStore.CANONICAL_V2, volumes = legacy.volumes.filter { it.id !in setOf("mariadb", "memcached") }
                .map { it.copy(id = "bookstack-${it.id}") },
            networks = listOf("bookstack-data", "bookstack-web", "identity-web"), processes = processes,
            databaseAccess = listOf(
                RuntimeDatabaseAccess("bookstack-migrate", "mariadb", "mariadb", "bookstack", "bookstack_migrate", "bookstack-migration.env", "bookstack-data"),
                RuntimeDatabaseAccess("bookstack-php", "mariadb", "mariadb", "bookstack", "bookstack_runtime", "bookstack-runtime.env", "bookstack-data"))),
            providerNetworks = mapOf("mariadb" to setOf("bookstack-data")), webNetworks = setOf("bookstack-web"),
            identityWebConsumers = setOf(CanonicalIdentityWebConsumer.BOOKSTACK_PHP))
    }

    fun releaseColdFragment(fresh: CanonicalProviderFragment): CanonicalProviderFragment {
        require(fresh.product == "bookstack" && fresh.spec.store == RuntimeStore.CANONICAL_V2 &&
            fresh.spec.processes.filter { it.oneShot }.map { it.id }.toSet() == setOf("bookstack-files-init", "bookstack-migrate"))
        return fresh.copy(spec = fresh.spec.copy(processes = fresh.spec.processes.filterNot { it.oneShot }.map { p ->
            p.copy(dependencies = p.dependencies.filterNot { it in setOf("bookstack-files-init", "bookstack-migrate") })
        }, databaseAccess = fresh.spec.databaseAccess.filterNot { it.consumer == "bookstack-migrate" }))
    }

    /** The one original realm carries this exact confidential BookStack browser
     * client. No direct grants, wildcard redirects, or local registration surface. */
    fun releaseOidcClient(secret: String): kotlinx.serialization.json.JsonObject {
        require(secret.matches(Regex("[a-f0-9]{64}")))
        return kotlinx.serialization.json.buildJsonObject {
            put("clientId", "bookstack"); put("enabled", true); put("protocol", "openid-connect")
            put("publicClient", false); put("secret", secret)
            put("standardFlowEnabled", true); put("directAccessGrantsEnabled", false)
            put("serviceAccountsEnabled", false); put("fullScopeAllowed", false)
            put("redirectUris", kotlinx.serialization.json.buildJsonArray {
                add("https://bookstack.datamancy.net/oidc/callback")
            })
            put("webOrigins", kotlinx.serialization.json.buildJsonArray {
                add("https://bookstack.datamancy.net")
            })
        }
    }

    /** A05 supplies the original owner UUID and exactly one app-scoped OIDC client secret. */
    fun releaseInputs(mariaCredentials: CanonicalMariaCredentialPair, appKey: String,
        originalOwnerId: String, oidcClientSecret: String, initialAdminPassword: String,
        freshApi: FreshNativeIngressGrants? = null, generation: String? = null,
        outsiderGrant: FreshBookstackOutsiderGrant? = null): Map<String, String> {
        val (migrationPassword, runtimePassword) = mariaCredentials
        require(listOf(oidcClientSecret, initialAdminPassword).all { it.matches(Regex("[a-f0-9]{64}")) } &&
            setOf(runtimePassword, migrationPassword, oidcClientSecret, initialAdminPassword).size == 4)
        require(appKey.matches(Regex("base64:[A-Za-z0-9+/]{43}=")) &&
            runCatching { java.util.UUID.fromString(originalOwnerId).toString() == originalOwnerId }.getOrDefault(false))
        val templates = FireflyRuntime.inputs { "0".repeat(64) }
        fun env(username: String, password: String) = """
            APP_ENV=production
            APP_DEBUG=false
            APP_KEY=$appKey
            APP_URL=https://bookstack.datamancy.net
            DB_HOST=mariadb
            DB_PORT=3306
            DB_DATABASE=bookstack
            DB_USERNAME=$username
            DB_PASSWORD=$password
            MYSQL_ATTR_SSL_CA=/run/secrets/mariadb-ca.pem
            MAIL_DRIVER=array
            STORAGE_TYPE=local_secure_restricted
            LOG_CHANNEL=stderr
            AUTH_METHOD=oidc
            OIDC_NAME=Platform Zero
            OIDC_CLIENT_ID=bookstack
            OIDC_CLIENT_SECRET=$oidcClientSecret
            OIDC_ISSUER=https://auth.datamancy.net/realms/p0v3
            OIDC_ISSUER_DISCOVER=true
            OIDC_USER_TO_GROUPS=false
            OIDC_FETCH_AVATAR=false
            OIDC_DUMP_USER_DETAILS=false
            APP_THEME=p0v3-closed
            SESSION_SECURE_COOKIE=true
            APP_TIMEZONE=UTC
        """.trimIndent() + "\n"
        require((freshApi == null && generation == null && outsiderGrant == null) ||
            (freshApi?.bookstackApiId != null && freshApi.bookstackApiSecret != null &&
                generation?.matches(Regex("q-[a-f0-9]{12}")) == true &&
                (outsiderGrant == null || outsiderGrant.subjectUuid != originalOwnerId)))
        val apiSource = freshApi?.let { FreshBookstackApiSource.inputs(it, outsiderGrant) }.orEmpty()
        return mapOf("bookstack-runtime.env" to env("bookstack_runtime", runtimePassword),
            "bookstack-migration.env" to env("bookstack_migrate", migrationPassword) +
                "P0V3_OWNER_SUB=$originalOwnerId\nP0V3_INITIAL_ADMIN_PASSWORD=$initialAdminPassword\n" +
                (if (freshApi == null) "" else apiSource.getValue("bookstack-api-grant.env") +
                    "P0V3_GENERATION=$generation\n"),
            // The selected Keycloak issuer at auth.datamancy.net is served by
            // this generation's private identity leaf, not a public ACME leaf.
            // Keep its CA separate from MariaDB's explicitly scoped TLS CA.
            "bookstack-fpm.conf" to templates.getValue("fpm.conf") + (if (freshApi == null) "" else
                "php_admin_value[curl.cainfo] = /run/secrets/identity-ca.pem\n" +
                "php_admin_value[openssl.cafile] = /run/secrets/identity-ca.pem\n"),
            "bookstack-health.php" to templates.getValue("health.php"),
            "bookstack-closed-registration.php" to """
                <?php
                use BookStack\Facades\Theme;
                use BookStack\Theming\ThemeEvents;
                Theme::listen(ThemeEvents::AUTH_PRE_REGISTER, function () { return false; });
            """.trimIndent() + "\n",
            "bookstack-nginx.conf" to templates.getValue("nginx.conf")
                .replace("/var/www/html/public", "/app/www/public")
                .replace("server_name firefly", "server_name bookstack")
                .replace("php:9000", "bookstack-php:9000"),
            "bookstack-admin.php" to """
                <?php
                require '/app/www/vendor/autoload.php';
                ${'$'}app = require '/app/www/bootstrap/app.php';
                ${'$'}app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
                ${'$'}code = Illuminate\Support\Facades\Artisan::call('bookstack:create-admin', [
                    '--initial' => true, '--email' => 'owner@localhost.invalid', '--name' => 'Original owner',
                    '--external-auth-id' => getenv('P0V3_OWNER_SUB'),
                    '--password' => getenv('P0V3_INITIAL_ADMIN_PASSWORD'), '--no-interaction' => true
                ]);
                if (${'$'}code !== 0 || BookStack\Users\Models\User::where('email', 'admin@admin.com')->exists()) exit(1);
            """.trimIndent() + "\n") + (if (freshApi == null) emptyMap() else mapOf(
            "bookstack-api.php" to apiSource.getValue("bookstack-api.php")))
    }

    fun inputs(): Map<String, String> {
        val root = RuntimePreparation.password()
        val database = RuntimePreparation.password()
        val key = Base64.getEncoder().encodeToString(java.util.HexFormat.of().parseHex(RuntimePreparation.password()))
        val env = "APP_ENV=production\nAPP_DEBUG=false\nAPP_KEY=base64:$key\nAPP_URL=http://bookstack:8080\nDB_HOST=mariadb\nDB_PORT=3306\nDB_DATABASE=bookstack\nDB_USERNAME=bookstack\nDB_PASSWORD=$database\nMAIL_DRIVER=array\nSTORAGE_TYPE=local_secure_restricted\nLOG_CHANNEL=stderr\nAUTH_METHOD=standard\nSESSION_SECURE_COOKIE=false\nAPP_TIMEZONE=UTC\n"
        val web = FireflyRuntime.inputs()
        return mapOf("mariadb.env" to "MARIADB_ROOT_PASSWORD=$root\n",
            "database-init.env" to "MARIADB_ROOT_PASSWORD=$root\nBOOKSTACK_DB_PASSWORD=$database\n",
            "bookstack.env" to env, "admin.env" to env + "P0V3_FIXTURE_PASSWORD=${RuntimePreparation.password()}\n",
            "fpm.conf" to web.getValue("fpm.conf"), "health.php" to web.getValue("health.php"),
            "nginx.conf" to web.getValue("nginx.conf").replace("/var/www/html/public", "/app/www/public").replace("server_name firefly", "server_name bookstack"),
            "admin.php" to """
                <?php
                require '/app/www/vendor/autoload.php';
                ${'$'}app = require '/app/www/bootstrap/app.php';
                ${'$'}app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
                ${'$'}code = Illuminate\Support\Facades\Artisan::call('bookstack:create-admin', [
                    '--initial' => true, '--email' => 'fixture@localhost.invalid', '--name' => 'Private fixture',
                    '--password' => getenv('P0V3_FIXTURE_PASSWORD'), '--no-interaction' => true
                ]);
                if (${'$'}code !== 0 || BookStack\Users\Models\User::where('email', 'admin@admin.com')->exists()) exit(1);
            """.trimIndent() + "\n")
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "bookstack", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base, ::inputs)
}
