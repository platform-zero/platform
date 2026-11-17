package net.datamancy.platform

/** Provider-less Firefly fragment. The canonical compiler owns PostgreSQL, role creation and networks. */
internal data class FireflyCanonicalFragment(
    val processes: List<RuntimeProcess>, val volumes: List<RuntimeVolume>,
    val inputs: Map<String, String>, val processOwners: Map<String, String>,
    val database: String = "firefly", val runtimeRole: String = "firefly_runtime", val migrationRole: String = "firefly_migration"
)

internal data class FireflyCanonicalProjection(val processes: List<RuntimeProcess>, val volumes: List<RuntimeVolume>,
    val processOwners: Map<String, String>)

/** Original Keycloak subject IDs are bound to native Firefly numeric users. The two
 * passwords remain in protected ONE-SHOT input only, never any serving daemon.
 */
internal data class FireflyOriginalSubjects(val ownerUuid: String, val outsiderUuid: String,
    val ownerPassword: String, val outsiderPassword: String, val generation: String) {
    init {
        require(listOf(ownerUuid, outsiderUuid).all {
            runCatching { java.util.UUID.fromString(it).toString() == it }.getOrDefault(false)
        } && ownerUuid != outsiderUuid &&
            listOf(ownerPassword, outsiderPassword).all { it.matches(Regex("[a-f0-9]{64}")) } &&
            ownerPassword != outsiderPassword && generation.matches(Regex("q-[a-f0-9]{12}")))
    }
}

internal object FireflyCanonical {
    /** Core runs this read-only Laravel probe against the ORIGINAL installed database after
     * both app users have actually completed first use. Original sealed onboarding credentials
     * are inputs; native account IDs and scoped roles are queried again, never inferred from
     * the journal receipt. Its stdout contains no credential or password hash.
     */
    fun nativeIssuanceReadbackSource(): String {
        val d = '$'
        return """
            <?php
            declare(strict_types=1);
            error_reporting(0); ini_set('display_errors', '0'); umask(0077); ob_start();
            try {
                require '/var/www/html/vendor/autoload.php';
                ${d}app = require '/var/www/html/bootstrap/app.php';
                ${d}app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
                ${d}ownerSub = getenv('P0V3_OWNER_SUB'); ${d}outsiderSub = getenv('P0V3_OUTSIDER_SUB');
                ${d}ownerPass = getenv('P0V3_OWNER_PASSWORD'); ${d}outsiderPass = getenv('P0V3_OUTSIDER_PASSWORD');
                if (!preg_match('/^[0-9a-f-]{36}${d}/D', ${d}ownerSub) ||
                    !preg_match('/^[0-9a-f-]{36}${d}/D', ${d}outsiderSub) || ${d}ownerSub === ${d}outsiderSub ||
                    !preg_match('/^[a-f0-9]{64}${d}/D', ${d}ownerPass) ||
                    !preg_match('/^[a-f0-9]{64}${d}/D', ${d}outsiderPass) || ${d}ownerPass === ${d}outsiderPass)
                    throw new RuntimeException('Foreign original finance grant');
                ${d}repo = app(FireflyIII\Repositories\User\UserRepositoryInterface::class);
                ${d}owner = ${d}repo->findByEmail(${d}ownerSub);
                ${d}outsider = ${d}repo->findByEmail(${d}outsiderSub);
                if (${d}owner === null || ${d}outsider === null || ${d}repo->count() !== 2 ||
                    ${d}owner->id === ${d}outsider->id || ${d}owner->blocked || ${d}outsider->blocked ||
                    !${d}owner->hasRole('owner') || ${d}outsider->hasRole('owner') ||
                    ${d}owner->getAdministrationId() === ${d}outsider->getAdministrationId() ||
                    ${d}outsider->groupMemberships()->where('user_group_id', ${d}owner->getAdministrationId())->exists() ||
                    !Illuminate\Support\Facades\Hash::check(${d}ownerPass, ${d}owner->password) ||
                    !Illuminate\Support\Facades\Hash::check(${d}outsiderPass, ${d}outsider->password))
                    throw new RuntimeException('Original native finance account/role/credential missing');
                while (ob_get_level()) ob_end_clean();
                echo json_encode(['owner' => 'owner', 'outsider' => 'outsider',
                    'ownerNativeId' => ${d}owner->id, 'outsiderNativeId' => ${d}outsider->id,
                    'ownerSubjectUuid' => ${d}owner->email, 'outsiderSubjectUuid' => ${d}outsider->email], JSON_THROW_ON_ERROR), "\n";
            } catch (Throwable ${d}error) { while (ob_get_level()) ob_end_clean(); exit(1); }
        """.trimIndent() + "\n"
    }

    /** Pure planning: no entropy, PKI, credentials or files are generated or returned. */
    fun projection(inventory: AcquiredInventory, postgresProcessId: String,
        includeNativeOnboarding: Boolean = false): FireflyCanonicalProjection {
        val shape = fragment(inventory, postgresProcessId, "postgres", "1".repeat(64), "2".repeat(64),
            "-----BEGIN CERTIFICATE-----\nplanning-only\n-----END CERTIFICATE-----\n",
            "base64:" + "A".repeat(43) + "=", "https://firefly.datamancy.net",
            includeNativeOnboarding = includeNativeOnboarding)
        return FireflyCanonicalProjection(shape.processes, shape.volumes, shape.processOwners)
    }

    /** Both roles/database must already exist; migration role owns schema, runtime role never owns it. */
    fun fragment(inventory: AcquiredInventory, postgresProcessId: String, databaseHost: String,
                 runtimePassword: String, migrationPassword: String, caPem: String, appKey: String,
                 publicOrigin: String, originalSubjects: FireflyOriginalSubjects? = null,
                 includeNativeOnboarding: Boolean = originalSubjects != null,
                 freshRemoteSubjects: Boolean = false,
                 freshImporterClientId: String? = null): FireflyCanonicalFragment {
        require(!freshRemoteSubjects || originalSubjects != null && includeNativeOnboarding)
        require(freshImporterClientId == null || freshRemoteSubjects &&
            freshImporterClientId.matches(Regex("[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")))
        require(includeNativeOnboarding || originalSubjects == null) { "No original users may leak into historical provider bytes" }
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
                "SITE_OWNER" -> if (includeNativeOnboarding) "SITE_OWNER=owner@localhost.invalid" else line
                "DB_HOST" -> "DB_HOST=$databaseHost"
                "DB_USERNAME" -> "DB_USERNAME=$user"
                "DB_PASSWORD" -> "DB_PASSWORD=$password"
                "PGSQL_SSL_MODE" -> "PGSQL_SSL_MODE=verify-full"
                "APP_URL" -> "APP_URL=$publicOrigin"
                "AUTHENTICATION_GUARD" -> if (freshRemoteSubjects) "AUTHENTICATION_GUARD=remote_user_guard" else line
                "COOKIE_SECURE" -> "COOKIE_SECURE=true"
                else -> line
            } } + "PGSSLROOTCERT=/run/secrets/firefly-db-ca.pem\nPGSSLMODE=verify-full\n" +
            (if (freshRemoteSubjects) "AUTHENTICATION_GUARD_HEADER=HTTP_X_FORWARDED_USER\n" +
                "AUTHENTICATION_GUARD_EMAIL=HTTP_X_FORWARDED_EMAIL\n" +
                "COOKIE_NAME=__Host-firefly_app\n" +
                "SESSION_DRIVER=file\n" else "")
        val names = mapOf("php" to "firefly-php", "firefly" to "firefly", "firefly-files-init" to "firefly-files-init", "firefly-migrate" to "firefly-migrate")
        val inputs = mutableMapOf(
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
        val users = processes.single { it.id == "firefly-migrate" }.copy(id = "firefly-users-init",
            dependencies = listOf("firefly-migrate") + if (freshRemoteSubjects) listOf("keycloak") else emptyList(),
            environmentFile = "firefly-onboarding.env",
            entrypoint = "/usr/local/bin/php", command = listOf("/run/secrets/firefly-users.php"), readiness = emptyList(),
            files = listOf(RuntimeFile("firefly-users.php", "/run/secrets/firefly-users.php"),
                RuntimeFile("firefly-db-ca.pem", "/run/secrets/firefly-db-ca.pem")))
        val configure = processes.single { it.id == "firefly-php" }.copy(id = "firefly-runtime-config", oneShot = true,
            dependencies = listOf(if (includeNativeOnboarding) "firefly-users-init" else "firefly-migrate"),
            entrypoint = "/bin/sh", readiness = emptyList(),
            command = listOf("-ec", "php artisan config:cache --no-interaction"))
        if (originalSubjects != null) {
            inputs["firefly-onboarding.env"] = env("firefly_migration", migrationPassword) +
                "P0V3_OWNER_PASSWORD=${originalSubjects.ownerPassword}\n" +
                "P0V3_OUTSIDER_PASSWORD=${originalSubjects.outsiderPassword}\n" +
                "P0V3_OWNER_SUB=${originalSubjects.ownerUuid}\n" +
                "P0V3_OUTSIDER_SUB=${originalSubjects.outsiderUuid}\n" +
                "P0V3_ORIGINAL_GENERATION=${originalSubjects.generation}\n" +
                (if (freshImporterClientId != null) "P0V3_IMPORTER_CLIENT_ID=$freshImporterClientId\n" else "")
            inputs["firefly-users.php"] = nativeUsersScript(freshRemoteSubjects, freshImporterClientId != null)
        }
        val all = processes + (if (includeNativeOnboarding) listOf(users, configure) else listOf(configure))
        return FireflyCanonicalFragment(all,
            legacy.volumes.filter { it.id != "postgres" }.map { it.copy(id = "firefly-${it.id}") }, inputs,
            all.associate { it.id to "firefly-iii" })
    }

    /** Real pinned Firefly v6.7.9 UserRepository::store/Role readback. The image's
     * system:create-first-user is testing-only and prints its password; NEVER use it.
     * Both users have native numeric IDs and one original Keycloak UUID mapping.
     * The protected intent survives any lost ACK; an existing intent is NOT replayed.
     */
    private fun nativeUsersScript(freshRemoteSubjects: Boolean = false, mintImporterClient: Boolean = false): String {
        val d = '$'
        return """
            <?php
            declare(strict_types=1);
            error_reporting(0); ini_set('display_errors', '0'); umask(0077);
            try {
                require '/var/www/html/vendor/autoload.php';
                ${d}app = require '/var/www/html/bootstrap/app.php';
                ${d}app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
                ${d}repository = app(FireflyIII\Repositories\User\UserRepositoryInterface::class);
                ${d}ownerEmail = 'owner@localhost.invalid';
                ${d}outsiderEmail = 'outsider@localhost.invalid';
                ${d}ownerPass = getenv('P0V3_OWNER_PASSWORD');
                ${d}outsiderPass = getenv('P0V3_OUTSIDER_PASSWORD');
                ${d}ownerSub = getenv('P0V3_OWNER_SUB');
                ${d}outsiderSub = getenv('P0V3_OUTSIDER_SUB');
                ${d}generation = getenv('P0V3_ORIGINAL_GENERATION');
                if (!preg_match('/^[a-f0-9]{64}$/D', ${d}ownerPass) ||
                    !preg_match('/^[a-f0-9]{64}$/D', ${d}outsiderPass) || ${d}ownerPass === ${d}outsiderPass ||
                    !preg_match('/^[0-9a-f-]{36}$/D', ${d}ownerSub) ||
                    !preg_match('/^[0-9a-f-]{36}$/D', ${d}outsiderSub) || ${d}ownerSub === ${d}outsiderSub ||
                    !preg_match('/^q-[a-f0-9]{12}$/D', ${d}generation)) throw new RuntimeException('Foreign identity binding');
                ${if (freshRemoteSubjects) "${d}ownerEmail = ${d}ownerSub; ${d}outsiderEmail = ${d}outsiderSub;" else ""}
                if (${d}repository->count() !== 0 || ${d}repository->getRole('owner') === null ||
                    ${d}repository->findByEmail(${d}ownerEmail) !== null ||
                    ${d}repository->findByEmail(${d}outsiderEmail) !== null)
                    throw new RuntimeException('Original users already exist or owner role absent');
                ${d}root = '/var/www/html/storage';
                if (!is_dir(${d}root) || is_link(${d}root)) throw new RuntimeException('Foreign native state volume');
                ${d}intent = ${d}root . '/p0v3-original-users-intent.json';
                ${d}receipt = ${d}root . '/p0v3-original-users-receipt.json';
                if (file_exists(${d}intent) || file_exists(${d}receipt)) throw new RuntimeException('Retained uncertain user intent');
                ${d}fp = fopen(${d}intent, 'x');
                if (${d}fp === false) throw new RuntimeException('No durable exclusive user intent');
                ${d}body = json_encode(['generation' => ${d}generation, 'ownerSub' => ${d}ownerSub,
                    'outsiderSub' => ${d}outsiderSub, 'ownerPasswordSha256' => hash('sha256', ${d}ownerPass),
                    'outsiderPasswordSha256' => hash('sha256', ${d}outsiderPass), 'attempted' => true], JSON_THROW_ON_ERROR);
                if (fwrite(${d}fp, ${d}body) !== strlen(${d}body) || !fflush(${d}fp) || !fsync(${d}fp))
                    throw new RuntimeException('Intent persistence uncertain');
                fclose(${d}fp);
                ${d}directory = fopen(${d}root, 'r');
                if (${d}directory === false || !fsync(${d}directory))
                    throw new RuntimeException('Original intent directory durability uncertain');
                fclose(${d}directory);
                // The native repository's store attaches exactly the existing owner role.
                ${d}owner = ${d}repository->store(['blocked' => false, 'email' => ${d}ownerEmail, 'role' => 'owner']);
                ${d}owner->password = Illuminate\Support\Facades\Hash::make(${d}ownerPass); ${d}owner->save();
                // Native registration creates users with NO global owner role; do not grant outsider owner.
                ${d}outsider = ${d}repository->store(['blocked' => false, 'email' => ${d}outsiderEmail]);
                ${d}outsider->password = Illuminate\Support\Facades\Hash::make(${d}outsiderPass); ${d}outsider->save();
                // The official UserGroupFactory creates the required separate
                // administration+OWNER membership. Group OWNER is not global owner:
                // outsider has NO `owner` global role, and cannot read owner accounts.
                ${d}factory = app(FireflyIII\Factory\UserGroupFactory::class);
                ${d}ownerGroup = ${d}factory->create(['title' => ${d}ownerEmail, 'user' => ${d}owner]);
                ${d}owner->user_group_id = ${d}ownerGroup->id; ${d}owner->save();
                ${d}outsiderGroup = ${d}factory->create(['title' => ${d}outsiderEmail, 'user' => ${d}outsider]);
                ${d}outsider->user_group_id = ${d}outsiderGroup->id; ${d}outsider->save();
                ${d}owner = ${d}repository->findByEmail(${d}ownerEmail);
                ${d}outsider = ${d}repository->findByEmail(${d}outsiderEmail);
                if (${d}repository->count() !== 2 || ${d}owner === null || ${d}outsider === null ||
                    ${d}owner->id === ${d}outsider->id || !${d}owner->hasRole('owner') ||
                    ${d}outsider->hasRole('owner') || ${d}owner->blocked || ${d}outsider->blocked ||
                    ${d}owner->getAdministrationId() !== ${d}ownerGroup->id ||
                    ${d}outsider->getAdministrationId() !== ${d}outsiderGroup->id ||
                    ${d}ownerGroup->id === ${d}outsiderGroup->id ||
                    ${d}owner->groupMemberships()->where('user_group_id', ${d}ownerGroup->id)->count() !== 1 ||
                    ${d}outsider->groupMemberships()->where('user_group_id', ${d}outsiderGroup->id)->count() !== 1 ||
                    ${d}outsider->groupMemberships()->where('user_group_id', ${d}ownerGroup->id)->exists() ||
                    !Illuminate\Support\Facades\Hash::check(${d}ownerPass, ${d}owner->password) ||
                    !Illuminate\Support\Facades\Hash::check(${d}outsiderPass, ${d}outsider->password))
                    throw new RuntimeException('Native original user/role readback denied');
                ${if (mintImporterClient) """
                // Pinned Passport 13.9 public PKCE client; native row must exist
                // before the user intent can receive its successful receipt.
                ${d}clientId = getenv('P0V3_IMPORTER_CLIENT_ID');
                if (!preg_match('/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}${d}/D', ${d}clientId) ||
                    app(Laravel\Passport\Client::class)->newQuery()->find(${d}clientId) !== null)
                    throw new RuntimeException('Importer client identity collision');
                ${d}client = app(Laravel\Passport\Client::class);
                ${d}client->id = ${d}clientId;
                ${d}client->name = 'P0 fresh manual-file importer';
                ${d}client->secret = null;
                ${d}client->provider = null;
                ${d}client->redirect_uris = ['https://firefly-importer.datamancy.net/callback'];
                ${d}client->grant_types = ['authorization_code'];
                ${d}client->revoked = false;
                ${d}client->save();
                ${d}client = app(Laravel\Passport\Client::class)->newQuery()->find(${d}clientId);
                if (${d}client === null || ${d}client->confidential() || ${d}client->revoked ||
                    ${d}client->redirect_uris !== ['https://firefly-importer.datamancy.net/callback'] ||
                    ${d}client->grant_types !== ['authorization_code'])
                    throw new RuntimeException('Native importer client policy mismatch');
                """.trimIndent() else ""}
                ${d}fp = fopen(${d}receipt, 'x');
                if (${d}fp === false) throw new RuntimeException('Protected native user receipt uncertain');
                ${d}body = json_encode(['generation' => ${d}generation,
                    'ownerSub' => ${d}ownerSub, 'outsiderSub' => ${d}outsiderSub,
                    'ownerId' => ${d}owner->id, 'outsiderId' => ${d}outsider->id,
                    'ownerGroupId' => ${d}ownerGroup->id, 'outsiderGroupId' => ${d}outsiderGroup->id,
                    'ownerRole' => 'owner', 'outsiderRole' => 'user'], JSON_THROW_ON_ERROR);
                if (fwrite(${d}fp, ${d}body) !== strlen(${d}body) || !fflush(${d}fp) || !fsync(${d}fp))
                    throw new RuntimeException('Original native ID persistence uncertain');
                fclose(${d}fp);
                ${d}directory = fopen(${d}root, 'r');
                if (${d}directory === false || !fsync(${d}directory))
                    throw new RuntimeException('Original receipt directory durability uncertain');
                fclose(${d}directory);
            } catch (Throwable ${d}error) {
                exit(1); // Never echo password, private subject, or uncertain effect.
            }
        """.trimIndent() + "\n"
    }

    /** V2 Firefly is ALREADY in CanonicalCoreRuntime.releaseProvidersSpec. Never add a second fragment. */
    fun releaseProjection(base: PrivateDeploymentSpec): FireflyCanonicalProjection {
        PrivateDeployment.validate(base)
        require(base.store == RuntimeStore.CANONICAL_V2 && base.processes.map { it.id }.toSet().containsAll(
            setOf("postgres", "firefly-db-init", "firefly-db-finalize", "firefly-files-init",
                "firefly-migrate", "firefly-users-init", "firefly-runtime-config", "firefly-php", "firefly")))
        require(base.databaseAccess.filter { it.database == "firefly" }.map { it.principal }.toSet() ==
            setOf("firefly_migration", "firefly_runtime"))
        require(base.processes.single { it.id == "firefly-db-init" }.oneShot &&
            base.processes.single { it.id == "firefly-db-finalize" }.oneShot &&
            base.processes.single { it.id == "firefly-db-finalize" }.command.last().contains("NOLOGIN"))
        val processes = base.processes.filter { it.id in setOf("firefly-db-init", "firefly-db-finalize",
            "firefly-files-init", "firefly-migrate", "firefly-users-init", "firefly-runtime-config", "firefly-php", "firefly") }
        return FireflyCanonicalProjection(processes, base.volumes.filter { it.id in setOf("firefly-storage", "firefly-cache") },
            processes.associate { it.id to "firefly-iii" })
    }

    /** Requires the A01 feature-owned cold projection and original immutable volume graph. */
    fun verifyReleaseCold(original: PrivateDeploymentSpec, restored: PrivateDeploymentSpec) {
        releaseProjection(original)
        PrivateDeployment.validate(restored)
        require(restored.store == original.store && restored.volumes == original.volumes &&
            restored.networks == original.networks && restored.processes.none { it.oneShot })
        val cold = restored.processes.single { it.id == "firefly-php" }
        val source = original.processes.single { it.id == "firefly-php" }
        require(cold.image == source.image && cold.imageId == source.imageId &&
            cold.userId == source.userId && cold.groupId == source.groupId &&
            cold.files == source.files && cold.volumes == source.volumes &&
            cold.environmentFile == source.environmentFile && cold.dependencies == listOf("postgres"))
        require(restored.databaseAccess.none { it.consumer in setOf("firefly-migrate", "firefly-users-init") } &&
            restored.processes.none { it.id in setOf("firefly-db-init", "firefly-db-finalize",
                "firefly-files-init", "firefly-migrate", "firefly-users-init", "firefly-runtime-config") })
    }

    /** Called only after whole-cohort authenticated cold import, never instead of import validation. */
    fun coldRestoreSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec {
        val ids = setOf("firefly-files-init", "firefly-migrate", "firefly-runtime-config", "firefly-php", "firefly") +
            (if (compiled.processes.any { it.id == "firefly-users-init" }) setOf("firefly-users-init") else emptySet())
        require((compiled.store != RuntimeStore.CANONICAL_V2 || "firefly-users-init" in ids) &&
            compiled.processes.map { it.id }.toSet().containsAll(ids)) { "Missing compiled canonical Firefly processes" }
        val retired = ids - setOf("firefly-php", "firefly")
        return compiled.copy(processes = compiled.processes.filterNot { it.id in retired }.map { p ->
            p.copy(dependencies = p.dependencies.filterNot { it in retired })
        }, databaseAccess = compiled.databaseAccess.filterNot { it.consumer in retired })
    }
}
