package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.*

/** Private Git hosting with a persistent SQLite database and no registration, mail, federation or runners. */
internal object ForgejoRuntime {
    /** Pin the explicitly supplied graph APP origin before any Authorization header or
     * attempted-effect marker. No legacy git alias, redirect, port or alternate host. */
    internal fun requireActorOrigin(selectedOrigin: java.net.URI): String {
        require(selectedOrigin.toASCIIString() == "https://forgejo.datamancy.net") {
            "Fresh Forgejo native actor origin differs from selected APP route"
        }
        return selectedOrigin.toASCIIString()
    }

    /** Native admin API issuance from the existing one-use bootstrap admin, not
     * public registration or a credential copied from OLD. Core supplies the
     * original CLI-generated bootstrap password and the original sealed fresh
     * actor credentials under its INSTALL owner lock. An attempted POST cannot
     * be replayed, including after a lost HTTP ACK. The admin is NOT either user.
     */
    fun enrollFreshActors(client: java.net.http.HttpClient, selectedOrigin: java.net.URI,
        journalRoot: Path, generation: String, bootstrapPassword: String,
        ownerPassword: String, outsiderPassword: String): Map<String, String> {
        val nativeOrigin = requireActorOrigin(selectedOrigin)
        require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
            bootstrapPassword.length == 64 && bootstrapPassword.none { it.isWhitespace() || Character.isISOControl(it) } &&
            listOf(ownerPassword, outsiderPassword).all { it.matches(Regex("[a-f0-9]{64}")) } &&
            setOf(bootstrapPassword, ownerPassword, outsiderPassword).size == 3 &&
            client.followRedirects() == java.net.http.HttpClient.Redirect.NEVER)
        ReleasePrivateFiles.directory(journalRoot)
        val attempted = journalRoot.resolve("forgejo-actors-$generation.attempted.json")
        val completed = journalRoot.resolve("forgejo-actors-$generation.completed.json")
        // CREATE_NEW + file/directory fsync precede the first native POST; never
        // infer a missing ACK or treat an already-enrolled account as a retry cue.
        require(!java.nio.file.Files.exists(completed, java.nio.file.LinkOption.NOFOLLOW_LINKS))
        val intent = kotlinx.serialization.json.buildJsonObject {
            put("generation", generation); put("attempted", true)
            put("ownerPasswordSha256", ReleaseLocks.sha256(ownerPassword.toByteArray(Charsets.UTF_8)))
            put("outsiderPasswordSha256", ReleaseLocks.sha256(outsiderPassword.toByteArray(Charsets.UTF_8)))
        }
        ReleasePrivateFiles.save(attempted, (intent.toString() + "\n").toByteArray(Charsets.UTF_8))
        val basic = java.util.Base64.getEncoder().encodeToString(
            "p0v3-bootstrap:$bootstrapPassword".toByteArray(Charsets.UTF_8))
        fun create(username: String) {
            val password = if (username == "owner") ownerPassword else outsiderPassword
            val body = kotlinx.serialization.json.buildJsonObject {
                put("username", username); put("email", "$username@localhost.invalid")
                put("password", password); put("must_change_password", false)
                put("restricted", false); put("visibility", "private")
            }.toString()
            val request = java.net.http.HttpRequest.newBuilder(java.net.URI.create("$nativeOrigin/api/v1/admin/users"))
                .timeout(java.time.Duration.ofSeconds(15)).header("Accept", "application/json")
                .header("Content-Type", "application/json").header("Authorization", "Basic $basic")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofString(body)).build()
            val response = client.send(request, java.net.http.HttpResponse.BodyHandlers.ofString())
            require(response.statusCode() == 201 && response.body().length <= 65536) {
                "Fresh Forgejo native user creation uncertain; no retry"
            }
            val created = kotlinx.serialization.json.Json.parseToJsonElement(response.body()).jsonObject
            require(created.getValue("login").jsonPrimitive.content == username &&
                created.getValue("id").jsonPrimitive.long > 0 &&
                !created.getValue("is_admin").jsonPrimitive.boolean) {
                "Fresh Forgejo native user differs from sealed actor"
            }
        }
        create("owner"); create("outsider")
        // Reauthenticate both NEW users with their own credentials. Bootstrap is
        // intentionally never an owner or outsider workflow credential.
        fun verify(username: String, password: String) {
            val authorization = java.util.Base64.getEncoder().encodeToString(
                "$username:$password".toByteArray(Charsets.UTF_8))
            val request = java.net.http.HttpRequest.newBuilder(java.net.URI.create("$nativeOrigin/api/v1/user"))
                .timeout(java.time.Duration.ofSeconds(10)).header("Authorization", "Basic $authorization")
                .header("Accept", "application/json").GET().build()
            val response = client.send(request, java.net.http.HttpResponse.BodyHandlers.ofString())
            require(response.statusCode() == 200 && response.body().length <= 65536)
            val actual = kotlinx.serialization.json.Json.parseToJsonElement(response.body()).jsonObject
            require(actual.getValue("login").jsonPrimitive.content == username &&
                !actual.getValue("is_admin").jsonPrimitive.boolean)
        }
        verify("owner", ownerPassword); verify("outsider", outsiderPassword)
        ReleasePrivateFiles.save(completed,
            ("{\"generation\":\"$generation\",\"owner\":\"owner\",\"outsider\":\"outsider\"}\n")
                .toByteArray(Charsets.UTF_8))
        return mapOf("owner" to "owner", "outsider" to "outsider")
    }

    /** Live private-CA HTTPS readback; call only after the original native INSTALL repo
     * journey with the original sealed actor credentials and exact private repo name.
     * No bootstrap admin, credential or Authorization value enters the result.
     */
    fun nativeIssuanceReadback(client: java.net.http.HttpClient, selectedOrigin: java.net.URI,
        owner: String, ownerPassword: String, outsider: String, outsiderPassword: String,
        originalPrivateRepo: String): Map<String, String> {
        val origin = requireActorOrigin(selectedOrigin)
        require(owner.matches(Regex("[a-z][a-z0-9-]{2,40}")) &&
            outsider.matches(Regex("[a-z][a-z0-9-]{2,40}")) && owner != outsider &&
            originalPrivateRepo.matches(Regex("p0v3-[a-f0-9]{24}")) &&
            listOf(ownerPassword, outsiderPassword).all { it.matches(Regex("[a-f0-9]{64}")) } &&
            ownerPassword != outsiderPassword && client.followRedirects() == java.net.http.HttpClient.Redirect.NEVER)
        fun get(username: String, password: String, path: String): java.net.http.HttpResponse<String> {
            val authorization = java.util.Base64.getEncoder().encodeToString("$username:$password".toByteArray(Charsets.UTF_8))
            val request = java.net.http.HttpRequest.newBuilder(java.net.URI.create(origin + path))
                .timeout(java.time.Duration.ofSeconds(10)).header("Authorization", "Basic $authorization")
                .header("Accept", "application/json").GET().build()
            val response = client.send(request, java.net.http.HttpResponse.BodyHandlers.ofString())
            require(response.body().length <= 65536) { "Unbounded native Forgejo response" }
            return response
        }
        fun identity(username: String, password: String) {
            val response = get(username, password, "/api/v1/user")
            require(response.statusCode() == 200) { "Native Forgejo actor authentication refused" }
            val user = kotlinx.serialization.json.Json.parseToJsonElement(response.body()).jsonObject
            require(user.getValue("login").jsonPrimitive.content == username &&
                user.getValue("id").jsonPrimitive.long > 0) { "Native Forgejo actor differs from original grant" }
        }
        identity(owner, ownerPassword); identity(outsider, outsiderPassword)
        val path = "/api/v1/repos/$owner/$originalPrivateRepo"
        val present = get(owner, ownerPassword, path)
        require(present.statusCode() == 200) { "Original Forgejo private repository absent" }
        val repository = kotlinx.serialization.json.Json.parseToJsonElement(present.body()).jsonObject
        require(repository.getValue("private").jsonPrimitive.boolean &&
            repository.getValue("name").jsonPrimitive.content == originalPrivateRepo &&
            repository.getValue("owner").jsonObject.getValue("login").jsonPrimitive.content == owner)
        require(get(outsider, outsiderPassword, path).statusCode() in setOf(403, 404)) {
            "Original Forgejo repository exposed to outsider"
        }
        return mapOf("owner" to owner, "outsider" to outsider,
            "nativeResourceId" to repository.getValue("id").jsonPrimitive.content)
    }

    fun spec(inventory: AcquiredInventory, name: String = "forgejo"): PrivateDeploymentSpec {
        val image = inventory.images.single { it.product == "forgejo" }
        require(image.architecture == "amd64" && image.os == "linux")
        val common = RuntimeProcess("forgejo", image.pinnedImage, image.imageId, 1000,
            entrypoint = "/usr/local/bin/forgejo", environmentFile = "forgejo.env",
            volumes = listOf(RuntimeMount("forgejo", "/data")), files = listOf(RuntimeFile("app.ini", "/etc/forgejo/app.ini")),
            memoryMiB = 1024, apparmorProfile = "p0v3-private-v1", readinessHttpPort = 3000, readinessHttpPath = "/api/healthz")
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("forgejo", 1000)), processes = listOf(
            common.copy(id = "forgejo-init", entrypoint = "/bin/sh", oneShot = true, readinessHttpPort = null,
                command = listOf("-ec", """
                    /usr/local/bin/forgejo --work-path /data --config /etc/forgejo/app.ini migrate
                    /usr/local/bin/forgejo --work-path /data --config /etc/forgejo/app.ini admin user create --username p0v3-bootstrap --password "${'$'}BOOTSTRAP_PASSWORD" --email bootstrap@localhost.invalid --admin --must-change-password=false
                """.trimIndent())),
            common.copy(dependencies = listOf("forgejo-init"), command = listOf("--work-path", "/data", "--config", "/etc/forgejo/app.ini", "web"))
        )).also { PrivateDeployment.validate(it) }
    }
    /** Staging restore: no database/admin initialization is allowed against recovered state. */
    fun restoreSpec(inventory: AcquiredInventory, name: String): PrivateDeploymentSpec {
        val source = spec(inventory, name)
        return source.copy(processes = listOf(
            source.processes.first().copy(id = "restore-check", command = listOf("-ec",
                "test -s /data/forgejo.db && test -d /data/repositories && test ! -e /data/.restore-in-progress")),
            source.processes.last().copy(dependencies = listOf("restore-check"))
        )).also { PrivateDeployment.validate(it) }
    }
    fun prepareRestore(inventory: AcquiredInventory, recoveredInputs: Path, base: Path = PrivateDeployment.BASE, name: String): Path {
        val inputs = listOf("app.ini", "forgejo.env").associateWith { ReleaseLocks.privateBytes(recoveredInputs.resolve(it)).decodeToString() }
        val path = RuntimePreparation.prepare(restoreSpec(inventory, name), base) { inputs }
        inputs.forEach { (file, value) -> require(ReleaseLocks.privateBytes(base.resolve(name).resolve(file)).decodeToString() == value) {
            "Restored runtime inputs differ; refusing replacement"
        } }
        return path
    }
    /** V2-only partial graph. Retains a single original SQLite volume; no cloned SQL provider. */
    fun canonicalFragment(inventory: AcquiredInventory, member: String): CanonicalProviderFragment {
        val original = spec(inventory, member)
        val init = original.processes.single { it.id == "forgejo-init" }.copy(
            environmentFile = "forgejo-bootstrap.env", networks = listOf("forgejo-web"))
        val daemon = original.processes.single { it.id == "forgejo" }.copy(
            environmentFile = "forgejo-runtime.env", networks = listOf("forgejo-web"))
        return CanonicalProviderFragment("forgejo", original.copy(
            store = RuntimeStore.CANONICAL_V2, networks = listOf("forgejo-web"),
            processes = listOf(init, daemon)), webNetworks = setOf("forgejo-web"))
    }

    /** Cold import preserves the original database, keys, principal and exact sealed config. */
    fun canonicalColdFragment(fresh: CanonicalProviderFragment): CanonicalProviderFragment {
        require(fresh.product == "forgejo" && fresh.spec.store == RuntimeStore.CANONICAL_V2 &&
            fresh.spec.processes.map { it.id } == listOf("forgejo-init", "forgejo"))
        val daemon = fresh.spec.processes.single { it.id == "forgejo" }
        return fresh.copy(spec = fresh.spec.copy(processes = listOf(daemon.copy(dependencies = emptyList()))))
    }

    /** Call only after pure complete-graph validation. Bootstrap password is never a daemon input. */
    fun canonicalInputs(secret: () -> String = RuntimePreparation::password): Map<String, String> {
        val bootstrap = secret(); val key = secret(); val internal = secret(); val jwt = secret()
        require(listOf(bootstrap, key, internal, jwt).all { it.matches(Regex("[a-f0-9]{64}")) } &&
            setOf(bootstrap, key, internal, jwt).size == 4)
        return mapOf("forgejo-bootstrap.env" to "HOME=/data\nUSER=git\nBOOTSTRAP_PASSWORD=$bootstrap\n",
            "forgejo-runtime.env" to "HOME=/data\nUSER=git\n",
            "app.ini" to """
                APP_NAME = Platform Zero private Forgejo
                RUN_USER = git
                RUN_MODE = prod
                WORK_PATH = /data
                [database]
                DB_TYPE = sqlite3
                PATH = /data/forgejo.db
                [repository]
                ROOT = /data/repositories
                DEFAULT_PRIVATE = private
                [server]
                APP_DATA_PATH = /data/app
                HTTP_ADDR = 0.0.0.0
                HTTP_PORT = 3000
                ROOT_URL = https://git.datamancy.net/
                DISABLE_SSH = true
                LFS_START_SERVER = false
                [security]
                INSTALL_LOCK = true
                SECRET_KEY = $key
                INTERNAL_TOKEN = $internal
                [oauth2]
                JWT_SIGNING_ALGORITHM = HS256
                JWT_SECRET = $jwt
                [service]
                DISABLE_REGISTRATION = true
                REQUIRE_SIGNIN_VIEW = true
                ENABLE_NOTIFY_MAIL = false
                [mailer]
                ENABLED = false
                [federation]
                ENABLED = false
                [actions]
                ENABLED = false
                [cron.update_checker]
                ENABLED = false
                [session]
                PROVIDER = file
                PROVIDER_CONFIG = /data/sessions
                [log]
                MODE = console
                LEVEL = Warn
            """.trimIndent() + "\n")
    }

    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "forgejo", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) {
            mapOf("forgejo.env" to "HOME=/data\nUSER=git\nBOOTSTRAP_PASSWORD=${RuntimePreparation.password()}\n",
                "app.ini" to """
                    APP_NAME = Platform Zero private Forgejo
                    RUN_USER = git
                    RUN_MODE = prod
                    WORK_PATH = /data
                    [database]
                    DB_TYPE = sqlite3
                    PATH = /data/forgejo.db
                    [repository]
                    ROOT = /data/repositories
                    DEFAULT_PRIVATE = private
                    [server]
                    APP_DATA_PATH = /data/app
                    HTTP_ADDR = 0.0.0.0
                    HTTP_PORT = 3000
                    ROOT_URL = http://forgejo:3000/
                    DISABLE_SSH = true
                    LFS_START_SERVER = false
                    [security]
                    INSTALL_LOCK = true
                    SECRET_KEY = ${RuntimePreparation.password()}
                    INTERNAL_TOKEN = ${RuntimePreparation.password()}
                    [oauth2]
                    JWT_SIGNING_ALGORITHM = HS256
                    JWT_SECRET = ${java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(java.util.HexFormat.of().parseHex(RuntimePreparation.password()))}
                    [service]
                    DISABLE_REGISTRATION = true
                    REQUIRE_SIGNIN_VIEW = true
                    ENABLE_NOTIFY_MAIL = false
                    [mailer]
                    ENABLED = false
                    [federation]
                    ENABLED = false
                    [actions]
                    ENABLED = false
                    [cron.update_checker]
                    ENABLED = false
                    [session]
                    PROVIDER = file
                    PROVIDER_CONFIG = /data/sessions
                    [log]
                    MODE = console
                    LEVEL = Warn
                """.trimIndent() + "\n")
        }
}
