package net.datamancy.platform

import java.nio.file.Path
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlinx.serialization.json.*

/** Closed, internal-only social fixture. Not federation activation, owner SSO or reviewed RSS publication. */
internal object MastodonRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "mastodon"): PrivateDeploymentSpec {
        val foundation = FoundationRuntime.spec(inventory, name)
        fun image(product: String) = inventory.images.single { it.product == product }.also {
            require(it.os == "linux" && it.architecture == "amd64")
        }
        val app = image("mastodon"); val stream = image("mastodon-streaming"); val web = image("element")
        val pg = foundation.processes.single { it.id == "postgres" }
        val rails = RuntimeProcess("mastodon", app.pinnedImage, app.imageId, 991,
            entrypoint = "/usr/local/bundle/bin/bundle", environmentFile = "mastodon.env",
            volumes = listOf(RuntimeMount("uploads", "/opt/mastodon/public/system")),
            tmpfs = listOf("/tmp", "/opt/mastodon/tmp"), apparmorProfile = "p0v3-private-v1", memoryMiB = 1536,
            command = listOf("exec", "puma", "-C", "config/puma.rb"), readinessHttpPort = 3000, readinessHttpPath = "/health")
        return PrivateDeploymentSpec(name = name,
            volumes = listOf(RuntimeVolume("postgres", 999), RuntimeVolume("valkey", 999), RuntimeVolume("uploads", 991), RuntimeVolume("bootstrap", 991)),
            processes = foundation.processes.filter { it.id in setOf("postgres-init", "postgres", "valkey") } + listOf(
                RuntimeProcess("mastodon-db-init", pg.image, pg.imageId, 999, dependencies = listOf("postgres"),
                    entrypoint = "/bin/sh", environmentFile = "database-init.env", oneShot = true, apparmorProfile = "p0v3-private-v1",
                    command = listOf("-ec", """
                        export PGPASSWORD="${'$'}POSTGRES_PASSWORD"
                        psql -X -h postgres -U postgres -v ON_ERROR_STOP=1 <<SQL
                        CREATE ROLE mastodon LOGIN PASSWORD '${'$'}MASTODON_PASSWORD';
                        CREATE DATABASE mastodon OWNER mastodon;
                        SQL
                    """.trimIndent())),
                rails.copy(id = "mastodon-migrate", dependencies = listOf("mastodon-db-init", "valkey"),
                    command = listOf("exec", "rails", "db:migrate", "db:seed"), oneShot = true, readinessHttpPort = null),
                rails.copy(id = "mastodon-accounts", dependencies = listOf("mastodon-migrate"), entrypoint = "/bin/sh", oneShot = true,
                    readinessHttpPort = null, volumes = rails.volumes + RuntimeMount("bootstrap", "/bootstrap"),
                    command = listOf("-ec", """
                        umask 077
                        bin/tootctl settings registrations close
                        bin/tootctl accounts create owner --email=owner@localhost.invalid --confirmed --approve --role=Owner > /bootstrap/owner.txt
                        bin/tootctl accounts create reader --email=reader@localhost.invalid --confirmed --approve > /bootstrap/reader.txt
                    """.trimIndent())),
                rails.copy(id = "mastodon-rss-accounts", dependencies = listOf("mastodon-accounts"), oneShot = true, readinessHttpPort = null,
                    command = listOf("exec", "rails", "runner", "/run/secrets/rss-bootstrap.rb"),
                    files = listOf("rss-bootstrap.rb", "rss-accounts.json").map { RuntimeFile(it, "/run/secrets/$it") },
                    volumes = rails.volumes + RuntimeMount("bootstrap", "/bootstrap")),
                rails.copy(dependencies = listOf("mastodon-rss-accounts"), entrypoint = "/usr/bin/tini",
                    command = listOf("--", "/usr/local/bundle/bin/bundle", "exec", "puma", "-C", "config/puma.rb")),
                rails.copy(id = "sidekiq", dependencies = listOf("mastodon-rss-accounts"), entrypoint = "/usr/bin/tini",
                    command = listOf("--", "/usr/local/bundle/bin/bundle", "exec", "sidekiq", "-c", "2"), readinessHttpPort = null,
                    readiness = listOf("/bin/sh", "-ec", "test -f /opt/mastodon/tmp/sidekiq-ready")),
                RuntimeProcess("streaming", stream.pinnedImage, stream.imageId, 991, dependencies = listOf("mastodon-rss-accounts"),
                    entrypoint = "/usr/local/bin/node", command = listOf("./streaming/index.js"), environmentFile = "streaming.env",
                    apparmorProfile = "p0v3-private-v1", memoryMiB = 512, readinessHttpPort = 4000, readinessHttpPath = "/api/v1/streaming/health"),
                RuntimeProcess("social", web.pinnedImage, web.imageId, 101, dependencies = listOf("mastodon", "streaming", "sidekiq"),
                    entrypoint = "/usr/sbin/nginx", command = listOf("-c", "/run/secrets/nginx.conf", "-g", "daemon off;"),
                    files = listOf("nginx.conf", "ca.pem", "web.pem", "web-key.pem").map { RuntimeFile(it, "/run/secrets/$it") },
                    apparmorProfile = "p0v3-private-v1", memoryMiB = 256, readinessHttpPort = 8080, readinessHttpPath = "/healthz")
            )).also { PrivateDeployment.validate(it) }
    }
    /** The canonical source joins ONE PostgreSQL and ONE Valkey cohort; never imports the
     * historical 47 RSS accounts/tokens or any local provider copy. The old V1 recipe above
     * remains byte-for-byte unchanged and is not an authority for new publisher grants. */
    fun canonicalFragment(inventory: AcquiredInventory, base: PrivateDeploymentSpec): CanonicalProviderFragment {
        require(base.store == RuntimeStore.CANONICAL_V2 &&
            base.processes.any { it.id == "postgres" && !it.oneShot } &&
            base.processes.any { it.id == "valkey" && !it.oneShot })
        val old = spec(inventory, base.name)
        val pg = base.processes.single { it.id == "postgres" }
        val original = old.processes.associateBy { it.id }
        val sql = RuntimeProcess("mastodon-db-init", pg.image, pg.imageId, pg.userId,
            dependencies = listOf("postgres"), entrypoint = "/bin/sh", oneShot = true,
            environmentFile = "mastodon-db-admin.env", files = listOf(RuntimeFile("postgres-ca.pem", "/run/secrets/postgres-ca.pem")),
            networks = listOf("db-admin"), apparmorProfile = "p0v3-private-v1",
            command = listOf("-ec", """
                export PGUSER=postgres PGDATABASE=postgres PGHOST=postgres PGSSLMODE=verify-full PGSSLROOTCERT=/run/secrets/postgres-ca.pem
                psql -X -v ON_ERROR_STOP=1 <<SQL
                CREATE ROLE mastodon_migration LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '${'$'}MASTODON_MIGRATION_PASSWORD';
                CREATE ROLE mastodon_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '${'$'}MASTODON_RUNTIME_PASSWORD';
                CREATE DATABASE mastodon OWNER mastodon_migration;
                REVOKE ALL ON DATABASE mastodon FROM PUBLIC;
                GRANT CONNECT ON DATABASE mastodon TO mastodon_runtime;
                SQL
                psql -X -d mastodon -v ON_ERROR_STOP=1 -c 'REVOKE CREATE ON SCHEMA public FROM PUBLIC'
            """.trimIndent()))
        val app = original.getValue("mastodon")
        val bootstrap = RuntimeMount("mastodon-bootstrap", "/bootstrap")
        val adoptSql = RuntimeProcess("mastodon-sql-adopt", pg.image, pg.imageId, 991,
            dependencies = listOf("mastodon-db-init"), entrypoint = "/bin/sh", oneShot = true,
            environmentFile = "mastodon-sql-adopt.env", volumes = listOf(bootstrap),
            files = listOf(RuntimeFile("postgres-ca.pem", "/run/secrets/postgres-ca.pem")),
            networks = listOf("mastodon-data"), apparmorProfile = "p0v3-private-v1", memoryMiB = 2048,
            command = listOf("-ec", """
                umask 077
                test -f /bootstrap/original-mastodon.dump; test ! -L /bootstrap/original-mastodon.dump
                printf '%s  %s\n' "${'$'}ORIGINAL_SQL_SHA256" /bootstrap/original-mastodon.dump | sha256sum -c -
                export PGHOST=postgres PGDATABASE=mastodon PGUSER=mastodon_migration
                export PGSSLMODE=verify-full PGSSLROOTCERT=/run/secrets/postgres-ca.pem
                pg_restore --exit-on-error --single-transaction --no-owner --no-privileges --dbname=mastodon /bootstrap/original-mastodon.dump
            """.trimIndent()))
        val originalCheck = app.copy(id = "mastodon-original-check", dependencies = listOf("mastodon-sql-adopt", "valkey"),
            environmentFile = "mastodon-migrate.env", volumes = app.volumes + bootstrap,
            command = listOf("exec", "rails", "runner", "/run/secrets/mastodon-original-check.rb"),
            files = listOf(RuntimeFile("mastodon-original-check.rb", "/run/secrets/mastodon-original-check.rb"),
                RuntimeFile("rss-accounts.json", "/run/secrets/rss-accounts.json")),
            oneShot = true, readinessHttpPort = null, networks = listOf("mastodon-data", "mastodon-cache"))
        val accounts = app.copy(id = "mastodon-accounts", dependencies = listOf("mastodon-original-check"),
            environmentFile = "mastodon-migrate.env", volumes = app.volumes + bootstrap,
            command = listOf("exec", "rails", "runner", "/run/secrets/mastodon-accounts.rb"),
            files = listOf(RuntimeFile("mastodon-accounts.rb", "/run/secrets/mastodon-accounts.rb"),
                RuntimeFile("mastodon-users.json", "/run/secrets/mastodon-users.json"),
                RuntimeFile("mastodon-oauth-custody.json", "/run/secrets/mastodon-oauth-custody.json")),
            oneShot = true, readinessHttpPort = null, networks = listOf("mastodon-data", "mastodon-cache"))
        val rssq = accounts.copy(id = "mastodon-rssq-provision", dependencies = listOf("mastodon-accounts"),
            command = listOf("exec", "rails", "runner", "/run/secrets/mastodon-rssq-provision.rb"),
            files = listOf(RuntimeFile("mastodon-rssq-provision.rb", "/run/secrets/mastodon-rssq-provision.rb"),
                RuntimeFile("mastodon-rssq-fixtures.json", "/run/secrets/mastodon-rssq-fixtures.json")))
        val finalize = sql.copy(id = "mastodon-db-finalize", dependencies = listOf("mastodon-rssq-provision"),
            command = listOf("-ec", """
                export PGUSER=postgres PGDATABASE=mastodon PGHOST=postgres PGSSLMODE=verify-full PGSSLROOTCERT=/run/secrets/postgres-ca.pem
                psql -X -v ON_ERROR_STOP=1 <<'SQL'
                GRANT USAGE ON SCHEMA public TO mastodon_runtime;
                GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO mastodon_runtime;
                GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO mastodon_runtime;
                ALTER DEFAULT PRIVILEGES FOR ROLE mastodon_migration IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO mastodon_runtime;
                ALTER DEFAULT PRIVILEGES FOR ROLE mastodon_migration IN SCHEMA public GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO mastodon_runtime;
                ALTER ROLE mastodon_migration NOLOGIN;
                SQL
            """.trimIndent()))
        val runtime = app.copy(dependencies = listOf("mastodon-db-finalize"),
            networks = listOf("mastodon-data", "mastodon-cache", "mastodon-web"))
        val sidekiq = original.getValue("sidekiq").copy(dependencies = listOf("mastodon-db-finalize"),
            networks = listOf("mastodon-data", "mastodon-cache"))
        val streaming = original.getValue("streaming").copy(dependencies = listOf("mastodon-db-finalize"),
            networks = listOf("mastodon-data", "mastodon-cache", "mastodon-web"),
            environmentFile = "mastodon-streaming.env")
        val web = original.getValue("social").copy(networks = listOf("mastodon-web"),
            files = original.getValue("social").files.map { file -> when (file.file) {
                "ca.pem", "web.pem", "web-key.pem" -> file.copy(file = "mastodon-${file.file}")
                "nginx.conf" -> file.copy(file = "mastodon-nginx.conf")
                else -> file
            } })
        val partial = PrivateDeploymentSpec(name = base.name, store = base.store,
            volumes = listOf(RuntimeVolume("uploads", 991), RuntimeVolume("mastodon-bootstrap", 991)),
            processes = listOf(sql, adoptSql, originalCheck, accounts, rssq, finalize, runtime, sidekiq, streaming, web),
            networks = listOf("mastodon-data", "mastodon-cache", "mastodon-web"),
            databaseAccess = listOf(
                RuntimeDatabaseAccess("mastodon-sql-adopt", "postgres", "postgres", "mastodon",
                    "mastodon_migration", "mastodon-sql-adopt.env", "mastodon-data"),
                RuntimeDatabaseAccess("mastodon-original-check", "postgres", "postgres", "mastodon",
                    "mastodon_migration", "mastodon-migrate.env", "mastodon-data"),
                RuntimeDatabaseAccess("mastodon", "postgres", "postgres", "mastodon",
                    "mastodon_runtime", "mastodon.env", "mastodon-data")))
        return CanonicalProviderFragment("mastodon", partial, webNetworks = setOf("mastodon-web"),
            providerNetworks = mapOf("postgres" to setOf("mastodon-data"), "valkey" to setOf("mastodon-cache")))
    }

    fun canonicalColdFragment(inventory: AcquiredInventory, base: PrivateDeploymentSpec,
        original: CanonicalProviderFragment): CanonicalProviderFragment {
        val fresh = canonicalFragment(inventory, base)
        require(original == fresh) { "Only the exact original social signing/media/SQL source can be imported" }
        val retirees = setOf("mastodon-db-init", "mastodon-sql-adopt", "mastodon-original-check",
            "mastodon-accounts", "mastodon-rssq-provision", "mastodon-db-finalize")
        val cold = fresh.spec.copy(processes = fresh.spec.processes.filterNot { it.id in retirees }.map { daemon ->
            when (daemon.id) {
                "mastodon", "sidekiq", "streaming" -> daemon.copy(dependencies = listOf("postgres", "valkey"))
                else -> daemon
            }
        }, unmountedRecoveryVolumes = setOf("mastodon-bootstrap"),
            databaseAccess = fresh.spec.databaseAccess.filter { it.consumer == "mastodon" })
        require(cold.processes.none { it.oneShot } && cold.volumes == fresh.spec.volumes &&
            cold.databaseAccess == fresh.spec.databaseAccess.filter { it.consumer == "mastodon" })
        return fresh.copy(spec = cold)
    }

    /** The original verified source is compulsory: never call the V1 fresh secret/47-account
     * bootstrap from canonical. No caller Boolean or invented LOCAL_DOMAIN can adopt SQL IDs. */
    fun canonicalInputs(postgresAdmin: String, valkeyPassword: String, users: Map<String, String>,
        original: MastodonRecovery.CanonicalSource, generation: String,
        adoption: MastodonRecovery.OriginalSqlReadback,
        fixtureIds: Set<String>,
        pki: () -> Map<String, String> = { PrivateWebPki.generate("social.datamancy.net") },
        password: () -> String = RuntimePreparation::password): Map<String, String> {
        require(listOf(postgresAdmin, valkeyPassword, adoption.dumpSha256,
            adoption.original47SqlSha256, adoption.originalTokenCustodySha256,
            adoption.sourceCopyReceiptSha256).all { it.matches(Regex("[a-f0-9]{64}")) } &&
            adoption.sourceBundleSha256 == original.originalBundleSha256 &&
            adoption.ownerId.matches(Regex("[1-9][0-9]{0,19}")) &&
            adoption.readerId.matches(Regex("[1-9][0-9]{0,19}")) &&
            adoption.ownerId != adoption.readerId &&
            generation.matches(Regex("q-[a-f0-9]{12}")) && generation != original.generation &&
            users.keys == setOf("owner", "reader") && users.values.all {
                it.matches(Regex("[a-zA-Z0-9!@#%^&*_-]{12,128}"))
            } && users.values.toSet().size == 2 && original.archiveHashes.keys ==
                setOf("postgres", "valkey", "uploads", "bootstrap"))
        val from = Regex("(?m)^DB_PASS=([a-f0-9]{64})$").find(original.originalEnvironment)?.groupValues?.get(1)
        val redis = Regex("(?m)^REDIS_PASSWORD=([a-f0-9]{64})$").find(original.originalEnvironment)?.groupValues?.get(1)
        require(from != null && redis != null &&
            "REDIS_HOST=valkey\n" in original.originalEnvironment &&
            "REDIS_HOST=valkey\n" in original.originalStreaming &&
            "LOCAL_DOMAIN=social.datamancy.net\n" in original.originalEnvironment) {
            "Original ActivityPub identity must already match the exact approved host; no silent domain rewrite"
        }
        // Only backend Nginx/SNI credentials are generated here, BEFORE the target is
        // sealed. Public original-host identity lives on Caddy as a later native
        // ACME_PUBLIC effective revision; NEVER treat this backend leaf as public.
        val certificates = pki()
        require(certificates.keys == setOf("ca.pem", "web.pem", "web-key.pem") &&
            certificates.values.all { it.startsWith("-----BEGIN ") })
        val old = certificates + mapOf("mastodon.env" to original.originalEnvironment,
            "streaming.env" to original.originalStreaming, "nginx.conf" to original.originalWeb)
        val migration = password(); val runtime = password()
        require(listOf(migration, runtime).all { it.matches(Regex("[a-f0-9]{64}")) } &&
            setOf(postgresAdmin, valkeyPassword, migration, runtime, *users.values.toTypedArray()).size == 6)
        val oldEnvironment = old.getValue("mastodon.env")
        require(oldEnvironment.endsWith("\n") && "DB_USER=mastodon\n" in oldEnvironment &&
            "DB_USER=mastodon\n" in old.getValue("streaming.env"))
        fun env(dbPassword: String, dbUser: String) = oldEnvironment
            .replace("DB_USER=mastodon\n", "DB_USER=$dbUser\n")
            .replace("DB_PASS=$from\n", "DB_PASS=$dbPassword\n")
            .replace("REDIS_PASSWORD=$redis\n", "REDIS_USER=mastodon\nREDIS_PASSWORD=$valkeyPassword\n")
            .replace("REDIS_HOST=valkey\n", "REDIS_HOST=mastodon-redis-bridge\n")
            .plus("DYNO=p0v3-mastodon-$generation\n")
            .replace("WEB_DOMAIN=social:8443\n", "WEB_DOMAIN=social.datamancy.net\n")
            .replace("STREAMING_API_BASE_URL=wss://social:8443\n",
                "STREAMING_API_BASE_URL=wss://social.datamancy.net\n")
        val streaming = old.getValue("streaming.env")
            .replace("DB_USER=mastodon\n", "DB_USER=mastodon_runtime\n")
            .replace("DB_PASS=$from\n", "DB_PASS=$runtime\n")
            .replace("REDIS_PASSWORD=$redis\n", "REDIS_USER=mastodon\nREDIS_PASSWORD=$valkeyPassword\n")
            .replace("REDIS_HOST=valkey\n", "REDIS_HOST=mastodon-redis-bridge\n")
        val web = old.getValue("nginx.conf").replace("server_name social;", "server_name social.datamancy.net;")
        require("LOCAL_DOMAIN=social.datamancy.net\n" in env(runtime, "mastodon_runtime") &&
            "DB_PASS=$runtime\n" in env(runtime, "mastodon_runtime") &&
            "DB_PASS=$migration\n" in env(migration, "mastodon_migration") &&
            "REDIS_PASSWORD=$valkeyPassword\n" in streaming &&
            "REDIS_HOST=mastodon-redis-bridge\n" in streaming &&
            "REDIS_HOST=mastodon-redis-bridge\n" in env(runtime, "mastodon_runtime") &&
            "server_name social.datamancy.net;" in web)
        val appUid = password(); val appSecret = password()
        val ownerToken = password(); val readerToken = password()
        require(listOf(appUid, appSecret, ownerToken, readerToken).all { it.matches(Regex("[a-f0-9]{64}")) } &&
            setOf(appUid, appSecret, ownerToken, readerToken, postgresAdmin, valkeyPassword,
                migration, runtime, *users.values.toTypedArray()).size == 10)
        val oauth = buildJsonObject {
            put("appUid", appUid); put("appSecret", appSecret)
            put("ownerToken", ownerToken); put("readerToken", readerToken)
        }.toString() + "\n"
        val accounts = """
            require 'json'
            require 'digest'
            original = JSON.parse(File.read('/run/secrets/mastodon-users.json'))
            raise 'Canonical original account selection changed' unless original.keys.sort == ['owner', 'reader']
            raise 'Original account secret changed' unless original.values.uniq.size == 2 &&
              original.values.all? { |value| value.match?(/\A[a-zA-Z0-9!@#%^&*_-]{12,128}\z/) }
            raise 'Original source registrations reopened' unless Setting.registrations_mode == 'none'
            original.each do |name, secret|
              account = Account.find_local(name)
              raise 'Original owner/reader ID or password unavailable' unless account&.user&.confirmed? &&
                account.user.approved? && !account.bot? && account.user.valid_password?(secret)
            end
            File.open('/bootstrap/owner-reader-oauth.intent', File::WRONLY | File::CREAT | File::EXCL, 0600) do |f|
              f.write(JSON.generate({ 'sourceOriginalIds' => original.keys.to_h { |name| [name,
                Account.find_local(name).id.to_s] }, 'generation' => ENV.fetch('P0V3_GENERATION') }))
              f.flush; f.fsync
            end
            File.open('/bootstrap', File::RDONLY) { |d| d.fsync }
            custody = JSON.parse(File.read('/run/secrets/mastodon-oauth-custody.json'))
            raise 'Original app/token custody changed' unless custody.keys.sort == ['appSecret', 'appUid', 'ownerToken', 'readerToken'] && custody.values.uniq.size == 4 && custody.values.all? { |value| value.match?(/\A[a-f0-9]{64}\z/) }
            app = Doorkeeper::Application.create!(uid: custody.fetch('appUid'), secret: custody.fetch('appSecret'),
              name: 'Canonical local owner/reader', redirect_uri: 'https://social.datamancy.net/fixture-callback',
              confidential: true, scopes: 'read:accounts read:statuses write:statuses write:media')
            { 'owner' => 'read:accounts read:statuses write:statuses write:media',
              'reader' => 'read:accounts read:statuses' }.each do |who, scopes|
              token = custody.fetch(who + 'Token')
              actor = Account.find_local(who)&.user
              raise 'Original OAuth principal absent' unless actor&.confirmed? && actor.approved?
              Doorkeeper::AccessToken.create!(application: app, resource_owner_id: actor.id,
                scopes: scopes, token: token, expires_in: nil)
            end
            raise 'Historical RSS authority touched' if app.name.include?('RSS') || Account.where(username: original.keys, bot: true).exists?
            File.open('/bootstrap/owner-reader-oauth.receipt', File::WRONLY | File::CREAT | File::EXCL, 0600) do |f|
              f.write(JSON.generate({ 'sourceOriginalIds' => original.keys.to_h { |name| [name,
                Account.find_local(name).id.to_s] }, 'tokenSha256' => {
                  'owner' => Digest::SHA256.hexdigest(custody.fetch('ownerToken')),
                  'reader' => Digest::SHA256.hexdigest(custody.fetch('readerToken')) } }))
              f.flush; f.fsync
            end
            File.open('/bootstrap', File::RDONLY) { |d| d.fsync }
        """.trimIndent() + "\n"
        val rssq = MastodonRecovery.syntheticRssqInputs(fixtureIds, generation, original.originalBundleSha256)
        val check = MastodonRecovery.canonicalOriginalCheckScript()
        return old.filterKeys { it in setOf("ca.pem", "web.pem", "web-key.pem") }
            .mapKeys { (file, _) -> "mastodon-$file" } + rssq + mapOf(
            "mastodon.env" to env(runtime, "mastodon_runtime"),
            "mastodon-migrate.env" to env(migration, "mastodon_migration") +
                "P0V3_GENERATION=$generation\nORIGINAL_SOURCE_BUNDLE_SHA256=${original.originalBundleSha256}\n" +
                "ORIGINAL_SELECTION_SHA256=${ReleaseLocks.sha256(original.originalSelection.toByteArray())}\n" +
                "ORIGINAL_SQL47_SHA256=${adoption.original47SqlSha256}\n" +
                "ORIGINAL_TOKEN_CUSTODY_SHA256=${adoption.originalTokenCustodySha256}\n" +
                "ORIGINAL_OWNER_ID=${adoption.ownerId}\nORIGINAL_READER_ID=${adoption.readerId}\n",
            "mastodon-sql-adopt.env" to "PGPASSWORD=$migration\nORIGINAL_SQL_SHA256=${adoption.dumpSha256}\n",
            "mastodon-streaming.env" to streaming, "mastodon-nginx.conf" to web,
            "mastodon-db-admin.env" to "PGPASSWORD=$postgresAdmin\nMASTODON_MIGRATION_PASSWORD=$migration\nMASTODON_RUNTIME_PASSWORD=$runtime\n",
            "mastodon-users.json" to buildJsonObject { users.forEach { (name, secret) -> put(name, secret) } }.toString() + "\n",
            "mastodon-oauth-custody.json" to oauth, "mastodon-accounts.rb" to accounts,
            "mastodon-original-check.rb" to check,
            "rss-accounts.json" to original.originalSelection)
    }

    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "mastodon", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }

    fun vapid(): Pair<String, String> {
        val generator = KeyPairGenerator.getInstance("EC"); generator.initialize(ECGenParameterSpec("secp256r1"))
        val keys = generator.generateKeyPair(); val public = keys.public as ECPublicKey
        fun fixed(bytes: ByteArray) = ByteArray(32).also { output ->
            val source = bytes.takeLast(32).toByteArray(); source.copyInto(output, 32 - source.size)
        }
        val encoder = Base64.getUrlEncoder().withoutPadding()
        return encoder.encodeToString(fixed((keys.private as ECPrivateKey).s.toByteArray())) to
            encoder.encodeToString(byteArrayOf(4) + fixed(public.w.affineX.toByteArray()) + fixed(public.w.affineY.toByteArray()))
    }
    fun inputs(pki: () -> Map<String, String> = { PrivateWebPki.generate("social") }): Map<String, String> {
        val postgres = RuntimePreparation.password(); val database = RuntimePreparation.password(); val redis = RuntimePreparation.password()
        val (vapidPrivate, vapidPublic) = vapid()
        val common = "DB_HOST=postgres\nDB_PORT=5432\nDB_NAME=mastodon\nDB_USER=mastodon\nDB_PASS=$database\nREDIS_HOST=valkey\nREDIS_PORT=6379\nREDIS_PASSWORD=$redis\n"
        val feeds = JsonArray(RssPacks.load().map { reviewed -> buildJsonObject {
            put("account", reviewed.feed.account); put("feedId", reviewed.feed.id); put("pack", reviewed.pack)
            put("displayName", reviewed.feed.display_name); put("source", reviewed.feed.source); put("url", reviewed.feed.url)
        } }).toString() + "\n"
        return pki() + mapOf(
            "rss-accounts.json" to feeds,
            "rss-bootstrap.rb" to """
                require 'json'
                require_relative '/opt/mastodon/lib/mastodon/cli/accounts'
                feeds = JSON.parse(File.read('/run/secrets/rss-accounts.json'))
                raise 'Unexpected feed selection' unless feeds.size == 47 && feeds.map { |f| f.fetch('account') }.uniq.size == 47
                app = Doorkeeper::Application.create!(name: 'Private RSS staging', redirect_uri: 'https://social:8443/fixture-callback', scopes: 'read:accounts write:statuses', confidential: true)
                tokens = feeds.map do |feed|
                  username = feed.fetch('account')
                  raise 'Unsafe feed account' unless username.match?(/\Arss_[a-z0-9_]{1,23}\z/)
                  File.open('/bootstrap/' + username + '.txt', File::WRONLY | File::CREAT | File::EXCL, 0600) do |output|
                    original = ${'$'}stdout
                    begin
                      ${'$'}stdout = output
                      Mastodon::CLI::Accounts.start(['create', username, '--email=' + username + '@localhost.invalid', '--confirmed', '--approve'])
                    ensure
                      ${'$'}stdout = original
                    end
                    output.flush
                    output.fsync
                  end
                  account = Account.find_local(username)
                  raise 'Feed account not initialized' unless account&.user&.confirmed? && account.user.approved?
                  account.update!(bot: true, locked: true, discoverable: false, indexable: false, display_name: feed.fetch('displayName'),
                    note: 'Automated feed mirror for ' + feed.fetch('source') + '. Feed: ' + feed.fetch('url') + '. Unofficial; publication disabled pending independent review.')
                  token = Doorkeeper::AccessToken.create!(application: app, resource_owner_id: account.user.id, scopes: 'read:accounts write:statuses', expires_in: nil)
                  { 'account' => username, 'accountId' => account.id.to_s, 'feedId' => feed.fetch('feedId'), 'pack' => feed.fetch('pack'), 'token' => token.token }
                end
                File.open('/bootstrap/rss-tokens.json', File::WRONLY | File::CREAT | File::EXCL, 0600) do |output|
                  output.write(JSON.generate({ 'schemaVersion' => 1, 'publicationEnabled' => false, 'accounts' => tokens }))
                  output.flush
                  output.fsync
                end
                File.open('/bootstrap', File::RDONLY) { |directory| directory.fsync }
                puts '47 private RSS bot accounts provisioned; publication remains disabled'
            """.trimIndent() + "\n",
            "postgres.env" to "POSTGRES_PASSWORD=$postgres\n",
            "database-init.env" to "POSTGRES_PASSWORD=$postgres\nMASTODON_PASSWORD=$database\n",
            "valkey.conf" to "bind 0.0.0.0\nprotected-mode yes\nport 6379\ndir /data\nappendonly yes\nappendfsync everysec\nrequirepass $redis\n",
            "streaming.env" to common + "NODE_ENV=production\nPORT=4000\nBIND=0.0.0.0\nSTREAMING_CLUSTER_NUM=1\n",
            "mastodon.env" to common + "RAILS_ENV=production\nNODE_ENV=production\nLOCAL_DOMAIN=social\nWEB_DOMAIN=social:8443\nSTREAMING_API_BASE_URL=wss://social:8443\nLIMITED_FEDERATION_MODE=true\nEMAIL_DOMAIN_ALLOWLIST=localhost.invalid\nAUTHORIZED_FETCH=true\nRAILS_LOG_TO_STDOUT=true\nRAILS_SERVE_STATIC_FILES=true\nSECRET_KEY_BASE=${RuntimePreparation.password()}\nACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY=${RuntimePreparation.password()}\nACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY=${RuntimePreparation.password()}\nACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT=${RuntimePreparation.password()}\nVAPID_PRIVATE_KEY=$vapidPrivate\nVAPID_PUBLIC_KEY=$vapidPublic\nSMTP_SERVER=127.0.0.1\nSMTP_PORT=9\nSMTP_FROM_ADDRESS=fixture@localhost.invalid\nWEB_CONCURRENCY=1\nMAX_THREADS=3\nDB_POOL=5\nPORT=3000\nBIND=0.0.0.0\nHOME=/tmp\nMASTODON_SIDEKIQ_READY_FILENAME=sidekiq-ready\n",
            "nginx.conf" to """
                worker_processes 1;
                pid /tmp/nginx.pid;
                error_log /tmp/nginx-error.log warn;
                events { worker_connections 512; }
                http {
                    access_log off;
                    client_body_temp_path /tmp/client_body;
                    proxy_temp_path /tmp/proxy;
                    fastcgi_temp_path /tmp/fastcgi;
                    uwsgi_temp_path /tmp/uwsgi;
                    scgi_temp_path /tmp/scgi;
                    map ${'$'}http_upgrade ${'$'}connection_upgrade { default upgrade; '' close; }
                    server { listen 8080; location = /healthz { return 200 'ready'; } location / { return 404; } }
                    server {
                        listen 8443 ssl;
                        server_name social;
                        ssl_certificate /run/secrets/web.pem;
                        ssl_certificate_key /run/secrets/web-key.pem;
                        ssl_protocols TLSv1.2 TLSv1.3;
                        client_max_body_size 10m;
                        proxy_set_header Host ${'$'}http_host;
                        proxy_set_header X-Forwarded-Proto https;
                        proxy_set_header X-Forwarded-For ${'$'}remote_addr;
                        location /api/v1/streaming {
                            proxy_pass http://streaming:4000;
                            proxy_http_version 1.1;
                            proxy_set_header Upgrade ${'$'}http_upgrade;
                            proxy_set_header Connection ${'$'}connection_upgrade;
                            proxy_read_timeout 120s;
                        }
                        location / { proxy_pass http://mastodon:3000; proxy_http_version 1.1; }
                    }
                }
            """.trimIndent() + "\n")
    }
}
