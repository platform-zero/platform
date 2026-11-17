package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.json.*

/** Quiesced social recovery: never replay migrations, account creation or token generation. */
internal object MastodonRecovery {
    fun spec(source: PrivateDeploymentSpec, inventory: AcquiredInventory, name: String, sourceHash: String): PrivateDeploymentSpec {
        require(source == MastodonRuntime.spec(inventory, source.name)) { "Unsupported social source recipe" }
        require(name != source.name && sourceHash.matches(Regex("[a-f0-9]{64}")))
        fun check(path: String) = BusinessRestoreGuards.marker(path, sourceHash)
        val checkAccounts = """
            require 'json'
            document = JSON.parse(File.read('/bootstrap/rss-tokens.json'))
            raise 'Recovered RSS publication gate changed' unless document.fetch('publicationEnabled') == false
            rows = document.fetch('accounts')
            expected = JSON.parse(File.read('/run/secrets/rss-accounts.json')).to_h { |feed| [feed.fetch('account'), feed] }
            raise 'Recovered RSS identities incomplete' unless rows.size == 47 && expected.size == 47 && rows.map { |r| r.fetch('account') }.sort == expected.keys.sort
            rows.each do |row|
              feed = expected.fetch(row.fetch('account'))
              raise 'Recovered RSS selection binding changed' unless row.fetch('feedId') == feed.fetch('feedId') && row.fetch('pack') == feed.fetch('pack')
              account = Account.find_local(row.fetch('account'))
              token = Doorkeeper::AccessToken.by_token(row.fetch('token'))
              raise 'Recovered RSS binding invalid' unless account&.bot? && account.id.to_s == row.fetch('accountId') && token && !token.revoked? && token.resource_owner_id == account.user.id && token.scopes.to_s == 'read:accounts write:statuses'
            end
            raise 'Recovered local accounts missing' unless ['owner', 'reader'].all? { |name| Account.find_local(name)&.user&.confirmed? }
            raise 'Recovered registrations not closed' unless Setting.registrations_mode == 'none'
            puts 'Recovered social identities validated; no migrations, seeds or token generation'
        """.trimIndent()
        return source.copy(name = name, processes = source.processes.map { p ->
            when (p.id) {
                "valkey" -> p.copy(entrypoint = "/bin/sh", command = listOf("-ec", check("/data") + "; exec /usr/local/bin/valkey-server /etc/valkey/valkey.conf"))
                "mastodon-migrate", "mastodon-accounts" -> p.copy(entrypoint = "/bin/sh",
                    volumes = listOf(RuntimeMount("uploads", "/opt/mastodon/public/system"), RuntimeMount("bootstrap", "/bootstrap")),
                    command = listOf("-ec", check("/opt/mastodon/public/system") + "; " + check("/bootstrap")))
                "mastodon-rss-accounts" -> p.copy(entrypoint = "/bin/sh",
                    command = listOf("-ec", check("/bootstrap") + "; exec /usr/local/bundle/bin/bundle exec rails runner \"\${1}\"", "restore-check", checkAccounts))
                else -> p
            }
        }).also { PrivateDeployment.validate(it) }
    }
    /** Version-matched Rails native readback AFTER the immutable source SQL dump and
     * original uploads/bootstrap import, BEFORE any new OAuth/synthetic principal.
     * Never seeds, migrates, mints or touches a historical RSS account/checkpoint. */
    internal fun canonicalOriginalCheckScript(): String = """
        require 'json'
        require 'digest'
        document = JSON.parse(File.read('/bootstrap/rss-tokens.json'))
        expected = JSON.parse(File.read('/run/secrets/rss-accounts.json'))
        raise 'Original 47 selection changed' unless expected.size == 47 &&
          expected.map { |f| f.fetch('account') }.uniq.size == 47 &&
          Digest::SHA256.file('/run/secrets/rss-accounts.json').hexdigest == ENV.fetch('ORIGINAL_SELECTION_SHA256')
        raise 'Original 47 token custody or scheduler permit changed' unless
          document.fetch('schemaVersion') == 1 && document.fetch('publicationEnabled') == false &&
          document.fetch('accounts').size == 47 &&
          document.fetch('accounts').map { |a| a.fetch('account') }.sort ==
            expected.map { |a| a.fetch('account') }.sort
        feeds = expected.to_h { |row| [row.fetch('account'), row] }
        observed = document.fetch('accounts').sort_by { |row| row.fetch('account') }.map do |row|
          feed = feeds.fetch(row.fetch('account'))
          raise 'Original RSS feed or pack mapping changed' unless
            row.fetch('feedId') == feed.fetch('feedId') && row.fetch('pack') == feed.fetch('pack')
          account = Account.find_local(row.fetch('account'))
          token = Doorkeeper::AccessToken.by_token(row.fetch('token'))
          raise 'Original SQL account/token ID/scope changed' unless account&.bot? &&
            account.id.to_s == row.fetch('accountId') && account.user&.confirmed? &&
            account.user.approved? && token && !token.revoked? &&
            token.resource_owner_id == account.user.id &&
            token.scopes.to_s == 'read:accounts write:statuses'
          { 'account' => account.username, 'accountId' => account.id.to_s,
            'tokenSha256' => Digest::SHA256.hexdigest(row.fetch('token')) }
        end
        original_sql = observed.to_h { |row|
          account = Account.find_local(row.fetch('account'))
          [row.fetch('account'), { 'accountId' => row.fetch('accountId'),
            'tokenSha256' => row.fetch('tokenSha256'), 'userId' => account.user.id.to_s }]
        }
        raise 'Original source COPY SQL differs from imported target' unless
          Digest::SHA256.hexdigest(JSON.generate(original_sql)) == ENV.fetch('ORIGINAL_SQL47_SHA256') &&
          Digest::SHA256.file('/bootstrap/rss-tokens.json').hexdigest ==
            ENV.fetch('ORIGINAL_TOKEN_CUSTODY_SHA256')
        raise 'Original owner or reader SQL identity missing/recreated' unless ['owner', 'reader'].all? { |who|
          account = Account.find_local(who)
          account&.user&.confirmed? && account.user.approved? && !account.bot? &&
            account.id.to_s == ENV.fetch("ORIGINAL_#{who.upcase}_ID")
        }
        raise 'Original social upload source absent' unless
          File.directory?('/opt/mastodon/public/system') && !File.symlink?('/opt/mastodon/public/system')
        raise 'Original signing/key source missing' unless
          %w[SECRET_KEY_BASE ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY
             ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT
             VAPID_PRIVATE_KEY VAPID_PUBLIC_KEY].all? { |key| ENV.fetch(key).size >= 32 }
        File.open('/bootstrap/original-adoption.json', File::WRONLY | File::CREAT | File::EXCL, 0600) do |f|
          f.write(JSON.generate({ 'schemaVersion' => 1,
            'sourceBundleSha256' => ENV.fetch('ORIGINAL_SOURCE_BUNDLE_SHA256'),
            'generationId' => ENV.fetch('P0V3_GENERATION'),
            'original47CustodySha256' => Digest::SHA256.file('/bootstrap/rss-tokens.json').hexdigest,
            'original47' => observed,
            'ownerId' => Account.find_local('owner').id.to_s,
            'readerId' => Account.find_local('reader').id.to_s }))
          f.flush; f.fsync
        end
        File.open('/bootstrap', File::RDONLY) { |dir| dir.fsync }
    """.trimIndent() + "\n"

    /** Produced by the fixed imported-source-COPY SQL exporter and independently bound by
     * COORD to authenticated source archive/copy custody before input preparation.
     * Not a caller success flag or a fresh replacement for any original SQL ID. */
    @kotlinx.serialization.Serializable internal data class OriginalSqlReadback(val sourceBundleSha256: String,
        val sourceCopyReceiptSha256: String, val originalTokenCustodySha256: String,
        val original47SqlSha256: String, val ownerId: String, val readerId: String,
        val dumpSha256: String)

    /** ONLY TWO predeclared DISJOINT synthetic qualification principals. Original 47
     * account IDs, productive scopes and token bytes are read-only inputs; no new
     * historical rss_* principal, publication or checkpoint is created. The source
     * bootstrap volume is first imported from authenticated original custody.
     * Exclusive durable intent precedes each Rails/SQL effect, never removed on
     * interruption or unknown acknowledgement. COORD copies resulting owner-only
     * token files into A04's disjoint controller qualification-custody contributor. */
    internal fun syntheticRssqInputs(fixtureIds: Set<String>, generation: String,
        originalBundleSha256: String): Map<String, String> {
        require(fixtureIds.size == 2 && fixtureIds.all { it.matches(Regex("rssq-[0-9a-f]{12}")) } &&
            generation.matches(Regex("q-[a-f0-9]{12}")) && originalBundleSha256.matches(Regex("[a-f0-9]{64}")))
        val selected = buildJsonObject {
            put("schemaVersion", 1); put("generationId", generation)
            put("originalBundleSha256", originalBundleSha256)
            put("fixtureIds", buildJsonArray { fixtureIds.sorted().forEach { add(it) } })
        }.toString() + "\n"
        val script = """
            require 'json'
            require 'digest'
            require 'fileutils'
            require 'securerandom'
            binding = JSON.parse(File.read('/run/secrets/mastodon-rssq-fixtures.json'))
            fixtures = binding.fetch('fixtureIds')
            raise 'Synthetic generation/fixture selection changed' unless binding.fetch('schemaVersion') == 1 &&
              binding.fetch('generationId').match?(/\Aq-[a-f0-9]{12}\z/) &&
              binding.fetch('originalBundleSha256').match?(/\A[a-f0-9]{64}\z/) &&
              fixtures.size == 2 && fixtures.uniq.size == 2 &&
              fixtures.all? { |id| id.match?(/\Arssq-[0-9a-f]{12}\z/) }
            historical = JSON.parse(File.read('/bootstrap/rss-tokens.json'))
            raise 'Original 47 missing before synthetic enrollment' unless historical.fetch('schemaVersion') == 1 &&
              historical.fetch('publicationEnabled') == false && historical.fetch('accounts').size == 47 &&
              historical.fetch('accounts').map { |a| a.fetch('account') }.uniq.size == 47
            historical.fetch('accounts').each do |row|
              account = Account.find_local(row.fetch('account'))
              token = Doorkeeper::AccessToken.by_token(row.fetch('token'))
              raise 'Original principal or productive scope changed' unless account&.bot? &&
                account.id.to_s == row.fetch('accountId') && token && !token.revoked? &&
                token.resource_owner_id == account.user.id &&
                token.scopes.to_s == 'read:accounts write:statuses'
            end
            target = '/bootstrap/qualification-custody'
            FileUtils.mkdir_p(target, mode: 0700)
            File.open('/bootstrap/rssq-enrollment.intent', File::WRONLY | File::CREAT | File::EXCL, 0600) do |f|
              f.write(JSON.generate({ 'schemaVersion' => 1, 'generationId' => binding.fetch('generationId'),
                'sourceBundleSha256' => binding.fetch('originalBundleSha256'), 'fixtures' => fixtures,
                'original47Sha256' => Digest::SHA256.file('/bootstrap/rss-tokens.json').hexdigest }))
              f.flush; f.fsync
            end
            File.open('/bootstrap', File::RDONLY) { |dir| dir.fsync }
            app = Doorkeeper::Application.create!(name: 'P0V3 restricted synthetic RSS qualification',
              redirect_uri: 'https://social.datamancy.net/fixture-callback', confidential: true,
              scopes: 'read:accounts read:statuses write:statuses')
            rows = fixtures.map do |id|
              username = id.tr('-', '_')
              raise 'Existing synthetic bot cannot be silently adopted' if Account.find_local(username)
              dir = File.join(target, id)
              Dir.mkdir(dir, 0700)
              File.open(File.join(dir, 'intent.json'), File::WRONLY | File::CREAT | File::EXCL, 0600) do |f|
                f.write(JSON.generate({ 'fixtureId' => id, 'account' => username, 'appId' => app.id.to_s }))
                f.flush; f.fsync
              end
              File.open(dir, File::RDONLY) { |d| d.fsync }
              account = Account.create!(username: username, domain: nil, bot: true, locked: true,
                discoverable: false, indexable: false)
              password = SecureRandom.hex(32)
              user = User.new(account: account, email: username + '@localhost.invalid', password: password,
                password_confirmation: password, confirmed_at: Time.current, approved: true)
              user.save!
              token = Doorkeeper::AccessToken.create!(application: app, resource_owner_id: user.id,
                scopes: 'read:accounts read:statuses write:statuses', expires_in: nil)
              File.open(File.join(dir, 'bot.token'), File::WRONLY | File::CREAT | File::EXCL, 0600) do |f|
                f.write(token.token); f.flush; f.fsync
              end
              File.open(dir, File::RDONLY) { |d| d.fsync }
              bound = Doorkeeper::AccessToken.by_token(token.token)
              raise 'Synthetic source authority changed' unless bound && !bound.revoked? &&
                bound.resource_owner_id == user.id && bound.scopes.to_s ==
                'read:accounts read:statuses write:statuses'
              { 'fixtureId' => id, 'account' => username, 'accountId' => account.id.to_s,
                'tokenSha256' => Digest::SHA256.hexdigest(token.token) }
            end
            File.open(File.join(target, 'receipt.json'), File::WRONLY | File::CREAT | File::EXCL, 0600) do |f|
              f.write(JSON.generate({ 'schemaVersion' => 1, 'generationId' => binding.fetch('generationId'),
                'sourceBundleSha256' => binding.fetch('originalBundleSha256'), 'fixtures' => rows,
                'original47Sha256' => Digest::SHA256.file('/bootstrap/rss-tokens.json').hexdigest }))
              f.flush; f.fsync
            end
            File.open(target, File::RDONLY) { |d| d.fsync }
        """.trimIndent() + "\n"
        return mapOf("mastodon-rssq-fixtures.json" to selected, "mastodon-rssq-provision.rb" to script)
    }

    /** The sole admissible ORIGINAL 47 source is a physically authenticated, whole-cohort
     * Kopia/capsule materialization. A caller-written account list, token JSON or Boolean
     * cannot manufacture the original provider SQL, uploads, cache and token custody.
     * This is a read-only admission; COORD must retain the source isolated while the
     * bounded version-matched native SQL/volume import is journalled separately. */
    internal data class CanonicalSource(val generation: String, val originalBundleSha256: String,
        val member: String, val originalEnvironment: String, val originalStreaming: String,
        val originalWeb: String, val originalSelection: String,
        val archives: Map<String, Path>, val archiveHashes: Map<String, String>)

    internal fun canonicalSource(recovered: RecoveredGeneration, inventory: AcquiredInventory): CanonicalSource {
        val root = recovered.root
        require(root.isAbsolute && root.normalize() == root && root.toRealPath() == root &&
            recovered.bundle.request.id == recovered.manifest.generation &&
            recovered.check.bundleSha256 == recovered.manifest.bundleSha256 &&
            recovered.check.capsule == recovered.manifest.id &&
            recovered.check.kopiaSnapshotId != null && recovered.check.kopiaReceiptSha256 != null) {
            "Original source requires authenticated native Kopia lineage, not a caller oracle"
        }
        val sources = recovered.bundle.members.filter { pin ->
            pin.spec.processes.any { it.id == "mastodon" } && pin.spec.store == RuntimeStore.LEGACY
        }
        require(sources.size == 1)
        val source = sources.single()
        val name = source.member.name
        require(source.spec == MastodonRuntime.spec(inventory, name) &&
            recovered.manifest.members.singleOrNull { it.name == name }?.fingerprint == source.runtimeFingerprint)
        fun originalInput(file: String): String {
            val sealed = source.inputHashes.getValue(file)
            val path = root.resolve("$name/inputs/$file")
            RecoveryCapsule.guard(path, 1048576)
            val bytes = Files.readAllBytes(path)
            require(ReleaseLocks.sha256(bytes) == sealed &&
                recovered.manifest.files.single { it.name == "$name/inputs/$file" }.sha256 == sealed)
            return bytes.decodeToString(throwOnInvalidSequence = true)
        }
        val environment = originalInput("mastodon.env")
        val selection = originalInput("rss-accounts.json")
        require(listOf("SECRET_KEY_BASE", "ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY",
            "ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY", "ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT",
            "VAPID_PRIVATE_KEY", "VAPID_PUBLIC_KEY").all { key ->
                Regex("(?m)^$key=\\S+${'$'}").containsMatchIn(environment)
            }) { "Original social signing keys incomplete" }
        val feeds = Json.parseToJsonElement(selection).jsonArray
        require(feeds.size == 47 && feeds.map { it.jsonObject.getValue("account").jsonPrimitive.content }.toSet().size == 47 &&
            feeds.map { it.jsonObject.getValue("account").jsonPrimitive.content }.toSet() ==
                RssPacks.load().map { it.feed.account }.toSet()) { "Original 47 feed selection changed" }
        val volumes = setOf("postgres", "valkey", "uploads", "bootstrap")
        require(volumes == source.spec.volumes.map { it.id }.toSet())
        val archives = volumes.associateWith { volume -> root.resolve("$name/volumes/$volume.tar") }
        val hashes = volumes.associateWith { volume ->
            val relative = "$name/volumes/$volume.tar"
            val registered = recovered.manifest.volumes.singleOrNull { it.name == relative }
                ?.sha256 ?: recovered.manifest.files.single { it.name == relative }.sha256
            val archive = archives.getValue(volume)
            RecoveryCapsule.guard(archive, RecoveryCapsule.MAX_TOTAL)
            require(RecoveryCapsule.fileHash(archive) == registered) { "Original social volume changed" }
            registered
        }
        return CanonicalSource(recovered.manifest.generation, recovered.manifest.bundleSha256,
            name, environment, originalInput("streaming.env"), originalInput("nginx.conf"),
            selection, archives, hashes)
    }

    fun prepare(inventory: AcquiredInventory, recovered: Path, name: String, base: Path = PrivateDeployment.BASE): Path {
        require(recovered.isAbsolute && recovered.normalize() == recovered && recovered.toRealPath() == recovered)
        val sourcePath = recovered.resolve("source-spec.json")
        val bytes = ReleaseLocks.privateBytes(sourcePath)
        val source = PrivateDeployment.read(sourcePath)
        val target = spec(source, inventory, name, ReleaseLocks.sha256(bytes))
        val inputs = SingleUserRestore.inputNames(source).associateWith {
            ReleaseLocks.privateBytes(recovered.resolve(it)).decodeToString(throwOnInvalidSequence = true)
        }
        if (Files.exists(base.resolve("$name.json"), NOFOLLOW_LINKS)) {
            inputs.forEach { (file, content) -> require(ReleaseLocks.privateBytes(base.resolve(name).resolve(file)).contentEquals(content.toByteArray())) {
                "Recovered social inputs changed; refusing replacement"
            } }
        }
        return RuntimePreparation.prepare(target, base) { inputs }
    }
}
