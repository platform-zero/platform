package net.datamancy.platform

import kotlinx.serialization.json.*

/** Fresh Mastodon, private bot feature and empty Redis DB1. No source SQL,
 * original upload volume, historical bot/owner ID, Redis dump or old token.
 * Installation jobs in mastodon/r3 mint their own local numeric IDs and token
 * custody; only a separate controller adopts the sealed new token ledger.
 */
internal object CanonicalFreshMastodonSource {
    fun inputs(generation: String, postgresAdmin: String, bridgePassword: String,
        password: () -> String): Map<String, String> {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
            listOf(postgresAdmin, bridgePassword).all { it.matches(Regex("[a-f0-9]{64}")) })
        val legacy = MastodonRuntime.inputs()
        val original = legacy.getValue("mastodon.env")
        val originalDb = Regex("(?m)^DB_PASS=([a-f0-9]{64})$").find(original)?.groupValues?.get(1)
            ?: error("Fresh Mastodon database credential absent")
        val originalRedis = Regex("(?m)^REDIS_PASSWORD=([a-f0-9]{64})$").find(original)?.groupValues?.get(1)
            ?: error("Fresh Mastodon cache credential absent")
        val migration = password(); val runtime = password()
        require(listOf(migration, runtime).all { it.matches(Regex("[a-f0-9]{64}")) } &&
            setOf(migration, runtime, bridgePassword, postgresAdmin).size == 4)
        fun env(source: String, role: String, secret: String) = source
            .replace("DB_USER=mastodon\n", "DB_USER=$role\n")
            .replace("DB_PASS=$originalDb\n", "DB_PASS=$secret\n")
            .replace("REDIS_PASSWORD=$originalRedis\n", "REDIS_USER=mastodon\nREDIS_PASSWORD=$bridgePassword\n")
            .replace("REDIS_HOST=valkey\n", "REDIS_HOST=mastodon-redis-bridge\n")
            .replace("LOCAL_DOMAIN=social\n", "LOCAL_DOMAIN=social.datamancy.net\n")
            .replace("WEB_DOMAIN=social:8443\n", "WEB_DOMAIN=social.datamancy.net\n")
            .replace("wss://social:8443\n", "wss://social.datamancy.net\n") +
            "PGSSLMODE=verify-full\nPGSSLROOTCERT=/run/secrets/postgres-ca.pem\n"
        val migrationEnv = env(original, "mastodon_migration", migration) + "P0V3_GENERATION=$generation\n"
        val runtimeEnv = env(original, "mastodon_runtime", runtime)
        val stream = env(legacy.getValue("streaming.env"), "mastodon_runtime", runtime) +
            "NODE_EXTRA_CA_CERTS=/run/secrets/postgres-ca.pem\n"
        val certs = PrivateWebPki.generate("social")
        require(certs.keys == setOf("ca.pem", "web.pem", "web-key.pem"))
        val users = """
            require 'json'
            require_relative '/opt/mastodon/lib/mastodon/cli/accounts'
            names = %w[owner reader]
            raise 'Fresh user selection changed' unless names.uniq.size == 2
            names.each do |name|
              raise 'Pre-existing local user is not fresh bootstrap' if Account.find_local(name)
              File.open('/bootstrap/' + name + '.txt', File::WRONLY | File::CREAT | File::EXCL, 0600) do |output|
                previous = ${'$'}stdout
                begin
                  ${'$'}stdout = output
                  Mastodon::CLI::Accounts.start(['create', name, '--email=' + name + '@localhost.invalid', '--confirmed', '--approve'])
                ensure
                  ${'$'}stdout = previous
                end
                output.flush; output.fsync
              end
              account = Account.find_local(name)
              raise 'Fresh local human missing' unless account&.user&.confirmed? && account.user.approved? && !account.bot?
              if name == 'owner'
                role = UserRole.find_by(name: 'Admin')
                raise 'Fresh realm administrator role absent' unless role
                account.user.update!(role: role)
              end
            end
            File.open('/bootstrap', File::RDONLY) { |directory| directory.fsync }
        """.trimIndent() + "\n"
        val rss = legacy.getValue("rss-bootstrap.rb")
        val anchor = "File.open('/bootstrap/rss-tokens.json', File::WRONLY | File::CREAT | File::EXCL, 0600) do |output|"
        require(rss.split(anchor).size == 2 && "feeds.size == 47" in rss)
        val observer = """
            raise 'Existing RSS observer is not fresh' if Account.find_local('rss_observer')
            File.open('/bootstrap/rss_observer.txt', File::WRONLY | File::CREAT | File::EXCL, 0600) do |output|
              previous = ${'$'}stdout
              begin
                ${'$'}stdout = output
                Mastodon::CLI::Accounts.start(['create', 'rss_observer', '--email=rss_observer@localhost.invalid', '--confirmed', '--approve'])
              ensure
                ${'$'}stdout = previous
              end
              output.flush; output.fsync
            end
            observer = Account.find_local('rss_observer')
            raise 'Fresh read-only observer missing' unless observer&.user&.confirmed? && observer.user.approved? && !observer.bot?
            feeds.each do |feed|
              bot = Account.find_local(feed.fetch('account'))
              raise 'Fresh bot missing' unless bot&.bot?
              Follow.create!(account: observer, target_account: bot)
            end
            raise 'Observer failed local follow policy' unless observer.following_count >= 47
            observer_token = Doorkeeper::AccessToken.create!(application: app, resource_owner_id: observer.user.id,
              scopes: 'read:accounts', expires_in: nil)
            tokens << { 'account' => 'rss_observer', 'accountId' => observer.id.to_s,
              'feedId' => 'observer', 'pack' => 'observer', 'token' => observer_token.token }
        """.trimIndent() + "\n"
        val nginx = legacy.getValue("nginx.conf").replace("server_name social;", "server_name social.datamancy.net;")
        return mapOf(
            "mastodon-db-admin.env" to "PGPASSWORD=$postgresAdmin\nMASTODON_MIGRATION_PASSWORD=$migration\nMASTODON_RUNTIME_PASSWORD=$runtime\n",
            "mastodon-migrate.env" to migrationEnv,
            "mastodon.env" to runtimeEnv,
            "mastodon-streaming.env" to stream,
            "mastodon-nginx.conf" to nginx,
            "mastodon-ca.pem" to certs.getValue("ca.pem"),
            "mastodon-web.pem" to certs.getValue("web.pem"),
            "mastodon-web-key.pem" to certs.getValue("web-key.pem"),
            "mastodon-fresh-users.rb" to users,
            "rss-accounts.json" to legacy.getValue("rss-accounts.json"),
            "rss-bootstrap.rb" to rss.replace(anchor, observer + anchor)
        )
    }
}
