package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path

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
