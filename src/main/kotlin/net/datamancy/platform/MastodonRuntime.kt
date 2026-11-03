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
