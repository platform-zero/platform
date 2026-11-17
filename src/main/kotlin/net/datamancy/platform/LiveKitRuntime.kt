package net.datamancy.platform

import java.nio.file.Path
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS

/** Private authenticated SFU; ephemeral rooms, no public TURN, Matrix authorizer or recording. */
internal object LiveKitRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "livekit"): PrivateDeploymentSpec {
        fun image(product: String) = inventory.images.single { it.product == product }.also {
            require(it.os == "linux" && it.architecture == "amd64")
        }
        val sfu = image("livekit"); val web = image("element")
        return PrivateDeploymentSpec(name = name, volumes = emptyList(), processes = listOf(
            RuntimeProcess("livekit", sfu.pinnedImage, sfu.imageId, 1000, entrypoint = "/livekit-server",
                command = listOf("--config", "/run/secrets/livekit.yaml"),
                files = listOf(RuntimeFile("livekit.yaml", "/run/secrets/livekit.yaml")),
                apparmorProfile = "p0v3-private-v1", memoryMiB = 1024, readinessHttpPort = 7880),
            RuntimeProcess("rtc", web.pinnedImage, web.imageId, 101, dependencies = listOf("livekit"),
                entrypoint = "/usr/sbin/nginx", command = listOf("-c", "/run/secrets/nginx.conf", "-g", "daemon off;"),
                files = listOf("nginx.conf", "web.pem", "web-key.pem", "ca.pem").map { RuntimeFile(it, "/run/secrets/$it") },
                apparmorProfile = "p0v3-private-v1", memoryMiB = 256, readinessHttpPort = 8080, readinessHttpPath = "/healthz")
        )).also { PrivateDeployment.validate(it) }
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "livekit", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }

    /** MatrixRTC app-only SFU, original E2EE call authorization and real embedded TURN.
     * Caddy remains the single shared HTTPS ingress; ephemeral participants are never cloned.
     */
    fun canonicalFragment(inventory: AcquiredInventory, base: PrivateDeploymentSpec): CanonicalProviderFragment {
        require(base.store == RuntimeStore.CANONICAL_V2 && base.processes.any { it.id == "caddy" && !it.oneShot })
        fun image(product: String) = inventory.images.single { it.product == product }.also {
            require(it.os == "linux" && it.architecture == "amd64")
        }
        val sfu = image("livekit"); val proxy = image("element"); val authorizer = image("matrix-rtc-authorizer")
        val livekit = RuntimeProcess("livekit", sfu.pinnedImage, sfu.imageId, 1000,
            entrypoint = "/livekit-server", command = listOf("--config", "/run/secrets/livekit.yaml"),
            files = listOf(RuntimeFile("livekit.yaml", "/run/secrets/livekit.yaml"),
                RuntimeFile("livekit-turn-template.yaml", "/run/secrets/livekit-turn-template.yaml"),
                RuntimeFile("rtc-turn.pem", "/run/secrets/rtc-turn.pem"),
                RuntimeFile("rtc-turn-key.pem", "/run/secrets/rtc-turn-key.pem")),
            // The single fixed qualification client net carries original-hostname TURN
            // only under A13's generation/guest egress deny policy. No public binding.
            networks = listOf("rtc-data", "rtc-turn", "qualification-web"), memoryMiB = 1024,
            apparmorProfile = "p0v3-private-v1", readinessHttpPort = 7880)
        val mint = RuntimeProcess("rtc-authorizer", authorizer.pinnedImage, authorizer.imageId, 65532,
            dependencies = listOf("synapse", "mas", "livekit"), entrypoint = "/lk-jwt-service",
            environmentFile = "rtc-authorizer.env", files = listOf(
                RuntimeFile("rtc-registration.yaml", "/run/secrets/rtc-registration.yaml"),
                RuntimeFile("identity-ca.pem", "/run/secrets/identity-ca.pem")),
            networks = listOf("rtc-data", "synapse-web"), memoryMiB = 256,
            apparmorProfile = "p0v3-private-v1", readinessHttpPort = 8080, readinessHttpPath = "/healthz")
        val web = RuntimeProcess("rtc-web", proxy.pinnedImage, proxy.imageId, 101,
            dependencies = listOf("rtc-authorizer"), entrypoint = "/usr/sbin/nginx",
            command = listOf("-c", "/run/secrets/rtc-nginx.conf", "-g", "daemon off;"),
            files = listOf(RuntimeFile("rtc-nginx.conf", "/run/secrets/rtc-nginx.conf")),
            networks = listOf("rtc-data", "rtc-web"), memoryMiB = 256,
            apparmorProfile = "p0v3-private-v1", readinessHttpPort = 8080, readinessHttpPath = "/healthz")
        val partial = PrivateDeploymentSpec(name = base.name, store = base.store,
            volumes = emptyList(), processes = listOf(livekit, mint, web),
            networks = listOf("rtc-data", "rtc-turn", "rtc-web", "qualification-web"))
        return CanonicalProviderFragment("livekit", partial,
            webNetworks = setOf("rtc-web", "qualification-web"))
    }

    fun canonicalColdFragment(inventory: AcquiredInventory, base: PrivateDeploymentSpec,
        original: CanonicalProviderFragment): CanonicalProviderFragment {
        val fresh = canonicalFragment(inventory, base)
        require(original == fresh && fresh.spec.processes.none { it.oneShot }) {
            "A recovered SFU may not recreate rooms, calls or server credentials"
        }
        return fresh
    }

    /** Bootstrap-only private TURN TLS: no public :5349/official client authority.
     * Only COORD's post-issuance effective revision may bind a public TURN port. */
    fun canonicalInputs(apiKey: String, apiSecret: String, matrixRegistration: String,
        turnPki: Map<String, String>): Map<String, String> {
        require(apiKey.matches(Regex("[a-f0-9]{64}")) && apiSecret.matches(Regex("[a-f0-9]{64}")) &&
            apiKey != apiSecret && matrixRegistration.contains("id: p0v3-matrix-rtc") &&
            turnPki.keys == setOf("ca.pem", "web.pem", "web-key.pem") &&
            turnPki.values.all { it.startsWith("-----BEGIN ") })
        val sealed = mapOf("rtc-turn.pem" to turnPki.getValue("web.pem"),
            "rtc-turn-key.pem" to turnPki.getValue("web-key.pem"),
            "livekit.yaml" to """
                port: 7880
                bind_addresses: [0.0.0.0]
                development: false
                keys:
                  "$apiKey": "$apiSecret"
                rtc:
                  tcp_port: 7881
                  port_range_start: 50000
                  port_range_end: 50020
                  use_external_ip: false
                  use_ice_lite: false
                  stun_servers: []
                  turn_servers: []
                turn:
                  enabled: false
                  domain: rtc.datamancy.net
                  udp_port: 3478
                  tls_port: 5349
                  cert_file: /run/secrets/rtc-turn.pem
                  key_file: /run/secrets/rtc-turn-key.pem
                room:
                  auto_create: false
                  empty_timeout: 60
                  departure_timeout: 10
                  max_participants: 8
                  enable_remote_unmute: false
                webhook:
                  api_key: '$apiKey'
                  urls: ['http://rtc-authorizer:8080/sfu_webhook']
                logging:
                  level: warn
                  pion_level: error
            """.trimIndent() + "\n",
            "rtc-authorizer.env" to """
                LIVEKIT_URL=ws://livekit:7880
                LIVEKIT_KEY=$apiKey
                LIVEKIT_SECRET=$apiSecret
                LIVEKIT_JWT_BIND=0.0.0.0:8080
                LIVEKIT_FULL_ACCESS_HOMESERVERS=matrix.datamancy.net
                LIVEKIT_HS_SERVER_NAME=matrix.datamancy.net
                LIVEKIT_AS_REGISTRATION_FILE=/run/secrets/rtc-registration.yaml
                LIVEKIT_CS_API_URL_OVERRIDES=matrix.datamancy.net=http://synapse:8008
                LIVEKIT_LOG_LEVEL=warn
                LIVEKIT_SANITY_CHECK_INTERVAL_SECONDS=15
            """.trimIndent() + "\n",
            "rtc-nginx.conf" to """
                worker_processes 1;
                pid /tmp/nginx.pid;
                error_log /tmp/nginx-error.log warn;
                events { worker_connections 512; }
                http {
                  access_log off;
                  map ${'$'}http_upgrade ${'$'}connection_upgrade { default upgrade; '' close; }
                  server {
                    listen 8080;
                    location = /healthz { return 200 'ready'; }
                    location = /fixture { default_type text/html; return 200 '<!doctype html><title>RTC test harness</title>'; }
                    location = /livekit/jwt/sfu/get { proxy_pass http://rtc-authorizer:8080/sfu/get; }
                    location = /livekit/jwt/get_token { proxy_pass http://rtc-authorizer:8080/get_token; }
                    location = /livekit/jwt/delegate_delayed_leave { proxy_pass http://rtc-authorizer:8080/delegate_delayed_leave; }
                    location /livekit/sfu/ {
                      proxy_pass http://livekit:7880/;
                      proxy_http_version 1.1;
                      proxy_set_header Host ${'$'}http_host;
                      proxy_set_header Upgrade ${'$'}http_upgrade;
                      proxy_set_header Connection ${'$'}connection_upgrade;
                      proxy_buffering off;
                      proxy_read_timeout 120s;
                    }
                    location / { return 404; }
                  }
                }
            """.trimIndent() + "\n")
        val template = turnTemplate(sealed.getValue("livekit.yaml"))
        return sealed + ("livekit-turn-template.yaml" to template)
    }

    /** The sealed effective template is NOT an active credential and NEVER starts the SFU.
     * Only the typed A02 actuator may mount its rendered config + cert/key as three
     * append-only revision secrets and restart the SAME livekit process. */
    private fun turnTemplate(bootstrap: String): String {
        val disabled = "turn:\n  enabled: false\n  domain: rtc.datamancy.net\n" +
            "  udp_port: 3478\n  tls_port: 5349\n" +
            "  cert_file: /run/secrets/rtc-turn.pem\n" +
            "  key_file: /run/secrets/rtc-turn-key.pem"
        val enabled = disabled.replace("enabled: false", "enabled: true")
            .replace("/run/secrets/rtc-turn.pem", "@REVISION_PEM@")
            .replace("/run/secrets/rtc-turn-key.pem", "@REVISION_KEY@")
        require(bootstrap.split(disabled).size == 2 && !bootstrap.contains("@REVISION_"))
        return bootstrap.replace(disabled, enabled)
    }

    /** Render ONLY the sealed template paired with this bootstrap. Immutable target
     * mounts and argv are owned by A02, with public ingress held until A15 native
     * TLS SNI readback and append-only adoption receipt; not by this pure helper. */
    fun effectivePublicTurnConfig(generation: String, certificate: PublicCertificateRevision,
        sealedBootstrap: String, sealedTemplate: String): String {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
            certificate.kind == "ACME_PUBLIC" && certificate.generation == generation &&
            certificate.host == "rtc.datamancy.net" && "rtc.datamancy.net" in certificate.dnsNames &&
            certificate.revisionId.matches(Regex("cert-[a-f0-9]{24}")) &&
            sealedTemplate == turnTemplate(sealedBootstrap)) {
            "Effective TURN config must derive from the exact disabled sealed bootstrap"
        }
        val base = "/run/turn-revisions/${certificate.revisionId}"
        val rendered = sealedTemplate.replace("@REVISION_PEM@", "$base/rtc-turn.pem")
            .replace("@REVISION_KEY@", "$base/rtc-turn-key.pem")
        require(!rendered.contains("@REVISION_") && rendered.contains("turn:\n  enabled: true"))
        return rendered
    }

    /** Post-issuance EFFECTIVE credential payload ONLY, never part of sealed fresh
     * canonicalInputs. COORD must first read native ACME_PUBLIC revision with
     * GenerationCredentialRevisions.readPublicCertificate and append a generation-
     * bound revision/atomic deployment reload, prove effective native TURN TLS leaf,
     * and gate all public :5349/official clients on that observation. This function
     * does not mutate a sealed bundle, issue ACME, publish, or activate TURN. */
    fun effectivePublicTurnInputs(generation: String, certificate: PublicCertificateRevision,
        chainPem: String, keyPem: String): Map<String, String> {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
            certificate.kind == "ACME_PUBLIC" && certificate.generation == generation &&
            certificate.host == "rtc.datamancy.net" && "rtc.datamancy.net" in certificate.dnsNames &&
            certificate.acmeDirectory == "https://acme-v02.api.letsencrypt.org/directory" &&
            chainPem.startsWith("-----BEGIN CERTIFICATE-----") &&
            keyPem.startsWith("-----BEGIN PRIVATE KEY-----") &&
            ReleaseLocks.sha256(chainPem.toByteArray()) == certificate.chainPemSha256 &&
            ReleaseLocks.sha256(keyPem.toByteArray()) == certificate.privateKeyPemSha256) {
            "Public TURN TLS needs the controller-authenticated effective ACME revision"
        }
        return mapOf("rtc-turn.pem" to chainPem, "rtc-turn-key.pem" to keyPem)
    }

    /** Source equality is checked by the generation compiler; no ephemeral call is claimed restored. */
    fun coldRestoreSpec(compiled: PrivateDeploymentSpec): PrivateDeploymentSpec {
        require(compiled.volumes.isEmpty() && compiled.processes.map { it.id }.toSet() == setOf("livekit", "rtc"))
        require(compiled.processes.none { it.oneShot })
        require(compiled.processes.single { it.id == "livekit" }.command == listOf("--config", "/run/secrets/livekit.yaml"))
        PrivateDeployment.validate(compiled)
        return compiled
    }

    /** Restore only this exact stateless recipe; rooms/participants are deliberately not backed up. */
    fun prepareRestore(inventory: AcquiredInventory, recovered: Path, name: String, base: Path = PrivateDeployment.BASE): Path {
        require(recovered.isAbsolute && recovered.normalize() == recovered && recovered.toRealPath() == recovered)
        val sourcePath = recovered.resolve("source-spec.json")
        ReleaseLocks.privateBytes(sourcePath)
        val source = PrivateDeployment.read(sourcePath)
        require(source == spec(inventory, source.name) && source.name != name) { "Unsupported SFU recovery recipe" }
        val inputs = SingleUserRestore.inputNames(source).associateWith {
            ReleaseLocks.privateBytes(recovered.resolve(it)).decodeToString(throwOnInvalidSequence = true)
        }
        if (Files.exists(base.resolve("$name.json"), NOFOLLOW_LINKS)) inputs.forEach { (file, content) ->
            require(ReleaseLocks.privateBytes(base.resolve(name).resolve(file)).contentEquals(content.toByteArray())) {
                "Recovered inputs changed; refusing replacement"
            }
        }
        return RuntimePreparation.prepare(source.copy(name = name), base) { inputs }
    }

    fun inputs(pki: () -> Map<String, String> = { PrivateWebPki.generate("rtc") }): Map<String, String> {
        val key = RuntimePreparation.password(); val secret = RuntimePreparation.password()
        return pki() + mapOf("livekit.yaml" to """
            port: 7880
            bind_addresses: [0.0.0.0]
            development: false
            keys:
              "$key": "$secret"
            rtc:
              tcp_port: 7881
              port_range_start: 50000
              port_range_end: 50020
              use_external_ip: false
              use_ice_lite: true
              stun_servers: []
              turn_servers: []
            turn:
              enabled: false
            room:
              auto_create: false
              empty_timeout: 60
              departure_timeout: 10
              max_participants: 8
              enable_remote_unmute: false
            logging:
              level: warn
              pion_level: error
        """.trimIndent() + "\n", "nginx.conf" to """
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
                    server_name rtc;
                    ssl_certificate /run/secrets/web.pem;
                    ssl_certificate_key /run/secrets/web-key.pem;
                    ssl_protocols TLSv1.2 TLSv1.3;
                    client_max_body_size 1m;
                    location = /fixture { default_type text/html; return 200 '<!doctype html><title>Private synthetic RTC fixture</title><body>Private synthetic RTC fixture</body>'; }
                    location / {
                        proxy_pass http://livekit:7880;
                        proxy_http_version 1.1;
                        proxy_set_header Host ${'$'}http_host;
                        proxy_set_header Upgrade ${'$'}http_upgrade;
                        proxy_set_header Connection ${'$'}connection_upgrade;
                        proxy_read_timeout 120s;
                        proxy_buffering off;
                    }
                }
            }
        """.trimIndent() + "\n")
    }
}
