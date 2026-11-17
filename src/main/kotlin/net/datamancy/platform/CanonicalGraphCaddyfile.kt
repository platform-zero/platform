package net.datamancy.platform

import kotlinx.serialization.json.*
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit

/** The r9 manifest's *module-owned* privateRoutes are the only ingress graph.
 * OLD reference labels are a completeness check, never executable routing.
 * No caller may supply a second topology. The rendered file is adapted before
 * sealing caddy.json; the Caddy admin API is not an independent route author.
 */
internal data class FreshNativeIngressGrants(val bookstackInternalToken: String, val qbittorrentBasicHash: String,
    val ntfySsoToken: String? = null, val bookstackApiId: String? = null,
    val bookstackApiSecret: String? = null, val outsiderBookstackApiId: String? = null,
    val outsiderBookstackApiSecret: String? = null) {
    init {
        require(bookstackInternalToken.matches(Regex("[a-f0-9]{64}")) &&
            qbittorrentBasicHash.matches(Regex("\\$2[aby]\\$1[234]\\$[./A-Za-z0-9]{53}")) &&
            (ntfySsoToken == null || ntfySsoToken.matches(Regex("tk_[A-Za-z0-9]{32}"))) &&
            (bookstackApiId == null && bookstackApiSecret == null ||
                bookstackApiId?.matches(Regex("p0v3-[a-f0-9]{32}")) == true &&
                bookstackApiSecret?.matches(Regex("[a-f0-9]{64}")) == true &&
                bookstackApiSecret != bookstackInternalToken) &&
            ((outsiderBookstackApiId == null && outsiderBookstackApiSecret == null) ||
                (outsiderBookstackApiId?.matches(Regex("p0v3-[a-f0-9]{32}")) == true &&
                    outsiderBookstackApiSecret?.matches(Regex("[a-f0-9]{64}")) == true &&
                    outsiderBookstackApiId != bookstackApiId &&
                    outsiderBookstackApiSecret !in setOf(bookstackApiSecret,bookstackInternalToken)))) {
            "Fresh native auth grants must be strong and bcrypt-hashed before adapting Caddy"
        }
    }
}

/** Non-secret source authority for only the *implemented* managed control/device API.
 * The native server is still required to start, verify issuer/CID and read back each route.
 */
internal data class FreshControlIngressSource(val generation: String, val grantFile: ActivationInput,
    val ntfyGrantFile: ActivationInput, val managedBrokerHost: ManagedBrokerHostBinding) {
    fun validate(spec: PrivateDeploymentSpec, native: FreshNativeIngressGrants) {
        // Graph input rendering reconstructs its own pending-r9 spec without a
        // controller pin; the sealed assembly separately verifies that pin.
        require(generation == spec.name.substring(0,14) &&
            spec.fragmentBinding?.recipe == CanonicalSharedYamlGraph.RECIPE &&
            managedBrokerHost.authenticationMode == "pi-openai-oauth-v2" &&
            grantFile.path == "/mnt/media/p0-v3/release-bootstrap-anchors/ingress/fresh/$generation.json" &&
            ntfyGrantFile.path == "/mnt/media/p0-v3/release-bootstrap-anchors/identity/ntfy-fresh/$generation.json" &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(grantFile.path),4096)) == grantFile.sha256 &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(ntfyGrantFile.path),4096)) == ntfyGrantFile.sha256 &&
            native.ntfySsoToken != null) { "Managed control/API route has no original protected source authority" }
        require(FreshNativeIngressCustody.qbittorrentPassword(Path.of(grantFile.path),native).matches(Regex("[a-f0-9]{64}")))
        val ntfy = FreshNtfyCustody.issueOnce(Path.of(ntfyGrantFile.path),
            Path.of("/home/gerald/p0_v3/.coord/rapid-completion/caddy-config-check-bin-142")) {
            error("Existing generation grant cannot be reissued")
        }
        require(ntfy.ssoToken == native.ntfySsoToken && spec.processes.any { it.id == "caddy" &&
            it.controlSocketMount?.let { mount -> mount.target == "/run/p0-control" &&
                mount.source == GenerationRuntime.BASE.resolve(generation).resolve("managed/control/run").toString() } == true }) {
            "Managed control HTTP socket is not the exact graph-mounted original"
        }
    }
}

internal object CanonicalGraphCaddyfile {
    /** Live native grants are never copied from an offline fixture. Adapt the
     * graph with the SHA-pinned CLI in a private temporary directory, with no
     * server start, network listener or token on argv. The resulting JSON is a
     * sealed runtime input and still requires native CA/effective readback. */
    fun adaptFresh(manifest: CanonicalSharedManifest, spec: PrivateDeploymentSpec,
        native: FreshNativeIngressGrants, binary: Path, requireFeatureClosure: Boolean = false,
        controlSource: FreshControlIngressSource? = null): String {
        if (requireFeatureClosure) require(native.ntfySsoToken != null && native.bookstackApiId != null &&
            native.bookstackApiSecret != null) {
            "Fresh ntfy and proposed BookStack API credentials must be source-bound before adaptation; native enrollment/readback occurs after application startup"
        }
        if (requireFeatureClosure) {
            controlSource?.validate(spec,native)
            val missing = requireNotNull(manifest.integratedReference).modules
                .flatMap { it.privateRoutes }.filter { route ->
                    route.policy == "FOLDED" && route.special != "kopia" ||
                        // Only the exact graph-mounted broker-supervised HTTP adjunct with
                        // original protected grant binding can back these typed endpoints.
                        route.special in setOf("controller", "agent-api") && controlSource == null ||
                        route.special == "finance" && route.process != "firefly-sso" ||
                        route.special == "finance-importer" && route.process != "firefly-importer-sso"
                }.map { it.label }.toSet()
            require(missing.isEmpty()) {
                "Source-only Caddy adaptation is not full feature closure: ${missing.sorted()}"
            }
        }
        require(Files.isRegularFile(binary, NOFOLLOW_LINKS) && !Files.isSymbolicLink(binary) &&
            ReleaseLocks.sha256(Files.readAllBytes(binary)) ==
                "678ade3bfc088749c81a681adc603333ee0bb023b6a6cfe3c0f58bef8ff854e9")
        val source = render(manifest, spec, native)
        val root = Files.createTempDirectory("p0-r9-native-caddy-", PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------")))
        try {
            val file = root.resolve("Caddyfile")
            Files.newByteChannel(file, setOf(java.nio.file.StandardOpenOption.CREATE_NEW,
                java.nio.file.StandardOpenOption.WRITE), PosixFilePermissions.asFileAttribute(
                    PosixFilePermissions.fromString("rw-------"))).use { channel ->
                val buffer = java.nio.ByteBuffer.wrap(source.toByteArray())
                while (buffer.hasRemaining()) channel.write(buffer)
            }
            val cmd = ProcessBuilder(binary.toString(), "adapt", "--config", file.toString(),
                "--adapter", "caddyfile").start()
            try {
                val bytes = cmd.inputStream.readNBytes(1_048_577)
                require(bytes.size in 5000..1_048_576 && cmd.waitFor(30, TimeUnit.SECONDS) && cmd.exitValue() == 0) {
                    "Fresh Caddy CLI adaptation failed; no source is sealed"
                }
                val json = bytes.toString(Charsets.UTF_8)
                val structure = Json.parseToJsonElement(json).jsonObject
                val hostSet = structure.getValue("apps").jsonObject.getValue("http").jsonObject
                    .getValue("servers").jsonObject.values.flatMap { server -> server.jsonObject
                        .getValue("routes").jsonArray.flatMap { route -> route.jsonObject["match"]?.jsonArray
                            ?.flatMap { it.jsonObject["host"]?.jsonArray?.map { h -> h.jsonPrimitive.content }.orEmpty() }
                            .orEmpty() } }.toSet()
                require(hostSet == requireNotNull(manifest.integratedReference).modules.flatMap {
                    it.privateRoutes.map(CanonicalIngressRoute::host)
                }.toSet() && native.bookstackInternalToken in json && native.qbittorrentBasicHash in json &&
                    "127.0.0.1:2019" in json) { "Adapted fresh-native ingress diverges from module route/credential graph" }
                return json
            } finally {
                if (cmd.isAlive) cmd.destroyForcibly()
                cmd.errorStream.close()
            }
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    /** The exact ownership/dashboard projection of the SAME module route graph.
     * No caller-supplied second host inventory or invented process is accepted.
     * Control-only/no-HTTP declarations have no application owner entry. */
    fun siteRoutes(manifest: CanonicalSharedManifest, spec: PrivateDeploymentSpec): List<SiteRouteOwner> {
        require(manifest.revision in setOf(9, 10) && spec.fragmentBinding?.recipe == CanonicalSharedYamlGraph.RECIPE)
        val candidates = requireNotNull(manifest.integratedReference).modules.flatMap { module ->
            module.privateRoutes.mapNotNull { route -> route.process?.let { process ->
                require(spec.processes.any { it.id == process && !it.oneShot && route.network in it.networks })
                SiteRouteOwner(route.host, module.id, "${spec.name}/$process", requireNotNull(route.port))
            } }
        }
        require(candidates.groupBy { it.host }.values.all { it.distinct().size == 1 })
        return candidates.distinct().sortedBy { it.host }
    }
    /** Packaged adapter output may be used only if the SAME selected graph
     * reproduces the exact source hash and all effective host matchers. */
    fun adaptedJson(manifest: CanonicalSharedManifest, spec: PrivateDeploymentSpec): String {
        val source = render(manifest, spec)
        val expectedSource = if (manifest.revision == 10) PackagedGraphFragment.r10CaddySourceHash()
            else PackagedGraphFragment.r9CaddySourceHash()
        require(ReleaseLocks.sha256(source.toByteArray()) == expectedSource) {
            "Module ingress graph differs from adapted Caddyfile provenance"
        }
        val json = (if (manifest.revision == 10) PackagedGraphFragment.r10CaddyJson()
            else PackagedGraphFragment.r9CaddyJson()).toString(Charsets.UTF_8)
        val parsed = Json.parseToJsonElement(json).jsonObject
        val hosts = parsed.getValue("apps").jsonObject.getValue("http").jsonObject
            .getValue("servers").jsonObject.values.flatMap { server -> server.jsonObject
                .getValue("routes").jsonArray.flatMap { route -> route.jsonObject["match"]?.jsonArray
                    ?.flatMap { it.jsonObject["host"]?.jsonArray?.map { host -> host.jsonPrimitive.content }.orEmpty() }
                    .orEmpty() } }.toSet()
        require(hosts == requireNotNull(manifest.integratedReference).modules.flatMap {
            it.privateRoutes.map(CanonicalIngressRoute::host)
        }.toSet() && parsed.getValue("admin").jsonObject.getValue("listen").jsonPrimitive.content == "127.0.0.1:2019") {
            "Adapted route host set diverges from module graph"
        }
        return json
    }
    private val host = Regex("(?:[a-z0-9-]+\\.)+[a-z0-9-]+")
    private val id = Regex("[a-z][a-z0-9-]{0,39}")
    private val groups = Regex("[a-z]+(?:\\|[a-z]+)*")
    private const val deny = "respond 503"
    /** Pure generator. Only a non-public Caddy CLI may adapt and validate its result. */
    fun render(manifest: CanonicalSharedManifest, spec: PrivateDeploymentSpec,
        native: FreshNativeIngressGrants? = null): String {
        require(manifest.revision in setOf(9, 10) && manifest.scope == "full-private" &&
            spec.fragmentBinding?.recipe == CanonicalSharedYamlGraph.RECIPE &&
            spec.fragmentBinding.phase in setOf("INSTALL", "RESTORE"))
        val modules = requireNotNull(manifest.integratedReference).modules
        val declarations = modules.flatMap { module -> module.privateRoutes.map { module to it } }
        val oldLabels = manifest.integratedReference.routes.map { it.label }.toSet()
        require(declarations.size in 45..80 && declarations.map { it.second.label }.distinct().size == declarations.size &&
            declarations.map { it.second.label }.toSet().containsAll(oldLabels)) {
            "Every OLD host must have an explicit fresh module disposition"
        }
        val processes = spec.processes.filterNot { it.oneShot }.associateBy { it.id }
        val caddy = processes.getValue("caddy")
        require(caddy.controlSocketMount?.let { mount ->
            mount.source == GenerationRuntime.BASE.resolve(spec.name.substring(0, 14))
                .resolve("managed/control/run").toString() && mount.target == "/run/p0-control"
        } == true) { "Controller/device routes require the selected managed host broker socket directory" }
        require(caddy.files.any { it.file == "identity-web.pem" && it.target == "/run/secrets/identity-web.pem" } &&
            caddy.files.any { it.file == "identity-web-key.pem" && it.target == "/run/secrets/identity-web-key.pem" } &&
            caddy.networkAliases.contains(RuntimeNetworkAlias("identity-web", "auth.datamancy.net"))) {
            "Fresh OIDC issuer must resolve to the same generation's trusted ingress certificate"
        }
        val ingressTrust=CanonicalPrivateIngressTrust.project(manifest,spec)
        if (declarations.any { it.second.special == "finance" }) {
            val transport = processes.getValue("firefly-native-api")
            val browser = processes.getValue("firefly-sso")
            val importer = processes.getValue("firefly-importer")
            val importerBrowser = processes.getValue("firefly-importer-sso")
            require(browser.networks.contains("firefly-web") && browser.networks.contains("identity-web") &&
                browser.readinessHttpPort == 4180 && browser.image == importerBrowser.image &&
                importerBrowser.networks.contains("firefly-importer-web") && importerBrowser.readinessHttpPort == 4180 &&
                importer.image != processes.getValue("firefly").image &&
                importer.networks.contains("finance-api") && transport.networks.contains("finance-api") &&
                transport.networks.contains("firefly-web") && transport.readinessHttpPort == 8081 &&
                transport.image == processes.getValue("caddy").image &&
                transport.files.any { it.file == "finance-native-api.caddyfile" &&
                    it.target == "/run/secrets/finance-native-api.caddyfile" }) {
                "Finance native dispatch requires the selected, owned, scoped transport"
            }
        }
        val prepared = declarations.map { (module, route) ->
            require(route.host == "datamancy.net" || route.host.endsWith(".datamancy.net") &&
                route.host.matches(host) && route.host.length <= 128)
            require(route.policy in setOf("OPEN", "APP", "AUTH", "GROUP", "NATIVE", "REDIRECT", "FOLDED", "CONTROL"))
            require(route.groups == null || route.policy == "GROUP" && route.groups.matches(groups))
            if (route.process != null) {
                val process = processes.getValue(route.process)
                require(process.id.matches(id) && route.port in 1..65535 &&
                    route.network in process.networks && route.network in caddy.networks &&
                    // Never give Caddy a data, SQL, admin or job network.
                    (route.network!!.endsWith("-web") || route.network in setOf("identity-web", "ingress-control")) &&
                    (module.id == "forgejo" && process.id == "forgejo" ||
                        module.id == "keycloak-auth-gateway" && process.id == "auth-gateway" ||
                        CanonicalSharedYamlGraph.pendingR9OwnerFor(process.id) == module.id)) {
                    "Module ${module.id} has no selected executable ingress peer for ${route.label}"
                }
                require((route.port == process.readinessHttpPort || route.port == 8443 && route.tlsName != null ||
                    process.id == "ntfy" && route.port == 8080 &&
                        process.command == listOf("serve", "--config=/run/secrets/ntfy.yml") &&
                        process.files.any { it.file == "ntfy-config.yml" && it.target == "/run/secrets/ntfy.yml" } ||
                    process.id == "opensearch" && route.port == 9200) &&
                    (route.port != 8443 || route.tlsName != null && route.caInput != null) &&
                    (route.tlsName == null) == (route.caInput == null) &&
                    (route.tlsName == null || route.tlsName.matches(host) || route.tlsName.matches(id)) &&
                    (route.caInput == null || route.caInput.matches(Regex("[a-z][a-z0-9-]*-ca\\.pem"))))
            } else require(route.port == null && route.network == null && route.tlsName == null &&
                route.policy in setOf("FOLDED", "CONTROL", "REDIRECT"))
            route
        }
        // Aliases to exactly the same app+policy are folded into one site; the
        // reference labels remain independently checked above.
        val hosts = prepared.groupBy { it.host }
        require(hosts.values.all { same -> same.map {
            listOf(it.process, it.network, it.port?.toString(), it.policy, it.special, it.tlsName, it.caInput, it.groups)
        }.distinct().size == 1 }) { "Conflicting alias ownership" }
        fun upstream(r: CanonicalIngressRoute, preserveNativeAuthorization: Boolean = false): String {
            val dial = "${r.process}:${r.port}"
            if (r.special == "ntfy" && !preserveNativeAuthorization && native?.ntfySsoToken != null)
                return "reverse_proxy $dial {\n    header_up Authorization \"Bearer ${native.ntfySsoToken}\"\n}"
            return if (r.tlsName == null) "reverse_proxy $dial" else """
                reverse_proxy https://$dial {
                    transport http {
                        tls_server_name ${r.tlsName}
                        tls_trusted_ca_certs /run/secrets/${r.caInput}
                        ${if (r.special == "search") "tls_client_auth /run/secrets/opensearch-reader.pem /run/secrets/opensearch-reader-key.pem" else ""}
                    }
                }
            """.trimIndent()
        }
        fun clearHeaders() = listOf("Remote-User", "Remote-Groups", "Remote-Name", "Remote-Email",
            "Remote_User", "Remote_Groups", "Remote_Name", "Remote_Email",
            "X-Remote-User", "X-Remote-Groups", "X-Remote-Name", "X-Remote-Email",
            "X_Remote_User", "X_Remote_Groups", "X_Remote_Name", "X_Remote_Email",
            "X-Webservices-SSO-Subject", "X-Webservices-SSO-Issuer",
            "X_Webservices_SSO_Subject", "X_Webservices_SSO_Issuer",
            "X-Auth-Request-User", "X-Auth-Request-Groups", "X-Auth-Request-Email",
            "X_Auth_Request_User", "X_Auth_Request_Groups", "X_Auth_Request_Email",
            "X-Trusted-Proxy-Secret", "X_Trusted_Proxy_Secret",
            "X-Forwarded-User", "X_Forwarded_User", "X-Forwarded-Email", "X_Forwarded_Email")
            .joinToString("") { "request_header -$it\n" } + "\n"
        fun groupRoute(r: CanonicalIngressRoute): String = """
            import p0_auth
            @permitted {
                header_regexp Remote-Groups (^|.*[,\s])(${r.groups})([,\s].*|${'$'})
                header_regexp X-Webservices-SSO-Subject ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}${'$'}
            }
            handle @permitted {
                ${upstream(r)}
            }
            respond 403
        """.trimIndent()
        val out = StringBuilder("""
            {
                admin 127.0.0.1:2019
                auto_https disable_redirects
            }
            (p0_auth) {
                # Auth is rechecked on every request; this does not promise immediate
                # Keycloak membership revocation during a still-valid cached session.
                ${clearHeaders()}
                request_header -Authorization
                forward_auth auth-gateway:4180 {
                    uri /oauth2/auth
                    copy_headers X-Auth-Request-Preferred-Username>Remote-User X-Auth-Request-User>X-Webservices-SSO-Subject X-Auth-Request-Groups>Remote-Groups X-Auth-Request-Email>Remote-Email
                    @unauth status 401 403
                    handle_response @unauth {
                        rewrite * /oauth2/start
                        reverse_proxy auth-gateway:4180 {
                            header_up X-Auth-Request-Redirect {scheme}://{host}{orig_uri}
                        }
                    }
                }
            }
        """.trimIndent() + "\n")
        for ((name, selected) in hosts.toSortedMap()) {
            val r = selected.first()
            val trust=ingressTrust.getValue(name)
            out.append("\nhttps://$name {\n    " +
                (if (trust.mode == PrivateIngressTrustMode.GRAPH_ISSUED_LEAF)
                    "tls ${requireNotNull(trust.caddyLeafTarget)} ${requireNotNull(trust.caddyKeyTarget)}"
                else "tls internal") + "\n")
            out.append("    route {\n")
            when (r.policy) {
                "FOLDED" -> out.append("        $deny\n")
                "REDIRECT" -> out.append("        redir https://${if (r.special == "apex-redirect") "datamancy.net" else "portal.datamancy.net"}{uri} 308\n")
                "CONTROL" -> when (r.special) {
                    "auth-gateway" -> out.append("        ${clearHeaders()}        ${upstream(r)}\n")
                    "onboarding" -> out.append("""
                        @start path /
                        redir @start https://keycloak-auth.datamancy.net/oauth2/start?rd=https%3A%2F%2Fonboarding.datamancy.net%2Fstatus 302
                        @status path /status
                        handle @status {
                            import p0_auth
                            @onboarded_subject header_regexp X-Webservices-SSO-Subject ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}${'$'}
                            header @onboarded_subject Content-Type application/json
                            respond @onboarded_subject `{"identity":"authenticated","requiredActions":"native-readback-pending","next":"https://auth.datamancy.net/realms/p0v3/account/"}` 200
                            respond 403
                        }
                        respond 404
                    """.trimIndent().prependIndent("        ").plus("\n"))
                    "controller" -> out.append("""
                        import p0_auth
                        @control_owner {
                            header_regexp Remote-Groups (^|.*[,\s])(admins|operators|users)([,\s].*|${'$'})
                            header_regexp X-Webservices-SSO-Subject ^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}${'$'}
                        }
                        handle @control_owner {
                            @typed_control path /ops/status /ops/lane/start /ops/lane/stop /ops/device-tokens /ops/device-tokens/*
                            handle @typed_control {
                                reverse_proxy unix//run/p0-control/http.sock
                            }
                            respond 404
                        }
                        respond 403
                    """.trimIndent().prependIndent("        ").plus("\n"))
                    "agent-api" -> out.append("""
                        @device_api path /v1/models /v1/chat/completions
                        handle @device_api {
                            ${clearHeaders()}
                            request_header -Cookie
                            reverse_proxy unix//run/p0-control/http.sock
                        }
                        respond 404
                    """.trimIndent().prependIndent("        ").plus("\n"))
                    else -> out.append("        respond 404\n")
                }
                else -> {
                    // Exact native path dispatch precedes the browser SSO gate.
                    when (r.special) {
                        "huly" -> out.append("        @account path /_accounts /_accounts/* /auth/openid /auth/openid/callback\n        handle @account {\n            ${clearHeaders()}            ${upstream(r)}\n        }\n")
                        "seafile" -> out.append("        @integration path /seafhttp/* /onlyoffice/editor-callback /onlyoffice/editor-callback/*\n        handle @integration {\n            ${clearHeaders()}            ${upstream(r)}\n        }\n")
                        "jupyterhub" -> out.append("        @session path /hub/api/* /user/*\n        handle @session {\n            ${clearHeaders()}            ${upstream(r)}\n        }\n")
                        "homeassistant" -> out.append("        @webhook path /api/webhook/*\n        handle @webhook {\n            ${clearHeaders()}            ${upstream(r)}\n        }\n        @mobile header_regexp User-Agent \"Home Assistant/\"\n        handle @mobile {\n            ${clearHeaders()}            ${upstream(r)}\n        }\n        @external_auth query external_auth=1\n        handle @external_auth {\n            ${clearHeaders()}            ${upstream(r)}\n        }\n")
                        "grafana" -> out.append("        @assets path /public/* /public/build/* /public/img/* /public/plugins/* /public/app/*\n        handle @assets {\n            ${clearHeaders()}            ${upstream(r)}\n        }\n")
                        "ntfy" -> out.append("        @native_token header_regexp Authorization ^Bearer[[:space:]]+tk_[A-Za-z0-9]+${'$'}\n        handle @native_token {\n            ${clearHeaders()}            ${upstream(r, preserveNativeAuthorization = true)}\n        }\n")
                        "sogo" -> out.append("        redir / /SOGo/ 302\n")
                        "finance" -> out.append("""
                            @local_auth path /login /register /password/* /forgot-password /reset-password* /profile/change-password /profile/change-email /oauth/clients* /oauth/personal-access-tokens* /api/v1/cron*
                            respond @local_auth 403
                            handle /sso/logged-out {
                                respond "Finance cookies cleared; confirm native identity logout." 200
                            }
                            @logout path /sso/logout /oauth2/sign_out
                            handle @logout {
                                header +Set-Cookie "__Host-firefly_app=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
                                header +Set-Cookie "laravel_token=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
                                header +Set-Cookie "XSRF-TOKEN=; Path=/; Secure; SameSite=Lax; Max-Age=0"
                                rewrite * /oauth2/sign_out
                                ${clearHeaders()}
                                reverse_proxy firefly-sso:4180 {
                                    header_up X-Auth-Request-Redirect https://firefly-importer.datamancy.net/sso/finish-logout
                                }
                            }
                            @native_finance path /oauth/token /api/v1/*
                            handle @native_finance {
                                ${clearHeaders()}
                                reverse_proxy firefly-native-api:8081
                            }
                        """.trimIndent().prependIndent("        ").plus("\n"))
                        "finance-importer" -> out.append("""
                            @logout path /sso/logout /oauth2/sign_out
                            redir @logout https://firefly.datamancy.net/sso/logout 303
                            handle /sso/finish-logout {
                                header +Set-Cookie "__Host-firefly_importer_app=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0"
                                header +Set-Cookie "XSRF-TOKEN=; Path=/; Secure; SameSite=Lax; Max-Age=0"
                                rewrite * /oauth2/sign_out
                                ${clearHeaders()}
                                reverse_proxy firefly-importer-sso:4180 {
                                    header_up X-Auth-Request-Redirect https://auth.datamancy.net/realms/p0v3/protocol/openid-connect/logout?client_id=firefly-sso&post_logout_redirect_uri=https%3A%2F%2Ffirefly.datamancy.net%2Fsso%2Flogged-out
                                }
                            }
                        """.trimIndent().prependIndent("        ").plus("\n"))
                        "portal", "portal-apex" -> out.append("        @matrix_client path /.well-known/matrix/client\n        header @matrix_client Content-Type application/json\n        respond @matrix_client `{\"m.homeserver\":{\"base_url\":\"https://matrix.datamancy.net/\"},\"io.element.e2ee\":{\"default\":true},\"org.matrix.msc4143.rtc_foci\":[{\"type\":\"livekit\",\"livekit_service_url\":\"https://matrix-rtc.datamancy.net/livekit/jwt\"}]}` 200\n        @matrix_server path /.well-known/matrix/server\n        header @matrix_server Content-Type application/json\n        respond @matrix_server `{\"m.server\":\"matrix.datamancy.net:443\"}` 200\n")
                        "forgejo" -> out.append("        @token_api path_regexp token_api ^/api/v1/users/[^/]+/tokens/?${'$'}\n        respond @token_api 403\n")
                        "matrix", "matrix-api" -> out.append("        @admin path /_synapse/admin /_synapse/admin/*\n        respond @admin 404\n")
                    }
                    when (r.policy) {
                        "OPEN", "APP" -> out.append("        ${clearHeaders()}        ${upstream(r)}\n")
                        "GROUP" -> out.append("        ${groupRoute(r).prependIndent("        ")}\n")
                        "AUTH" -> out.append("        import p0_auth\n        ${upstream(r)}\n")
                        "NATIVE" -> when (r.special) {
                            "seafile-native" -> out.append("        @api path /api/* /api2/* /seafdav* /seafhttp/*\n        handle @api {\n            ${clearHeaders()}            ${upstream(r)}\n        }\n        respond 404\n")
                            "matrix-api" -> out.append("        @api path /_matrix/federation/* /_matrix/client/* /_matrix/media/*\n        handle @api {\n            ${clearHeaders()}            ${upstream(r)}\n        }\n        respond 404\n")
                            "home-native", "donetick-native", "matrix", "matrix-rtc" ->
                                out.append("        ${clearHeaders()}        ${upstream(r)}\n")
                            "ntfy-native" -> out.append("        @native_token header_regexp Authorization ^Bearer[[:space:]]+tk_[A-Za-z0-9]+${'$'}\n        handle @native_token {\n            ${clearHeaders()}            ${upstream(r, preserveNativeAuthorization = true)}\n        }\n        @native_basic header_regexp Authorization (?i)^Basic[[:space:]]\n        handle @native_basic {\n            ${clearHeaders()}            ${upstream(r, preserveNativeAuthorization = true)}\n        }\n        respond 401\n")
                            "qbittorrent-native" -> if (native == null) out.append("        $deny\n") else
                                out.append("        @api path /api/v2/*\n        handle @api {\n            ${clearHeaders()}            basic_auth bcrypt {\n                android-test-runner ${native.qbittorrentBasicHash}\n            }\n            ${upstream(r, preserveNativeAuthorization = true)}\n        }\n        respond 404\n")
                            "bookstack-api" -> if (native?.bookstackApiId == null || native.bookstackApiSecret == null)
                                out.append("        $deny\n") else out.append("        @internal_api {\n            path /api /api/*\n            header X-Internal-Token ${native.bookstackInternalToken}\n        }\n        handle @internal_api {\n            ${clearHeaders()}            request_header -X-Internal-Token\n            request_header -Authorization\n            reverse_proxy ${r.process}:${r.port} {\n                header_up Authorization \"Token ${native.bookstackApiId}:${native.bookstackApiSecret}\"\n            }\n        }\n        @api path /api /api/*\n        respond @api 403\n        respond 404\n")
                            else -> throw IllegalArgumentException("Missing reviewed native policy: ${r.special}")
                        }
                    }
                }
            }
            out.append("    }\n}\n")
        }
        return out.toString()
    }
}
