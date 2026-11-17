package net.datamancy.platform

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Flow
import java.util.concurrent.TimeUnit
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

internal data class CaddyReply(val status: Int, val body: ByteArray, val etag: String?)
internal fun interface CaddyTransport { fun exchange(method: String, path: String, etag: String?, body: ByteArray?): CaddyReply }

/** Fixed callback page contains no query reflection, token, redirect or success claim. The protected
 * browser wrapper captures URL code/state, never Caddy itself or a public evidence screenshot. */
internal fun operatorCallback(): JsonObject = buildJsonObject {
    put("handler", "static_response"); put("status_code", 200)
    put("headers", buildJsonObject {
        put("Content-Type", buildJsonArray { add("text/html; charset=utf-8") })
        put("Cache-Control", buildJsonArray { add("no-store") })
        put("Referrer-Policy", buildJsonArray { add("no-referrer") })
        put("Content-Security-Policy", buildJsonArray { add("default-src 'none'; frame-ancestors 'none'") })
    })
    put("body", "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Return to controller</title>" +
        "<p>Return to the protected controller to finish sign-in.</p></html>")
}

/** Bounded asynchronous subscriber: response body delivery is included in the request deadline. */
internal class BoundedCaddyBody(private val maximum: Int) : HttpResponse.BodySubscriber<ByteArray> {
    private val result = CompletableFuture<ByteArray>()
    private val bytes = java.io.ByteArrayOutputStream()
    private var subscription: Flow.Subscription? = null
    override fun getBody() = result
    override fun onSubscribe(value: Flow.Subscription) {
        if (subscription != null) { value.cancel(); return }
        subscription = value; value.request(1)
    }
    override fun onNext(items: List<ByteBuffer>) {
        if (result.isDone) return
        for (item in items) {
            if (item.remaining().toLong() + bytes.size() > maximum) {
                subscription?.cancel(); result.completeExceptionally(IllegalStateException("Caddy response exceeds bound")); return
            }
            val part = ByteArray(item.remaining()); item.get(part); bytes.write(part)
        }
        subscription?.request(1)
    }
    override fun onError(error: Throwable) { result.completeExceptionally(error) }
    override fun onComplete() { result.complete(bytes.toByteArray()) }
}

internal class LocalCaddyTransport(endpoint: String) : CaddyTransport {
    private val endpoint = URI.create(endpoint).also {
        require(it.scheme == "http" && it.host == "127.0.0.1" && it.port in 1024..65535 &&
            it.rawPath.isEmpty() && it.rawQuery == null && it.rawFragment == null && it.rawUserInfo == null) {
            "Explicit loopback-only Caddy admin endpoint required"
        }
    }
    private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
        .followRedirects(HttpClient.Redirect.NEVER).build()
    override fun exchange(method: String, path: String, etag: String?, body: ByteArray?): CaddyReply {
        require((method == "GET" && path == "/config/" && etag == null && body == null) ||
            (((method == "PATCH" && path.matches(Regex("/config/apps/http/servers/[a-z][a-z0-9-]{0,63}/routes"))) ||
                (method == "POST" && path == "/config/")) &&
                etag != null && etag.matches(Regex("\"/config/ [a-f0-9]{16}\"")) && body != null && body.size in 1..4 * 1024 * 1024))
        val request = HttpRequest.newBuilder(endpoint.resolve(path)).timeout(Duration.ofSeconds(30))
            .method(method, body?.let(HttpRequest.BodyPublishers::ofByteArray) ?: HttpRequest.BodyPublishers.noBody())
        if (etag != null) request.header("If-Match", etag).header("Content-Type", "application/json")
        val pending = client.sendAsync(request.build(), HttpResponse.BodyHandler { BoundedCaddyBody(4 * 1024 * 1024) })
        try {
            val reply = pending.get(30, TimeUnit.SECONDS)
            return CaddyReply(reply.statusCode(), reply.body(), reply.headers().firstValue("ETag").orElse(null))
        } catch (error: InterruptedException) {
            pending.cancel(true); Thread.currentThread().interrupt(); throw error
        } catch (error: Exception) { pending.cancel(true); throw IllegalStateException("Caddy admin exchange failed; do not replay a write", error) }
    }
}

@Serializable internal data class CaddySiteBinding(val site: String, val server: String, val endpoint: String, val approvedHosts: Set<String>)
@OptIn(ExperimentalSerializationApi::class)
@Serializable internal data class CaddyUpstream(val host: String, val dial: String,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val tlsServerName: String? = null,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val trustedCaFile: String? = null,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val trustedCaSha256: String? = null,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val forwardOriginalHost: Boolean = false)

/** Pinned native upstream TLS and forwarded public identity. The exact Host/SNI correction is
 * special to Hub: native nginx authenticates `hub` while CHProxy validates the public origin.
 * This never changes global DNS, disables TLS, or forwards an unapproved arbitrary Host. */
internal fun caddyOwnedUpstreamProxy(upstream: CaddyUpstream, stripControlCookie: Boolean): JsonObject = buildJsonObject {
    val nativePort = upstream.dial.substringAfterLast(':').toIntOrNull()
    require(((nativePort != 443 && nativePort != 8443) || upstream.tlsServerName != null) &&
        (upstream.tlsServerName == null) == (upstream.trustedCaFile == null) &&
        (upstream.tlsServerName == null) == (upstream.trustedCaSha256 == null) &&
        (upstream.tlsServerName == null || upstream.tlsServerName.matches(Regex("[a-z][a-z0-9.-]{0,62}")) &&
            upstream.trustedCaFile?.matches(Regex("/run/secrets/[a-z][a-z0-9-]{0,63}\\.pem")) == true &&
            upstream.trustedCaSha256?.matches(Regex("[a-f0-9]{64}")) == true) &&
        (upstream.host != "notebooks.datamancy.net" ||
            upstream.tlsServerName == "hub" && upstream.trustedCaFile == "/run/secrets/hub-ca.pem" &&
            upstream.forwardOriginalHost && upstream.dial.endsWith("-hub:8443")) &&
        (!upstream.forwardOriginalHost || upstream.host == "notebooks.datamancy.net")) {
        "A private HTTPS upstream must have exact CA/SNI, and Hub must preserve its approved public origin"
    }
    put("handler", "reverse_proxy")
    put("upstreams", buildJsonArray { add(buildJsonObject { put("dial", upstream.dial) }) })
    if (upstream.tlsServerName != null) put("transport", buildJsonObject {
        put("protocol", "http")
        put("tls", buildJsonObject {
            put("server_name", upstream.tlsServerName)
            put("ca", buildJsonObject { put("provider", "file")
                put("pem_files", buildJsonArray { add(requireNotNull(upstream.trustedCaFile)) }) })
        })
    })
    if (stripControlCookie || upstream.forwardOriginalHost) put("headers", buildJsonObject {
        put("request", buildJsonObject {
            if (stripControlCookie) put("replace", buildJsonObject { put("Cookie", buildJsonArray {
                add(buildJsonObject { put("search_regexp", "^__Host-p0v3_acceptance=[a-f0-9]{64};[ \\t]*"); put("replace", "") })
                add(buildJsonObject { put("search_regexp", "(^|;[ \\t]*)__Host-p0v3_acceptance=[a-f0-9]{64}"); put("replace", "") })
            }) })
            if (upstream.forwardOriginalHost) put("set", buildJsonObject {
                put("Host", buildJsonArray { add("hub") })
                put("X-Forwarded-Host", buildJsonArray { add("notebooks.datamancy.net") })
                put("X-Forwarded-Proto", buildJsonArray { add("https") })
            })
        })
    })
}
internal fun auditNativeUpstreamCa(spec: PrivateDeploymentSpec, upstream: CaddyUpstream) {
    if (upstream.tlsServerName == null) {
        require(upstream.trustedCaFile == null && upstream.trustedCaSha256 == null)
        return
    }
    val target = requireNotNull(upstream.trustedCaFile)
    val sha = requireNotNull(upstream.trustedCaSha256)
    val file = spec.processes.single { it.id == "caddy" }.files.single { it.target == target }.file
    val original = ReleasePrivateFiles.read(PrivateDeployment.BASE.resolve(spec.name).resolve(file), 65536)
    require(ReleaseLocks.sha256(original) == sha &&
        original.decodeToString(throwOnInvalidSequence = true).contains("-----BEGIN CERTIFICATE-----")) {
        "Native upstream TLS trust must be an immutable generation-sealed Caddy CA input"
    }
}

@Serializable internal data class CaddyChangeIntent(val schemaVersion: Int = 1, val operation: String, val bindingSha256: String,
    val beforeConfigurationSha256: String, val etag: String, val before: JsonObject?, val after: JsonObject?, val routes: JsonArray)
@Serializable internal data class CaddyChangeResult(val operation: String, val intentSha256: String,
    val status: String, val observedConfigurationSha256: String, val observedSlotSha256: String?)
internal data class CaddyObservation(val configuration: JsonObject, val etag: String, val routes: JsonArray, val slot: JsonObject?)

/** One owned route group, whole-configuration ETag compare-and-swap. Never changes listeners, issuers or unrelated routes.
 * This is an actuator, not activation authority. Its caller must hold release/activation authority for public effects.
 * Failed writes retain a global per-site pending claim; reconciliation observes and never resends the PATCH.
 */
internal class TransactionalCaddy(private val root: Path, private val binding: CaddySiteBinding,
    private val transport: CaddyTransport, private val upstreamAudit: ((CaddyUpstream) -> Unit)? = null) {
    companion object {
        private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
        private val slug = Regex("[a-z][a-z0-9-]{0,63}")
        private val hex = Regex("[a-f0-9]{64}")
        private val operationId = Regex("r-[a-f0-9]{12}")
        private fun canonical(value: JsonElement): JsonElement = when (value) {
            is JsonObject -> JsonObject(value.toSortedMap().mapValues { canonical(it.value) })
            is JsonArray -> JsonArray(value.map(::canonical))
            else -> value
        }
        fun digest(value: JsonElement) = ReleaseLocks.sha256(canonical(value).toString().toByteArray())
        fun inRuntime(root: Path, binding: CaddySiteBinding, spec: PrivateDeploymentSpec, fingerprint: String): TransactionalCaddy {
            require(slug.matches(binding.site) && root == Path.of("/mnt/media/p0-v3/caddy-transactions").resolve(binding.site))
            NamespaceCaddyTransport.checkBinding(binding, spec)
            return TransactionalCaddy(root, binding, NamespaceCaddyTransport.real(spec, fingerprint),
                { upstream -> auditNativeUpstreamCa(spec, upstream) })
        }
        fun real(root: Path, binding: CaddySiteBinding): TransactionalCaddy {
            require(slug.matches(binding.site) && root == Path.of("/mnt/media/p0-v3/caddy-transactions").resolve(binding.site)) {
                "Canonical per-site Caddy journal required; pending operations cannot be bypassed with a new directory"
            }
            return TransactionalCaddy(root, binding, LocalCaddyTransport(binding.endpoint))
        }
    }
    init {
        require(slug.matches(binding.site) && slug.matches(binding.server) && binding.approvedHosts.size in 1..64 &&
            binding.approvedHosts.all { AcmePreflight.hostPattern.matches(it) && it.length <= 253 && it.split('.').all { label -> label.length <= 63 } }) {
            "Exact approved datamancy.net subdomains required; no apex or wildcard"
        }
        val endpoint = URI.create(binding.endpoint)
        require(endpoint.scheme == "http" && endpoint.host == "127.0.0.1" && endpoint.port in 1024..65535 &&
            endpoint.rawPath.isEmpty() && endpoint.rawQuery == null && endpoint.rawUserInfo == null && endpoint.rawFragment == null)
    }
    private val slotId get() = "p0v3-${binding.site}"
    private fun bindingBytes() = json.encodeToString(binding.copy(approvedHosts = binding.approvedHosts.toSortedSet())).toByteArray()
    private fun <T> locked(action: () -> T): T = ReleasePrivateFiles.locked(root) {
        val path = root.resolve("binding.json"); val bytes = bindingBytes()
        if (Files.exists(path, NOFOLLOW_LINKS)) require(ReleasePrivateFiles.read(path).contentEquals(bytes)) { "Foreign Caddy site journal" }
        else ReleasePrivateFiles.save(path, bytes)
        action()
    }
    private fun observe(): CaddyObservation {
        val reply = transport.exchange("GET", "/config/", null, null)
        require(reply.status == 200 && reply.body.size in 1..4 * 1024 * 1024 &&
            reply.etag?.matches(Regex("\"/config/ [a-f0-9]{16}\"")) == true) { "Bounded Caddy configuration with root ETag required" }
        val config = json.parseToJsonElement(reply.body.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val server = config.getValue("apps").jsonObject.getValue("http").jsonObject.getValue("servers").jsonObject
            .getValue(binding.server).jsonObject
        require(server["logs"]?.jsonObject?.get("should_log_credentials") != JsonPrimitive(true)) { "Caddy credential logging must remain disabled" }
        val routes = server.getValue("routes").jsonArray
        require(routes.size <= 256)
        val slots = routes.map { it.jsonObject }.filter { it["@id"] == JsonPrimitive(slotId) }
        require(slots.size <= 1) { "Duplicate owned Caddy route group" }
        return CaddyObservation(config, requireNotNull(reply.etag), routes, slots.singleOrNull())
    }
    /** One read-only native observation binds the whole configuration and owned route
     * group to the same Caddy response. No site journal write or route publication. */
    fun observeOriginalRoute(): Pair<String, String?> = observe().let { digest(it.configuration) to it.slot?.let(::digest) }
    /** Read-only observation, usable by activation admission; does not enroll or mutate Caddy. */
    fun observeSlotSha256(): String? = observe().slot?.let(::digest)
    fun observeConfigurationSha256(): String = digest(observe().configuration)
    /** Reject an open or hand-modified group even if its bytes were presented as a restricted binding. */
    fun observeRestrictedSlotSha256(generation: String, upstreams: List<CaddyUpstream>): String {
        val slot = requireNotNull(observe().slot)
        val handler = slot.getValue("handle").jsonArray.single().jsonObject
        val operation = handler.getValue("@id").jsonPrimitive.content.removePrefix("$slotId-")
        val pattern = handler.getValue("routes").jsonArray.first().jsonObject.getValue("match").jsonArray.single().jsonObject
            .getValue("header_regexp").jsonObject.getValue("Cookie").jsonObject.getValue("pattern").jsonPrimitive.content
        val token = pattern.substringAfter("__Host-p0v3_acceptance=", "").substringBefore("(;|$)")
        require(hex.matches(token) && slot == revision(operation, generation, upstreams, token)) { "Exact restricted route revision required" }
        return digest(slot)
    }

    private fun checkUnrelated(route: JsonObject) {
        val matches = route["match"]?.jsonArray
        if (matches != null) {
            require(matches.isNotEmpty() && matches.all { match ->
                val hosts = match.jsonObject["host"]?.jsonArray
                hosts != null && hosts.isNotEmpty() && hosts.all { host ->
                    val name = host.jsonPrimitive.content
                    name.matches(Regex("[a-z0-9.-]+")) && name !in binding.approvedHosts
                }
            }) { "Overlapping or unbounded unrelated route; no implicit adoption" }
        } else {
            // Adapted Caddyfiles may wrap host-constrained routes in a subroute. No catch-all handlers allowed.
            val handlers = route.getValue("handle").jsonArray
            require(handlers.size == 1 && handlers.single().jsonObject["handler"] == JsonPrimitive("subroute"))
            val children = handlers.single().jsonObject.getValue("routes").jsonArray
            require(children.isNotEmpty()); children.forEach { checkUnrelated(it.jsonObject) }
        }
    }
    private fun onboardingLanding(): JsonObject = buildJsonObject {
        put("handler", "static_response"); put("status_code", 200)
        put("headers", buildJsonObject { put("Content-Type", buildJsonArray { add("text/html; charset=utf-8") })
            put("Cache-Control", buildJsonArray { add("no-store") }) })
        put("body", "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Sign in</title>" +
            "<a href=\"https://auth.datamancy.net/realms/p0v3/account/\">Sign in with Keycloak</a></html>")
    }
    fun revision(operation: String, generation: String, upstreams: List<CaddyUpstream>, acceptanceToken: String?): JsonObject {
        require(operationId.matches(operation) && generation.matches(Regex("q-[a-f0-9]{12}")))
        require(upstreams.size == binding.approvedHosts.count { it != "start.datamancy.net" } &&
            upstreams.map { it.host }.toSet() == binding.approvedHosts - "start.datamancy.net" &&
            upstreams.all { it.dial.matches(Regex("p0v3-live-$generation-[a-z][a-z0-9-]{0,70}:[0-9]{1,5}")) && it.dial.substringAfterLast(':').toInt() in 1..65535 })
        require(acceptanceToken == null || hex.matches(acceptanceToken))
        upstreams.forEach { upstream ->
            caddyOwnedUpstreamProxy(upstream, true) // Preserve historical control-cookie strip bytes.
            upstreamAudit?.invoke(upstream) // Native V2 sealed CA ownership before any route CAS.
        }
        return buildJsonObject {
            put("@id", slotId); put("terminal", true)
            put("match", buildJsonArray { add(buildJsonObject { put("host", JsonArray(binding.approvedHosts.sorted().map(::JsonPrimitive))) }) })
            put("handle", buildJsonArray { add(buildJsonObject {
                put("handler", "subroute"); put("@id", "$slotId-$operation")
                put("routes", buildJsonArray {
                    for (host in binding.approvedHosts.sorted())
                        for (startPath in if (host == "start.datamancy.net")
                            listOf("/identity/operator/callback", "/") else listOf<String?>(null)) add(buildJsonObject {
                        put("match", buildJsonArray { add(buildJsonObject {
                            put("host", buildJsonArray { add(host) })
                            if (startPath != null) put("path", buildJsonArray { add(startPath) })
                            if (acceptanceToken != null && host != "start.datamancy.net") put("header_regexp", buildJsonObject {
                                put("Cookie", buildJsonObject { put("pattern", "(^|;[ \\t]*)__Host-p0v3_acceptance=$acceptanceToken(;|$)") })
                            })
                        }) })
                        put("handle", buildJsonArray { add(if (startPath == "/") onboardingLanding()
                            else if (startPath == "/identity/operator/callback") operatorCallback()
                            else caddyOwnedUpstreamProxy(upstreams.single { it.host == host }, true).let { proxy ->
                                if (CanonicalProtectedCaddyRoute.groupPolicy(host) != null)
                                    CanonicalProtectedCaddyRoute.guarded(host, generation, proxy)
                                else proxy
                            }
                        ) }); put("terminal", true)
                    })
                    if (acceptanceToken != null) add(buildJsonObject {
                        put("handle", buildJsonArray { add(buildJsonObject { put("handler", "static_response"); put("status_code", 503) }) }); put("terminal", true)
                    })
                })
            }) })
        }
    }
    fun replace(operation: String, expectedConfiguration: String, expectedSlot: String?, generation: String,
        upstreams: List<CaddyUpstream>, acceptanceToken: String?): CaddyChangeResult = locked {
        change(operation, expectedConfiguration, expectedSlot, revision(operation, generation, upstreams, acceptanceToken))
    }
    private fun change(operation: String, expectedConfiguration: String, expectedSlot: String?, after: JsonObject?): CaddyChangeResult {
        require(operationId.matches(operation) && hex.matches(expectedConfiguration) && (expectedSlot == null || hex.matches(expectedSlot)))
        require(!Files.exists(root.resolve("pending.json"), NOFOLLOW_LINKS)) { "Uncertain Caddy change retained; reconcile, never retry with another ID" }
        val current = observe()
        if ("start.datamancy.net" in binding.approvedHosts) {
            val appServer = current.configuration["apps"]?.jsonObject?.get("http")?.jsonObject?.get("servers")
                ?.jsonObject?.get(binding.server)?.jsonObject
            require(appServer != null && "logs" !in appServer) {
                "Operator PKCE callback query must not enter an enabled Caddy access log"
            }
        }
        require(digest(current.configuration) == expectedConfiguration && current.slot?.let(::digest) == expectedSlot) { "Caddy binding changed before cutover" }
        current.routes.filter { it != current.slot }.forEach { checkUnrelated(it.jsonObject) }
        val routes = current.routes.toMutableList()
        if (current.slot == null) { if (after != null) routes.add(0, after) }
        else { val index = routes.indexOf(current.slot); if (after == null) routes.removeAt(index) else routes[index] = after }
        val intent = CaddyChangeIntent(operation = operation, bindingSha256 = ReleaseLocks.sha256(bindingBytes()),
            beforeConfigurationSha256 = expectedConfiguration, etag = current.etag, before = current.slot, after = after, routes = JsonArray(routes))
        val bytes = json.encodeToString(intent).toByteArray(); val hash = ReleaseLocks.sha256(bytes)
        ReleasePrivateFiles.save(root.resolve("$operation.intent.json"), bytes)
        ReleasePrivateFiles.save(root.resolve("pending.json"), bytes)
        val response = transport.exchange("PATCH", "/config/apps/http/servers/${binding.server}/routes", current.etag, intent.routes.toString().toByteArray())
        check(response.status in 200..299) { "Caddy change not acknowledged; retained intent requires observation" }
        return complete(intent, hash, requireApplied = true)
    }
    private fun complete(intent: CaddyChangeIntent, hash: String, requireApplied: Boolean): CaddyChangeResult {
        val current = observe()
        val status = when (current.slot) {
            intent.after -> "applied"
            intent.before -> "not-applied"
            else -> error("Owned Caddy slot diverged; no overwrite or automatic rollback")
        }
        require(!requireApplied || status == "applied") { "Caddy acknowledged without desired configuration; reconcile" }
        val result = CaddyChangeResult(intent.operation, hash, status, digest(current.configuration), current.slot?.let(::digest))
        val path = root.resolve("${intent.operation}.result.json")
        if (Files.exists(path, NOFOLLOW_LINKS)) {
            val prior = json.decodeFromString<CaddyChangeResult>(ReleasePrivateFiles.read(path).decodeToString())
            require(prior.operation == result.operation && prior.intentSha256 == hash && prior.status == result.status && prior.observedSlotSha256 == result.observedSlotSha256)
        } else ReleasePrivateFiles.save(path, json.encodeToString(result).toByteArray())
        ReleasePrivateFiles.removeExact(root.resolve("pending.json"), json.encodeToString(intent).toByteArray())
        return result
    }
    fun reconcile(operation: String, expectedIntent: String): CaddyChangeResult = locked {
        require(operationId.matches(operation) && hex.matches(expectedIntent))
        val bytes = ReleasePrivateFiles.read(root.resolve("$operation.intent.json"))
        require(ReleaseLocks.sha256(bytes) == expectedIntent && ReleasePrivateFiles.read(root.resolve("pending.json")).contentEquals(bytes))
        val intent = json.decodeFromString<CaddyChangeIntent>(bytes.decodeToString())
        require(intent.schemaVersion == 1 && intent.operation == operation && intent.bindingSha256 == ReleaseLocks.sha256(bindingBytes()))
        complete(intent, expectedIntent, requireApplied = false)
    }
    /** Compare/observe rollback of this exact earlier change; never replaces the whole Caddy configuration. */
    fun revert(operation: String, priorOperation: String, priorIntent: String, expectedConfiguration: String): CaddyChangeResult = locked {
        require(operationId.matches(priorOperation) && hex.matches(priorIntent))
        val bytes = ReleasePrivateFiles.read(root.resolve("$priorOperation.intent.json"))
        require(ReleaseLocks.sha256(bytes) == priorIntent)
        val intent = json.decodeFromString<CaddyChangeIntent>(bytes.decodeToString())
        val result = json.decodeFromString<CaddyChangeResult>(ReleasePrivateFiles.read(root.resolve("$priorOperation.result.json")).decodeToString())
        require(intent.schemaVersion == 1 && intent.operation == priorOperation && result.operation == priorOperation &&
            intent.bindingSha256 == ReleaseLocks.sha256(bindingBytes()) && result.intentSha256 == priorIntent && result.status == "applied")
        change(operation, expectedConfiguration, intent.after?.let(::digest), intent.before)
    }
}

@OptIn(ExperimentalSerializationApi::class)
@Serializable internal data class InternalServiceBinding(val operation: String, val site: String,
    val generationId: String, val targetFingerprint: String, val frontendNetwork: String,
    val frontendAddress: String, val consumerAddresses: Map<String, String>, val server: String,
    val host: String, val upstreamDial: String, val upstreamTlsServerName: String,
    val originalCertificate: ActivationInput, val originalPrivateKey: ActivationInput,
    val certificateFile: String, val privateKeyFile: String,
    val originalUpstreamCa: ActivationInput, val upstreamCaFile: String,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val nativePublicCertificate: Boolean = false)
@Serializable internal data class InternalServiceIntent(val binding: InternalServiceBinding,
    val before: JsonObject, val after: JsonObject, val etag: String)
@Serializable internal data class InternalServiceResult(val operation: String, val intentSha256: String,
    val beforeSha256: String, val afterSha256: String)

internal fun internalRouteConsumers(site: String, method: String, path: String,
    members: Map<String, String>): Set<String> {
    if (site != "identity") return members.keys
    // MAS' reviewed upstream_oauth2 OIDC provider uses discovery, JWKS, token and
    // userinfo. BookStack PHP only discovery/JWKS/token; the historical auth gateway
    // has discovery/JWKS/token/userinfo, while Keykeeper retains its own
    // introspection/logout, never a broad discovery or userinfo capability.
    val relative = path.removePrefix("/realms/p0v3/protocol/openid-connect/")
    return when {
        method == "GET" && path == "/realms/p0v3/.well-known/openid-configuration" ->
            members.keys.intersect(setOf("mas", "bookstack-php", "auth-gateway"))
        method == "GET" && relative == "certs" -> members.keys.intersect(setOf("mas", "bookstack-php", "keykeeper", "auth-gateway"))
        method == "GET" && relative == "userinfo" -> members.keys.intersect(setOf("mas", "auth-gateway"))
        method == "POST" && relative == "token" -> members.keys.intersect(setOf("mas", "bookstack-php", "keykeeper", "auth-gateway"))
        method == "POST" && relative in setOf("token/introspect", "logout") -> members.keys.intersect(setOf("keykeeper"))
        else -> emptySet()
    }
}

/** An app-to-app Caddy listener is separate from public 443 and runner-only restore 443.
 * Only the actual sealed consumer process IPs, original Host/SNI and fixed native service
 * routes can use it. Upstream CA+name validation and native JWT/secret/signed URL remain required.
 * Generation-local alias and same-network membership come from the owned runtime graph.
 */
internal class InternalServiceRoutes(private val root: Path, private val binding: InternalServiceBinding,
    private val spec: PrivateDeploymentSpec, private val transport: CaddyTransport,
    private val frontendAddress: () -> String, private val consumerAddress: (String) -> String,
    private val certificateCheck: (ByteArray, String) -> Unit = { bytes, host ->
        val leaf = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(bytes.inputStream()) as java.security.cert.X509Certificate
        leaf.checkValidity()
        val identities = leaf.subjectAlternativeNames
        val names = identities?.filter { it[0] == 2 }?.map { it[1] as String }?.toSet()
        require(identities != null && identities.all { it[0] == 2 } &&
            names != null && names == setOf(host) && names.all(AcmePreflight.hostPattern::matches)) {
            "Original internal listener must have a valid exact nonwildcard hostname certificate"
        }
    },
    private val sealedInputRead: (String) -> ByteArray = { file ->
        ReleasePrivateFiles.read(PrivateDeployment.BASE.resolve(spec.name).resolve(file), 65536)
    },
    private val sourceLeafSha256: (ByteArray) -> String = { bytes ->
        val cert = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(bytes.inputStream())
        ReleaseLocks.sha256(cert.encoded)
    },
    private val publicLeafSha256: (String) -> String = { host -> observePublicCertificate(host).sha256 },
    private val nativeListenerAudit: (() -> Long)? = null) {
    private val json = Json { encodeDefaults = true }
    private val hex = Regex("[a-f0-9]{64}")
    init {
        PrivateDeployment.validate(spec)
        require(binding.operation.matches(Regex("r-[a-f0-9]{12}")) &&
            binding.generationId.matches(Regex("q-[a-f0-9]{12}")) &&
            binding.targetFingerprint.matches(hex) && spec.name.startsWith("${binding.generationId}-") &&
            spec.store == RuntimeStore.CANONICAL_V2 &&
            (if (binding.nativePublicCertificate) spec.ingress?.approvedHosts?.contains(binding.host) == true &&
                "ingress-egress" in spec.networks else spec.ingress == null &&
                "ingress-egress" !in spec.networks) &&
            binding.site in setOf("office", "identity") &&
            binding.frontendNetwork == (if (binding.site == "office") "onlyoffice-web" else "identity-web") &&
            binding.host == (if (binding.site == "office") "files.datamancy.net" else "auth.datamancy.net") &&
            binding.server == "p0v3-internal-${binding.site}-${binding.frontendNetwork}" &&
            binding.frontendAddress.matches(Regex("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) &&
            java.net.InetAddress.getByName(binding.frontendAddress).isSiteLocalAddress &&
            binding.frontendNetwork in spec.networks &&
            binding.consumerAddresses.isNotEmpty() && binding.consumerAddresses.size <= 4 &&
            (if (binding.site == "office")
                binding.consumerAddresses.keys == setOf("onlyoffice-docservice", "onlyoffice-front")
             else "keykeeper" in binding.consumerAddresses.keys &&
                binding.consumerAddresses.keys.all { it in setOf("keykeeper", "bookstack-php", "mas") }) &&
            binding.consumerAddresses.keys.all { id -> id != "caddy" &&
                id != (if (binding.site == "office") "seafile-files" else "keycloak") &&
                spec.processes.any { it.id == id && binding.frontendNetwork in it.networks }
            } && binding.consumerAddresses.values.toSet().size == binding.consumerAddresses.size &&
            binding.consumerAddresses.values.all { it.matches(Regex("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) &&
                java.net.InetAddress.getByName(it).isSiteLocalAddress && it != binding.frontendAddress } &&
            binding.upstreamTlsServerName == (if (binding.site == "office") "seafile-files" else "keycloak") &&
            binding.upstreamDial == "p0v3-live-${spec.name}-${binding.upstreamTlsServerName}:8443" &&
            listOf(binding.originalCertificate, binding.originalPrivateKey, binding.originalUpstreamCa)
                .all { it.sha256.matches(hex) } &&
            (if (binding.nativePublicCertificate) binding.certificateFile.isEmpty() &&
                binding.privateKeyFile.isEmpty() &&
                binding.upstreamCaFile.matches(Regex("/run/secrets/[a-z][a-z0-9-]{0,63}\\.pem"))
             else listOf(binding.certificateFile, binding.privateKeyFile, binding.upstreamCaFile).toSet().size == 3 &&
                listOf(binding.certificateFile, binding.privateKeyFile, binding.upstreamCaFile).all {
                    it.matches(Regex("/run/secrets/[a-z][a-z0-9-]{0,63}\\.pem"))
                })) {  "Internal route is not a fixed original-host, audited frontend network service" }
        val caddy = spec.processes.single { it.id == "caddy" }
        require(binding.frontendNetwork in caddy.networks &&
            "NET_BIND_SERVICE" in caddy.capabilities &&
            caddy.networks.none { it.endsWith("-data") || it.endsWith("-admin") } &&
            spec.processes.single { it.id == binding.upstreamTlsServerName }.networks.any {
                it in caddy.networks && it.endsWith("-web")
            } &&
            caddy.networkAliases.filter { it.network == binding.frontendNetwork }.map { it.host }.toSet() ==
                setOf(binding.host) && caddy.files.map { it.target }.containsAll(
                    if (binding.nativePublicCertificate) listOf(binding.upstreamCaFile)
                    else listOf(binding.certificateFile, binding.privateKeyFile, binding.upstreamCaFile)) &&
            spec.processes.filter { binding.frontendNetwork in it.networks }
                .map { it.id }.toSet() == binding.consumerAddresses.keys + "caddy" +
                spec.processes.filter { it.id == binding.upstreamTlsServerName &&
                    binding.frontendNetwork in it.networks }.map { it.id }.toSet()) {
            "Only exact native consumer process IDs and Caddy may occupy this frontend"
        }
    }
    private fun original(input: ActivationInput): ByteArray =
        ReleasePrivateFiles.read(Path.of(input.path), 65536).also {
            require(ReleaseLocks.sha256(it) == input.sha256) { "Original internal crypto input changed" }
        }
    private fun content(input: ActivationInput, target: String): ByteArray = original(input).also { bytes ->
        val runtimeFile = spec.processes.single { it.id == "caddy" }.files.single { it.target == target }
        require(sealedInputRead(runtimeFile.file).contentEquals(bytes)) {
            "Internal TLS identity/CA must be immutable original source input, not recreated"
        }
    }
    private fun route(method: String, path: String): JsonObject = buildJsonObject {
        put("terminal", true)
        put("match", buildJsonArray { add(buildJsonObject {
            put("host", buildJsonArray { add(binding.host) })
            put("method", buildJsonArray { add(method) })
            put("path", buildJsonArray { add(path) })
            val scopedConsumers = internalRouteConsumers(binding.site, method, path, binding.consumerAddresses)
            put("remote_ip", buildJsonObject {
                put("ranges", JsonArray(scopedConsumers.map { binding.consumerAddresses.getValue(it) }.sorted()
                    .map { JsonPrimitive("$it/32") }))
            })
        }) })
        put("handle", buildJsonArray { add(buildJsonObject {
            put("handler", "reverse_proxy")
            put("upstreams", buildJsonArray { add(buildJsonObject { put("dial", binding.upstreamDial) }) })
            put("transport", buildJsonObject {
                put("protocol", "http")
                put("tls", buildJsonObject {
                    put("server_name", binding.upstreamTlsServerName)
                    put("ca", buildJsonObject {
                        put("provider", "file")
                        put("pem_files", buildJsonArray { add(binding.upstreamCaFile) })
                    })
                })
            })
            if (binding.site == "office") put("headers", buildJsonObject { put("request", buildJsonObject {
                put("set", buildJsonObject { put("Host", buildJsonArray { add("seafile-files") }) })
            }) })
        }) })
    }
    private fun server(): JsonObject = buildJsonObject {
        put("@id", binding.server); put("listen", buildJsonArray { add("${binding.frontendAddress}:443") })
        put("strict_sni_host", true)
        put("automatic_https", buildJsonObject { put("disable", true) })
        put("tls_connection_policies", buildJsonArray { add(buildJsonObject {
            put("match", buildJsonObject { put("sni", buildJsonArray { add(binding.host) }) })
        }) })
        put("routes", buildJsonArray {
            if (binding.site == "office") {
                add(route("GET", "/seafhttp/files/*")); add(route("HEAD", "/seafhttp/files/*"))
                add(route("POST", "/onlyoffice/editor-callback/"))
            } else {
                if ("bookstack-php" in binding.consumerAddresses || "mas" in binding.consumerAddresses)
                    add(route("GET", "/realms/p0v3/.well-known/openid-configuration"))
                add(route("GET", "/realms/p0v3/protocol/openid-connect/certs"))
                if ("mas" in binding.consumerAddresses)
                    add(route("GET", "/realms/p0v3/protocol/openid-connect/userinfo"))
                for (path in listOf("/realms/p0v3/protocol/openid-connect/token/introspect",
                    "/realms/p0v3/protocol/openid-connect/token", "/realms/p0v3/protocol/openid-connect/logout"))
                    add(route("POST", path))
            }
            add(buildJsonObject { put("terminal", true); put("handle", buildJsonArray { add(buildJsonObject {
                put("handler", "static_response"); put("status_code", 403)
            }) }) })
        })
    }
    private fun config(before: JsonObject): JsonObject {
        fun obj(parent: JsonObject, key: String) = parent[key]?.jsonObject ?: JsonObject(emptyMap())
        fun set(parent: JsonObject, key: String, value: JsonElement) = JsonObject(parent + (key to value))
        val apps = obj(before, "apps"); val http = obj(apps, "http"); val servers = obj(http, "servers")
        val tls = obj(apps, "tls"); val certs = obj(tls, "certificates")
        val existing = certs["load_files"]?.jsonArray ?: JsonArray(emptyList())
        val certificate = buildJsonObject {
            put("certificate", binding.certificateFile); put("key", binding.privateKeyFile)
        }
        require(servers[binding.server] == null && existing.count { it == certificate } <= 1 &&
            servers.values.none { server -> server.jsonObject["listen"]?.jsonArray?.any {
                it.jsonPrimitive.content in setOf("${binding.frontendAddress}:443", ":443", "0.0.0.0:443", "[::]:443")
            } == true }) { "Internal Caddy cannot replace a public, runner or wildcard listener" }
        if (binding.nativePublicCertificate) {
            val automated = certs["automate"]?.jsonArray ?: JsonArray(emptyList())
            val policies = tls["automation"]?.jsonObject?.get("policies")?.jsonArray ?: JsonArray(emptyList())
            val ownedPolicies = policies.filter { policy -> policy.jsonObject["subjects"]?.jsonArray?.any {
                it.jsonPrimitive.content == binding.host } == true }
            require(binding.host in automated.map { it.jsonPrimitive.content } &&
                ownedPolicies.size == 1 && ownedPolicies.single().jsonObject["issuers"]?.jsonArray
                    ?.singleOrNull()?.jsonObject?.let { issuer ->
                        issuer["module"] == JsonPrimitive("acme") &&
                            issuer["ca"] == JsonPrimitive(AcmeEnvironment.PRODUCTION.directory)
                    } == true &&
                before["storage"]?.jsonObject?.let { storage ->
                    storage["module"] == JsonPrimitive("file_system") &&
                        storage["root"] == JsonPrimitive("/data/caddy")
                } == true &&
                servers.values.any { server -> server.jsonObject["listen"]?.jsonArray?.any {
                    val listen = it.jsonPrimitive.content
                    listen.endsWith(":443") && listen != "${binding.frontendAddress}:443" &&
                        listen !in setOf(":443", "0.0.0.0:443", "[::]:443")
                } == true }) { "Public source internal route requires its actual owned ACME policy and exact-IP public listener" }
        } else require(tls["automation"]?.jsonObject?.get("policies")?.jsonArray?.isEmpty() != false &&
            certs["automate"]?.jsonArray?.isEmpty() != false) {
            "Restored internal listener must use preserved original crypto without ACME"
        }
        val load = if (binding.nativePublicCertificate) existing
            else JsonArray(existing + if (certificate in existing) emptyList() else listOf(certificate))
        val nextCertificates = if (binding.nativePublicCertificate) certs else set(certs, "load_files", load)
        val nextApps = set(set(apps, "tls", set(tls, "certificates", nextCertificates)),
            "http", set(http, "servers", JsonObject(servers + (binding.server to server()))))
        return set(before, "apps", nextApps)
    }
    fun install(expectedSha256: String): InternalServiceResult {
        require(expectedSha256.matches(hex) && frontendAddress() == binding.frontendAddress &&
            binding.consumerAddresses.all { (id, address) -> consumerAddress(id) == address }) {
            "Private frontend/consumer IPs changed after generation binding"
        }
        val originalLeaf = if (binding.nativePublicCertificate) original(binding.originalCertificate)
            else content(binding.originalCertificate, binding.certificateFile)
        certificateCheck(originalLeaf, binding.host)
        if (binding.nativePublicCertificate) {
            original(binding.originalPrivateKey)
            require(publicLeafSha256(binding.host) == sourceLeafSha256(originalLeaf)) {
                "Canonical internal listener must reuse the currently live original public ACME leaf"
            }
        } else content(binding.originalPrivateKey, binding.privateKeyFile)
        val privateCa = content(binding.originalUpstreamCa, binding.upstreamCaFile)
        require(privateCa.decodeToString(throwOnInvalidSequence = true).contains("-----BEGIN CERTIFICATE-----")) {
            "Verified native HTTPS upstream requires original pinned CA"
        }
        val reply = transport.exchange("GET", "/config/", null, null)
        require(reply.status == 200 && reply.etag?.matches(Regex("\"/config/ [a-f0-9]{16}\"")) == true &&
            reply.body.size in 1..4 * 1024 * 1024)
        val before = json.parseToJsonElement(reply.body.decodeToString()).jsonObject
        require(TransactionalCaddy.digest(before) == expectedSha256)
        val after = config(before)
        val intent = InternalServiceIntent(binding, before, after, requireNotNull(reply.etag))
        val bytes = json.encodeToString(intent).encodeToByteArray()
        ReleasePrivateFiles.locked(root) {
            require(!Files.exists(root.resolve("internal.pending"), NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve("${binding.operation}.intent.json"), NOFOLLOW_LINKS))
            ReleasePrivateFiles.save(root.resolve("${binding.operation}.intent.json"), bytes)
            ReleasePrivateFiles.save(root.resolve("internal.pending"), bytes)
        }
        val applied = transport.exchange("POST", "/config/", reply.etag, after.toString().encodeToByteArray())
        require(applied.status in 200..299) { "Uncertain internal route; native read-only reconciliation required" }
        val observed = transport.exchange("GET", "/config/", null, null)
        require(observed.status == 200 &&
            json.parseToJsonElement(observed.body.decodeToString()).jsonObject == after &&
            frontendAddress() == binding.frontendAddress &&
            binding.consumerAddresses.all { (id, address) -> consumerAddress(id) == address }) {
            "Internal route changed or consumer network detached; retain uncertain intent"
        }
        nativeListenerAudit?.invoke()?.let { require(it > 1) { "Internal HTTPS listener namespace changed" } }
        val result = InternalServiceResult(binding.operation, ReleaseLocks.sha256(bytes), expectedSha256,
            TransactionalCaddy.digest(after))
        ReleasePrivateFiles.locked(root) {
            require(ReleasePrivateFiles.read(root.resolve("internal.pending")).contentEquals(bytes))
            ReleasePrivateFiles.save(root.resolve("${binding.operation}.result.json"), json.encodeToString(result).encodeToByteArray())
            ReleasePrivateFiles.removeExact(root.resolve("internal.pending"), bytes)
        }
        return result
    }
    /** A lost native POST acknowledgement is read back, never retried or treated as a callback success. */
    fun reconcile(expectedIntentSha256: String): InternalServiceResult {
        require(expectedIntentSha256.matches(hex) && frontendAddress() == binding.frontendAddress &&
            binding.consumerAddresses.all { (id, address) -> consumerAddress(id) == address })
        val bytes = ReleasePrivateFiles.locked(root) { ReleasePrivateFiles.read(root.resolve("internal.pending")) }
        require(ReleaseLocks.sha256(bytes) == expectedIntentSha256 &&
            ReleasePrivateFiles.read(root.resolve("${binding.operation}.intent.json")).contentEquals(bytes))
        val intent = json.decodeFromString<InternalServiceIntent>(bytes.decodeToString())
        require(intent.binding == binding)
        val observed = transport.exchange("GET", "/config/", null, null)
        require(observed.status == 200 && observed.body.size in 1..4 * 1024 * 1024)
        val current = json.parseToJsonElement(observed.body.decodeToString()).jsonObject
        require(current == intent.after) { "Internal native write is absent or foreign; keep uncertain intent, no replay" }
        nativeListenerAudit?.invoke()?.let { require(it > 1) { "Reconciled internal listener is not actually bound" } }
        val result = InternalServiceResult(binding.operation, expectedIntentSha256,
            TransactionalCaddy.digest(intent.before), TransactionalCaddy.digest(current))
        ReleasePrivateFiles.locked(root) {
            require(ReleasePrivateFiles.read(root.resolve("internal.pending")).contentEquals(bytes))
            ReleasePrivateFiles.save(root.resolve("${binding.operation}.result.json"), json.encodeToString(result).encodeToByteArray())
            ReleasePrivateFiles.removeExact(root.resolve("internal.pending"), bytes)
        }
        return result
    }
    companion object {
        fun real(root: Path, binding: InternalServiceBinding, target: PrivateDeploymentSpec): InternalServiceRoutes {
            require(root == Path.of("/mnt/media/p0-v3/internal-routes").resolve(binding.site)
                .resolve(binding.generationId).resolve(binding.frontendNetwork))
            privateControlDirectory(root.parent.parent.parent)
            privateControlDirectory(root.parent.parent)
            privateControlDirectory(root.parent)
            privateControlDirectory(root)
            return InternalServiceRoutes(root, binding, target,
                NamespaceCaddyTransport.real(target, binding.targetFingerprint),
                { NamespaceCaddyTransport.ownedProcessAddress(target, binding.targetFingerprint,
                    "caddy", binding.frontendNetwork) },
                { id -> NamespaceCaddyTransport.ownedProcessAddress(target, binding.targetFingerprint,
                    id, binding.frontendNetwork) },
                nativeListenerAudit = { NamespaceCaddyTransport.auditInternalListener(target, binding.targetFingerprint,
                    binding.frontendNetwork, binding.frontendAddress) })
        }
    }
}

@OptIn(ExperimentalSerializationApi::class)
@Serializable internal data class RestoredBridgeBinding(val operation: String, val site: String,
    val sourceGeneration: String, val targetGeneration: String, val targetFingerprint: String,
    val clientNetwork: String, val clientAddress: String, val allowedClients: Set<String>, val server: String,
    val quiesceOperation: String, val sourceStoppedProofSha256: String,
    val targetPrivateReadinessSha256: String, val originalHosts: Set<String>, val upstreams: List<CaddyUpstream>,
    val sourceCertificates: Map<String, ActivationInput>, val sourcePrivateKeys: Map<String, ActivationInput>,
    val certificateFiles: Map<String, String>, val keyFiles: Map<String, String>,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val nativeClientCapabilities: Set<String> = emptySet(),
    @EncodeDefault(EncodeDefault.Mode.NEVER) val qualifierClientInvocationId: String? = null,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val qualifierClientContainerId: String? = null,
    @EncodeDefault(EncodeDefault.Mode.NEVER) val qualifierClientAddress: String? = null)
@Serializable internal data class RestoredBridgeResult(val operation: String, val intentSha256: String,
    val action: String, val beforeSha256: String, val afterSha256: String)
@Serializable internal data class RestoredBridgeIntent(val binding: RestoredBridgeBinding, val action: String,
    val before: JsonObject, val after: JsonObject, val etag: String)
@Serializable internal data class BridgeResumeProof(val binding: RestoredBridgeBinding,
    val removal: RestoredBridgeResult, val isolationSha256: String, val proofSha256: String)

/** Private target Caddy 443 bridge: original Host/SNI + original certificate, without a cookie or public
 * host publication. Only a sealed, dedicated client network admits official UI journeys. The caller
 * must retain generation isolation locks through removal, target stop and source resume. */
internal class RestrictedRestoreBridge(private val root: Path, private val binding: RestoredBridgeBinding,
    private val spec: PrivateDeploymentSpec, private val transport: CaddyTransport,
    private val sourceStopped: () -> Boolean, private val targetIsolationProof: () -> String?,
    private val targetPrivateReadinessProof: () -> String?, private val clientAddressProof: () -> String,
    private val certificateCheck: (ByteArray, String, Set<String>) -> Unit = ::verifyBridgeCertificate,
    private val sealedInputRead: (String) -> ByteArray = { file ->
        ReleasePrivateFiles.read(PrivateDeployment.BASE.resolve(spec.name).resolve(file), 65536)
    }, private val nativeListenerAudit: (() -> Long)? = null) {
    private val json = Json { encodeDefaults = true }
    private val hash = Regex("[a-f0-9]{64}")
    private val id = "p0v3-${binding.site}-restore"
    init {
        PrivateDeployment.validate(spec)
        require(binding.operation.matches(Regex("r-[a-f0-9]{12}")) && binding.site.matches(Regex("[a-z][a-z0-9-]{0,39}")) &&
            binding.sourceGeneration.matches(Regex("q-[a-f0-9]{12}")) && binding.targetGeneration.matches(Regex("q-[a-f0-9]{12}")) &&
            binding.sourceGeneration != binding.targetGeneration && hash.matches(binding.targetFingerprint) &&
            binding.quiesceOperation.matches(Regex("r-[a-f0-9]{12}")) && hash.matches(binding.sourceStoppedProofSha256) &&
            hash.matches(binding.targetPrivateReadinessSha256) &&
            binding.originalHosts.isNotEmpty() && binding.originalHosts.size <= 64 &&
            binding.originalHosts.all(AcmePreflight.hostPattern::matches) &&
            (binding.allowedClients.isNotEmpty() || binding.nativeClientCapabilities == setOf("rss-mastodon")) &&
            binding.allowedClients.all { it.matches(Regex("[a-z][a-z0-9-]{0,39}")) } &&
            binding.nativeClientCapabilities.all { it == "rss-mastodon" } &&
            ((binding.qualifierClientInvocationId == null && binding.qualifierClientContainerId == null &&
                binding.qualifierClientAddress == null) ||
                binding.qualifierClientInvocationId?.matches(Regex("[a-z][a-z0-9-]{0,95}")) == true &&
                binding.qualifierClientContainerId?.matches(hash) == true &&
                binding.qualifierClientAddress?.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) == true &&
                binding.qualifierClientAddress != binding.clientAddress &&
                binding.nativeClientCapabilities.isEmpty()) &&
            binding.clientNetwork.matches(Regex("[a-z][a-z0-9-]{0,39}")) &&
            binding.clientAddress.matches(Regex("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) &&
            java.net.InetAddress.getByName(binding.clientAddress).isSiteLocalAddress &&
            binding.server.matches(Regex("[a-z][a-z0-9-]{0,39}")) &&
            binding.sourceCertificates.keys == binding.originalHosts && binding.sourcePrivateKeys.keys == binding.originalHosts &&
            binding.certificateFiles.keys == binding.originalHosts && binding.keyFiles.keys == binding.originalHosts &&
            (binding.certificateFiles.values + binding.keyFiles.values).toSet().size == 2 * binding.originalHosts.size &&
            (binding.certificateFiles.values + binding.keyFiles.values).all {
                it.matches(Regex("/run/secrets/[a-z][a-z0-9-]{0,63}\\.pem"))
            } && (binding.sourceCertificates.values + binding.sourcePrivateKeys.values).all { it.sha256.matches(hash) })
        require(spec.name.startsWith("${binding.targetGeneration}-") && spec.store == RuntimeStore.CANONICAL_V2 && spec.ingress == null &&
            spec.networks.contains(binding.clientNetwork) && spec.processes.single { it.id == "caddy" }.let { caddy ->
                binding.clientNetwork in caddy.networks && "NET_BIND_SERVICE" in caddy.capabilities &&
                caddy.files.map { it.target }.containsAll(
                    binding.certificateFiles.values + binding.keyFiles.values) &&
                    caddy.networkAliases.filter { it.network == binding.clientNetwork }.map { it.host }.toSet() == binding.originalHosts
            }) { "Bridge must use the exact isolated target and generation-local DNS aliases" }
        require(spec.processes.filter { binding.clientNetwork in it.networks }.map { it.id }.toSet() == binding.allowedClients + "caddy") {
            "Bridge network contains an unauthorized process"
        }
        require(binding.upstreams.size == binding.originalHosts.count { it != "start.datamancy.net" } &&
            binding.upstreams.map { it.host }.toSet() == binding.originalHosts - "start.datamancy.net" &&
            binding.upstreams.all { it.dial.matches(Regex("p0v3-live-${binding.targetGeneration}-[a-z][a-z0-9-]{0,70}:[0-9]{1,5}")) &&
                it.dial.substringAfterLast(':').toInt() in 1..65535 }) { "Bridge may route only to exact restored services" }
    }
    private fun observe(): Pair<JsonObject, String> {
        val reply = transport.exchange("GET", "/config/", null, null)
        require(reply.status == 200 && reply.body.size in 1..4 * 1024 * 1024 &&
            reply.etag?.matches(Regex("\"/config/ [a-f0-9]{16}\"")) == true)
        return json.parseToJsonElement(reply.body.decodeToString(throwOnInvalidSequence = true)).jsonObject to requireNotNull(reply.etag)
    }
    private fun routes() = buildJsonArray {
        for (host in binding.originalHosts.sorted())
            for (startPath in if (host == "start.datamancy.net")
                listOf("/identity/operator/callback", "/") else listOf<String?>(null)) add(buildJsonObject {
            val routeId = when (startPath) {
                "/" -> "entry"
                "/identity/operator/callback" -> "operator-callback"
                else -> "app"
            }
            put("@id", "$id-${host.replace('.', '-')}-$routeId"); put("terminal", true)
            put("match", buildJsonArray { add(buildJsonObject {
                put("host", buildJsonArray { add(host) })
                if (startPath != null) put("path", buildJsonArray { add(startPath) })
            }) })
            put("handle", buildJsonArray { add(if (startPath == "/identity/operator/callback") operatorCallback()
                else if (startPath == "/") buildJsonObject {
                put("handler", "static_response"); put("status_code", 200)
                put("headers", buildJsonObject { put("Content-Type", buildJsonArray { add("text/html; charset=utf-8") })
                    put("Cache-Control", buildJsonArray { add("no-store") }) })
                put("body", "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><title>Sign in</title>" +
                    "<a href=\"https://auth.datamancy.net/realms/p0v3/account/\">Sign in with Keycloak</a></html>")
            } else caddyOwnedUpstreamProxy(binding.upstreams.single { it.host == host }, false)) })
        })
        add(buildJsonObject { put("terminal", true); put("handle", buildJsonArray { add(buildJsonObject {
            put("handler", "static_response"); put("status_code", 503)
        }) }) })
    }
    private fun withBridge(configuration: JsonObject, add: Boolean): JsonObject {
        fun obj(parent: JsonObject, key: String) = parent[key]?.jsonObject ?: JsonObject(emptyMap())
        fun put(parent: JsonObject, key: String, value: JsonElement) = JsonObject(parent + (key to value))
        val apps = obj(configuration, "apps"); val http = obj(apps, "http"); val servers = obj(http, "servers")
        val tls = obj(apps, "tls"); val certificates = obj(tls, "certificates")
        val entry = certificates["load_files"]?.jsonArray ?: JsonArray(emptyList())
        val certs = binding.originalHosts.sorted().map { host -> buildJsonObject {
            put("certificate", binding.certificateFiles.getValue(host)); put("key", binding.keyFiles.getValue(host))
        } }
        val matches = entry.count { it in certs }
        if (add) require(servers.values.none { serverValue ->
            serverValue.jsonObject["listen"]?.jsonArray?.any {
                it.jsonPrimitive.content in setOf("${binding.clientAddress}:443", ":443", "0.0.0.0:443", "[::]:443")
            } == true
        } && tls["automation"]?.jsonObject?.get("policies")?.jsonArray?.isEmpty() != false &&
            certificates["automate"]?.jsonArray?.isEmpty() != false) { "Bridge cannot adopt its client IP, a wildcard listener or ACME policy" }
        require(matches <= certs.size && (if (add) servers[binding.server] == null
            else matches == certs.size &&
            certs.all { it in entry } && servers[binding.server] == server()))
        val updated = if (add) servers + (binding.server to server()) else servers - binding.server
        val internalActive = servers.keys.any { it.startsWith("p0v3-internal-${binding.site}-") }
        val newCertificates = if (add) entry + certs.filterNot { it in entry }
            else if (internalActive) entry else entry.filterNot { it in certs }
        val updatedApps = put(put(apps, "tls", put(tls, "certificates",
            put(certificates, "load_files", JsonArray(newCertificates)))), "http", put(http, "servers", JsonObject(updated)))
        return put(configuration, "apps", updatedApps)
    }
    private fun server(): JsonObject = buildJsonObject {
        put("@id", id); put("listen", buildJsonArray { add("${binding.clientAddress}:443") })
        put("strict_sni_host", true); put("automatic_https", buildJsonObject { put("disable", true) })
        put("tls_connection_policies", buildJsonArray { add(buildJsonObject {
            put("match", buildJsonObject { put("sni", JsonArray(binding.originalHosts.sorted().map(::JsonPrimitive))) })
        }) })
        val admittedIp = binding.qualifierClientAddress ?: binding.clientAddress // RSS helper enters Caddy namespace.
        put("routes", buildJsonArray {
            add(buildJsonObject {
                put("match", buildJsonArray { add(buildJsonObject {
                    put("remote_ip", buildJsonObject {
                        put("ranges", buildJsonArray { add("$admittedIp/32") })
                    })
                }) })
                put("handle", buildJsonArray { add(buildJsonObject {
                    put("handler", "subroute"); put("routes", routes())
                }) }); put("terminal", true)
            })
            add(buildJsonObject { put("terminal", true); put("handle", buildJsonArray { add(buildJsonObject {
                put("handler", "static_response"); put("status_code", 403)
            }) }) })
        })
    }
    private fun transition(operation: String, action: String, expectedSha256: String, before: JsonObject, etag: String): RestoredBridgeResult {
        require(operation.matches(Regex("r-[a-f0-9]{12}")) && hash.matches(expectedSha256) &&
            TransactionalCaddy.digest(before) == expectedSha256 && !Files.exists(root.resolve("bridge.pending"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("$operation.intent.json"), NOFOLLOW_LINKS))
        val after = withBridge(before, action == "install")
        val intent = RestoredBridgeIntent(binding, action, before, after, etag)
        val bytes = json.encodeToString(intent).toByteArray()
        ReleasePrivateFiles.locked(root) {
            require(!Files.exists(root.resolve("bridge.pending"), NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve("client.pending"), NOFOLLOW_LINKS)) {
                "Uncertain namespace client retains its bridge and source-stop fence"
            }
            ReleasePrivateFiles.save(root.resolve("$operation.intent.json"), bytes)
            ReleasePrivateFiles.save(root.resolve("bridge.pending"), bytes)
        }
        val reply = transport.exchange("POST", "/config/", etag, after.toString().toByteArray())
        require(reply.status in 200..299) { "Uncertain bridge write; reconciliation only" }
        val observed = observe().first
        require(observed == after) { "Bridge changed during write; do not open source" }
        if (action == "install") nativeListenerAudit?.invoke()?.let { require(it > 1) {
            "Runner-only original-SNI listener is not natively bound to client-network IP"
        } }
        val result = RestoredBridgeResult(operation, ReleaseLocks.sha256(bytes), action, expectedSha256, TransactionalCaddy.digest(observed))
        ReleasePrivateFiles.locked(root) {
            require(ReleasePrivateFiles.read(root.resolve("bridge.pending")).contentEquals(bytes))
            ReleasePrivateFiles.save(root.resolve("$operation.result.json"), json.encodeToString(result).toByteArray())
            ReleasePrivateFiles.removeExact(root.resolve("bridge.pending"), bytes)
        }
        return result
    }
    fun install(expectedConfigurationSha256: String): RestoredBridgeResult {
        binding.qualifierClientInvocationId?.let { invocation ->
            val nativePath = GenerationRuntime.BASE.resolve(binding.targetGeneration)
                .resolve("qualification-client").resolve(invocation).resolve("native.json")
            val native = json.decodeFromString<QualificationClientNative>(
                ReleasePrivateFiles.read(nativePath).decodeToString())
            require(native.containerId == binding.qualifierClientContainerId &&
                native.clientIp == binding.qualifierClientAddress && native.netnsInode > 1 &&
                Files.readSymbolicLink(Path.of("/proc/${native.pid}/ns/net")).toString() ==
                    "net:[${native.netnsInode}]") {
                "Official private client is not natively attached to the exact original-SNI bridge"
            }
            val inspect = PrivateRootfulCommands(30, spec.store).run(listOf("inspect", "--type", "container",
                "p0v3-qc-${binding.targetGeneration}-$invocation"))
            require(inspect.exitCode == 0 && inspect.output.length in 1..262144 &&
                json.parseToJsonElement(inspect.output).jsonArray.single().jsonObject.let { observed ->
                    observed.getValue("Id").jsonPrimitive.content == native.containerId &&
                        observed.getValue("State").jsonObject.getValue("Running").jsonPrimitive.boolean &&
                        observed.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject
                            .getValue("p0v3-live-${spec.name}-${binding.clientNetwork}").jsonObject
                            .getValue("IPAddress").jsonPrimitive.content == native.clientIp
                }) { "Official client CID/namespace or native Podman network changed before bridge CAS" }
        }
        require(sourceStopped() && targetIsolationProof() == null &&
            targetPrivateReadinessProof() == binding.targetPrivateReadinessSha256 &&
            clientAddressProof() == binding.clientAddress) {
            "Source must be stopped; private and outbound-blocked target client bridge must be independently ready"
        }
        binding.upstreams.forEach { upstream ->
            caddyOwnedUpstreamProxy(upstream, false)
            auditNativeUpstreamCa(spec, upstream)
        }
        val sealed = spec.processes.single { it.id == "caddy" }.files.associateBy { it.target }
        for (host in binding.originalHosts.sorted()) {
            val original = binding.sourceCertificates.getValue(host)
            val originalKey = binding.sourcePrivateKeys.getValue(host)
            val cert = ReleasePrivateFiles.read(Path.of(original.path), 65536)
            val key = ReleasePrivateFiles.read(Path.of(originalKey.path), 65536)
            require(ReleaseLocks.sha256(cert) == original.sha256 && ReleaseLocks.sha256(key) == originalKey.sha256 &&
                sealedInputRead(requireNotNull(sealed[binding.certificateFiles.getValue(host)]).file).contentEquals(cert) &&
                sealedInputRead(requireNotNull(sealed[binding.keyFiles.getValue(host)]).file).contentEquals(key)) {
                "Original certificate or private key does not match sealed restored Caddy inputs"
            }
            certificateCheck(cert, host, binding.originalHosts)
        }
        val (before, etag) = observe()
        return transition(binding.operation, "install", expectedConfigurationSha256, before, etag)
    }
    private fun removeAfterFence(operation: String, expectedConfigurationSha256: String): RestoredBridgeResult {
        require(sourceStopped() && targetIsolationProof() == null) { "Bridge removal must precede target isolation and source resume" }
        val (before, etag) = observe()
        return transition(operation, "remove", expectedConfigurationSha256, before, etag)
    }
    /** A browser/Android case cannot remove its original-SNI bridge while its QClient
     * still has a live namespace. Verify the exact durable stop receipt AND native Podman. */
    fun remove(operation: String, expectedConfigurationSha256: String,
        fence: QualificationClientFence): RestoredBridgeResult {
        require(fence.invocationId == binding.qualifierClientInvocationId &&
            fence.containerId == binding.qualifierClientContainerId &&
            fence.generationId == binding.targetGeneration &&
            fence.clientNetnsInode > 1 && hexOrHash(fence.stoppedContainerStateSha256)) {
            "A foreign or caller-asserted client fence cannot remove the original-SNI bridge"
        }
        require(nativeQualificationClientFence(binding.targetGeneration, spec, fence) == fence)
        return removeAfterFence(operation, expectedConfigurationSha256)
    }
    /** Only the controller-native RSS GET path has no browser/Android container to fence;
     * its own one-use pending client intent is checked by transition/sourceResumeProof. */
    fun remove(operation: String, expectedConfigurationSha256: String): RestoredBridgeResult {
        require(binding.nativeClientCapabilities == setOf("rss-mastodon") &&
            binding.qualifierClientInvocationId == null && binding.qualifierClientContainerId == null) {
            "Browser/Android bridge removal requires typed native QClient fence"
        }
        return removeAfterFence(operation, expectedConfigurationSha256)
    }
    private fun hexOrHash(value: String) = hash.matches(value)
    fun reconcile(operation: String, expectedIntentSha256: String): RestoredBridgeResult {
        require(operation.matches(Regex("r-[a-f0-9]{12}")) && hash.matches(expectedIntentSha256))
        val bytes = ReleasePrivateFiles.locked(root) { ReleasePrivateFiles.read(root.resolve("bridge.pending")) }
        require(ReleaseLocks.sha256(bytes) == expectedIntentSha256 &&
            ReleasePrivateFiles.read(root.resolve("$operation.intent.json")).contentEquals(bytes))
        val intent = json.decodeFromString<RestoredBridgeIntent>(bytes.decodeToString())
        require(intent.binding == binding && intent.action in setOf("install", "remove") && sourceStopped())
        val observed = observe().first
        require(observed == intent.after || observed == intent.before) { "Bridge state diverged; never replay" }
        val action = if (observed == intent.after) intent.action else "not-applied"
        if (action == "install") nativeListenerAudit?.invoke()?.let { require(it > 1) {
            "Reconciled runner-only listener is not natively bound to the client network"
        } }
        val result = RestoredBridgeResult(operation, expectedIntentSha256, action,
            TransactionalCaddy.digest(intent.before), TransactionalCaddy.digest(observed))
        ReleasePrivateFiles.locked(root) {
            require(ReleasePrivateFiles.read(root.resolve("bridge.pending")).contentEquals(bytes))
            ReleasePrivateFiles.save(root.resolve("$operation.result.json"), json.encodeToString(result).toByteArray())
            ReleasePrivateFiles.removeExact(root.resolve("bridge.pending"), bytes)
        }
        return result
    }
    /** Only after the bridge is proven absent and the exact target has been stopped and fenced. */
    fun sourceResumeProof(removed: RestoredBridgeResult, isolationSha256: String): String {
        require(removed.action == "remove" && hash.matches(isolationSha256) && sourceStopped() &&
            targetIsolationProof() == isolationSha256)
        val saved = json.decodeFromString<RestoredBridgeResult>(ReleasePrivateFiles.read(root.resolve("${removed.operation}.result.json")).decodeToString())
        require(saved == removed && hash.matches(removed.afterSha256)) { "Bridge removal evidence changed" }
        binding.qualifierClientInvocationId?.let { invocation ->
            val journal = GenerationRuntime.BASE.resolve(binding.targetGeneration)
                .resolve("qualification-client").resolve(invocation)
            val fence = json.decodeFromString<QualificationClientFence>(
                ReleasePrivateFiles.read(journal.resolve("fenced.json")).decodeToString())
            require(fence.containerId == binding.qualifierClientContainerId &&
                nativeQualificationClientFence(binding.targetGeneration, spec, fence) == fence)
        }
        val digest = ReleaseLocks.sha256(json.encodeToString(removed).toByteArray() + isolationSha256.toByteArray())
        val record = json.encodeToString(BridgeResumeProof(binding, removed, isolationSha256, digest)).toByteArray()
        ReleasePrivateFiles.locked(root) {
            require(!Files.exists(root.resolve("client.pending"), NOFOLLOW_LINKS)) {
                "An uncertain native client cannot authorize source resume"
            }
            val path = root.resolve("${removed.operation}.resume-proof.json")
            if (Files.exists(path, NOFOLLOW_LINKS)) require(ReleasePrivateFiles.read(path).contentEquals(record))
            else ReleasePrivateFiles.save(path, record)
        }
        return digest
    }
    companion object {
        private fun verifyBridgeCertificate(bytes: ByteArray, host: String, hosts: Set<String>) {
            val leaf = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(bytes.inputStream()) as java.security.cert.X509Certificate
            leaf.checkValidity()
            val identities = leaf.subjectAlternativeNames
            val sans = identities?.filter { it[0] == 2 }?.map { it[1] as String }?.toSet()
            require(identities != null && identities.all { it[0] == 2 } && sans != null && host in sans &&
                sans.all { it in hosts && AcmePreflight.hostPattern.matches(it) }) {
                "Original certificate must cover the host without unrelated or wildcard identities"
            }
        }
        fun real(root: Path, binding: RestoredBridgeBinding, target: PrivateDeploymentSpec, source: PrivateDeploymentSpec,
            sourceFingerprint: String): RestrictedRestoreBridge {
            require(root == Path.of("/mnt/media/p0-v3/restored-bridges").resolve(binding.site).resolve(binding.targetGeneration) &&
                source.name.startsWith("${binding.sourceGeneration}-") && sourceFingerprint.matches(Regex("[a-f0-9]{64}")) &&
                sealedRestoredBridgeSource(source, binding.sourceGeneration, sourceFingerprint,
                    binding.site, binding.originalHosts))
            val quiesceRoot = Path.of("/mnt/media/p0-v3/ingress-succession").resolve(binding.site)
            val record = Json.decodeFromString<ListenerBridgeQuiesceResult>(ReleasePrivateFiles.read(
                quiesceRoot.resolve("${binding.quiesceOperation}.bridge-result.json")).decodeToString())
            val stoppedBytes = ReleasePrivateFiles.read(quiesceRoot.resolve("${binding.quiesceOperation}.intent.json"))
            val stoppedBinding = Json.decodeFromString<ListenerSuccessionBinding>(stoppedBytes.decodeToString())
            require(record.operation == binding.quiesceOperation && record.sourceGeneration == binding.sourceGeneration &&
                record.targetGeneration == binding.targetGeneration && record.sourceStoppedProofSha256 == binding.sourceStoppedProofSha256 &&
                record.intentSha256 == ReleaseLocks.sha256(stoppedBytes) &&
                stoppedBinding.operation == binding.quiesceOperation && stoppedBinding.site == binding.site &&
                stoppedBinding.source == binding.sourceGeneration && stoppedBinding.sourceFingerprint == sourceFingerprint &&
                stoppedBinding.target == binding.targetGeneration && stoppedBinding.targetFingerprint == binding.targetFingerprint &&
                binding.originalHosts.all { it in stoppedBinding.approvedHosts }) {
                "Restored bridge lacks durable source-listener quiescence"
            }
            privateControlDirectory(root.parent.parent); privateControlDirectory(root.parent); privateControlDirectory(root)
            val runtime = PrivateDeployment.real(mapOf(source.name to sourceFingerprint, target.name to binding.targetFingerprint))
            return RestrictedRestoreBridge(root, binding, target, NamespaceCaddyTransport.real(target, binding.targetFingerprint),
                { runtime.status(source).all { it.state != "running" } && listOf(80, 443).all { hostIngressPortOwner(it) == PortOwner.FREE } },
                { runtime.audit(target).let { audit ->
                    if (audit.maintenanceId != null && audit.statuses.all { it.state != "running" })
                        ReleaseLocks.sha256(Json.encodeToString(audit).toByteArray()) else null
                } },
                { runtime.audit(target).let { audit ->
                    if (target.ingress == null && "ingress-egress" !in target.networks && audit.maintenanceId == null &&
                        target.processes.filterNot { it.oneShot }.all { process ->
                            audit.statuses.single { it.id == process.id }.state == "running"
                        } && audit.statuses.none { it.state == "failed" })
                        ReleaseLocks.sha256(Json.encodeToString(audit).toByteArray()) else null
                } },
                { NamespaceCaddyTransport.ownedClientAddress(target, binding.targetFingerprint, binding.clientNetwork) },
                nativeListenerAudit = { NamespaceCaddyTransport.auditInternalListener(target,
                    binding.targetFingerprint, binding.clientNetwork, binding.clientAddress) })
        }
    }
}

@Serializable internal data class QualificationInstallIngressBinding(val operation: String, val site: String,
    val generationId: String, val fingerprint: String, val publicServer: String,
    val clientNetwork: String, val caddyClientIp: String, val clientIp: String,
    val clientInvocationId: String, val clientContainerId: String, val approvedHosts: Set<String>)
@Serializable internal data class QualificationInstallIngressIntent(val binding: QualificationInstallIngressBinding,
    val action: String, val before: JsonObject, val after: JsonObject, val etag: String)
@Serializable internal data class QualificationInstallIngressResult(val action: String,
    val bindingSha256: String, val beforeSha256: String, val afterSha256: String,
    val nativeListenerInode: Long)

/** Fresh INSTALL uses source Caddy's SAME managed ACME leaf on an INTERNAL client-only IP.
 * It never publishes a second host port, creates a certificate, changes the ACME scheduler,
 * or copies public route IDs. RESTORE uses RestrictedRestoreBridge with original cert+key.
 */
internal class QualificationInstallIngress(private val root: Path,
    private val binding: QualificationInstallIngressBinding, private val spec: PrivateDeploymentSpec,
    private val transport: CaddyTransport, private val sourcePublicIp: () -> String,
    private val caddyClientIp: () -> String, private val client: () -> QualificationClientNative,
    private val nativeListener: () -> Long, private val nativeListenerAbsent: () -> Long,
    private val clientFence: (QualificationClientFence) -> QualificationClientFence = {
        nativeQualificationClientFence(binding.generationId, spec, it)
    }) {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val serverId = "p0v3-${binding.site}-qualified-install"
    private val hex = Regex("[a-f0-9]{64}")
    init {
        PrivateDeployment.validate(spec)
        require(binding.operation.matches(Regex("r-[a-f0-9]{12}")) &&
            binding.site.matches(Regex("[a-z][a-z0-9-]{0,39}")) &&
            binding.generationId.matches(Regex("q-[a-f0-9]{12}")) &&
            spec.name.startsWith("${binding.generationId}-") && hex.matches(binding.fingerprint) &&
            binding.clientNetwork == "qualification-web" &&
            binding.clientNetwork in spec.processes.single { it.id == "caddy" }.networks &&
            spec.store == RuntimeStore.CANONICAL_V2 && spec.ingress != null &&
            spec.ingress!!.approvedHosts == binding.approvedHosts &&
            binding.approvedHosts.isNotEmpty() && binding.approvedHosts.size <= 64 &&
            binding.approvedHosts.all(AcmePreflight.hostPattern::matches) &&
            binding.clientInvocationId.matches(Regex("[a-z][a-z0-9-]{0,95}")) &&
            binding.clientContainerId.matches(hex) &&
            binding.caddyClientIp.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            binding.clientIp.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            binding.caddyClientIp != binding.clientIp &&
            sourcePublicIp() != binding.caddyClientIp &&
            caddyClientIp() == binding.caddyClientIp) {
            "Fresh installation client route requires the actual source+client generation"
        }
    }
    private fun present(): Pair<JsonObject, String> {
        val reply = transport.exchange("GET", "/config/", null, null)
        require(reply.status == 200 && reply.body.size in 1..4 * 1024 * 1024 &&
            reply.etag?.matches(Regex("\"/config/ [a-f0-9]{16}\"")) == true)
        return json.parseToJsonElement(reply.body.decodeToString(throwOnInvalidSequence = true)).jsonObject to requireNotNull(reply.etag)
    }
    private fun server(config: JsonObject): JsonObject {
        val source = config.getValue("apps").jsonObject.getValue("http").jsonObject.getValue("servers")
            .jsonObject.getValue(binding.publicServer).jsonObject
        require(source.getValue("listen").jsonArray.map { it.jsonPrimitive.content } ==
            listOf("${sourcePublicIp()}:443") &&
            source.getValue("strict_sni_host").jsonPrimitive.boolean &&
            source.getValue("tls_connection_policies").jsonArray.single().jsonObject.getValue("match")
                .jsonObject.getValue("sni").jsonArray.map { it.jsonPrimitive.content }.toSet() == binding.approvedHosts &&
            source.getValue("routes").jsonArray.size == 1 &&
            source.getValue("routes").jsonArray.single().jsonObject.getValue("match").jsonArray.single()
                .jsonObject.getValue("host").jsonArray.map { it.jsonPrimitive.content }.toSet() == binding.approvedHosts &&
            source.getValue("routes").jsonArray.single().jsonObject.getValue("handle").jsonArray.single()
                .jsonObject.getValue("handler").jsonPrimitive.content == "subroute" &&
            config.getValue("apps").jsonObject.getValue("tls").jsonObject.getValue("certificates")
                .jsonObject.getValue("automate").jsonArray.map { it.jsonPrimitive.content }.toSet()
                .containsAll(binding.approvedHosts)) { "Fresh private client ingress cannot adopt an unowned public TLS server" }
        fun withoutIds(value: JsonElement): JsonElement = when (value) {
            is JsonObject -> JsonObject(value.filterKeys { it != "@id" }.mapValues { withoutIds(it.value) })
            is JsonArray -> JsonArray(value.map(::withoutIds))
            else -> value
        }
        val routes = withoutIds(source.getValue("routes")).jsonArray
        return buildJsonObject {
            put("listen", buildJsonArray { add("${binding.caddyClientIp}:443") })
            put("strict_sni_host", true)
            put("automatic_https", buildJsonObject { put("disable", true) })
            put("tls_connection_policies", source.getValue("tls_connection_policies"))
            put("routes", buildJsonArray {
                add(buildJsonObject {
                    put("match", buildJsonArray { add(buildJsonObject {
                        put("remote_ip", buildJsonObject {
                            put("ranges", buildJsonArray { add("${binding.clientIp}/32") })
                        })
                    }) })
                    put("handle", buildJsonArray { add(buildJsonObject {
                        put("handler", "subroute"); put("routes", routes)
                    }) }); put("terminal", true)
                })
                add(buildJsonObject { put("terminal", true); put("handle", buildJsonArray { add(buildJsonObject {
                    put("handler", "static_response"); put("status_code", 403)
                }) }) })
            })
        }
    }
    private fun changed(config: JsonObject, add: Boolean): JsonObject {
        fun put(obj: JsonObject, key: String, value: JsonElement): JsonObject = JsonObject(obj + (key to value))
        val apps = config.getValue("apps").jsonObject; val http = apps.getValue("http").jsonObject
        val servers = http.getValue("servers").jsonObject
        require((serverId in servers) != add && servers.entries.none { (key, item) ->
            key != serverId && item.jsonObject["listen"]?.jsonArray?.any {
                it.jsonPrimitive.content == "${binding.caddyClientIp}:443"
            } == true
        }) { "Client IP:443 is already owned by an unrelated Caddy listener" }
        val after = if (add) put(servers, serverId, server(config)) else JsonObject(servers - serverId)
        return put(config, "apps", put(apps, "http", put(http, "servers", after)))
    }
    private fun mutate(action: String, fence: QualificationClientFence? = null): QualificationInstallIngressResult {
        require(action in setOf("install", "remove"))
        if (action == "install") require(client().let {
            it.containerId == binding.clientContainerId && it.clientIp == binding.clientIp
        }) { "Fresh private route requires live native client readback" }
        if (action == "remove") require(fence != null && fence.invocationId == binding.clientInvocationId &&
            fence.generationId == binding.generationId && fence.containerId == binding.clientContainerId &&
            hex.matches(fence.stoppedContainerStateSha256) && clientFence(fence) == fence) {
            "Client must be natively stopped before fresh bridge removal"
        }
        val (before, etag) = present()
        if (action == "remove") {
            val installed = json.decodeFromString<QualificationInstallIngressIntent>(ReleasePrivateFiles.read(
                root.resolve("${binding.operation}-install.intent.json")).decodeToString())
            require(installed.binding == binding && installed.action == "install" &&
                before == installed.after && Files.exists(root.resolve("${binding.operation}-install.result.json"), NOFOLLOW_LINKS)) {
                "Cannot remove a changed or unacknowledged fresh private client route"
            }
        }
        val after = changed(before, action == "install")
        val intent = QualificationInstallIngressIntent(binding, action, before, after, etag)
        val bytes = json.encodeToString(intent).encodeToByteArray()
        ReleasePrivateFiles.locked(root) {
            require(!Files.exists(root.resolve("pending.json"), NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve("${binding.operation}-$action.intent.json"), NOFOLLOW_LINKS))
            ReleasePrivateFiles.save(root.resolve("${binding.operation}-$action.intent.json"), bytes)
            ReleasePrivateFiles.save(root.resolve("pending.json"), bytes)
        }
        val applied = transport.exchange("POST", "/config/", etag, after.toString().encodeToByteArray())
        require(applied.status in 200..299) { "Fresh private client ingress uncertain, never replay POST" }
        val current = present().first
        require(current == after && caddyClientIp() == binding.caddyClientIp &&
            (action != "install" || client().containerId == binding.clientContainerId))
        val inode = if (action == "install") nativeListener() else nativeListenerAbsent()
        require(inode > 1) { "Native qualification IP:443 listener disagrees with Caddy JSON" }
        val result = QualificationInstallIngressResult(action, ReleaseLocks.sha256(bytes),
            TransactionalCaddy.digest(before), TransactionalCaddy.digest(after), inode)
        ReleasePrivateFiles.locked(root) {
            require(ReleasePrivateFiles.read(root.resolve("pending.json")).contentEquals(bytes))
            ReleasePrivateFiles.save(root.resolve("${binding.operation}-$action.result.json"), json.encodeToString(result).encodeToByteArray())
            ReleasePrivateFiles.removeExact(root.resolve("pending.json"), bytes)
        }
        return result
    }
    fun install(): QualificationInstallIngressResult = mutate("install")
    fun remove(fence: QualificationClientFence): QualificationInstallIngressResult = mutate("remove", fence)
    /** Lost POST acknowledgement: only native Caddy readback can adopt the exact after-state.
     * A write that never happened remains pending; no second POST or caller success flag. */
    fun reconcile(expectedIntentSha256: String): QualificationInstallIngressResult {
        require(hex.matches(expectedIntentSha256))
        val bytes = ReleasePrivateFiles.locked(root) { ReleasePrivateFiles.read(root.resolve("pending.json")) }
        require(ReleaseLocks.sha256(bytes) == expectedIntentSha256)
        val intent = json.decodeFromString<QualificationInstallIngressIntent>(bytes.decodeToString())
        require(intent.binding == binding && intent.action in setOf("install", "remove") &&
            ReleasePrivateFiles.read(root.resolve("${binding.operation}-${intent.action}.intent.json")).contentEquals(bytes))
        val current = present().first
        require(current == intent.after && caddyClientIp() == binding.caddyClientIp) {
            "Uncertain fresh qualification server absent or changed: no replay"
        }
        val inode = if (intent.action == "install") nativeListener() else nativeListenerAbsent()
        require(inode > 1)
        val result = QualificationInstallIngressResult(intent.action, expectedIntentSha256,
            TransactionalCaddy.digest(intent.before), TransactionalCaddy.digest(current), inode)
        ReleasePrivateFiles.locked(root) {
            require(ReleasePrivateFiles.read(root.resolve("pending.json")).contentEquals(bytes))
            ReleasePrivateFiles.save(root.resolve("${binding.operation}-${intent.action}.result.json"), json.encodeToString(result).encodeToByteArray())
            ReleasePrivateFiles.removeExact(root.resolve("pending.json"), bytes)
        }
        return result
    }
    companion object {
        fun real(root: Path, binding: QualificationInstallIngressBinding, spec: PrivateDeploymentSpec,
            client: () -> QualificationClientNative): QualificationInstallIngress {
            require(root == Path.of("/mnt/media/p0-v3/qualification-ingress")
                .resolve(binding.site).resolve(binding.generationId))
            privateControlDirectory(root.parent.parent); privateControlDirectory(root.parent); privateControlDirectory(root)
            return QualificationInstallIngress(root, binding, spec,
                NamespaceCaddyTransport.real(spec, binding.fingerprint),
                { NamespaceCaddyTransport.ownedPublicAddress(spec, binding.fingerprint) },
                { NamespaceCaddyTransport.ownedProcessAddress(spec, binding.fingerprint, "caddy", binding.clientNetwork) },
                client,
                { NamespaceCaddyTransport.auditInternalListener(spec, binding.fingerprint,
                    binding.clientNetwork, binding.caddyClientIp) },
                { NamespaceCaddyTransport.auditNoInternalListener(spec, binding.fingerprint,
                    binding.clientNetwork, binding.caddyClientIp) })
        }
    }
}
