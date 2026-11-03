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
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

internal data class CaddyReply(val status: Int, val body: ByteArray, val etag: String?)
internal fun interface CaddyTransport { fun exchange(method: String, path: String, etag: String?, body: ByteArray?): CaddyReply }

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
@Serializable internal data class CaddyUpstream(val host: String, val dial: String)
@Serializable internal data class CaddyChangeIntent(val schemaVersion: Int = 1, val operation: String, val bindingSha256: String,
    val beforeConfigurationSha256: String, val etag: String, val before: JsonObject?, val after: JsonObject?, val routes: JsonArray)
@Serializable internal data class CaddyChangeResult(val operation: String, val intentSha256: String,
    val status: String, val observedConfigurationSha256: String, val observedSlotSha256: String?)
internal data class CaddyObservation(val configuration: JsonObject, val etag: String, val routes: JsonArray, val slot: JsonObject?)

/** One owned route group, whole-configuration ETag compare-and-swap. Never changes listeners, issuers or unrelated routes.
 * This is an actuator, not activation authority. Its caller must hold release/activation authority for public effects.
 * Failed writes retain a global per-site pending claim; reconciliation observes and never resends the PATCH.
 */
internal class TransactionalCaddy(private val root: Path, private val binding: CaddySiteBinding, private val transport: CaddyTransport) {
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
            return TransactionalCaddy(root, binding, NamespaceCaddyTransport.real(spec, fingerprint))
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
    fun revision(operation: String, generation: String, upstreams: List<CaddyUpstream>, acceptanceToken: String?): JsonObject {
        require(operationId.matches(operation) && generation.matches(Regex("q-[a-f0-9]{12}")))
        require(upstreams.size == binding.approvedHosts.size && upstreams.map { it.host }.toSet() == binding.approvedHosts &&
            upstreams.all { it.dial.matches(Regex("p0v3-live-$generation-[a-z][a-z0-9-]{0,70}:[0-9]{1,5}")) && it.dial.substringAfterLast(':').toInt() in 1..65535 })
        require(acceptanceToken == null || hex.matches(acceptanceToken))
        return buildJsonObject {
            put("@id", slotId); put("terminal", true)
            put("match", buildJsonArray { add(buildJsonObject { put("host", JsonArray(binding.approvedHosts.sorted().map(::JsonPrimitive))) }) })
            put("handle", buildJsonArray { add(buildJsonObject {
                put("handler", "subroute"); put("@id", "$slotId-$operation")
                put("routes", buildJsonArray {
                    for (upstream in upstreams.sortedBy { it.host }) add(buildJsonObject {
                        put("match", buildJsonArray { add(buildJsonObject {
                            put("host", buildJsonArray { add(upstream.host) })
                            if (acceptanceToken != null) put("header_regexp", buildJsonObject {
                                put("Cookie", buildJsonObject { put("pattern", "(^|;[ \\t]*)__Host-p0v3_acceptance=$acceptanceToken(;|$)") })
                            })
                        }) })
                        put("handle", buildJsonArray { add(buildJsonObject {
                            put("handler", "reverse_proxy"); put("upstreams", buildJsonArray { add(buildJsonObject { put("dial", upstream.dial) }) })
                            // Cookie is redacted by Caddy; strip only our control cookie before proxying, preserving app sessions.
                            put("headers", buildJsonObject { put("request", buildJsonObject {
                                put("replace", buildJsonObject { put("Cookie", buildJsonArray {
                                    add(buildJsonObject { put("search_regexp", "^__Host-p0v3_acceptance=[a-f0-9]{64};[ \\t]*"); put("replace", "") })
                                    add(buildJsonObject { put("search_regexp", "(^|;[ \\t]*)__Host-p0v3_acceptance=[a-f0-9]{64}"); put("replace", "") })
                                }) })
                            }) })
                        }) }); put("terminal", true)
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
