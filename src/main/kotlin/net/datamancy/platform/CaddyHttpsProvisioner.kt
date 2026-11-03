package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

@Serializable internal data class HttpsProvisionIntent(val operation: String, val bindingSha256: String,
    val before: JsonObject, val after: JsonObject, val configuration: JsonObject)
@Serializable internal data class HttpsProvisionResult(val operation: String, val intentSha256: String,
    val status: String, val configurationSha256: String)

/** Explicit listener enrollment, not release activation. Caddy owns ACME keys, issuance and renewal.
 * Call before route cutover, under the caller's site lifecycle lock. Never adopts an existing server,
 * edits host trust, replaces unrelated certificates, or retries a possibly dispatched write.
 */
internal class CaddyHttpsProvisioner(private val root: Path, private val binding: CaddySiteBinding,
    private val transport: CaddyTransport) {
    companion object {
        private val json = Json { encodeDefaults = true }
        private val opPattern = Regex("r-[a-f0-9]{12}")
        private val hashPattern = Regex("[a-f0-9]{64}")
        fun inRuntime(root: Path, binding: CaddySiteBinding, spec: PrivateDeploymentSpec, fingerprint: String): CaddyHttpsProvisioner {
            require(root == Path.of("/mnt/media/p0-v3/caddy-https").resolve(binding.site))
            NamespaceCaddyTransport.checkBinding(binding, spec)
            return CaddyHttpsProvisioner(root, binding, NamespaceCaddyTransport.real(spec, fingerprint))
        }
        fun real(root: Path, binding: CaddySiteBinding): CaddyHttpsProvisioner {
            require(root == Path.of("/mnt/media/p0-v3/caddy-https").resolve(binding.site))
            return CaddyHttpsProvisioner(root, binding, LocalCaddyTransport(binding.endpoint))
        }
    }
    init {
        // Reuse all route-binding admission, including loopback admin and exact non-apex hosts.
        TransactionalCaddy(root, binding, transport)
        require(binding.server.length <= 56)
    }
    private val httpServer = "${binding.server}-http01"
    private val policyId = "p0v3-${binding.site}-acme"
    private val bindingBytes get() = json.encodeToString(binding.copy(approvedHosts = binding.approvedHosts.toSortedSet())).toByteArray()
    private fun <T> locked(action: () -> T): T = ReleasePrivateFiles.locked(root) {
        val path = root.resolve("binding.json")
        if (Files.exists(path, NOFOLLOW_LINKS)) require(ReleasePrivateFiles.read(path).contentEquals(bindingBytes))
        else ReleasePrivateFiles.save(path, bindingBytes)
        action()
    }
    private fun obj(value: JsonObject, key: String) = value[key]?.jsonObject ?: buildJsonObject { }
    private fun servers(config: JsonObject) = obj(obj(obj(config, "apps"), "http"), "servers")
    private fun tls(config: JsonObject) = obj(obj(config, "apps"), "tls")
    private fun policies(config: JsonObject) = obj(tls(config), "automation")["policies"]?.jsonArray ?: JsonArray(emptyList())
    private fun automated(config: JsonObject) = obj(tls(config), "certificates")["automate"]?.jsonArray ?: JsonArray(emptyList())
    private fun put(objectValue: JsonObject, key: String, value: JsonElement) = JsonObject(objectValue + (key to value))
    private fun withServers(config: JsonObject, value: JsonObject): JsonObject {
        val apps = obj(config, "apps")
        return put(config, "apps", put(apps, "http", put(obj(apps, "http"), "servers", value)))
    }
    private fun owned(config: JsonObject): JsonObject = buildJsonObject {
        put("http", servers(config)[httpServer] ?: JsonNull)
        put("https", servers(config)[binding.server] ?: JsonNull)
        val matches = policies(config).filter { it.jsonObject["@id"] == JsonPrimitive(policyId) }
        require(matches.size <= 1) { "Duplicate owned ACME policy" }
        put("policy", matches.singleOrNull() ?: JsonNull)
        put("automate", JsonArray(automated(config).filter { it.jsonPrimitive.content in binding.approvedHosts }))
    }
    private fun observe(): Pair<JsonObject, String> {
        val reply = transport.exchange("GET", "/config/", null, null)
        require(reply.status == 200 && reply.body.size in 1..4 * 1024 * 1024 &&
            reply.etag?.matches(Regex("\"/config/ [a-f0-9]{16}\"")) == true)
        return json.parseToJsonElement(reply.body.decodeToString(throwOnInvalidSequence = true)).jsonObject to requireNotNull(reply.etag)
    }
    fun observeConfigurationSha256(): String = TransactionalCaddy.digest(observe().first)
    private fun challengeServer(nonces: Map<String, String>): JsonObject {
        require(nonces.keys == binding.approvedHosts && nonces.values.distinct().size == nonces.size &&
            nonces.values.all { it.matches(Regex("[a-zA-Z0-9_-]{32,128}")) })
        return buildJsonObject {
            put("listen", buildJsonArray { add(":80") })
            put("automatic_https", buildJsonObject { put("disable", true) })
            put("routes", buildJsonArray {
                for ((host, nonce) in nonces.toSortedMap()) add(buildJsonObject {
                    put("match", buildJsonArray { add(buildJsonObject {
                        put("host", buildJsonArray { add(host) })
                        put("path", buildJsonArray { add("/.well-known/acme-challenge/$nonce") })
                        put("method", buildJsonArray { add("GET") })
                    }) })
                    put("handle", buildJsonArray { add(buildJsonObject {
                        put("handler", "static_response"); put("status_code", 200); put("body", "p0v3-http01-$nonce")
                    }) }); put("terminal", true)
                })
                add(buildJsonObject { put("handle", buildJsonArray { add(buildJsonObject {
                    put("handler", "static_response"); put("status_code", 404)
                }) }); put("terminal", true) })
            })
        }
    }
    /** Refuses ambiguous preexisting ownership rather than adopting a shared 80/443 listener. */
    fun stageHttp01(operation: String, expectedConfiguration: String, nonces: Map<String, String>,
        portOwner: (Int) -> PortOwner): HttpsProvisionResult = locked {
        val server = challengeServer(nonces)
        val (before, etag) = admission(operation, expectedConfiguration)
        require(listOf(80, 443).all { portOwner(it) in setOf(PortOwner.FREE, PortOwner.OWNED_V3) }) { "Fresh listeners require free ports or independently audited owned publication" }
        require(servers(before)[httpServer] == null && servers(before)[binding.server] == null)
        require(owned(before).getValue("policy") == JsonNull && owned(before).getValue("automate").jsonArray.isEmpty())
        // No reliance on a port-only inference: also inspect Caddy's configured listener ownership.
        require(servers(before).values.none { serverValue -> serverValue.jsonObject["listen"]?.jsonArray?.any {
            it.jsonPrimitive.content.substringAfterLast(':') in setOf("80", "443")
        } == true }) { "Existing Caddy listener is not ours" }
        foreignPolicies(before)
        change(operation, before, withServers(before, put(servers(before), httpServer, server)), etag)
    }
    /** One CAS enrolls only these hosts. Automatic renewal persists in Caddy's existing durable storage. */
    fun provision(operation: String, expectedConfiguration: String, nonces: Map<String, String>,
        environment: AcmeEnvironment, observation: AcmeObservation): HttpsProvisionResult = locked {
        val (before, etag) = admission(operation, expectedConfiguration)
        require(servers(before)[httpServer] == challengeServer(nonces) && servers(before)[binding.server] == null)
        require(owned(before).getValue("policy") == JsonNull && owned(before).getValue("automate").jsonArray.isEmpty())
        require(observation.portOwner(80) == PortOwner.OWNED_V3 && observation.portOwner(443) in setOf(PortOwner.FREE, PortOwner.OWNED_V3))
        AcmePreflight.check(binding.approvedHosts, binding.approvedHosts, observation, nonces::getValue)
        // Default/ephemeral storage is not sufficient. Preserve, rather than reset, the owned Caddy store.
        val storage = before.getValue("storage").jsonObject
        require(storage["module"] == JsonPrimitive("file_system") && storage["root"] == JsonPrimitive("/data/caddy"))
        foreignPolicies(before)
        val https = buildJsonObject {
            put("listen", buildJsonArray { add(":443") }); put("routes", JsonArray(emptyList()))
            put("strict_sni_host", true)
            put("automatic_https", buildJsonObject { put("disable_redirects", true) })
            put("tls_connection_policies", buildJsonArray { add(buildJsonObject {
                put("match", buildJsonObject { put("sni", JsonArray(binding.approvedHosts.sorted().map(::JsonPrimitive))) })
            }) })
        }
        var after = withServers(before, put(servers(before), binding.server, https))
        val policy = buildJsonObject {
            put("@id", policyId); put("subjects", JsonArray(binding.approvedHosts.sorted().map(::JsonPrimitive)))
            put("issuers", buildJsonArray { add(buildJsonObject {
                put("module", "acme"); put("ca", environment.directory)
                put("challenges", buildJsonObject { put("tls-alpn", buildJsonObject { put("disabled", true) }) })
            }) })
        }
        val tls = tls(before)
        val updatedTls = put(put(tls, "automation", put(obj(tls, "automation"), "policies", JsonArray(policies(before) + policy))),
            "certificates", put(obj(tls, "certificates"), "automate", JsonArray(automated(before) + binding.approvedHosts.sorted().map(::JsonPrimitive))))
        after = put(after, "apps", put(obj(after, "apps"), "tls", updatedTls))
        change(operation, before, after, etag)
    }
    private fun foreignPolicies(config: JsonObject) {
        require(automated(config).all { it.jsonPrimitive.content.matches(Regex("[a-z0-9.-]+")) &&
            it.jsonPrimitive.content !in binding.approvedHosts }) { "Overlapping or wildcard managed certificate cannot be adopted" }
        require(policies(config).all { policy ->
            val subjects = policy.jsonObject["subjects"]?.jsonArray
            subjects != null && subjects.isNotEmpty() && subjects.all {
                val host = it.jsonPrimitive.content
                host.matches(Regex("[a-z0-9.-]+")) && host !in binding.approvedHosts
            }
        }) { "Catch-all or overlapping ACME policy cannot be adopted" }
        // Existing manually loaded certificates cannot be proved disjoint from names without parsing them.
        require(obj(tls(config), "certificates").keys.all { it == "automate" }) { "Manual certificate ownership is ambiguous" }
    }
    private fun admission(operation: String, expected: String): Pair<JsonObject, String> {
        require(opPattern.matches(operation) && hashPattern.matches(expected))
        require(!Files.exists(root.resolve("pending.json"), NOFOLLOW_LINKS)) { "Uncertain listener operation; observe, never retry" }
        require(!Files.exists(root.resolve("$operation.intent.json"), NOFOLLOW_LINKS)) { "Operation already used" }
        return observe().also { require(TransactionalCaddy.digest(it.first) == expected) { "Stale Caddy configuration" } }
    }
    private fun change(operation: String, before: JsonObject, after: JsonObject, etag: String): HttpsProvisionResult {
        val intent = HttpsProvisionIntent(operation, ReleaseLocks.sha256(bindingBytes), owned(before), owned(after), after)
        val bytes = json.encodeToString(intent).toByteArray()
        ReleasePrivateFiles.save(root.resolve("$operation.intent.json"), bytes)
        ReleasePrivateFiles.save(root.resolve("pending.json"), bytes)
        val response = transport.exchange("POST", "/config/", etag, after.toString().toByteArray())
        check(response.status in 200..299) { "Unacknowledged listener provisioning; reconciliation required" }
        return complete(intent, bytes, true)
    }
    private fun complete(intent: HttpsProvisionIntent, bytes: ByteArray, requireApplied: Boolean): HttpsProvisionResult {
        val (config, _) = observe()
        val status = when (owned(config)) {
            intent.after -> "applied"
            intent.before -> "not-applied"
            else -> error("Owned listener or policy diverged; retained pending operation")
        }
        require(!requireApplied || status == "applied")
        val result = HttpsProvisionResult(intent.operation, ReleaseLocks.sha256(bytes), status, TransactionalCaddy.digest(config))
        val path = root.resolve("${intent.operation}.result.json")
        if (Files.exists(path, NOFOLLOW_LINKS)) {
            val prior = json.decodeFromString<HttpsProvisionResult>(ReleasePrivateFiles.read(path).decodeToString())
            require(prior.operation == result.operation && prior.intentSha256 == result.intentSha256 && prior.status == status)
        } else ReleasePrivateFiles.save(path, json.encodeToString(result).toByteArray())
        ReleasePrivateFiles.removeExact(root.resolve("pending.json"), bytes)
        return result
    }
    fun reconcile(operation: String, expectedIntent: String): HttpsProvisionResult = locked {
        require(opPattern.matches(operation) && hashPattern.matches(expectedIntent))
        val bytes = ReleasePrivateFiles.read(root.resolve("$operation.intent.json"))
        require(ReleaseLocks.sha256(bytes) == expectedIntent && ReleasePrivateFiles.read(root.resolve("pending.json")).contentEquals(bytes))
        val intent = json.decodeFromString<HttpsProvisionIntent>(bytes.decodeToString())
        require(intent.operation == operation && intent.bindingSha256 == ReleaseLocks.sha256(bindingBytes))
        complete(intent, bytes, false)
    }
}
