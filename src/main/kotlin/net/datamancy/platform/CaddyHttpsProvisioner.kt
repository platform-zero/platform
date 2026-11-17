package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.time.Instant
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

@Serializable internal data class HttpsProvisionIntent(val operation: String, val bindingSha256: String,
    val before: JsonObject, val after: JsonObject, val configuration: JsonObject)
@Serializable internal data class HttpsProvisionResult(val operation: String, val intentSha256: String,
    val status: String, val configurationSha256: String)

/** Explicit listener enrollment, not release activation. Caddy owns ACME keys, issuance and renewal.
 * Call before route cutover, under the caller's site lifecycle lock. Never adopts an existing server,
 * edits host trust, replaces unrelated certificates, or retries a possibly dispatched write.
 */
internal class CaddyHttpsProvisioner(private val root: Path, private val binding: CaddySiteBinding,
    private val transport: CaddyTransport, private val ingressAddress: String? = null,
    private val nativeListenerAudit: ((Boolean) -> Unit)? = null) {
    companion object {
        private val json = Json { encodeDefaults = true }
        private val opPattern = Regex("r-[a-f0-9]{12}")
        private val hashPattern = Regex("[a-f0-9]{64}")
        fun inRuntime(root: Path, binding: CaddySiteBinding, spec: PrivateDeploymentSpec, fingerprint: String): CaddyHttpsProvisioner {
            require(root == Path.of("/mnt/media/p0-v3/caddy-https").resolve(binding.site))
            NamespaceCaddyTransport.checkBinding(binding, spec)
            val primaryAddress = NamespaceCaddyTransport.ownedPublicAddress(spec, fingerprint)
            return CaddyHttpsProvisioner(root, binding, NamespaceCaddyTransport.real(spec, fingerprint), primaryAddress,
                { https -> NamespaceCaddyTransport.auditPublicListeners(spec, fingerprint, primaryAddress, https) })
        }
        fun real(root: Path, binding: CaddySiteBinding): CaddyHttpsProvisioner {
            require(root == Path.of("/mnt/media/p0-v3/caddy-https").resolve(binding.site))
            return CaddyHttpsProvisioner(root, binding, LocalCaddyTransport(binding.endpoint))
        }
    }
    init {
        // Reuse all route-binding admission, including loopback admin and exact non-apex hosts.
        TransactionalCaddy(root, binding, transport)
        require(binding.server.length <= 56 && (ingressAddress == null ||
            ingressAddress.matches(Regex("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) &&
            java.net.InetAddress.getByName(ingressAddress).isSiteLocalAddress))
    }
    private fun publicListen(port: Int) = if (ingressAddress == null) ":$port" else "$ingressAddress:$port"
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
    /** Independently read Caddy's installed PRODUCTION ACME scheduler policy and durable store.
     * Caddy, never this observer, performs due renewal. No forced issuance or temporary policy. */
    fun ownedAutomaticRenewalPolicy(expectedConfiguration: String): String {
        val config = observe().first
        require(hashPattern.matches(expectedConfiguration) && TransactionalCaddy.digest(config) == expectedConfiguration)
        val owned = owned(config)
        require(policies(config).filter { it.jsonObject["@id"] != JsonPrimitive(policyId) }.all { policy ->
            policy.jsonObject["subjects"]?.jsonArray?.all { subject ->
                subject.jsonPrimitive.content.matches(Regex("[a-z0-9.-]+")) &&
                    subject.jsonPrimitive.content !in binding.approvedHosts
            } == true
        } && obj(tls(config), "certificates").keys.all { it == "automate" }) {
            "Unrelated policy or manual certificate overlaps owned renewal hosts"
        }
        val policy = owned["policy"]?.jsonObject ?: error("Owned native renewal policy absent")
        require(owned["http"]?.jsonObject?.get("listen")?.jsonArray?.singleOrNull() == JsonPrimitive(publicListen(80)) &&
            owned["https"]?.jsonObject?.get("listen")?.jsonArray?.singleOrNull() == JsonPrimitive(publicListen(443)) &&
            policy["@id"] == JsonPrimitive(policyId) &&
            policy["subjects"]?.jsonArray?.map { it.jsonPrimitive.content } == binding.approvedHosts.sorted() &&
            policy["issuers"]?.jsonArray?.singleOrNull()?.jsonObject?.let { issuer ->
                issuer["module"] == JsonPrimitive("acme") && issuer["ca"] == JsonPrimitive(AcmeEnvironment.PRODUCTION.directory)
            } == true && owned["automate"]?.jsonArray?.map { it.jsonPrimitive.content } == binding.approvedHosts.sorted() &&
            owned["https"] != JsonNull && owned["http"] != JsonNull &&
            config["storage"]?.jsonObject?.let { storage ->
                storage["module"] == JsonPrimitive("file_system") && storage["root"] == JsonPrimitive("/data/caddy")
            } == true) { "Native Caddy production ACME renewal policy or durable store changed" }
        return ReleaseLocks.sha256(json.encodeToString(owned).toByteArray())
    }
    private fun challengeServer(nonces: Map<String, String>): JsonObject {
        require(nonces.keys == binding.approvedHosts && nonces.values.distinct().size == nonces.size &&
            nonces.values.all { it.matches(Regex("[a-zA-Z0-9_-]{32,128}")) })
        return buildJsonObject {
            put("listen", buildJsonArray { add(publicListen(80)) })
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
            put("listen", buildJsonArray { add(publicListen(443)) }); put("routes", JsonArray(emptyList()))
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
        if (status == "applied") nativeListenerAudit?.invoke(intent.after["https"] != JsonNull)
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

@Serializable internal data class PublicCertificateIdentity(val host: String, val sha256: String, val notAfter: String)
@Serializable internal data class PublicRenewalIntent(val operation: String, val configurationSha256: String,
    val nativePolicySha256: String, val previous: Map<String, PublicCertificateIdentity>, val budgetSeconds: Int)
@Serializable internal data class PublicRenewalResult(val operation: String, val intentSha256: String,
    val previous: Map<String, PublicCertificateIdentity>, val current: Map<String, PublicCertificateIdentity>,
    val changed: Boolean)

/** Observe Caddy's bounded automatic ACME renewal, never overwrite its old certificate or initiate
 * an uncertain second issuance. Previous identity remains usable until a newly issued cert is read
 * through validated public TLS with a strictly later expiry. Failure retains observation intent. */
internal class CaddyPublicRenewal(private val root: Path, private val hosts: Set<String>,
    private val configuration: () -> String, private val certificate: (String) -> PublicCertificateIdentity = ::observePublicCertificate,
    private val sleep: (Long) -> Unit = Thread::sleep, private val nativePolicy: () -> String) {
    private val json = Json { encodeDefaults = true }
    fun observe(operation: String, expectedConfiguration: String, previous: Map<String, PublicCertificateIdentity>,
        budgetSeconds: Int): PublicRenewalResult {
        require(operation.matches(Regex("r-[a-f0-9]{12}")) && expectedConfiguration.matches(Regex("[a-f0-9]{64}")) &&
            hosts.isNotEmpty() && hosts.size <= 64 && hosts.all(AcmePreflight.hostPattern::matches) && previous.keys == hosts &&
            budgetSeconds in 10..300 && previous.all { (host, identity) ->
                identity.host == host && identity.sha256.matches(Regex("[a-f0-9]{64}")) &&
                    Instant.parse(identity.notAfter).isAfter(Instant.now())
            } && configuration() == expectedConfiguration &&
            hosts.sorted().associateWith(certificate) == previous) {
            "Previous public certificate identity must be observed live before renewal admission"
        }
        val policySha = nativePolicy()
        require(policySha.matches(Regex("[a-f0-9]{64}"))) { "Native Caddy renewal policy must be audited" }
        val intent = PublicRenewalIntent(operation, expectedConfiguration, policySha, previous, budgetSeconds)
        val bytes = json.encodeToString(intent).toByteArray()
        val previousBinding = root.resolve("previous-${ReleaseLocks.sha256(json.encodeToString(previous).toByteArray())}.renewal")
        ReleasePrivateFiles.locked(root) {
            require(!Files.exists(root.resolve("renewal.pending"), NOFOLLOW_LINKS) &&
                !Files.exists(previousBinding, NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve("$operation.intent.json"), NOFOLLOW_LINKS)) { "Uncertain or already renewed certificate revision retained" }
            ReleasePrivateFiles.save(previousBinding, operation.toByteArray())
            ReleasePrivateFiles.save(root.resolve("$operation.intent.json"), bytes)
            ReleasePrivateFiles.save(root.resolve("renewal.pending"), bytes)
        }
        val deadline = System.nanoTime() + budgetSeconds * 1_000_000_000L
        var observed: Map<String, PublicCertificateIdentity> = emptyMap()
        do {
            require(configuration() == expectedConfiguration && nativePolicy() == policySha) {
                "Native Caddy renewal policy or generation changed during renewal"
            }
            observed = hosts.sorted().associateWith { certificate(it) }
            require(observed.all { (host, current) -> current.host == host && current.sha256.matches(Regex("[a-f0-9]{64}")) &&
                Instant.parse(current.notAfter).isAfter(Instant.now()) &&
                (current == previous.getValue(host) ||
                    (current.sha256 != previous.getValue(host).sha256 && Instant.parse(current.notAfter).isAfter(Instant.parse(previous.getValue(host).notAfter))))
            }) { "Caddy returned a changed certificate without a later valid expiry; retain previous" }
            if (observed.all { (host, current) -> current != previous.getValue(host) }) break
            if (System.nanoTime() >= deadline) break
            sleep(minOf(1_000L, (deadline - System.nanoTime()) / 1_000_000L).coerceAtLeast(1))
        } while (System.nanoTime() < deadline)
        require(observed.all { (host, current) -> current != previous.getValue(host) }) { "Public renewal not proven; prior certificate remains authoritative" }
        val result = PublicRenewalResult(operation, ReleaseLocks.sha256(bytes), previous, observed, true)
        ReleasePrivateFiles.locked(root) {
            require(ReleasePrivateFiles.read(root.resolve("renewal.pending")).contentEquals(bytes))
            ReleasePrivateFiles.save(root.resolve("$operation.result.json"), json.encodeToString(result).toByteArray())
            ReleasePrivateFiles.removeExact(root.resolve("renewal.pending"), bytes)
        }
        return result
    }
}

/** Hostname verification and the normal public trust chain are mandatory; no local trust override. */
internal fun observePublicCertificate(host: String): PublicCertificateIdentity {
    require(AcmePreflight.hostPattern.matches(host))
    val socket = SSLSocketFactory.getDefault().createSocket() as SSLSocket
    socket.use {
        it.soTimeout = 5_000
        it.connect(InetSocketAddress(host, 443), 5_000)
        val parameters = it.sslParameters
        parameters.endpointIdentificationAlgorithm = "HTTPS"
        parameters.serverNames = listOf(javax.net.ssl.SNIHostName(host))
        it.sslParameters = parameters
        it.startHandshake()
        val leaf = it.session.peerCertificates.first() as X509Certificate
        leaf.checkValidity()
        val digest = MessageDigest.getInstance("SHA-256").digest(leaf.encoded).joinToString("") { byte -> "%02x".format(byte) }
        return PublicCertificateIdentity(host, digest, leaf.notAfter.toInstant().toString())
    }
}
