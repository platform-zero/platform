package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.security.cert.CertificateFactory
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

internal data class CaddyAdminTarget(val pid: Int, val containerId: String)

/** Connects to the audited Caddy's private loopback, never broadens its admin listen address.
 * Each request holds the runtime lock. Root helper source is included in the pinned controller,
 * not downloaded or selected by the request. Timeout leaves any dispatched write uncertain.
 */
internal class NamespaceCaddyTransport(
    private val audited: (Boolean, (CaddyAdminTarget) -> CaddyReply) -> CaddyReply,
    private val helper: (ByteArray) -> ByteArray = ::runCaddyNamespaceHelper
) : CaddyTransport {
    companion object {
        fun real(spec: PrivateDeploymentSpec, fingerprint: String): NamespaceCaddyTransport {
            require(spec.store == RuntimeStore.CANONICAL_V2 && fingerprint.matches(Regex("[a-f0-9]{64}")))
            val runtime = PrivateDeployment.real(mapOf(spec.name to fingerprint))
            return NamespaceCaddyTransport({ mutation, action -> runtime.withCaddyAdmin(spec, fingerprint, mutation, action) })
        }
        /** A private restored bridge must bind Caddy to ONLY its audited client-network IP.
         * Listening on :443 would expose the no-cookie bridge on every application web network. */
        fun ownedClientAddress(spec: PrivateDeploymentSpec, fingerprint: String, clientNetwork: String,
            commands: RuntimeCommands = PrivateRootfulCommands(30, spec.store),
            audited: (PrivateDeploymentSpec, String) -> RuntimeAudit = { target, pin ->
                PrivateDeployment.real(mapOf(target.name to pin)).audit(target)
            }): String {
            require(spec.ingress == null && "ingress-egress" !in spec.networks)
            return ownedProcessAddress(spec, fingerprint, "caddy", clientNetwork, commands, audited)
        }
        /** Same native label/network inspection for a named, pinned internal service consumer.
         * No DNS lookup, caller-supplied address, host listener or fabricated process identity. */
        fun ownedProcessAddress(spec: PrivateDeploymentSpec, fingerprint: String, processId: String, networkName: String,
            commands: RuntimeCommands = PrivateRootfulCommands(30, spec.store),
            audited: (PrivateDeploymentSpec, String) -> RuntimeAudit = { target, pin ->
                PrivateDeployment.real(mapOf(target.name to pin)).audit(target)
            }): String {
            PrivateDeployment.validate(spec)
            require(spec.store == RuntimeStore.CANONICAL_V2 && fingerprint.matches(Regex("[a-f0-9]{64}")) &&
                processId.matches(Regex("[a-z][a-z0-9-]{0,63}")) &&
                networkName in spec.networks && networkName in spec.processes.single { it.id == processId }.networks)
            val audit = audited(spec, fingerprint)
            require(audit.name == spec.name && audit.fingerprint == fingerprint && audit.maintenanceId == null &&
                audit.statuses.single { it.id == processId }.state == "running")
            val container = "p0v3-live-${spec.name}-$processId"
            val network = "p0v3-live-${spec.name}-$networkName"
            val observed = commands.run(listOf("inspect", "--type", "container", container))
            require(observed.exitCode == 0 && observed.output.length in 1..4194304)
            val objects = Json.parseToJsonElement(observed.output).jsonArray
            require(objects.size == 1)
            val state = objects.single().jsonObject
            val labels = state.getValue("Config").jsonObject.getValue("Labels").jsonObject
            require(labels["io.p0v3.private-deployment"] == JsonPrimitive(spec.name) &&
                labels["io.p0v3.runtime-fingerprint"] == JsonPrimitive(fingerprint) &&
                state.getValue("State").jsonObject.getValue("Running").jsonPrimitive.boolean)
            val attached = state.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject
            require(attached.keys == spec.processes.single { it.id == processId }.networks.map {
                "p0v3-live-${spec.name}-$it"
            }.toSet()) { "Native Caddy network changed after private runtime audit" }
            val address = attached.getValue(network).jsonObject.getValue("IPAddress").jsonPrimitive.content
            require(address.matches(Regex("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) &&
                java.net.InetAddress.getByName(address).isSiteLocalAddress) { "Unowned client network address" }
            return address
        }
        /** Public Caddy's PRIMARY interface is the exact app-owned ingress-egress network;
         * Podman host 80/443 publication must forward to this interface, never an arbitrary
         * frontend network. Address discovery occurs after bootstrap, not in the sealed plan. */
        fun ownedPublicAddress(spec: PrivateDeploymentSpec, fingerprint: String,
            commands: RuntimeCommands = PrivateRootfulCommands(30, spec.store),
            audited: (PrivateDeploymentSpec, String) -> RuntimeAudit = { target, pin ->
                PrivateDeployment.real(mapOf(target.name to pin)).audit(target)
            }): String {
            PrivateDeployment.validate(spec)
            val publication = requireNotNull(spec.ingress)
            val caddy = spec.processes.single { it.id == "caddy" }
            require(spec.store == RuntimeStore.CANONICAL_V2 &&
                spec.networks.first() == "ingress-egress" && caddy.networks.first() == "ingress-egress" &&
                publication.listenAddress.matches(Regex("[0-9]{1,3}(\\.[0-9]{1,3}){3}"))) {
                "Public host forwarding requires an audited primary ingress interface"
            }
            val address = ownedProcessAddress(spec, fingerprint, "caddy", "ingress-egress", commands, audited)
            val observed = commands.run(listOf("inspect", "--type", "container", "p0v3-live-${spec.name}-caddy"))
            require(observed.exitCode == 0 && observed.output.length in 1..4194304)
            val container = Json.parseToJsonElement(observed.output).jsonArray.single().jsonObject
            val hostConfig = container.getValue("HostConfig").jsonObject
            val expectedNetwork = "p0v3-live-${spec.name}-ingress-egress"
            val bindings = hostConfig.getValue("PortBindings").jsonObject
            require(hostConfig.getValue("NetworkMode").jsonPrimitive.content == expectedNetwork &&
                bindings.keys == setOf("80/tcp", "443/tcp") &&
                listOf(80, 443).all { port ->
                    val entries = bindings.getValue("$port/tcp").jsonArray
                    entries.size == 1 && entries.single().jsonObject.let { entry ->
                        entry.getValue("HostIp").jsonPrimitive.content == publication.listenAddress &&
                            entry.getValue("HostPort").jsonPrimitive.content == port.toString()
                    }
                }) { "Podman public 80/443 publication does not target pinned primary network" }
            return address
        }
        /** Read-only /proc/net TCP listener inventory INSIDE the audited Caddy namespace.
         * In addition to Caddy JSON CAS, require actual 80/443 bound to the same primary IP;
         * separate exact-IP internal frontend 443 listeners are permitted, wildcards never. */
        fun auditPublicListeners(spec: PrivateDeploymentSpec, fingerprint: String,
            address: String, requireHttps: Boolean,
            helper: (ByteArray) -> ByteArray = ::runCaddyNamespaceHelper): Long {
            require(address == ownedPublicAddress(spec, fingerprint))
            val runtime = PrivateDeployment.real(mapOf(spec.name to fingerprint))
            val response = runtime.withCaddyAdmin(spec, fingerprint, false) { target ->
                val request = buildJsonObject {
                    put("operation", "audit-public-listeners"); put("pid", target.pid)
                    put("containerId", target.containerId); put("address", address)
                    put("requireHttps", requireHttps)
                }
                helper(request.toString().encodeToByteArray())
            }
            require(response.size in 1..8192)
            val record = Json.parseToJsonElement(response.decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(record.keys == setOf("address", "http", "https", "networkInode") &&
                record.getValue("address").jsonPrimitive.content == address &&
                record.getValue("http").jsonArray.map { it.jsonPrimitive.content } == listOf(address) &&
                (address in record.getValue("https").jsonArray.map { it.jsonPrimitive.content }) == requireHttps &&
                "0.0.0.0" !in record.getValue("https").jsonArray.map { it.jsonPrimitive.content } &&
                record.getValue("networkInode").jsonPrimitive.long > 1) {
                "Native 80/443 listener audit disagrees with exact primary ingress IP"
            }
            return record.getValue("networkInode").jsonPrimitive.long
        }
        fun auditInternalListener(spec: PrivateDeploymentSpec, fingerprint: String, network: String,
            address: String, helper: (ByteArray) -> ByteArray = ::runCaddyNamespaceHelper): Long {
            require(address == ownedProcessAddress(spec, fingerprint, "caddy", network))
            val runtime = PrivateDeployment.real(mapOf(spec.name to fingerprint))
            val response = runtime.withCaddyAdmin(spec, fingerprint, false) { target ->
                helper(buildJsonObject {
                    put("operation", "audit-internal-listener"); put("pid", target.pid)
                    put("containerId", target.containerId); put("address", address)
                }.toString().encodeToByteArray())
            }
            require(response.size in 1..8192)
            val record = Json.parseToJsonElement(response.decodeToString(throwOnInvalidSequence = true)).jsonObject
            val listening = record["https"]?.jsonArray?.map { it.jsonPrimitive.content }
            val http = record["http"]?.jsonArray?.map { it.jsonPrimitive.content }
            require(record.keys == setOf("address", "http", "https", "networkInode") &&
                record.getValue("address").jsonPrimitive.content == address &&
                listening != null && address in listening && "0.0.0.0" !in listening &&
                http != null && address !in http && "0.0.0.0" !in http &&
                record.getValue("networkInode").jsonPrimitive.long > 1)
            return record.getValue("networkInode").jsonPrimitive.long
        }
        /** Stop-only native readback after removing the fresh private qualification listener.
         * An uncertain old listener cannot be hidden by a successful Caddy JSON CAS. */
        fun auditNoInternalListener(spec: PrivateDeploymentSpec, fingerprint: String, network: String,
            address: String, helper: (ByteArray) -> ByteArray = ::runCaddyNamespaceHelper): Long {
            require(address == ownedProcessAddress(spec, fingerprint, "caddy", network))
            val runtime = PrivateDeployment.real(mapOf(spec.name to fingerprint))
            val response = runtime.withCaddyAdmin(spec, fingerprint, false) { target ->
                helper(buildJsonObject {
                    put("operation", "audit-absent-internal-listener"); put("pid", target.pid)
                    put("containerId", target.containerId); put("address", address)
                }.toString().encodeToByteArray())
            }
            require(response.size in 1..8192)
            val record = Json.parseToJsonElement(response.decodeToString(throwOnInvalidSequence = true)).jsonObject
            val listening = record["https"]?.jsonArray?.map { it.jsonPrimitive.content }
            val http = record["http"]?.jsonArray?.map { it.jsonPrimitive.content }
            require(record.keys == setOf("address", "http", "https", "networkInode") &&
                record.getValue("address").jsonPrimitive.content == address &&
                listening != null && address !in listening && "0.0.0.0" !in listening &&
                http != null && address !in http && "0.0.0.0" !in http &&
                record.getValue("networkInode").jsonPrimitive.long > 1) {
                "Fresh qualification listener is still bound; do not resume original source"
            }
            return record.getValue("networkInode").jsonPrimitive.long
        }
        fun checkBinding(binding: CaddySiteBinding, spec: PrivateDeploymentSpec) {
            require(binding.endpoint == "http://127.0.0.1:2019") { "Namespaced admin uses only container-loopback port 2019" }
            spec.ingress?.let { require(it.site == binding.site && it.approvedHosts == binding.approvedHosts) { "Ingress approval differs from sealed publication" } }
        }
    }
    override fun exchange(method: String, path: String, etag: String?, body: ByteArray?): CaddyReply {
        val read = method == "GET" && path == "/config/" && etag == null && body == null
        val write = ((method == "POST" && path == "/config/") || (method == "PATCH" &&
            path.matches(Regex("/config/apps/http/servers/[a-z][a-z0-9-]{0,63}/routes")))) &&
            etag?.matches(Regex("\"/config/ [a-f0-9]{16}\"")) == true && body != null && body.size in 1..4 * 1024 * 1024
        require(read || write)
        return audited(!read) { target ->
            require(target.pid > 1 && target.containerId.matches(Regex("[a-f0-9]{64}")))
            val request = buildJsonObject {
                put("pid", target.pid); put("containerId", target.containerId); put("method", method); put("path", path)
                put("etag", etag?.let(::JsonPrimitive) ?: JsonNull)
                put("body", body?.let { JsonPrimitive(Base64.getEncoder().encodeToString(it)) } ?: JsonNull)
            }
            val bytes = helper(request.toString().toByteArray())
            require(bytes.size in 1..8 * 1024 * 1024)
            val response = Json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(response.keys == setOf("status", "etag", "body"))
            val status = response.getValue("status").jsonPrimitive.int
            val responseBody = Base64.getDecoder().decode(response.getValue("body").jsonPrimitive.content)
            require(status in 100..599 && responseBody.size <= 4 * 1024 * 1024)
            CaddyReply(status, responseBody, response["etag"]?.takeUnless { it == JsonNull }?.jsonPrimitive?.content)
        }
    }
}

@Serializable internal data class RssIngressClientRequest(val operation: String, val generationId: String,
    val bridgeBindingFile: String, val bridgeBindingSha256: String, val targetFingerprint: String,
    val clientAddress: String, val clientNetwork: String, val originalHost: String,
    val originalLeafSha256: String, val ca: ActivationInput, val bearer: ActivationInput,
    val phase: String, val phaseClaimSha256: String, val caseClaimSha256: String,
    val invocationId: String, val account: String, val botAccount: String, val method: String, val path: String,
    val idempotencyKey: String? = null, val body: ActivationInput? = null)

/** The response body is a private 0600 file, never stdout, acceptance evidence or a public URI. */
@Serializable internal data class RssIngressClientResult(val operation: String, val bridgeBindingSha256: String,
    val phaseClaimSha256: String, val caseClaimSha256: String, val invocationId: String,
    val targetFingerprint: String, val clientNetwork: String, val clientAddress: String,
    val targetCaddyPid: Int, val clientProcessId: Int, val clientNetworkInode: Long,
    val status: Int, val leafSha256: String, val responseFile: String, val responseSha256: String)

/** The original per-case source scope is pure: pack adapters cannot acquire bot/status
 * authority even with a syntactically valid live phase/case claim. */
internal fun exactRssNativeReadScope(serviceId: String, account: String, botAccount: String,
    path: String): Boolean {
    val pack = serviceId.removePrefix("rss-pack-")
    val packCase = serviceId.startsWith("rss-pack-") && pack in setOf("analysis", "aus-state", "aus",
        "china-state", "china", "tas", "us-state", "us", "world")
    val workflow = serviceId in setOf("mastodon-rss-publisher", "rss-jobs")
    val real = account.matches(Regex("rss_[a-z0-9_]+")) && botAccount.isEmpty()
    val bot = account.matches(Regex("rssq_[a-f0-9]{12}")) && botAccount == account
    return (workflow || packCase) && (real || workflow && bot) &&
        (path == "/api/v1/accounts/verify_credentials" || workflow &&
            path.matches(Regex("/api/v1/statuses/[0-9]{1,32}(/source)?")))
}

/** Real controller-native HTTP client, not a container/application process or host-loopback proxy.
 * Only a sealed RSS case continuation can spend its one-use request. Admission, helper exit,
 * private response commit and bridge removal share a durable pending fence. The caller retains
 * controller exclusion + target/source isolation locks across the ENTIRE qualification phase.
 */
internal class RestoredIngressClient(private val root: Path, private val generation: Path,
    private val binding: RestoredBridgeBinding, private val sourceStopped: () -> Boolean,
    private val clientAddress: () -> String, private val configuration: () -> CaddyReply,
    private val audited: ((CaddyAdminTarget) -> ByteArray) -> ByteArray,
    private val helper: (ByteArray) -> ByteArray = ::runCaddyNamespaceHelper) {
    private val json = Json { encodeDefaults = true }
    private val hash = Regex("[a-f0-9]{64}")
    private fun content(input: ActivationInput, maximum: Int): ByteArray {
        require(input.sha256.matches(hash))
        return ReleasePrivateFiles.read(Path.of(input.path), maximum).also {
            require(ReleaseLocks.sha256(it) == input.sha256) { "Protected private client input changed" }
        }
    }
    /** Qualifier-selected RESTORE context binds source INSTALL result, invocation, original
     * oracle artifact and preserved token SHA to THIS live case. A caller cannot choose a
     * different 0600 generation file or relabel a synthetic bot as one of the real47. */
    private fun originalPrincipal(request: RssIngressClientRequest) {
        val claimPath = generation.resolve("rss/qualification-intents/${request.invocationId}.intent.json")
        val claimBytes = ReleasePrivateFiles.read(claimPath, 8192)
        require(ReleaseLocks.sha256(claimBytes) == request.caseClaimSha256)
        val claim = json.decodeFromString<RssQualificationIntent>(claimBytes.decodeToString())
        val workflow = claim.serviceId in setOf("mastodon-rss-publisher", "rss-jobs")
        val pack = claim.serviceId.removePrefix("rss-pack-")
        require(claim.invocationId == request.invocationId && claim.phase == "RESTORE" &&
            claim.generation == request.generationId && claim.phaseClaimSha256 == request.phaseClaimSha256 &&
            exactRssNativeReadScope(claim.serviceId, request.account, request.botAccount, request.path)) {
            "Pack cases may read only original feed account identity, never a synthetic bot or status"
        }
        val caseDirectory = Path.of(claim.caseDirectory)
        val contextBytes = ReleasePrivateFiles.read(caseDirectory.resolve("context.json"))
        require(ReleaseLocks.sha256(contextBytes) == claim.contextSha256)
        val context = json.parseToJsonElement(contextBytes.decodeToString()).jsonObject
        val sourcePath = Path.of(requireNotNull(context["sourceObservation"]).jsonPrimitive.content)
        val originalPath = Path.of(requireNotNull(context["sourceInvocation"]).jsonPrimitive.content)
        require(sourcePath.isAbsolute && sourcePath.normalize() == sourcePath &&
            sourcePath.fileName.toString() == "native-result.json" &&
            originalPath == sourcePath.parent.resolve("intent.json") &&
            sourcePath.parent.fileName.toString() == caseDirectory.fileName.toString()) {
            "Synthetic or foreign original RSS source observation"
        }
        val source = json.parseToJsonElement(ReleasePrivateFiles.read(sourcePath).decodeToString()).jsonObject
        val original = json.parseToJsonElement(ReleasePrivateFiles.read(originalPath).decodeToString()).jsonObject
        val current = json.parseToJsonElement(ReleasePrivateFiles.read(caseDirectory.resolve("intent.json")).decodeToString()).jsonObject
        fun obj(parent: JsonObject, name: String): JsonObject = requireNotNull(parent[name]).jsonObject
        fun text(parent: JsonObject, name: String) = requireNotNull(parent[name]).jsonPrimitive.content
        val originalBinding = obj(original, "binding")
        val currentBinding = obj(current, "binding")
        val assertions = obj(source, "assertions")
        require(source.getValue("schemaVersion").jsonPrimitive.int == 2 &&
            assertions.isNotEmpty() && assertions.keys == original.getValue("requiredAssertions").jsonArray
                .map { it.jsonPrimitive.content }.toSet() &&
            text(source, "phase") == "INSTALL" && text(originalBinding, "phase") == "INSTALL" &&
            text(currentBinding, "phase") == "RESTORE" && text(original, "serviceId") == claim.serviceId &&
            text(source, "serviceId") == claim.serviceId && text(current, "serviceId") == claim.serviceId &&
            text(originalBinding, "trialId") == text(currentBinding, "trialId") &&
            originalBinding["candidate"] == currentBinding["candidate"] &&
            text(source, "invocationId") == text(original, "invocationId") &&
            text(current, "invocationId") == request.invocationId &&
            text(originalBinding, "generationId") != request.generationId &&
            text(currentBinding, "generationId") == request.generationId &&
            text(source, "generationId") == text(originalBinding, "generationId") &&
            assertions.values.all { it.jsonPrimitive.boolean } &&
            obj(source, "artifacts").containsKey("oracle.json")) {
            "Original source oracle must be from the same passed INSTALL trial and candidate"
        }
        val oraclePath = sourcePath.parent.resolve("oracle.json")
        val oracleBytes = ReleasePrivateFiles.read(oraclePath)
        require(ReleaseLocks.sha256(oracleBytes) == text(obj(source, "artifacts"), "oracle.json")) {
            "Original RSS account oracle artifact changed"
        }
        val oracle = json.parseToJsonElement(oracleBytes.decodeToString()).jsonObject
        val expectedTokenPath: Path
        val originalTokenSha256: String
        if (request.account.matches(Regex("rssq_[a-f0-9]{12}"))) {
            require(workflow) { "A pack cannot borrow a publishing workflow bot" }
            val fixtureId = text(context, "fixtureId")
            require(request.botAccount == request.account && request.account == text(context, "fixtureSyntheticAccount") &&
                fixtureId.matches(Regex("rssq-[a-f0-9]{12}")) &&
                fixtureId == text(oracle, "fixtureId")) { "Synthetic bot identity differs from original fixture" }
            expectedTokenPath = generation.resolve("rss/qualification-custody/$fixtureId/bot.token")
            require(text(context, "fixtureSyntheticTokenFile") == expectedTokenPath.toString())
            originalTokenSha256 = text(oracle, "syntheticTokenSha256")
        } else {
            require(request.botAccount == "" && request.account.matches(Regex("rss_[a-z0-9_]+")))
            expectedTokenPath = generation.resolve("rss/tokens/${request.account}.token")
            val accounts = requireNotNull(oracle["accounts"]).jsonArray.map { it.jsonObject }
            val names = accounts.map { text(it, "account") }.toSet()
            if (workflow) require(accounts.size == 47 && names.size == 47) {
                "Publishing workflow requires the entire original real47 principal ledger"
            } else {
                val expected = RssPacks.load().filter { it.pack == pack }.map { it.feed.account }.toSet()
                require(text(oracle, "pack") == pack && expected.isNotEmpty() &&
                    accounts.size == expected.size && names == expected) {
                    "Pack source oracle must contain EXACTLY its approved reviewed feed accounts"
                }
            }
            val matching = accounts.filter { text(it, "account") == request.account }
            require(matching.size == 1 && text(matching.single(), "id").matches(Regex("[0-9]{1,32}")) &&
                matching.single().getValue("statuses").jsonPrimitive.int >= 0) {
                "Real original RSS principal absent or changed"
            }
            originalTokenSha256 = text(matching.single(), "tokenSha256")
            require(Path.of(text(context, "tokenDirectory")) == generation.resolve("rss/tokens"))
        }
        require(Path.of(request.bearer.path) == expectedTokenPath && request.bearer.sha256.matches(hash) &&
            request.bearer.sha256 == originalTokenSha256) {
            "Only the original source token preserved in the exact restored credential slot is authorized"
        }
    }
    private fun admitted(request: RssIngressClientRequest): RestoredBridgeResult {
        require(request.operation.matches(Regex("r-[a-f0-9]{12}")) &&
            request.operation != binding.operation && request.generationId == binding.targetGeneration &&
            generation.isAbsolute && generation.normalize() == generation &&
            generation.fileName.toString() == request.generationId &&
            request.targetFingerprint == binding.targetFingerprint &&
            request.clientNetwork == binding.clientNetwork && request.clientAddress == binding.clientAddress &&
            request.originalHost == "social.datamancy.net" && request.originalHost in binding.originalHosts &&
            "rss-mastodon" in binding.nativeClientCapabilities &&
            request.phase == "RESTORE" && request.method == "GET" && request.body == null &&
            request.idempotencyKey == null && request.invocationId.matches(Regex("case-[a-f0-9-]{36}")) &&
            request.phaseClaimSha256.matches(hash) && request.caseClaimSha256.matches(hash) &&
            request.originalLeafSha256.matches(hash) && request.bridgeBindingSha256.matches(hash) &&
            (request.botAccount == "" || request.botAccount.matches(Regex("rssq_[a-f0-9]{12}"))) &&
            (request.account.matches(Regex("rss_[a-z0-9_]+")) || request.account.matches(Regex("rssq_[a-f0-9]{12}"))) &&
            (request.path == "/api/v1/accounts/verify_credentials" ||
                request.path.matches(Regex("/api/v1/statuses/[0-9]{1,32}(/source)?")))) {
            "Native client must be a fixed original-SNI, read-only RSS RESTORE continuation"
        }
        val intentPath = root.resolve("${binding.operation}.intent.json")
        require(Path.of(request.bridgeBindingFile) == intentPath &&
            request.bridgeBindingSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(intentPath))) {
            "Unbound installed original-host bridge"
        }
        val intent = json.decodeFromString<RestoredBridgeIntent>(ReleasePrivateFiles.read(intentPath).decodeToString())
        val result = json.decodeFromString<RestoredBridgeResult>(ReleasePrivateFiles.read(
            root.resolve("${binding.operation}.result.json")).decodeToString())
        require(intent.binding == binding && intent.action == "install" && result.action == "install" &&
            result.operation == binding.operation && result.intentSha256 == request.bridgeBindingSha256 &&
            !Files.exists(root.resolve("bridge.pending"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("client.pending"), NOFOLLOW_LINKS) &&
            sourceStopped() && clientAddress() == request.clientAddress) {
            "Source resumed, Caddy bridge changed, or another native client has unresolved authority"
        }
        val observed = configuration()
        require(observed.status == 200 && observed.body.size in 1..4 * 1024 * 1024 &&
            TransactionalCaddy.digest(json.parseToJsonElement(observed.body.decodeToString()).jsonObject) == result.afterSha256) {
            "Restored original-host bridge is not presently installed"
        }
        val original = content(binding.sourceCertificates.getValue(request.originalHost), 65536)
        val leaf = CertificateFactory.getInstance("X.509").generateCertificate(original.inputStream())
        require(ReleaseLocks.sha256(leaf.encoded) == request.originalLeafSha256) {
            "Original source TLS leaf cannot be replaced with a new restored identity"
        }
        RssQualificationIntents.requireClear(generation, request.invocationId,
            request.caseClaimSha256, request.phaseClaimSha256)
        originalPrincipal(request)
        return result
    }
    fun request(input: RssIngressClientRequest): RssIngressClientResult {
        val installed = admitted(input)
        val ca = content(input.ca, 65536).decodeToString(throwOnInvalidSequence = true)
        val token = content(input.bearer, 2048).decodeToString(throwOnInvalidSequence = true).trimEnd('\n')
        val tokenPath = Path.of(input.bearer.path)
        require(tokenPath.startsWith(generation) && tokenPath.fileName.toString().matches(Regex("[a-z0-9.-]{1,64}")) &&
            token.matches(Regex("[A-Za-z0-9._~+/-]{20,2048}")) &&
            ca.contains("-----BEGIN CERTIFICATE-----")) { "Unowned RSS principal or CA trust anchor" }
        val intent = json.encodeToString(input).toByteArray()
        val path = root.resolve("client.${input.operation}.intent.json")
        ReleasePrivateFiles.locked(root) {
            val bridgeIntents = Files.list(root).use { stream ->
                val entries = stream.limit(1025).toList()
                require(entries.size <= 1024) { "Unbounded restored namespace client journal" }
                entries.map { it.fileName.toString() }
                    .filter { it.matches(Regex("r-[a-f0-9]{12}\\.intent\\.json")) }
            }
            require(bridgeIntents == listOf("${binding.operation}.intent.json") &&
                !Files.exists(root.resolve("client.pending"), NOFOLLOW_LINKS) &&
                !Files.exists(path, NOFOLLOW_LINKS) && !Files.exists(root.resolve("bridge.pending"), NOFOLLOW_LINKS)) {
                "Bridge was removed or a namespace client is uncertain; never start after source-resume eligibility"
            }
            ReleasePrivateFiles.save(path, intent)
            ReleasePrivateFiles.save(root.resolve("client.pending"), intent)
        }
        // The persisted intent precedes the FIRST native dial. Lost acknowledgments retain the
        // pending fence; a GET is never silently repeated, and POST is impossible on RESTORE.
        var targetPid = 0
        var targetNamespaceInode = 0L
        val output = audited { target ->
            require(target.pid > 1 && target.containerId.matches(hash) && sourceStopped() &&
                clientAddress() == input.clientAddress)
            val nativeInode = Files.readSymbolicLink(Path.of("/proc/${target.pid}/ns/net")).toString()
            require(nativeInode.matches(Regex("net:\\[[0-9]+]")))
            targetPid = target.pid
            targetNamespaceInode = nativeInode.substringAfter('[').substringBefore(']').toLong()
            val native = buildJsonObject {
                put("operation", "private-client"); put("operationId", input.operation)
                put("pid", target.pid); put("containerId", target.containerId)
                put("clientNetwork", input.clientNetwork); put("address", input.clientAddress)
                put("host", input.originalHost); put("caPem", ca); put("leafSha256", input.originalLeafSha256)
                put("method", input.method); put("path", input.path); put("token", token)
                put("body", JsonNull); put("phase", input.phase); put("account", input.account)
                put("botAccount", input.botAccount)
                put("idempotencyKey", JsonNull)
                put("phaseClaimSha256", input.phaseClaimSha256); put("caseClaimSha256", input.caseClaimSha256)
                put("invocationId", input.invocationId)
            }
            val bytes = helper(native.toString().encodeToByteArray())
            require(bytes.size in 1..2 * 1024 * 1024 &&
                Files.readSymbolicLink(Path.of("/proc/${target.pid}/ns/net")).toString() == nativeInode) {
                "Audited Caddy namespace changed during native client request"
            }
            bytes
        }
        val response = json.parseToJsonElement(output.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(response.keys == setOf("operationId", "phaseClaimSha256", "caseClaimSha256", "clientProcessId",
            "clientNetworkInode", "status", "leafSha256", "body") &&
            response.getValue("operationId").jsonPrimitive.content == input.operation &&
            response.getValue("phaseClaimSha256").jsonPrimitive.content == input.phaseClaimSha256 &&
            response.getValue("caseClaimSha256").jsonPrimitive.content == input.caseClaimSha256 &&
            response.getValue("leafSha256").jsonPrimitive.content == input.originalLeafSha256 &&
            targetPid > 1 && targetNamespaceInode > 1 &&
            response.getValue("clientProcessId").jsonPrimitive.int > 1 &&
            response.getValue("clientNetworkInode").jsonPrimitive.long == targetNamespaceInode) {
            "Unbound namespace client response; retain uncertain intent"
        }
        val body = Base64.getDecoder().decode(response.getValue("body").jsonPrimitive.content)
        require(body.size in 1..1024 * 1024)
        val reply = RssIngressClientResult(input.operation, input.bridgeBindingSha256,
            input.phaseClaimSha256, input.caseClaimSha256, input.invocationId, input.targetFingerprint,
            input.clientNetwork, input.clientAddress, targetPid, response.getValue("clientProcessId").jsonPrimitive.int,
            response.getValue("clientNetworkInode").jsonPrimitive.long, response.getValue("status").jsonPrimitive.int,
            input.originalLeafSha256, root.resolve("client.${input.operation}.response.bin").toString(), ReleaseLocks.sha256(body))
        require(reply.status in 100..599 && installed.afterSha256.matches(hash) && sourceStopped() &&
            clientAddress() == input.clientAddress)
        RssQualificationIntents.requireClear(generation, input.invocationId, input.caseClaimSha256, input.phaseClaimSha256)
        ReleasePrivateFiles.locked(root) {
            require(ReleasePrivateFiles.read(root.resolve("client.pending")).contentEquals(intent))
            ReleasePrivateFiles.save(Path.of(reply.responseFile), body)
            val record = json.encodeToString(reply).toByteArray()
            ReleasePrivateFiles.save(root.resolve("client.${input.operation}.result.json"), record)
            ReleasePrivateFiles.removeExact(root.resolve("client.pending"), intent)
        }
        return reply
    }
    companion object {
        fun real(generation: Path, bridgeBindingFile: Path, bridgeBindingSha256: String,
            source: PrivateDeploymentSpec, sourceFingerprint: String,
            target: PrivateDeploymentSpec): RestoredIngressClient {
            val bytes = ReleasePrivateFiles.read(bridgeBindingFile)
            require(bridgeBindingSha256.matches(Regex("[a-f0-9]{64}")) && ReleaseLocks.sha256(bytes) == bridgeBindingSha256)
            val intent = Json.decodeFromString<RestoredBridgeIntent>(bytes.decodeToString())
            val binding = intent.binding
            val root = Path.of("/mnt/media/p0-v3/restored-bridges").resolve(binding.site).resolve(binding.targetGeneration)
            require(bridgeBindingFile == root.resolve("${binding.operation}.intent.json") && intent.action == "install" &&
                generation.fileName.toString() == binding.targetGeneration &&
                source.name.startsWith("${binding.sourceGeneration}-") && sourceFingerprint.matches(Regex("[a-f0-9]{64}")) &&
                target.name.startsWith("${binding.targetGeneration}-") && target.store == RuntimeStore.CANONICAL_V2 &&
                target.ingress == null && binding.targetFingerprint.matches(Regex("[a-f0-9]{64}")) &&
                "rss-mastodon" in binding.nativeClientCapabilities && binding.clientNetwork in target.networks)
            // Validates source quiescence, original site/host authority, exact source+target
            // fingerprints and private client-only network before constructing any client.
            RestrictedRestoreBridge.real(root, binding, target, source, sourceFingerprint)
            val runtime = PrivateDeployment.real(mapOf(source.name to sourceFingerprint,
                target.name to binding.targetFingerprint))
            return RestoredIngressClient(root, generation, binding,
                { runtime.status(source).all { it.state != "running" } &&
                    listOf(80, 443).all { hostIngressPortOwner(it) == PortOwner.FREE } },
                { NamespaceCaddyTransport.ownedClientAddress(target, binding.targetFingerprint, binding.clientNetwork) },
                { NamespaceCaddyTransport.real(target, binding.targetFingerprint).exchange("GET", "/config/", null, null) },
                { action -> runtime.withCaddyAdmin(target, binding.targetFingerprint, false, action) })
        }
    }
}

internal fun runCaddyNamespaceHelper(request: ByteArray): ByteArray {
    val source = requireNotNull(NamespaceCaddyTransport::class.java.getResourceAsStream("/runtime/caddy-admin.py"))
        .use { it.readNBytes(65537) }.also { require(it.size in 1..65536) }.decodeToString(throwOnInvalidSequence = true)
    return runBoundedCaddyHelper(listOf("/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-c", source), request)
}

/** Exposed internally for synthetic subprocess unit fixtures, not a caller-controlled production CLI. */
internal fun runBoundedCaddyHelper(command: List<String>, request: ByteArray, seconds: Long = 35): ByteArray {
    require(request.size in 1..8 * 1024 * 1024 && seconds in 1..35)
    val builder = ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD)
    builder.environment().clear()
    val process = builder.start()
    val input = CompletableFuture.runAsync { process.outputStream.use { it.write(request) } }
    val output = CompletableFuture.supplyAsync { process.inputStream.use { it.readNBytes(8 * 1024 * 1024 + 1) } }
    try {
        check(process.waitFor(seconds, TimeUnit.SECONDS)) { "Caddy namespace exchange timed out; never replay a write" }
        input.get(1, TimeUnit.SECONDS)
        check(process.exitValue() == 0) { "Caddy namespace helper failed; retain uncertain intent" }
        return output.get(1, TimeUnit.SECONDS).also { require(it.size in 1..8 * 1024 * 1024) }
    } catch (error: InterruptedException) {
        Thread.currentThread().interrupt(); throw error
    } finally {
        process.descendants().forEach { it.destroyForcibly() }
        if (process.isAlive) process.destroyForcibly()
        input.cancel(true); output.cancel(true)
    }
}
