package net.datamancy.platform

import java.nio.file.Files
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.decodeFromString
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Only A11's three genuinely LOCAL provider endpoints. Public Grafana/Prom/Alert native
 * cases use the real pinned QClient/Caddy/Keykeeper original-Host/SNI path instead. */
@Serializable internal data class NativeQualificationRequest(val operation: String,
    val generationId: String, val targetMemberName: String, val targetFingerprint: String,
    val invocationId: String, val caseDirectory: String, val caseIntentSha256: String,
    val caseClaimSha256: String, val phase: String, val serviceId: String,
    val processId: String, val method: String, val path: String,
    val assertion: String, val authorizationMode: String = "NONE", val authorization: ActivationInput? = null,
    val body: ActivationInput? = null, val ca: ActivationInput? = null,
    val clientCert: ActivationInput? = null, val clientKey: ActivationInput? = null,
    val originalLeafSha256: String? = null, val sourceStopped: ActivationInput? = null,
    val sourceStoppedProofSha256: String? = null, val responseFile: String)

/** status=0/responseKind=TLS_ALERT only for real node client-certificate handshake refusal.
 * The responseFile is always a private mode0600 artifact (TLS alert JSON, not fake HTTP). */
@Serializable internal data class NativeQualificationResult(val operation: String,
    val invocationId: String, val caseClaimSha256: String, val targetFingerprint: String,
    val serviceId: String, val processId: String, val targetContainerId: String,
    val targetPid: Int, val targetNetnsInode: Long, val clientPid: Int,
    val requestSha256: String, val status: Int, val responseKind: String,
    val serverLeafSha256: String?, val responseFile: String, val responseSha256: String)

internal data class NativeQualificationTarget(val containerId: String, val pid: Int,
    val netnsInode: Long, val address: String, val port: Int)

/** Shared CASE AUTHORITY only, never a network/command capability. CrowdSec/OpenSearch/Office
 * must implement their own fixed endpoint/method/role table and per-operation one-use outbox. */
@Serializable internal data class NativeQualificationCaseBinding(val generationId: String, val invocationId: String,
    val caseDirectory: String, val caseIntentSha256: String, val caseClaimSha256: String,
    val serviceId: String, val phase: String, val targetMemberName: String,
    val targetFingerprint: String)
internal data class NativeQualificationCaseAuthority(val binding: NativeQualificationCaseBinding,
    val intent: JsonObject, val context: JsonObject, val claim: JsonObject)
internal object NativeQualificationClaims {
    private val json = Json { ignoreUnknownKeys = false }
    private val hash = Regex("[a-f0-9]{64}")
    fun read(binding: NativeQualificationCaseBinding): NativeQualificationCaseAuthority {
        require(binding.generationId.matches(Regex("q-[a-f0-9]{12}")) &&
            binding.invocationId.matches(Regex("[a-z][a-z0-9-]{0,95}")) &&
            binding.serviceId in setOf("alloy", "loki", "node-exporter", "onlyoffice", "crowdsec", "opensearch", "qbittorrent") &&
            binding.phase in setOf("INSTALL", "RESTORE") &&
            binding.targetMemberName.startsWith("${binding.generationId}-") &&
            binding.targetFingerprint.matches(hash) && binding.caseIntentSha256.matches(hash) &&
            binding.caseClaimSha256.matches(hash))
        val case = Path.of(binding.caseDirectory)
        require(case.isAbsolute && case.normalize() == case && case.toRealPath() == case &&
            Files.getPosixFilePermissions(case) == PosixFilePermissions.fromString("rwx------"))
        val bytes = ReleasePrivateFiles.read(case.resolve("intent.json"), 65536)
        val contextBytes = ReleasePrivateFiles.read(case.resolve("context.json"), 4194304)
        val intent = json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val context = json.parseToJsonElement(contextBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val phaseBinding = intent.getValue("binding").jsonObject
        require(ReleaseLocks.sha256(bytes) == binding.caseIntentSha256 &&
            intent.getValue("contextSha256").jsonPrimitive.content == ReleaseLocks.sha256(contextBytes) &&
            intent.getValue("invocationId").jsonPrimitive.content == binding.invocationId &&
            intent.getValue("serviceId").jsonPrimitive.content == binding.serviceId &&
            intent.getValue("surface").jsonPrimitive.content == "HEADLESS" &&
            intent.getValue("variant").jsonPrimitive.content == "NATIVE" &&
            phaseBinding.getValue("generationId").jsonPrimitive.content == binding.generationId &&
            phaseBinding.getValue("phase").jsonPrimitive.content == binding.phase &&
            "caseClaimSha256" !in context && "caseIntentSha256" !in context)
        // The protected claim is outside the runner's case mount and is minted only AFTER
        // both immutable raw files exist; otherwise a self-hashing authority cycle forms.
        val claimPath = GenerationRuntime.BASE.resolve(binding.generationId)
            .resolve("native-qualification-claims/${binding.invocationId}.json")
        val claimBytes = ReleasePrivateFiles.read(claimPath, 8192)
        val claim = json.parseToJsonElement(claimBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(ReleaseLocks.sha256(claimBytes) == binding.caseClaimSha256 &&
            claim.getValue("invocationId").jsonPrimitive.content == binding.invocationId &&
            claim.getValue("generationId").jsonPrimitive.content == binding.generationId &&
            claim.getValue("serviceId").jsonPrimitive.content == binding.serviceId &&
            claim.getValue("phase").jsonPrimitive.content == binding.phase &&
            claim.getValue("targetMemberName").jsonPrimitive.content == binding.targetMemberName &&
            claim.getValue("targetFingerprint").jsonPrimitive.content == binding.targetFingerprint &&
            claim.getValue("caseIntentSha256").jsonPrimitive.content == binding.caseIntentSha256 &&
            claim.getValue("contextSha256").jsonPrimitive.content == ReleaseLocks.sha256(contextBytes) &&
            claim.getValue("trialId") == phaseBinding.getValue("trialId") &&
            claim.getValue("candidate") == phaseBinding.getValue("candidate") &&
            claim.getValue("manifestSha256") == intent.getValue("manifestSha256")) {
            "Native case authority does not bind the original sealed invocation and protected target"
        }
        return NativeQualificationCaseAuthority(binding, intent, context, claim)
    }
}

internal data class NativeLogFixture(val run: String, val stamp: Long, val messageSha256: String)

internal fun nativeQualifiedPath(request: NativeQualificationRequest, fixture: NativeLogFixture?): Int {
    require(request.operation.matches(Regex("nq-[a-f0-9]{12}")) &&
        request.invocationId.matches(Regex("[a-z][a-z0-9-]{0,95}")) &&
        request.phase in setOf("INSTALL", "RESTORE") &&
        request.assertion in setOf("POSITIVE", "TLS_CLIENT_DENIAL", "PRIVATE_NETWORK_DENIAL") &&
        request.authorizationMode == "NONE" && request.authorization == null &&
        (request.phase == "INSTALL" || request.method == "GET" && request.body == null)) {
        "Only immutable locally confined original-provider cases may reach a private socket"
    }
    val query = fixture?.takeIf { it.run.matches(Regex("obs-[a-f0-9]{12}")) &&
        it.stamp > 1_000_000_000L && it.messageSha256.matches(Regex("[a-f0-9]{64}")) }?.let {
        "/loki/api/v1/query_range?query=%7Bjob%3D%22p0v3-acceptance%22%2Crun%3D%22${it.run}%22%7D" +
            "&start=${it.stamp - 1_000_000_000L}&end=${Math.addExact(it.stamp, 5_000_000_000L)}&limit=10"
    }
    return when {
        request.serviceId == "alloy" && request.processId == "alloy" &&
            request.method == "POST" && request.path == "/loki/api/v1/push" &&
            request.phase == "INSTALL" && request.assertion == "POSITIVE" && request.body != null &&
            request.ca == null && request.clientCert == null && request.clientKey == null -> 3500
        request.serviceId in setOf("alloy", "loki") && request.processId == "loki" &&
            request.method == "GET" && query != null && request.path == query &&
            request.body == null && request.ca == null && request.clientCert == null && request.clientKey == null &&
            request.assertion in setOf("POSITIVE", "PRIVATE_NETWORK_DENIAL") -> 3100
        request.serviceId == "node-exporter" && request.processId == "node" &&
            request.method == "GET" && request.path == "/metrics" &&
            request.body == null && request.ca != null &&
            request.originalLeafSha256?.matches(Regex("[a-f0-9]{64}")) == true &&
            (request.assertion == "POSITIVE" && request.clientCert != null && request.clientKey != null ||
                request.assertion == "TLS_CLIENT_DENIAL" && request.clientCert == null && request.clientKey == null) -> 9100
        else -> throw IllegalArgumentException("No fixed local native provider capability for this path/principal/phase")
    }
}

internal fun nativePrivateProviderProcess(spec: PrivateDeploymentSpec, processId: String): RuntimeProcess {
    val network = "observability-net"
    require(network in spec.networks &&
        spec.processes.filter { network in it.networks }.all { it.id in setOf(
            "node", "alloy", "loki", "prometheus", "grafana", "alertmanager", "metrics-init") }) {
        "A unique internal observability-only network is required in the composed release"
    }
    return spec.processes.single { it.id == processId }.also {
        require(processId in setOf("node", "alloy", "loki") &&
            it.networks == listOf(network) && !it.oneShot && it.userId != 0 &&
            it.capabilities.isEmpty() && it.id != spec.nativeIngress?.processId && it.id != "caddy") {
            "Only the original unprivileged local provider may own this native endpoint"
        }
    }
}

/** This is an actuator, not a qualifier: A11 adapters inspect original semantic log/metric
 * bytes after response. All operations are journal-first, generation-bound and one-use. */
internal class NativeQualificationClient(private val root: Path, private val spec: PrivateDeploymentSpec,
    private val fingerprint: String, private val inspect: (String, Int) -> NativeQualificationTarget,
    private val helper: (ByteArray) -> ByteArray = ::runCaddyNamespaceHelper) {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val hash = Regex("[a-f0-9]{64}")
    companion object {
        fun real(generation: Path, spec: PrivateDeploymentSpec, fingerprint: String): NativeQualificationClient {
            require(generation == GenerationRuntime.BASE.resolve(generation.fileName) &&
                generation.fileName.toString().matches(Regex("q-[a-f0-9]{12}")) &&
                spec.name.startsWith("${generation.fileName}-") &&
                spec.store == RuntimeStore.CANONICAL_V2 && fingerprint.matches(Regex("[a-f0-9]{64}")))
            val commands = PrivateRootfulCommands(30, spec.store)
            return NativeQualificationClient(generation.resolve("native-qualification"), spec, fingerprint,
                { process, port ->
                    val selected = nativePrivateProviderProcess(spec, process)
                    val inspected = commands.run(listOf("inspect", "--type", "container",
                        "p0v3-live-${spec.name}-$process"))
                    require(inspected.exitCode == 0 && inspected.output.length in 1..262144)
                    val entry = Json.parseToJsonElement(inspected.output).jsonArray.single().jsonObject
                    val config = entry.getValue("Config").jsonObject
                    val state = entry.getValue("State").jsonObject
                    val networks = entry.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject
                    require(entry.getValue("Id").jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")) &&
                        entry.getValue("Image").jsonPrimitive.content.removePrefix("sha256:") == selected.imageId &&
                        config.getValue("Labels").jsonObject.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
                        config.getValue("Labels").jsonObject.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == fingerprint &&
                        state.getValue("Running").jsonPrimitive.boolean && state.getValue("Pid").jsonPrimitive.int > 1 &&
                        networks.keys == selected.networks.map { "p0v3-live-${spec.name}-$it" }.toSet()) {
                        "No originally pinned and running local-only provider owns this native namespace"
                    }
                    val pid = state.getValue("Pid").jsonPrimitive.int
                    val inode = requireNotNull(Regex("net:\\[([0-9]+)]").matchEntire(
                        Files.readSymbolicLink(Path.of("/proc/$pid/ns/net")).toString())).groupValues[1].toLong()
                    val address = networks.getValue("p0v3-live-${spec.name}-observability-net").jsonObject
                        .getValue("IPAddress").jsonPrimitive.content
                    val octets = address.split('.').takeIf { it.size == 4 }?.map { it.toIntOrNull() }
                    require(inode > 1 && octets != null && octets.all { it != null && it in 0..255 } &&
                        java.net.InetAddress.getByAddress(octets.map { it!!.toByte() }.toByteArray()).isSiteLocalAddress)
                    NativeQualificationTarget(entry.getValue("Id").jsonPrimitive.content, pid, inode, address, port)
                })
        }
    }
    private fun input(source: ActivationInput?, maximum: Int): ByteArray? {
        if (source == null) return null
        require(source.sha256.matches(hash))
        return ReleasePrivateFiles.read(Path.of(source.path), maximum).also {
            require(ReleaseLocks.sha256(it) == source.sha256) { "Original private request input changed" }
        }
    }
    private fun case(request: NativeQualificationRequest): NativeLogFixture? {
        PrivateDeployment.validate(spec)
        require(request.generationId.matches(Regex("q-[a-f0-9]{12}")) &&
            root == GenerationRuntime.BASE.resolve(request.generationId).resolve("native-qualification") &&
            spec.name == request.targetMemberName && spec.name.startsWith("${request.generationId}-") &&
            fingerprint == request.targetFingerprint && hash.matches(fingerprint) &&
            spec.store == RuntimeStore.CANONICAL_V2 &&
            request.caseIntentSha256.matches(hash) && request.caseClaimSha256.matches(hash))
        nativePrivateProviderProcess(spec, request.processId)
        val sealed = NativeQualificationClaims.read(NativeQualificationCaseBinding(request.generationId,
            request.invocationId, request.caseDirectory, request.caseIntentSha256,
            request.caseClaimSha256, request.serviceId, request.phase, spec.name, fingerprint))
        val case = Path.of(request.caseDirectory)
        val intent = sealed.intent
        val context = sealed.context
        var oracle: JsonObject? = null
        var fixture: NativeLogFixture? = null
        if (request.phase == "RESTORE") {
            val source = Path.of(context.getValue("sourceObservation").jsonPrimitive.content)
            val sourceIntent = Path.of(context.getValue("sourceInvocation").jsonPrimitive.content)
            require(source.isAbsolute && source.normalize() == source &&
                source.fileName.toString() == "native-result.json" &&
                sourceIntent == source.parent.resolve("intent.json"))
            val original = json.parseToJsonElement(ReleasePrivateFiles.read(sourceIntent).decodeToString()).jsonObject
            val observed = json.parseToJsonElement(ReleasePrivateFiles.read(source).decodeToString()).jsonObject
            require(original.getValue("serviceId") == intent.getValue("serviceId") &&
                original.getValue("surface") == intent.getValue("surface") &&
                original.getValue("variant") == intent.getValue("variant") &&
                original.getValue("journey") == intent.getValue("journey") &&
                original.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content == "INSTALL" &&
                observed.getValue("phase").jsonPrimitive.content == "INSTALL" &&
                observed.getValue("generationId").jsonPrimitive.content != request.generationId &&
                original.getValue("binding").jsonObject.getValue("trialId") ==
                    intent.getValue("binding").jsonObject.getValue("trialId") &&
                original.getValue("binding").jsonObject.getValue("candidate") ==
                    intent.getValue("binding").jsonObject.getValue("candidate") &&
                observed.getValue("assertions").jsonObject.values.all { it.jsonPrimitive.boolean } &&
                observed.getValue("artifacts").jsonObject.containsKey("oracle.json")) {
                "Original INSTALL trial and oracle cannot be fabricated for native RESTORE"
            }
            val oracleBytes = ReleasePrivateFiles.read(source.parent.resolve("oracle.json"))
            require(ReleaseLocks.sha256(oracleBytes) == observed.getValue("artifacts").jsonObject
                .getValue("oracle.json").jsonPrimitive.content)
            oracle = json.parseToJsonElement(oracleBytes.decodeToString()).jsonObject
            val sourceStopped = requireNotNull(request.sourceStopped)
            val stoppedFile = Path.of(sourceStopped.path)
            val stopped = json.decodeFromString<ListenerBridgeQuiesceResult>(
                requireNotNull(input(sourceStopped, 8192)).decodeToString())
            require(stoppedFile.parent.parent == Path.of("/mnt/media/p0-v3/ingress-succession") &&
                stoppedFile.fileName.toString() == "${stopped.operation}.bridge-result.json" &&
                request.sourceStoppedProofSha256 == stopped.sourceStoppedProofSha256 &&
                stopped.targetGeneration == request.generationId &&
                stopped.sourceGeneration == observed.getValue("generationId").jsonPrimitive.content &&
                stopped.sourceStoppedProofSha256.matches(hash)) {
                "Only the actual original source-listener stop claim permits local native restore readback"
            }
            if (request.serviceId == "node-exporter") {
                require(oracle.getValue("kind").jsonPrimitive.content == "node-exporter-original" &&
                    oracle.getValue("targetProcessId").jsonPrimitive.content == "node" &&
                    oracle.getValue("sourceGenerationId").jsonPrimitive.content == stopped.sourceGeneration &&
                    request.ca?.sha256 == oracle.getValue("caSha256").jsonPrimitive.content &&
                    request.originalLeafSha256 == oracle.getValue("serverLeafSha256").jsonPrimitive.content &&
                    (request.assertion == "TLS_CLIENT_DENIAL" ||
                        request.clientCert?.sha256 == oracle.getValue("clientCertSha256").jsonPrimitive.content &&
                        request.clientKey?.sha256 == oracle.getValue("clientKeySha256").jsonPrimitive.content)) {
                    "Node original mTLS identity and client key must be preserved"
                }
            } else {
                val expected = if (request.serviceId == "alloy") "alloy-original-log" else "loki-original-history"
                fixture = NativeLogFixture(oracle.getValue("run").jsonPrimitive.content,
                    oracle.getValue("stamp").jsonPrimitive.long,
                    oracle.getValue("messageSha256").jsonPrimitive.content)
                require(oracle.getValue("kind").jsonPrimitive.content == expected &&
                    oracle.getValue("sourceGenerationId").jsonPrimitive.content == stopped.sourceGeneration &&
                    fixture.run.matches(Regex("obs-[a-f0-9]{12}")) &&
                    fixture.messageSha256.matches(hash)) {
                    "Only the original log run and message may be read from restored Loki"
                }
            }
        } else {
            require(request.sourceStopped == null && request.sourceStoppedProofSha256 == null &&
                "sourceObservation" !in context && "sourceInvocation" !in context)
            if (request.serviceId == "alloy") {
                val run = "obs-${ReleaseLocks.sha256(request.invocationId.encodeToByteArray()).take(12)}"
                val sourceLog = json.parseToJsonElement(ReleasePrivateFiles.read(
                    case.resolve("alloy-source-log.intent.json"), 8192).decodeToString()).jsonObject
                require(sourceLog.getValue("run").jsonPrimitive.content == run &&
                    sourceLog.getValue("schemaVersion").jsonPrimitive.int == 1 &&
                    sourceLog.getValue("bodySha256").jsonPrimitive.content.matches(hash))
                val stamp = sourceLog.getValue("stamp").jsonPrimitive.long
                val message = "P0 private original Alloy log $run"
                if (request.method == "POST") {
                    val raw = requireNotNull(input(request.body, 1024 * 1024))
                    require(sourceLog.getValue("bodySha256").jsonPrimitive.content == request.body?.sha256)
                    val data = json.parseToJsonElement(raw.decodeToString()).jsonObject
                    val stream = data.getValue("streams").jsonArray.single().jsonObject
                    val labels = stream.getValue("stream").jsonObject
                    val row = stream.getValue("values").jsonArray.single().jsonArray
                    require(labels.keys == setOf("job", "run") &&
                        labels.getValue("job").jsonPrimitive.content == "p0v3-acceptance" &&
                        labels.getValue("run").jsonPrimitive.content == run &&
                        row.size == 2 && row[0].jsonPrimitive.content == stamp.toString() &&
                        row[1].jsonPrimitive.content == message)
                } else {
                    val post = "nq-${ReleaseLocks.sha256((request.invocationId + "\nalloy\nowned-source-log-push")
                        .encodeToByteArray()).take(12)}"
                    val home = root.resolve(request.invocationId)
                    val attempted = json.decodeFromString<NativeQualificationRequest>(
                        ReleasePrivateFiles.read(home.resolve("$post.intent.json")).decodeToString())
                    val receipt = json.decodeFromString<NativeQualificationResult>(
                        ReleasePrivateFiles.read(home.resolve("$post.result.json")).decodeToString())
                    require(attempted.method == "POST" && attempted.serviceId == "alloy" &&
                        attempted.processId == "alloy" && attempted.phase == "INSTALL" &&
                        attempted.body?.sha256 == sourceLog.getValue("bodySha256").jsonPrimitive.content &&
                        attempted.caseClaimSha256 == request.caseClaimSha256 &&
                        receipt.operation == post && receipt.serviceId == "alloy" &&
                        receipt.processId == "alloy" && receipt.status in setOf(200, 202, 204) &&
                        receipt.responseKind == "HTTP" &&
                        !Files.exists(home.resolve("pending.json"), NOFOLLOW_LINKS)) {
                        "Alloy original one-use POST must complete before reading its Loki log"
                    }
                }
                fixture = NativeLogFixture(run, stamp, ReleaseLocks.sha256(message.encodeToByteArray()))
            } else if (request.serviceId == "loki") {
                val source = Path.of(context.getValue("alloySourceOracleFile").jsonPrimitive.content)
                val observation = Path.of(context.getValue("alloySourceObservationFile").jsonPrimitive.content)
                val original = ReleasePrivateFiles.read(source, 8192)
                val observedBytes = ReleasePrivateFiles.read(observation, 65536)
                require(source.isAbsolute && source.normalize() == source &&
                    source.fileName.toString() == "oracle.json" &&
                    observation == source.parent.resolve("native-result.json") &&
                    ReleaseLocks.sha256(original) ==
                        context.getValue("alloySourceOracleSha256").jsonPrimitive.content &&
                    ReleaseLocks.sha256(observedBytes) ==
                        context.getValue("alloySourceObservationSha256").jsonPrimitive.content)
                val log = json.parseToJsonElement(original.decodeToString()).jsonObject
                val observed = json.parseToJsonElement(observedBytes.decodeToString()).jsonObject
                val previous = json.parseToJsonElement(ReleasePrivateFiles.read(source.parent.resolve("result.json"),
                    65536).decodeToString()).jsonObject
                require(log.getValue("kind").jsonPrimitive.content == "alloy-original-log" &&
                    log.getValue("sourceGenerationId").jsonPrimitive.content == request.generationId &&
                    observed.getValue("schemaVersion").jsonPrimitive.int == 2 &&
                    observed.getValue("serviceId").jsonPrimitive.content == "alloy" &&
                    observed.getValue("surface").jsonPrimitive.content == "HEADLESS" &&
                    observed.getValue("variant").jsonPrimitive.content == "NATIVE" &&
                    observed.getValue("phase").jsonPrimitive.content == "INSTALL" &&
                    observed.getValue("generationId").jsonPrimitive.content == request.generationId &&
                    observed.getValue("artifacts").jsonObject.getValue("oracle.json").jsonPrimitive.content ==
                        ReleaseLocks.sha256(original) &&
                    observed.getValue("assertions").jsonObject.values.all { it.jsonPrimitive.boolean } &&
                    previous.getValue("passed").jsonPrimitive.boolean &&
                    previous.getValue("finished").jsonPrimitive.boolean &&
                    previous.getValue("exitCode").jsonPrimitive.int == 0 &&
                    previous.getValue("observationSha256").jsonPrimitive.content ==
                        ReleaseLocks.sha256(observedBytes) &&
                    previous.getValue("artifactHashes").jsonObject.getValue("oracle.json").jsonPrimitive.content ==
                        ReleaseLocks.sha256(original)) {
                    "Only a completed original same-generation Alloy case can authorize a Loki query"
                }
                fixture = NativeLogFixture(log.getValue("run").jsonPrimitive.content,
                    log.getValue("stamp").jsonPrimitive.long, log.getValue("messageSha256").jsonPrimitive.content)
            } else if (request.serviceId == "node-exporter") {
                val tls = context.getValue("nodeTls").jsonObject
                require(tls.getValue("caSha256").jsonPrimitive.content == request.ca?.sha256 &&
                    tls.getValue("serverLeafSha256").jsonPrimitive.content == request.originalLeafSha256 &&
                    (request.assertion == "TLS_CLIENT_DENIAL" ||
                        tls.getValue("clientCertSha256").jsonPrimitive.content == request.clientCert?.sha256 &&
                        tls.getValue("clientKeySha256").jsonPrimitive.content == request.clientKey?.sha256))
            }
        }
        nativeQualifiedPath(request, fixture)
        if (request.serviceId == "node-exporter" && request.assertion == "TLS_CLIENT_DENIAL") {
            val positive = "nq-${ReleaseLocks.sha256((request.invocationId +
                "\nnode-exporter\noriginal-textfile-scrape").encodeToByteArray()).take(12)}"
            val home = root.resolve(request.invocationId)
            val first = json.decodeFromString<NativeQualificationResult>(ReleasePrivateFiles.read(
                home.resolve("$positive.result.json")).decodeToString())
            require(first.status == 200 && first.responseKind == "HTTP" &&
                first.operation == positive && first.processId == "node" &&
                first.caseClaimSha256 == request.caseClaimSha256 &&
                first.serverLeafSha256 == request.originalLeafSha256 &&
                first.targetFingerprint == request.targetFingerprint &&
                !Files.exists(home.resolve("pending.json"), NOFOLLOW_LINKS)) {
                "A genuine original same-target positive TLS leaf and metric must precede node denial"
            }
        }
        return fixture
    }
    private fun native(request: NativeQualificationRequest, port: Int): NativeQualificationTarget {
        return inspect(request.processId, port).also { require(it.port == port &&
            it.containerId.matches(hash) && it.pid > 1 && it.netnsInode > 1) }
    }
    private fun makeRoot() {
        ReleasePrivateFiles.directory(root.parent)
        if (!Files.exists(root, NOFOLLOW_LINKS)) {
            Files.createDirectory(root, PosixFilePermissions.asFileAttribute(
                PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root.parent)
        }
        ReleasePrivateFiles.directory(root)
    }
    private fun networkDenial(request: NativeQualificationRequest, target: NativeQualificationTarget,
        requestSha: String, home: Path, intentBytes: ByteArray): NativeQualificationResult {
        require(request.method == "GET" && request.processId == "loki" &&
            request.serviceId in setOf("loki", "alloy") && target.port == 3100)
        val qRoot = GenerationRuntime.BASE.resolve(request.generationId)
            .resolve("qualification-client").resolve(request.invocationId)
        val qnative = json.decodeFromString<QualificationClientNative>(
            ReleasePrivateFiles.read(qRoot.resolve("native.json"), 8192).decodeToString())
        val policy = json.decodeFromString<QualificationTurnPolicy>(
            ReleasePrivateFiles.read(qRoot.resolve("turn-policy.json"), 8192).decodeToString())
        val qintent = json.decodeFromString<QualificationClientIntent>(
            ReleasePrivateFiles.read(qRoot.resolve("intent.json"), 8192).decodeToString())
        val gateBytes = ReleasePrivateFiles.read(Path.of(request.caseDirectory)
            .resolve("qualification-client-gate.json"), 8192)
        val gate = json.parseToJsonElement(gateBytes.decodeToString()).jsonObject
        require(qnative.containerId.matches(hash) && qnative.pid > 1 && qnative.netnsInode > 1 &&
            target.netnsInode != qnative.netnsInode &&
            qintent.network == "qualification-web" &&
            qintent.requestSha256.matches(hash) &&
            gate.getValue("invocationId").jsonPrimitive.content == request.invocationId &&
            gate.getValue("nativeContainerId").jsonPrimitive.content == qnative.containerId &&
            gate.getValue("requestSha256").jsonPrimitive.content == qintent.requestSha256 &&
            gate.getValue("policySha256").jsonPrimitive.content == ReleaseLocks.sha256(
                ReleasePrivateFiles.read(qRoot.resolve("turn-policy.json"), 8192)) &&
            policy.containerId == qnative.containerId && policy.containerPid == qnative.pid &&
            policy.containerNetnsInode == qnative.netnsInode &&
            policy.invocationId == request.invocationId &&
            policy.generationId == request.generationId &&
            policy.nftTable.matches(Regex("p0v3_qc_[a-f0-9]{12}"))) {
            "No already-running fixed native QClient denial policy exists for this exact case"
        }
        // Pin native Podman running identity immediately before the unauthorized socket.
        val observed = PrivateRootfulCommands(30, spec.store).run(listOf("inspect", "--type", "container",
            "p0v3-qc-${request.generationId}-${request.invocationId}"))
        require(observed.exitCode == 0 && observed.output.length in 1..262144)
        val container = Json.parseToJsonElement(observed.output).jsonArray.single().jsonObject
        require(container.getValue("Id").jsonPrimitive.content == qnative.containerId &&
            container.getValue("State").jsonObject.getValue("Pid").jsonPrimitive.int == qnative.pid &&
            container.getValue("State").jsonObject.getValue("Running").jsonPrimitive.boolean &&
            Files.readSymbolicLink(Path.of("/proc/${qnative.pid}/ns/net")).toString() ==
                "net:[${qnative.netnsInode}]" &&
            policy.nftTable.matches(Regex("p0v3_qc_[a-f0-9]{12}")))
        val helperSource = requireNotNull(NativeQualificationClient::class.java
            .getResourceAsStream("/runtime/native-qualifier.py")).use { it.readNBytes(65537) }
        require(helperSource.size in 1..65536)
        val helperRequest = buildJsonObject {
            put("operation", "native-network-denial"); put("operationId", request.operation)
            put("invocationId", request.invocationId); put("caseClaimSha256", request.caseClaimSha256)
            put("qclientPid", qnative.pid); put("qclientContainerId", qnative.containerId)
            put("qclientNetnsInode", qnative.netnsInode); put("table", policy.nftTable)
            put("targetAddress", target.address); put("targetPort", target.port)
            put("targetContainerId", target.containerId); put("targetPid", target.pid)
            put("targetNetnsInode", target.netnsInode); put("serviceId", request.serviceId)
            put("processId", request.processId); put("requestSha256", requestSha)
        }
        val probe = runBoundedCaddyHelper(listOf("/usr/bin/sudo", "-n", "/usr/bin/python3",
            "-I", "-c", helperSource.decodeToString(throwOnInvalidSequence = true)),
            helperRequest.toString().encodeToByteArray(), 20)
        val result = json.parseToJsonElement(probe.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(result.getValue("targetContainerId").jsonPrimitive.content == target.containerId &&
            result.getValue("targetPid").jsonPrimitive.int == target.pid &&
            result.getValue("targetNetnsInode").jsonPrimitive.long == target.netnsInode &&
            result.getValue("qclientContainerId").jsonPrimitive.content == qnative.containerId &&
            result.getValue("qclientNetnsInode").jsonPrimitive.long == qnative.netnsInode &&
            result.getValue("caseClaimSha256").jsonPrimitive.content == request.caseClaimSha256 &&
            result.getValue("requestSha256").jsonPrimitive.content == requestSha &&
            result.getValue("dropCounterAfter").jsonPrimitive.long >
                result.getValue("dropCounterBefore").jsonPrimitive.long &&
            result.getValue("connectFailed").jsonPrimitive.boolean &&
            result.getValue("clientPid").jsonPrimitive.int > 1)
        val response = home.resolve("${request.operation}.response")
        val evidence = result.toString().encodeToByteArray()
        ReleasePrivateFiles.save(response, evidence)
        val typed = NativeQualificationResult(request.operation, request.invocationId,
            request.caseClaimSha256, fingerprint, request.serviceId, request.processId,
            target.containerId, target.pid, target.netnsInode,
            result.getValue("clientPid").jsonPrimitive.int, requestSha, 0, "NETWORK_DENIAL",
            null, response.toString(), ReleaseLocks.sha256(evidence))
        ReleasePrivateFiles.save(home.resolve("${request.operation}.result.json"),
            json.encodeToString(typed).encodeToByteArray())
        ReleasePrivateFiles.removeExact(home.resolve("pending.json"), intentBytes)
        return typed
    }
    fun request(request: NativeQualificationRequest): NativeQualificationResult {
        val fixture = case(request)
        val port = nativeQualifiedPath(request, fixture)
        require(request.responseFile == root.resolve(request.invocationId)
            .resolve("${request.operation}.response").toString())
        val target = native(request, port)
        if (request.serviceId == "node-exporter" && request.assertion == "TLS_CLIENT_DENIAL") {
            val positive = "nq-${ReleaseLocks.sha256((request.invocationId +
                "\nnode-exporter\noriginal-textfile-scrape").encodeToByteArray()).take(12)}"
            val first = json.decodeFromString<NativeQualificationResult>(ReleasePrivateFiles.read(
                root.resolve(request.invocationId).resolve("$positive.result.json")).decodeToString())
            require(first.targetContainerId == target.containerId && first.targetPid == target.pid &&
                first.targetNetnsInode == target.netnsInode) {
                "Node missing-certificate alert must be from the already verified positive original TLS process"
            }
        }
        val body = input(request.body, 1024 * 1024)
        val ca = input(request.ca, 65536)
        val cert = input(request.clientCert, 65536)
        val key = input(request.clientKey, 65536)
        makeRoot()
        val home = root.resolve(request.invocationId)
        if (!Files.exists(home, NOFOLLOW_LINKS)) {
            Files.createDirectory(home, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root)
        }
        return ReleasePrivateFiles.locked(home) {
            // The A11 adapter persists this exact request BEFORE the protected CLI. Its
            // sorted JSON wire bytes, not reserialized Kotlin property order, bind result.
            val requestBytes = ReleasePrivateFiles.read(home.resolve("${request.operation}.request.json"), 65536)
            require(json.decodeFromString<NativeQualificationRequest>(requestBytes.decodeToString()) == request)
            val requestSha = ReleaseLocks.sha256(requestBytes)
            require(!Files.exists(home.resolve("pending.json"), NOFOLLOW_LINKS) &&
                !Files.exists(home.resolve("${request.operation}.intent.json"), NOFOLLOW_LINKS) &&
                !Files.exists(home.resolve("${request.operation}.response"), NOFOLLOW_LINKS)) {
                "An attempted native effect may not be resent after a lost response"
            }
            val intentBytes = requestBytes
            ReleasePrivateFiles.save(home.resolve("${request.operation}.intent.json"), intentBytes)
            ReleasePrivateFiles.save(home.resolve("pending.json"), intentBytes)
            if (request.assertion == "PRIVATE_NETWORK_DENIAL") {
                return@locked networkDenial(request, target, requestSha, home, intentBytes)
            }
            val helperRequest = buildJsonObject {
                put("operation", "native-qualification"); put("operationId", request.operation)
                put("pid", target.pid); put("containerId", target.containerId)
                put("netnsInode", target.netnsInode); put("invocationId", request.invocationId)
                put("caseClaimSha256", request.caseClaimSha256)
                put("requestSha256", requestSha); put("serviceId", request.serviceId)
                put("processId", request.processId); put("phase", request.phase)
                put("assertion", request.assertion); put("method", request.method)
                put("path", request.path); put("address", target.address)
                put("port", port); put("host", request.processId)
                put("caPem", ca?.decodeToString(throwOnInvalidSequence = true)?.let(::JsonPrimitive) ?: JsonNull)
                put("leafSha256", request.originalLeafSha256?.let(::JsonPrimitive) ?: JsonNull)
                put("clientCert", cert?.decodeToString(throwOnInvalidSequence = true)?.let(::JsonPrimitive) ?: JsonNull)
                put("clientKey", key?.decodeToString(throwOnInvalidSequence = true)?.let(::JsonPrimitive) ?: JsonNull)
                put("authorizationMode", "NONE"); put("authorization", JsonNull)
                put("body", body?.let { JsonPrimitive(Base64.getEncoder().encodeToString(it)) } ?: JsonNull)
            }
            val resultBytes = helper(helperRequest.toString().encodeToByteArray())
            require(resultBytes.size in 1..8 * 1024 * 1024)
            val output = json.parseToJsonElement(resultBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
            val base = setOf("status", "responseKind", "body", "containerId", "pid", "netnsInode", "clientPid")
            require(output.keys == base + "serverLeafSha256" ||
                output.keys == base && request.assertion == "TLS_CLIENT_DENIAL")
            val status = output.getValue("status").jsonPrimitive.int
            val kind = output.getValue("responseKind").jsonPrimitive.content
            require(output.getValue("containerId").jsonPrimitive.content == target.containerId &&
                output.getValue("pid").jsonPrimitive.int == target.pid &&
                output.getValue("netnsInode").jsonPrimitive.long == target.netnsInode &&
                (request.assertion == "TLS_CLIENT_DENIAL" && status == 0 && kind == "TLS_ALERT" ||
                    request.assertion == "POSITIVE" && status in 200..299 && kind == "HTTP")) {
                "Only native target process namespace and actual allowed protocol outcome are accepted"
            }
            val bytes = Base64.getDecoder().decode(output.getValue("body").jsonPrimitive.content)
            require(bytes.size <= 1024 * 1024 && (bytes.isNotEmpty() ||
                request.serviceId == "alloy" && request.processId == "alloy" &&
                request.method == "POST" && status == 204) &&
                output.getValue("clientPid").jsonPrimitive.int > 1 &&
                (request.serviceId != "node-exporter" ||
                request.assertion == "TLS_CLIENT_DENIAL" ||
                output.getValue("serverLeafSha256").jsonPrimitive.content == request.originalLeafSha256))
            val response = home.resolve("${request.operation}.response")
            if (bytes.isNotEmpty()) ReleasePrivateFiles.save(response, bytes)
            else {
                // HTTP204 has a genuine zero-byte body. A private empty mode0600 artifact
                // preserves its SHA256 without fabricating a product response.
                FileChannel.open(response, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS),
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use {
                    it.force(true)
                }
                ReleasePrivateFiles.sync(home)
            }
            val result = NativeQualificationResult(request.operation, request.invocationId, request.caseClaimSha256,
                fingerprint, request.serviceId, request.processId, target.containerId, target.pid, target.netnsInode,
                output.getValue("clientPid").jsonPrimitive.int, requestSha, status, kind,
                output["serverLeafSha256"]?.takeUnless { it == JsonNull }?.jsonPrimitive?.content,
                response.toString(), ReleaseLocks.sha256(bytes))
            ReleasePrivateFiles.save(home.resolve("${request.operation}.result.json"), json.encodeToString(result).encodeToByteArray())
            ReleasePrivateFiles.removeExact(home.resolve("pending.json"), intentBytes)
            result
        }
    }
}

/** A12's ORIGINAL index/document, not a general search API or a user-provided native socket.
 * The case-to-controller request broker is COORD-owned; this actuator consumes a 0600
 * generation-owned copy and never accepts an arbitrary host, URL, index or credential. */
@Serializable internal data class OpenSearchNativeQualificationRequest(val operation: String,
    val binding: NativeQualificationCaseBinding, val role: String, val action: String,
    val ca: ActivationInput, val adminCert: ActivationInput, val adminKey: ActivationInput,
    val nodeCert: ActivationInput, val nodeKey: ActivationInput, val serverLeafSha256: String,
    val originalDocumentSha256: String, val body: ActivationInput? = null,
    val sourceStopped: ActivationInput? = null, val sourceStoppedProofSha256: String? = null,
    val responseFile: String)
@Serializable internal data class OpenSearchNativeQualificationResult(val operation: String,
    val invocationId: String, val caseClaimSha256: String, val targetFingerprint: String,
    val targetContainerId: String, val targetPid: Int, val targetNetnsInode: Long,
    val clientPid: Int, val requestSha256: String, val role: String, val action: String,
    val status: Int, val serverLeafSha256: String, val originalDocumentSha256: String,
    val responseFile: String, val responseSha256: String)

internal data class OpenSearchNativeFixedOperation(val method: String, val path: String,
    val document: String, val privateText: String)
internal fun openSearchNativeFixedOperation(request: OpenSearchNativeQualificationRequest,
    original: JsonObject): OpenSearchNativeFixedOperation {
    val b = request.binding
    val hash = Regex("[a-f0-9]{64}")
    require(b.serviceId == "opensearch" && b.phase in setOf("INSTALL", "RESTORE") &&
        request.operation.matches(Regex("nq-[a-f0-9]{12}")) &&
        request.serverLeafSha256.matches(hash) && request.originalDocumentSha256.matches(hash) &&
        original.keys == setOf("privateText", "sourceGeneration", "version") &&
        original.getValue("version").jsonPrimitive.int == 1 &&
        original.getValue("sourceGeneration").jsonPrimitive.content.matches(Regex("q-[a-f0-9]{12}")))
    val text = original.getValue("privateText").jsonPrimitive.content
    require(text.matches(Regex("a12-original-native-search-[a-z][a-z0-9-]{0,95}")) &&
        (b.phase == "RESTORE" || text == "a12-original-native-search-${b.invocationId}" &&
            original.getValue("sourceGeneration").jsonPrimitive.content == b.generationId))
    val path = "/p0v3-private-history/_doc/original-private-event"
    return when (request.action) {
        "CREATE" -> {
            require(b.phase == "INSTALL" && request.role == "ADMIN" && request.body != null)
            OpenSearchNativeFixedOperation("PUT", "$path?op_type=create&refresh=wait_for",
                "original-private-event", text)
        }
        "DOCUMENT" -> {
            require(request.role == "ADMIN" && request.body == null)
            OpenSearchNativeFixedOperation("GET", path, "original-private-event", text)
        }
        "HISTORY" -> {
            require(request.role == "ADMIN" && request.body == null)
            val query = java.net.URLEncoder.encode("privateText.keyword:$text", Charsets.UTF_8).replace("+", "%20")
            OpenSearchNativeFixedOperation("GET", "/p0v3-private-history/_search?q=$query&size=2",
                "original-private-event", text)
        }
        "DENY" -> {
            require(request.role == "NODE" && request.body == null)
            OpenSearchNativeFixedOperation("GET", path, "original-private-event", text)
        }
        else -> throw IllegalArgumentException("No fixed native OpenSearch action")
    }
}

internal class OpenSearchNativeQualificationClient(private val root: Path, private val spec: PrivateDeploymentSpec,
    private val fingerprint: String, private val inspect: () -> NativeQualificationTarget,
    private val helper: (ByteArray) -> ByteArray = ::runCaddyNamespaceHelper) {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val hash = Regex("[a-f0-9]{64}")
    companion object {
        fun real(generation: Path, spec: PrivateDeploymentSpec, fingerprint: String): OpenSearchNativeQualificationClient {
            require(generation == GenerationRuntime.BASE.resolve(generation.fileName) &&
                generation.fileName.toString().matches(Regex("q-[a-f0-9]{12}")) &&
                spec.name.startsWith("${generation.fileName}-") && spec.store == RuntimeStore.CANONICAL_V2 &&
                fingerprint.matches(Regex("[a-f0-9]{64}")))
            val commands = PrivateRootfulCommands(30, spec.store)
            return OpenSearchNativeQualificationClient(generation.resolve("native-qualification"), spec, fingerprint, {
                val process = spec.processes.single { it.id == "opensearch" }
                val inspection = commands.run(listOf("inspect", "--type", "container", "p0v3-live-${spec.name}-opensearch"))
                require(inspection.exitCode == 0 && inspection.output.length in 1..262144)
                val entry = Json.parseToJsonElement(inspection.output).jsonArray.single().jsonObject
                val config = entry.getValue("Config").jsonObject
                val state = entry.getValue("State").jsonObject
                val networks = entry.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject
                require(entry.getValue("Id").jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")) &&
                    entry.getValue("Image").jsonPrimitive.content.removePrefix("sha256:") == process.imageId &&
                    config.getValue("Labels").jsonObject.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
                    config.getValue("Labels").jsonObject.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == fingerprint &&
                    state.getValue("Running").jsonPrimitive.boolean && state.getValue("Pid").jsonPrimitive.int > 1 &&
                    networks.keys == setOf("p0v3-live-${spec.name}-opensearch-data"))
                val pid = state.getValue("Pid").jsonPrimitive.int
                val inode = requireNotNull(Regex("net:\\[([0-9]+)]").matchEntire(
                    Files.readSymbolicLink(Path.of("/proc/$pid/ns/net")).toString())).groupValues[1].toLong()
                val address = networks.getValue("p0v3-live-${spec.name}-opensearch-data").jsonObject
                    .getValue("IPAddress").jsonPrimitive.content
                val octets = address.split('.').takeIf { it.size == 4 }?.map { it.toIntOrNull() }
                require(inode > 1 && octets != null && octets.all { it != null && it in 0..255 } &&
                    java.net.InetAddress.getByAddress(octets.map { it!!.toByte() }.toByteArray()).isSiteLocalAddress)
                NativeQualificationTarget(entry.getValue("Id").jsonPrimitive.content, pid, inode, address, 9200)
            })
        }
    }
    private fun bytes(input: ActivationInput, limit: Int): ByteArray =
        ReleasePrivateFiles.read(Path.of(input.path), limit).also {
            require(input.sha256.matches(hash) && ReleaseLocks.sha256(it) == input.sha256)
        }
    fun request(request: OpenSearchNativeQualificationRequest): OpenSearchNativeQualificationResult {
        val b = request.binding
        PrivateDeployment.validate(spec)
        require(root == GenerationRuntime.BASE.resolve(b.generationId).resolve("native-qualification") &&
            b.targetMemberName == spec.name && b.targetFingerprint == fingerprint &&
            b.serviceId == "opensearch" && spec.store == RuntimeStore.CANONICAL_V2 &&
            spec.networks.contains("opensearch-data") &&
            spec.processes.filter { "opensearch-data" in it.networks }.all {
                it.id in setOf("opensearch", "opensearch-config-init", "opensearch-security-init") } &&
            spec.processes.single { it.id == "opensearch" }.let {
                it.networks == listOf("opensearch-data") && !it.oneShot && it.userId != 0 && it.capabilities.isEmpty() } &&
            request.responseFile == root.resolve(b.invocationId).resolve("${request.operation}.response").toString())
        val sealed = NativeQualificationClaims.read(b)
        val context = sealed.context
        val metadata = context.getValue("opensearchNative").jsonObject
        val pins = listOf("ca" to request.ca, "adminCert" to request.adminCert,
            "adminKey" to request.adminKey, "nodeCert" to request.nodeCert, "nodeKey" to request.nodeKey)
        val staged = mapOf("ca" to "ca.pem", "adminCert" to "admin.pem", "adminKey" to "admin-key.pem",
            "nodeCert" to "node.pem", "nodeKey" to "node-key.pem")
        val material = pins.associate { (id, source) ->
            val expected = PrivateDeployment.BASE.resolve(spec.name).resolve("opensearch-${staged.getValue(id)}")
            require(source.path == expected.toString() &&
                metadata.getValue("${id}File").jsonPrimitive.content == source.path &&
                metadata.getValue("${id}Sha256").jsonPrimitive.content == source.sha256)
            id to bytes(source, 65536).decodeToString(throwOnInvalidSequence = true)
        }
        require(metadata.getValue("serverLeafSha256").jsonPrimitive.content == request.serverLeafSha256)
        var originalSequence: Pair<Int, Int>? = null
        val original = if (b.phase == "INSTALL") {
            require("sourceObservation" !in context && "sourceInvocation" !in context &&
                request.sourceStopped == null && request.sourceStoppedProofSha256 == null)
            buildJsonObject {
                put("privateText", "a12-original-native-search-${b.invocationId}")
                put("sourceGeneration", b.generationId); put("version", 1)
            }
        } else {
            val path = Path.of(context.getValue("sourceObservation").jsonPrimitive.content)
            val sourceIntent = Path.of(context.getValue("sourceInvocation").jsonPrimitive.content)
            require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path &&
                path.fileName.toString() == "native-result.json" &&
                sourceIntent == path.parent.resolve("intent.json") && sourceIntent.toRealPath() == sourceIntent &&
                Files.getPosixFilePermissions(path.parent) == PosixFilePermissions.fromString("rwx------"))
            val prior = json.parseToJsonElement(ReleasePrivateFiles.read(sourceIntent, 65536).decodeToString()).jsonObject
            val observed = json.parseToJsonElement(ReleasePrivateFiles.read(path, 1048576).decodeToString()).jsonObject
            require(prior.getValue("serviceId").jsonPrimitive.content == "opensearch" &&
                prior.getValue("journey") == sealed.intent.getValue("journey") &&
                prior.getValue("surface").jsonPrimitive.content == "HEADLESS" &&
                prior.getValue("variant").jsonPrimitive.content == "NATIVE" &&
                prior.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content == "INSTALL" &&
                prior.getValue("binding").jsonObject.getValue("trialId") ==
                    sealed.intent.getValue("binding").jsonObject.getValue("trialId") &&
                prior.getValue("binding").jsonObject.getValue("candidate") ==
                    sealed.intent.getValue("binding").jsonObject.getValue("candidate") &&
                observed.getValue("schemaVersion").jsonPrimitive.int == 2 &&
                observed.getValue("serviceId") == prior.getValue("serviceId") &&
                observed.getValue("surface") == prior.getValue("surface") &&
                observed.getValue("variant") == prior.getValue("variant") &&
                observed.getValue("journey") == prior.getValue("journey") &&
                observed.getValue("phase").jsonPrimitive.content == "INSTALL" &&
                observed.getValue("invocationId").jsonPrimitive.content == prior.getValue("invocationId").jsonPrimitive.content &&
                observed.getValue("generationId").jsonPrimitive.content != b.generationId &&
                observed.getValue("assertions").jsonObject.keys ==
                    prior.getValue("requiredAssertions").jsonArray.map { it.jsonPrimitive.content }.toSet() &&
                observed.getValue("assertions").jsonObject.values.all { it.jsonPrimitive.boolean } &&
                observed.getValue("artifacts").jsonObject.containsKey("oracle.json"))
            val oracleBytes = ReleasePrivateFiles.read(path.parent.resolve("oracle.json"), 1048576)
            require(ReleaseLocks.sha256(oracleBytes) == observed.getValue("artifacts").jsonObject
                .getValue("oracle.json").jsonPrimitive.content)
            val oracle = json.parseToJsonElement(oracleBytes.decodeToString()).jsonObject
            val mtls = oracle.getValue("originalMtls").jsonObject
            require(oracle.getValue("documentId").jsonPrimitive.content == "original-private-event" &&
                oracle.getValue("index").jsonPrimitive.content == "p0v3-private-history")
            val sequence = oracle.getValue("sequence").jsonPrimitive.int to
                oracle.getValue("primaryTerm").jsonPrimitive.int
            require(sequence.first >= 0 && sequence.second > 0)
            originalSequence = sequence
            require(pins.all { (id, input) -> mtls.getValue("${id}Sha256").jsonPrimitive.content == input.sha256 } &&
                mtls.getValue("serverLeafSha256").jsonPrimitive.content == request.serverLeafSha256)
            val stopped = requireNotNull(request.sourceStopped)
            val stoppedFile = Path.of(stopped.path)
            val quiesced = json.decodeFromString<ListenerBridgeQuiesceResult>(bytes(stopped, 8192).decodeToString())
            require(stoppedFile.parent.parent == Path.of("/mnt/media/p0-v3/ingress-succession") &&
                stoppedFile.fileName.toString() == "${quiesced.operation}.bridge-result.json" &&
                quiesced.targetGeneration == b.generationId &&
                quiesced.sourceGeneration == observed.getValue("generationId").jsonPrimitive.content &&
                request.sourceStoppedProofSha256 == quiesced.sourceStoppedProofSha256 &&
                quiesced.sourceStoppedProofSha256.matches(hash))
            oracle.getValue("originalDocument").jsonObject
        }
        val operation = openSearchNativeFixedOperation(request, original)
        val canonical = json.encodeToString(JsonObject.serializer(), original).encodeToByteArray()
        require(ReleaseLocks.sha256(canonical) == request.originalDocumentSha256)
        val body = if (request.action == "CREATE") bytes(requireNotNull(request.body), 8192) else null
        require(body == null || body.contentEquals(canonical))
        val target = inspect()
        require(target.port == 9200 && target.pid > 1 && target.netnsInode > 1 && target.containerId.matches(hash))
        ReleasePrivateFiles.directory(root.parent)
        if (!Files.exists(root, NOFOLLOW_LINKS)) {
            Files.createDirectory(root, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root.parent)
        }
        ReleasePrivateFiles.directory(root)
        val home = root.resolve(b.invocationId)
        if (!Files.exists(home, NOFOLLOW_LINKS)) {
            Files.createDirectory(home, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root)
        }
        return ReleasePrivateFiles.locked(home) {
            val requestBytes = ReleasePrivateFiles.read(home.resolve("${request.operation}.request.json"), 65536)
            require(json.decodeFromString<OpenSearchNativeQualificationRequest>(requestBytes.decodeToString()) == request)
            val requestSha = ReleaseLocks.sha256(requestBytes)
            require(!Files.exists(home.resolve("pending.json"), NOFOLLOW_LINKS) &&
                !Files.exists(home.resolve("${request.operation}.intent.json"), NOFOLLOW_LINKS) &&
                !Files.exists(home.resolve("${request.operation}.response"), NOFOLLOW_LINKS)) {
                "An uncertain original OpenSearch effect may never be replayed"
            }
            ReleasePrivateFiles.save(home.resolve("${request.operation}.intent.json"), requestBytes)
            ReleasePrivateFiles.save(home.resolve("pending.json"), requestBytes)
            val wire = buildJsonObject {
                put("operation", "opensearch-qualification"); put("operationId", request.operation)
                put("pid", target.pid); put("containerId", target.containerId)
                put("netnsInode", target.netnsInode); put("invocationId", b.invocationId)
                put("caseClaimSha256", b.caseClaimSha256); put("requestSha256", requestSha)
                put("phase", b.phase); put("role", request.role); put("action", request.action)
                put("method", operation.method); put("path", operation.path)
                put("address", target.address); put("port", 9200); put("host", "opensearch")
                put("caPem", material.getValue("ca")); put("leafSha256", request.serverLeafSha256)
                put("clientCert", material.getValue(if (request.role == "NODE") "nodeCert" else "adminCert"))
                put("clientKey", material.getValue(if (request.role == "NODE") "nodeKey" else "adminKey"))
                put("originalPrivateText", operation.privateText)
                put("originalDocument", original)
                put("originalSequence", originalSequence?.first?.let { JsonPrimitive(it) } ?: JsonNull)
                put("originalPrimaryTerm", originalSequence?.second?.let { JsonPrimitive(it) } ?: JsonNull)
                put("body", body?.let { JsonPrimitive(Base64.getEncoder().encodeToString(it)) } ?: JsonNull)
            }
            val response = helper(wire.toString().encodeToByteArray())
            require(response.size in 1..8 * 1024 * 1024)
            val output = json.parseToJsonElement(response.decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(output.keys == setOf("status", "responseKind", "body", "serverLeafSha256",
                "containerId", "pid", "netnsInode", "clientPid"))
            val status = output.getValue("status").jsonPrimitive.int
            require(output.getValue("containerId").jsonPrimitive.content == target.containerId &&
                output.getValue("pid").jsonPrimitive.int == target.pid &&
                output.getValue("netnsInode").jsonPrimitive.long == target.netnsInode &&
                output.getValue("clientPid").jsonPrimitive.int > 1 &&
                output.getValue("responseKind").jsonPrimitive.content == "HTTP" &&
                output.getValue("serverLeafSha256").jsonPrimitive.content == request.serverLeafSha256 &&
                (request.action == "CREATE" && status == 201 ||
                    request.action in setOf("DOCUMENT", "HISTORY") && status == 200 ||
                    request.action == "DENY" && status in setOf(401, 403)))
            val payload = Base64.getDecoder().decode(output.getValue("body").jsonPrimitive.content)
            require(payload.size <= 1024 * 1024 &&
                (request.action != "DENY" || !payload.toString(Charsets.UTF_8).contains(operation.privateText)))
            val resultFile = home.resolve("${request.operation}.response")
            if (payload.isNotEmpty()) ReleasePrivateFiles.save(resultFile, payload)
            else {
                // An actual empty HTTP 401/403 denial has an empty body, not fabricated JSON.
                FileChannel.open(resultFile, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS),
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use {
                    it.force(true)
                }
                ReleasePrivateFiles.sync(home)
            }
            val result = OpenSearchNativeQualificationResult(request.operation, b.invocationId,
                b.caseClaimSha256, fingerprint, target.containerId, target.pid, target.netnsInode,
                output.getValue("clientPid").jsonPrimitive.int, requestSha, request.role, request.action,
                status, request.serverLeafSha256, request.originalDocumentSha256,
                resultFile.toString(), ReleaseLocks.sha256(payload))
            ReleasePrivateFiles.save(home.resolve("${request.operation}.result.json"),
                json.encodeToString(result).encodeToByteArray())
            ReleasePrivateFiles.removeExact(home.resolve("pending.json"), requestBytes)
            result
        }
    }
}
