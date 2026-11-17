package net.datamancy.platform

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit

/** Exact synthetic CrowdSec source and client protocol. This does not delegate to a
 * caller-selected shell, URL, log path, public firewall or CAPI. Controller must bind
 * native action effects to the actual guarded generation/target with a durable outbox. */
@Serializable internal enum class CrowdsecNativeAction {
    APPEND_SYNTHETIC_LOG, READ_ALERTS, ADD_EXPIRING_DECISION, READ_DECISIONS,
    ADD_REVOCABLE_DECISION, REVOKE_DECISION, DENY_BOUNCER, READ_ORIGINAL_HISTORY
}
@Serializable internal data class CrowdsecNativeIntent(val operation: String, val generationId: String,
    val memberName: String, val invocationId: String, val phase: String,
    val action: CrowdsecNativeAction, val originalAlertId: Long? = null,
    val originalDecisionId: Long? = null, val sourceOracleSha256: String? = null)
@Serializable internal data class CrowdsecNativeQualificationRequest(val intent: CrowdsecNativeIntent,
    val binding: NativeQualificationCaseBinding, val targetIsolationProofSha256: String,
    val ca: ActivationInput, val serverLeafSha256: String,
    val sourceStopped: ActivationInput? = null, val sourceStoppedProofSha256: String? = null,
    val responseFile: String)
@Serializable internal data class CrowdsecNativeResult(val operation: String, val generationId: String,
    val invocationId: String, val action: CrowdsecNativeAction, val targetContainerId: String,
    val targetPid: Int, val targetNetnsInode: Long, val targetIsolationProofSha256: String,
    val sourceLogSha256: String?, val alertId: Long?, val decisionId: Long?,
    val realExpiryEpochSeconds: Long?, val revoked: Boolean, val privateBouncerResponseSha256: String,
    val caseClaimSha256: String = "", val requestSha256: String = "", val targetFingerprint: String = "",
    val status: Int = 0, val serverLeafSha256: String = "", val clientPid: Int = 0,
    val responseFile: String = "")

/** Deterministic release-owned original log, exact fixed path on only CrowdSec's
 * own synthetic `logs` mount. Bounded repeated 401 events exercise the installed
 * `p0v3/private-http` parser and `p0v3/private-http-abuse` scenario. */
internal object CrowdsecNativeQualification {
    const val IP = "198.51.100.18" // reserved documentation address, never a public victim
    const val LOG_PATH = "/synthetic-logs/http.log"
    const val SCENARIO = "p0v3/private-http-abuse"
    const val EXPIRING_IP = "198.51.100.19"
    const val REVOCABLE_IP = "198.51.100.20"
    private val digest = Regex("[a-f0-9]{64}")
    private val generation = Regex("q-[a-f0-9]{12}")
    private val invocation = Regex("[a-z][a-z0-9-]{0,95}")
    private val installOnly = setOf(CrowdsecNativeAction.APPEND_SYNTHETIC_LOG,
        CrowdsecNativeAction.ADD_EXPIRING_DECISION, CrowdsecNativeAction.ADD_REVOCABLE_DECISION,
        CrowdsecNativeAction.REVOKE_DECISION)
    fun line(timestampUtc: String): String {
        require(timestampUtc.matches(Regex("20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")))
        return List(3) { "$timestampUtc $IP 401 GET /a12-original-private-probe" }.joinToString("\n", postfix = "\n")
    }
    fun requireIntent(intent: CrowdsecNativeIntent, target: PrivateDeploymentSpec): Unit {
        require(intent.operation.matches(Regex("cnq-[a-f0-9]{12}")) &&
            intent.generationId.matches(generation) && intent.invocationId.matches(invocation) &&
            intent.memberName == target.name && target.name.startsWith("${intent.generationId}-") &&
            target.store == RuntimeStore.CANONICAL_V2 && intent.phase in setOf("INSTALL", "RESTORE") &&
            !(intent.phase == "RESTORE" && intent.action in installOnly) &&
            (intent.phase != "RESTORE" || intent.sourceOracleSha256?.matches(digest) == true) &&
            (intent.phase == "RESTORE" || intent.sourceOracleSha256 == null) &&
            (intent.action != CrowdsecNativeAction.REVOKE_DECISION ||
                intent.phase == "INSTALL" && intent.originalDecisionId != null && intent.originalDecisionId > 0) &&
            (intent.originalAlertId == null || intent.originalAlertId > 0) &&
            (intent.originalDecisionId == null || intent.originalDecisionId > 0))
        val guard = target.processes.single { it.id == "guard" }
        require(!guard.oneShot && guard.userId != 0 && guard.capabilities.isEmpty() &&
            guard.networks == listOf("guard-data") && target.networks == listOf("guard-data") &&
            guard.volumes.any { it == RuntimeMount("logs", "/synthetic-logs") } &&
            guard.volumes.any { it == RuntimeMount("data", "/data") } &&
            target.processes.none { it.id == "caddy" } && target.nativeIngress == null) {
            "Only original isolated CrowdSec detector and its private LAPI are admitted"
        }
    }
    /** Actual post-intent case authority and original server CA + bouncer API-key bytes.
     * The key is NEVER mounted into a QClient or carried in a case/context/argv/log. */
    fun sealedRequest(request: CrowdsecNativeQualificationRequest,
        spec: PrivateDeploymentSpec, fingerprint: String): NativeQualificationCaseAuthority {
        val b = request.binding
        requireIntent(request.intent, spec)
        require(b.serviceId == "crowdsec" && b.phase == request.intent.phase &&
            b.generationId == request.intent.generationId &&
            b.invocationId == request.intent.invocationId &&
            b.targetMemberName == spec.name && b.targetFingerprint == fingerprint &&
            request.targetIsolationProofSha256.matches(digest) &&
            request.serverLeafSha256.matches(digest) &&
            request.responseFile == GenerationRuntime.BASE.resolve(b.generationId)
                .resolve("native-qualification/${b.invocationId}/${request.intent.operation}.response").toString())
        val authority = NativeQualificationClaims.read(b)
        val fields = authority.context.getValue("crowdsecNative").jsonObject
        val caPath = PrivateDeployment.BASE.resolve(spec.name).resolve("crowdsec-ca.pem")
        require(request.ca.path == caPath.toString() && request.ca.sha256.matches(digest) &&
            fields.getValue("caFile").jsonPrimitive.content == request.ca.path &&
            fields.getValue("caSha256").jsonPrimitive.content == request.ca.sha256 &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(caPath, 65536)) == request.ca.sha256)
        val adopted = GenerationRuntime.BASE.resolve(b.generationId)
            .resolve("credential-revisions/crowdsec-bouncer-api-key")
        val originalKey = ReleasePrivateFiles.read(adopted, 8192)
        require(originalKey.size in 32..512 && originalKey.decodeToString(throwOnInvalidSequence = true)
            .trim().matches(Regex("[A-Za-z0-9_-]{32,511}")) &&
            fields.getValue("serverLeafSha256").jsonPrimitive.content == request.serverLeafSha256 &&
            (b.phase == "INSTALL" && request.sourceStopped == null &&
                request.sourceStoppedProofSha256 == null || b.phase == "RESTORE" &&
                request.sourceStopped != null && request.sourceStoppedProofSha256?.matches(digest) == true)) {
            "No original private guard server CA or adopted sealed bouncer API key"
        }
        return authority
    }
    /** Native exact target/container/volume inspection, NEVER a registry-only health claim. */
    internal fun target(spec: PrivateDeploymentSpec, fingerprint: String,
        command: RuntimeCommands): NativeQualificationTarget {
        require(spec.store == RuntimeStore.CANONICAL_V2 && fingerprint.matches(digest) &&
            spec.processes.single { it.id == "guard" }.networks == listOf("guard-data"))
        val native = command.run(listOf("inspect", "--type", "container", "p0v3-live-${spec.name}-guard"))
        require(native.exitCode == 0 && native.output.length in 1..262144)
        val container = Json.parseToJsonElement(native.output).jsonArray.single().jsonObject
        val state = container.getValue("State").jsonObject
        val labels = container.getValue("Config").jsonObject.getValue("Labels").jsonObject
        val net = container.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject
        val process = spec.processes.single { it.id == "guard" }
        val cid = container.getValue("Id").jsonPrimitive.content
        val pid = state.getValue("Pid").jsonPrimitive.int
        val mounts = container.getValue("Mounts").jsonArray
        require(cid.matches(digest) && state.getValue("Running").jsonPrimitive.boolean && pid > 1 &&
            container.getValue("Image").jsonPrimitive.content.removePrefix("sha256:") == process.imageId &&
            labels.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
            labels.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == fingerprint &&
            net.keys == setOf("p0v3-live-${spec.name}-guard-data") &&
            mounts.count { it.jsonObject.getValue("Destination").jsonPrimitive.content == LOG_PATH &&
                it.jsonObject.getValue("Name").jsonPrimitive.content == "p0v3-live-${spec.name}-volume-logs" } == 1 &&
            mounts.count { it.jsonObject.getValue("Destination").jsonPrimitive.content == "/data" &&
                it.jsonObject.getValue("Name").jsonPrimitive.content == "p0v3-live-${spec.name}-volume-data" } == 1) {
            "No genuinely running, isolated original guard with bound image/log/state volumes"
        }
        val inode = requireNotNull(Regex("net:\\[([0-9]+)]").matchEntire(
            Files.readSymbolicLink(Path.of("/proc/$pid/ns/net")).toString())).groupValues[1].toLong()
        val address = net.getValue("p0v3-live-${spec.name}-guard-data").jsonObject
            .getValue("IPAddress").jsonPrimitive.content
        require(inode > 1 && address.matches(Regex("[0-9]{1,3}(?:\\.[0-9]{1,3}){3}")) &&
            java.net.InetAddress.getByName(address).isSiteLocalAddress)
        return NativeQualificationTarget(cid,pid,inode,address,8443)
    }

    /** A fixed, bounded native command. Only PODMAN exec into the actual pinned guard is
     * admitted. A single INSTALL synthetic append streams exactly three typed lines to
     * tee; no shell, caller path, arbitrary cscli arguments or host log is accepted. */
    internal fun nativeAction(intent: CrowdsecNativeIntent, target: NativeQualificationTarget,
        store: RuntimeStore = RuntimeStore.CANONICAL_V2, containerName: String): ByteArray {
        require(store == RuntimeStore.CANONICAL_V2 && target.containerId.matches(digest) &&
            target.pid > 1 && target.netnsInode > 1 && target.port == 8443 &&
            containerName.matches(Regex("p0v3-live-q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,63}-guard")))
        store.verifyConfiguration()
        val script = when (intent.action) {
            CrowdsecNativeAction.DENY_BOUNCER -> return ByteArray(0) // fixed TLS/API-key denial is performed by the guarded namespace helper
            CrowdsecNativeAction.APPEND_SYNTHETIC_LOG -> listOf("/usr/bin/tee", "-a", LOG_PATH)
            CrowdsecNativeAction.READ_ALERTS, CrowdsecNativeAction.READ_ORIGINAL_HISTORY ->
                listOf("/usr/local/bin/cscli", "-c", "/run/secrets/crowdsec.yaml", "alerts", "list", "-o", "json")
            CrowdsecNativeAction.READ_DECISIONS -> listOf("/usr/local/bin/cscli", "-c", "/run/secrets/crowdsec.yaml",
                "decisions", "list", "-o", "json")
            CrowdsecNativeAction.ADD_EXPIRING_DECISION, CrowdsecNativeAction.ADD_REVOCABLE_DECISION ->
                listOf("/usr/local/bin/cscli", "-c", "/run/secrets/crowdsec.yaml", "decisions", "add", "--ip",
                    if (intent.action == CrowdsecNativeAction.ADD_EXPIRING_DECISION) EXPIRING_IP else REVOCABLE_IP,
                    "--duration", if (intent.action == CrowdsecNativeAction.ADD_EXPIRING_DECISION) "8s" else "30m",
                    "--type", "ban", "--reason", SCENARIO)
            CrowdsecNativeAction.REVOKE_DECISION -> listOf("/usr/local/bin/cscli", "-c",
                "/run/secrets/crowdsec.yaml", "decisions", "delete", "--id",
                requireNotNull(intent.originalDecisionId).toString())
        }
        val argv = store.prefix() + listOf("exec", "--user", "1000", "-i", containerName) + script
        val output = Files.createTempFile("p0v3-guard-native-", ".out",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        val errors = Files.createTempFile("p0v3-guard-native-", ".err",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        try {
            val process = ProcessBuilder(argv).redirectOutput(output.toFile()).redirectError(errors.toFile()).apply {
                listOf("CONTAINER_HOST","CONTAINER_CONNECTION","DOCKER_HOST","PODMAN_HOST",
                    "CONTAINERS_CONF","CONTAINERS_CONF_OVERRIDE","CONTAINERS_STORAGE_CONF").forEach(environment()::remove)
            }.start()
            process.outputStream.use { pipe ->
                if (intent.action == CrowdsecNativeAction.APPEND_SYNTHETIC_LOG) {
                    // Controller operation time is actual UTC; never adjust the host clock.
                    val stamp = java.time.Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS).toString()
                    pipe.write(line(stamp).encodeToByteArray()); pipe.flush()
                }
            }
            if (!process.waitFor(30, TimeUnit.SECONDS)) {
                process.toHandle().descendants().use { it.toList().asReversed().forEach { child -> child.destroyForcibly() } }
                process.destroyForcibly().waitFor()
                error("Original synthetic native action uncertain; retain durable attempted intent")
            }
            require(process.exitValue() == 0 && Files.size(output) <= 1048576 && Files.size(errors) <= 4096) {
                "Original synthetic native action uncertain; no replay"
            }
            return Files.readAllBytes(output)
        } finally {
            Files.deleteIfExists(output); Files.deleteIfExists(errors)
        }
    }

    fun requireResult(intent: CrowdsecNativeIntent, result: CrowdsecNativeResult,
        containerId: String, pid: Int, netns: Long, isolationProofSha256: String): Unit {
        require(result.operation == intent.operation && result.invocationId == intent.invocationId &&
            result.generationId == intent.generationId && result.action == intent.action &&
            result.targetContainerId == containerId && containerId.matches(digest) &&
            result.targetPid == pid && pid > 1 && result.targetNetnsInode == netns && netns > 1 &&
            isolationProofSha256.matches(digest) &&
            result.targetIsolationProofSha256 == isolationProofSha256 &&
            result.privateBouncerResponseSha256.matches(digest) &&
            (result.sourceLogSha256 == null || result.sourceLogSha256.matches(digest)) &&
            (result.alertId == null || result.alertId > 0) &&
            (result.decisionId == null || result.decisionId > 0) &&
            (result.realExpiryEpochSeconds == null || result.realExpiryEpochSeconds > 1_000_000_000L)) {
            "Native CrowdSec LAPI/log/decision evidence does not belong to this isolated target"
        }
    }
}
