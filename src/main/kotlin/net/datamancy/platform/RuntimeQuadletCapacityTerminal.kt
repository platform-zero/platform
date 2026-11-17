package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Capacity release only: a distinct terminal observation, NEVER an original
 * isolate.result.json, backup admission, source resume or release qualification.
 * The exact original CIDs are checked again against the one locked native census.
 */
@Serializable internal data class QuadletCapacityTerminalObservation(val schemaVersion: Int = 1,
    val generation: String, val bundleSha256: String, val member: String, val fingerprint: String,
    val fenceId: String, val originalEvidenceSha256: Map<String, String>,
    val installedPolicy: Map<String, String>, val stoppedCids: Map<String, String>,
    val originalServeAcknowledged: Boolean, val publicActivation: Boolean = false,
    val originalIsolationAcknowledged: Boolean = false)

internal object RuntimeQuadletCapacityTerminal {
    private val json = Json { encodeDefaults = true }
    private const val NAME = "quadlet-capacity.terminal.json"
    fun matchesOriginalCids(member: String, cids: Map<String, String>,
        observed: List<RuntimeCapacityCensus.Container>): Boolean {
        val prefix = "p0v3-live-$member-"
        val actual = observed.filter { it.name.startsWith(prefix) || it.member == member }
        return actual.size == cids.size && actual.associate { it.name to it.cid } ==
            cids.mapKeys { (process, _) -> "$prefix$process" }
    }
    private fun bytes(root: Path, name: String, limit: Int = 8192): ByteArray =
        ReleasePrivateFiles.read(root.resolve(name), limit)
    private fun <T> evidence(root: Path, name: String, limit: Int = 8192, decode: (ByteArray) -> T,
        hashes: MutableMap<String, String>): T {
        val original = bytes(root, name, limit)
        hashes[name] = ReleaseLocks.sha256(original)
        return decode(original)
    }
    private fun proof(root: Path, bundle: GenerationBundle, expected: String): QuadletCapacityTerminalObservation {
        val pin = bundle.members.single()
        val spec = pin.spec
        require(bundle.request.id == root.fileName.toString() && spec.name.startsWith("${bundle.request.id}-") &&
            spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
            bundle.request.store == RuntimeStore.CANONICAL_V2 &&
            ReleaseLocks.sha256(bytes(root, "bundle.json", 1048576)) == expected)
        val original = sortedMapOf<String, String>()
        val stageIntent = evidence(root, "stage.intent.json", decode = { json.decodeFromString<GenerationIntent>(it.decodeToString()) }, hashes = original)
        val stageResult = evidence(root, "stage.result.json", decode = { json.decodeFromString<GenerationOutcome>(it.decodeToString()) }, hashes = original)
        require(stageIntent == GenerationIntent("stage", expected) && stageResult.action == "stage" &&
            stageResult.passed && stageResult.bundleSha256 == expected && stageResult.failureType == null) {
            "Quadlet capacity observation requires a completed original serving stage"
        }
        val installIntent = evidence(root, "quadlet-install-${spec.name}.intent.json", 65536,
            { json.decodeFromString<QuadletInstallIntent>(it.decodeToString()) }, original)
        val install = evidence(root, "quadlet-install-${spec.name}.result.json", decode = {
            json.decodeFromString<QuadletInstallResult>(it.decodeToString()) }, hashes = original)
        require(installIntent.generation == bundle.request.id && installIntent.bundleSha256 == expected &&
            installIntent.member == spec.name && install.intentSha256 == original.getValue("quadlet-install-${spec.name}.intent.json") &&
            install.installedAuditSha256.keys == spec.processes.map { it.id }.toSet()) {
            "Original installed policy does not match the complete member"
        }
        val serveFile = root.resolve("quadlet-serve.result.json")
        val serving = if (Files.exists(serveFile, NOFOLLOW_LINKS)) evidence(root, serveFile.fileName.toString(), decode = {
            json.decodeFromString<QuadletServeResult>(it.decodeToString()) }, hashes = original).also {
            val request = evidence(root, "quadlet-serve-stop.intent.json", decode = {
                json.decodeFromString<QuadletServeStopRequest>(it.decodeToString()) }, hashes = original)
            require(request.schemaVersion == 1 && request.generation == bundle.request.id &&
                request.member == spec.name && request.bundleSha256 == expected &&
                request.reason in setOf("operator-controlled", "monotonic-deadline") &&
                it.schemaVersion == 1 && it.bundleSha256 == expected && it.fenced &&
                it.stoppedCids.keys == spec.processes.map { process -> process.id }.toSet()) {
                "Incomplete original controlled serving stop"
            }
        } else null
        val stopped = linkedMapOf<String, String>()
        for (process in spec.processes) {
            val id = process.id
            val originalStart = evidence(root, "quadlet-member-${spec.name}-$id.intent.json", decode = {
                json.decodeFromString<QuadletDelegationIntent>(it.decodeToString()) }, hashes = original)
            val startName = "quadlet-delegate-${spec.name}-$id-start.intent.json"
            val delegatedStart = evidence(root, startName, decode = { it }, hashes = original)
            val acknowledgedStart = evidence(root, "quadlet-delegate-${spec.name}-$id-start.ack.json", decode = {
                json.decodeFromString<QuadletDelegationAck>(it.decodeToString()) }, hashes = original)
            val member = evidence(root, "quadlet-member-${spec.name}-$id.result.json", decode = {
                json.decodeFromString<QuadletMemberStart>(it.decodeToString()) }, hashes = original)
            val launchIntentName = "quadlet-launch-${spec.name}-$id.intent.json"
            val launchIntent = evidence(root, launchIntentName, decode = {
                json.decodeFromString<QuadletLaunchIntent>(it.decodeToString()) }, hashes = original)
            val launch = evidence(root, "quadlet-launch-${spec.name}-$id.result.json", decode = {
                json.decodeFromString<QuadletLaunchResult>(it.decodeToString()) }, hashes = original)
            require(originalStart.schemaVersion == 1 && originalStart.action == "start" &&
                originalStart.member == spec.name && originalStart.process == id &&
                originalStart.fingerprint == pin.runtimeFingerprint && originalStart.bundleSha256 == expected &&
                originalStart.installedAuditSha256 == install.installedAuditSha256[id] &&
                json.encodeToString(originalStart).toByteArray().contentEquals(delegatedStart) &&
                acknowledgedStart.schemaVersion == 1 && acknowledgedStart.action == "start" &&
                acknowledgedStart.intentSha256 == original.getValue(startName) &&
                acknowledgedStart.installedAuditSha256 == originalStart.installedAuditSha256 &&
                member.schemaVersion == 1 && member.bundleSha256 == expected &&
                member.member == spec.name && member.process == id &&
                member.installedAuditSha256 == install.installedAuditSha256[id] &&
                member.status.id == id && (if (process.oneShot) member.status.state == "completed" && member.status.exitCode == 0
                    else member.status.state == "running") &&
                launchIntent.schemaVersion == 1 && launchIntent.member == spec.name &&
                launchIntent.process == id && launchIntent.fingerprint == pin.runtimeFingerprint &&
                launchIntent.generatedArgvSha256.matches(Regex("[a-f0-9]{64}")) &&
                launchIntent.delegationSha256 == original.getValue(startName) &&
                launch.schemaVersion == 1 && launch.nativeAcknowledged &&
                launch.intentSha256 == original.getValue(launchIntentName) &&
                launch.imageId == process.imageId && launch.containerId == member.containerId &&
                launch.containerId.matches(Regex("[a-f0-9]{64}"))) {
                "Foreign original Quadlet launch or member ACK"
            }
            val stopName = "quadlet-stop-${spec.name}-$id"
            val lossName = "quadlet-owner-loss-${spec.name}-$id"
            val stop = root.resolve("$stopName.result.json")
            val loss = root.resolve("$lossName.result.json")
            if (serving != null) {
                require(Files.exists(stop, NOFOLLOW_LINKS) && !Files.exists(loss, NOFOLLOW_LINKS) &&
                    serving.stoppedCids[id] == launch.containerId) { "Controlled stop differs from original CID" }
            }
            when {
                Files.exists(stop, NOFOLLOW_LINKS) -> {
                    val stopIntentName = "$stopName.intent.json"
                    evidence(root, stopIntentName, decode = { it }, hashes = original)
                    val result = evidence(root, "$stopName.result.json", decode = {
                        json.decodeFromString<QuadletStopResult>(it.decodeToString()) }, hashes = original)
                    require(result.schemaVersion == 1 && result.stopped && result.containerId == launch.containerId &&
                        result.intentSha256 == original.getValue(stopIntentName)) { "Stopped CID lacks original stop ACK" }
                }
                Files.exists(loss, NOFOLLOW_LINKS) -> {
                    val intentName = "$lossName.intent.json"
                    val content = evidence(root, intentName, decode = { it.decodeToString() }, hashes = original)
                    val result = evidence(root, "$lossName.result.json", decode = { it.decodeToString() }, hashes = original)
                    require(content == "quadlet-owner-loss-v1\n${original.getValue(launchIntentName)}\n${launch.containerId}\n" &&
                        result == "quadlet-owner-loss-stopped-v1\n${original.getValue(intentName)}\n${launch.containerId}\n") {
                        "Owner-loss containment did not acknowledge the exact original CID"
                    }
                }
                else -> require(serving == null && process.oneShot &&
                    !Files.exists(stop, NOFOLLOW_LINKS) && !Files.exists(loss, NOFOLLOW_LINKS)) {
                    "Daemon without original controlled stop or owner-loss containment"
                }
            }
            stopped[id] = launch.containerId
        }
        val memberRoot = PrivateDeployment.BASE.resolve(spec.name)
        val fence = requireNotNull(RuntimeMaintenance.read(memberRoot, pin.runtimeFingerprint)) {
            "Terminated Quadlet member lacks original maintenance fence"
        }
        return QuadletCapacityTerminalObservation(generation = bundle.request.id, bundleSha256 = expected,
            member = spec.name, fingerprint = pin.runtimeFingerprint, fenceId = fence.id,
            originalEvidenceSha256 = original, installedPolicy = install.installedAuditSha256,
            stoppedCids = stopped, originalServeAcknowledged = serving != null)
    }
    fun read(root: Path, bundle: GenerationBundle, expected: String): QuadletCapacityTerminalObservation? {
        val file = root.resolve(NAME)
        if (!Files.exists(file, NOFOLLOW_LINKS)) return null
        val saved = json.decodeFromString<QuadletCapacityTerminalObservation>(bytes(root, NAME, 65536).decodeToString())
        require(saved == proof(root, bundle, expected) && !saved.originalIsolationAcknowledged &&
            !saved.publicActivation) { "Changed original Quadlet terminal capacity evidence" }
        return saved
    }
    fun record(root: Path, bundle: GenerationBundle, expected: String,
        runtimeRoot: Path = PrivateDeployment.BASE,
        audit: (PrivateDeploymentSpec, RuntimeProcess) -> String = { spec, p -> RuntimeQuadletInstalledAudit().audit(spec, p) },
        stoppedUnit: (String) -> Boolean = ::quadletTerminalUnit,
        census: RuntimeCapacityCensus = RuntimeCapacityCensus(),
        commands: RuntimeCommands = PrivateRootfulCommands(45, RuntimeStore.CANONICAL_V2)): QuadletCapacityTerminalObservation {
        require(runtimeRoot == PrivateDeployment.BASE && !Files.exists(root.resolve(NAME), NOFOLLOW_LINKS))
        val pin = bundle.members.single(); val spec = pin.spec
        return PrivateDeployment.withOrderedNativeLocks(listOf(spec.name), runtimeRoot) {
            val receipt = proof(root, bundle, expected)
            require(spec.processes.associate { it.id to audit(spec, it) } == receipt.installedPolicy &&
                spec.processes.all { stoppedUnit("${RuntimeQuadlets.unit(spec, it)}.service") }) {
                "Quadlet terminal has an active or changed installed systemd unit"
            }
            val observed = census.snapshot(spec.store)
            require(census.quiescent(listOf(RuntimeCapacityCensus.Member(spec, pin.runtimeFingerprint)), observed) &&
                matchesOriginalCids(spec.name, receipt.stoppedCids, observed)) {
                "Original CID, owner label, namespace or native stopped state changed"
            }
            for (p in spec.processes) {
                val cid = receipt.stoppedCids.getValue(p.id)
                val inspected = commands.run(listOf("container", "inspect", cid))
                require(inspected.exitCode == 0 && inspected.output.toByteArray().size in 1..65536)
                val item = json.parseToJsonElement(inspected.output).jsonArray.single().jsonObject
                val state = item.getValue("State").jsonObject
                require(item.getValue("Id").jsonPrimitive.content == cid &&
                    item.getValue("Name").jsonPrimitive.content == "p0v3-live-${spec.name}-${p.id}" &&
                    state.getValue("Running").jsonPrimitive.content == "false" &&
                    state.getValue("ExitCode").jsonPrimitive.content.toInt() in (if (p.oneShot) setOf(0) else setOf(0, 143))) {
                    "Native terminal CID lacks a clean exit"
                }
            }
            ReleasePrivateFiles.save(root.resolve(NAME), json.encodeToString(receipt).toByteArray())
            receipt
        }
    }
    /** Existing failed-stage observation has no original stage success and is
     * never rewritten. Bind every retained original stopped CID on each admission.
     */
    fun failedStage(root: Path, bundle: GenerationBundle, expected: String): Pair<String, Map<String, String>>? {
        val file = root.resolve("quadlet-stage.terminal.json")
        if (!Files.exists(file, NOFOLLOW_LINKS)) return null
        val pin = bundle.members.single(); val spec = pin.spec
        val receipt = json.decodeFromString<QuadletStageTerminalObservation>(bytes(root, file.fileName.toString(), 65536).decodeToString())
        require(receipt.schemaVersion == 1 && receipt.generation == bundle.request.id &&
            receipt.bundleSha256 == expected && receipt.member == spec.name && !receipt.startAuthorized &&
            !Files.exists(root.resolve("stage.result.json"), NOFOLLOW_LINKS) &&
            receipt.originalStageIntentSha256 == ReleaseLocks.sha256(bytes(root, "stage.intent.json")) &&
            receipt.originalInstallResultSha256 == ReleaseLocks.sha256(bytes(root, "quadlet-install-${spec.name}.result.json")) &&
            receipt.observedPolicy.keys == spec.processes.map { it.id }.toSet() &&
            receipt.disposition == (if (receipt.observedStoppedCids.isEmpty() &&
                receipt.observedUnacknowledgedCids.isEmpty()) "terminal-failed-before-native-launch"
                else "terminal-fenced-stopped-after-partial-start") &&
            RuntimeMaintenance.read(PrivateDeployment.BASE.resolve(spec.name), pin.runtimeFingerprint)?.id == receipt.fenceId) {
            "Foreign failed-stage terminal observation"
        }
        val install = json.decodeFromString<QuadletInstallResult>(bytes(root,
            "quadlet-install-${spec.name}.result.json").decodeToString())
        require(receipt.observedPolicy == install.installedAuditSha256 &&
            (receipt.observedStoppedCids.keys intersect receipt.observedUnacknowledgedCids.keys).isEmpty() &&
            (receipt.observedStoppedCids.keys + receipt.observedUnacknowledgedCids.keys).toSet() ==
                spec.processes.filter { Files.exists(root.resolve(
                    "quadlet-launch-${spec.name}-${it.id}.intent.json"), NOFOLLOW_LINKS) }.map { it.id }.toSet())
        for ((process, cid) in receipt.observedStoppedCids) {
            require(cid.matches(Regex("[a-f0-9]{64}")) && spec.processes.any { it.id == process })
            val launchIntent = bytes(root, "quadlet-launch-${spec.name}-$process.intent.json")
            val launch = json.decodeFromString<QuadletLaunchResult>(bytes(root,
                "quadlet-launch-${spec.name}-$process.result.json").decodeToString())
            val stopIntent = bytes(root, "quadlet-stop-${spec.name}-$process.intent.json")
            val stop = json.decodeFromString<QuadletStopResult>(bytes(root,
                "quadlet-stop-${spec.name}-$process.result.json").decodeToString())
            require(launch.nativeAcknowledged && launch.containerId == cid &&
                launch.intentSha256 == ReleaseLocks.sha256(launchIntent) &&
                stop.stopped && stop.containerId == cid && stop.intentSha256 == ReleaseLocks.sha256(stopIntent))
        }
        require(receipt.uncertainEmergencyIntentSha256.keys == receipt.observedUnacknowledgedCids
            .filterValues { it.exitCode == -1 }.keys &&
            receipt.createdOwnerLossIntentSha256.keys == receipt.observedUnacknowledgedCids
                .filterValues { it.reason == "never-started-created-cid-missing-original-launch-and-stop-ack" }.keys) {
            "Unacknowledged emergency exit lacks explicit separate intent custody"
        }
        for ((process, unacknowledged) in receipt.observedUnacknowledgedCids) {
            val p = spec.processes.single { it.id == process }
            val launchIntent = bytes(root, "quadlet-launch-${spec.name}-$process.intent.json")
            val request = json.decodeFromString<QuadletLaunchIntent>(launchIntent.decodeToString())
            val memberIntent = json.decodeFromString<QuadletDelegationIntent>(bytes(root,
                "quadlet-member-${spec.name}-$process.intent.json").decodeToString())
            val startDelegation = bytes(root, "quadlet-delegate-${spec.name}-$process-start.intent.json")
            require(request.member == spec.name && request.process == process &&
                request.fingerprint == pin.runtimeFingerprint &&
                request.delegationSha256 == ReleaseLocks.sha256(startDelegation) &&
                memberIntent.action == "start" && memberIntent.member == spec.name &&
                memberIntent.process == process && memberIntent.bundleSha256 == expected &&
                memberIntent.fingerprint == pin.runtimeFingerprint &&
                memberIntent.installedAuditSha256 == install.installedAuditSha256[process] &&
                Files.exists(root.resolve("quadlet-delegate-${spec.name}-$process-stop.intent.json"), NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve("quadlet-stop-${spec.name}-$process.intent.json"), NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve("quadlet-stop-${spec.name}-$process.result.json"), NOFOLLOW_LINKS)) {
                "Missing original stop ACK cannot be promoted to an original stop"
            }
            val launchFile = root.resolve("quadlet-launch-${spec.name}-$process.result.json")
            val launch = if (Files.exists(launchFile, NOFOLLOW_LINKS))
                json.decodeFromString<QuadletLaunchResult>(bytes(root, launchFile.fileName.toString()).decodeToString())
                else null
            require(unacknowledged.reason == when {
                process in receipt.createdOwnerLossIntentSha256 ->
                    "never-started-created-cid-missing-original-launch-and-stop-ack"
                launch == null -> "missing-original-launch-and-stop-ack"
                else -> "missing-original-stop-ack"
            })
            if (launch == null) require(!Files.exists(root.resolve(
                "quadlet-member-${spec.name}-$process.result.json"), NOFOLLOW_LINKS))
            else require(launch.nativeAcknowledged && launch.imageId == p.imageId &&
                launch.intentSha256 == ReleaseLocks.sha256(launchIntent) &&
                launch.containerId == unacknowledged.cid)
            val observed = inspectUnacknowledged(spec, p, pin.runtimeFingerprint)
            if (process in receipt.createdOwnerLossIntentSha256) require(
                launch == null && observed.reason == "native-created-never-started-read-only" &&
                receipt.createdOwnerLossIntentSha256[process] == createdOwnerLossIntentSha256(root,
                    spec.name, process, ReleaseLocks.sha256(launchIntent), observed.cid)) {
                "Never-started CID or original guardian readback changed"
            }
            if (observed.exitCode == -1) require(receipt.uncertainEmergencyIntentSha256[process] ==
                RuntimeQuadletEmergencyContainment.uncertainStoppedIntentSha256(root, expected, spec,
                    p, pin.runtimeFingerprint, receipt.fenceId, observed)) {
                "Uncertain emergency intent or exact stopped original CID changed"
            }
            require(unacknowledged == observed.copy(reason = unacknowledged.reason)) {
                "Unacknowledged stopped CID or image changed since the separate terminal observation"
            }
        }
        return receipt.fenceId to (receipt.observedStoppedCids +
            receipt.observedUnacknowledgedCids.mapValues { it.value.cid })
    }
}
