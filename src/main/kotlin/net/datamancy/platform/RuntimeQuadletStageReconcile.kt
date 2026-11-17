package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Native terminal facts are NOT replacements for missing original helper ACKs. */
@Serializable internal data class QuadletUnacknowledgedCid(val cid: String, val imageId: String,
    val exitCode: Int, val reason: String)

/** Read-only native identity, never an original launch/stop result. */
internal fun inspectUnacknowledged(spec: PrivateDeploymentSpec, process: RuntimeProcess,
    fingerprint: String): QuadletUnacknowledgedCid {
    val name = "p0v3-live-${spec.name}-${process.id}"
    val response = PrivateRootfulCommands(45, spec.store).run(listOf("container", "inspect", name))
    require(response.exitCode == 0 && response.output.toByteArray().size in 1..65536)
    return parseUnacknowledgedNative(spec, process, fingerprint, response.output)
}

internal fun parseUnacknowledgedNative(spec: PrivateDeploymentSpec, process: RuntimeProcess,
    fingerprint: String, output: String): QuadletUnacknowledgedCid {
    require(process in spec.processes && output.toByteArray().size in 1..65536)
    val name = "p0v3-live-${spec.name}-${process.id}"
    val item = Json.parseToJsonElement(output).jsonArray.single().jsonObject
    val labels = item.getValue("Config").jsonObject.getValue("Labels").jsonObject
    val state = item.getValue("State").jsonObject
    val cid = item.getValue("Id").jsonPrimitive.content
    val image = item.getValue("Image").jsonPrimitive.content.removePrefix("sha256:")
    val exit = state.getValue("ExitCode").jsonPrimitive.content.toInt()
    val status = state.getValue("Status").jsonPrimitive.content
    val neverStarted = status == "created" && !process.oneShot && exit == 0 &&
        state.getValue("Pid").jsonPrimitive.content == "0" &&
        state.getValue("StartedAt").jsonPrimitive.content == "0001-01-01T00:00:00Z"
    require(cid.matches(Regex("[a-f0-9]{64}")) && item.getValue("Name").jsonPrimitive.content == name &&
        image == process.imageId && labels.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
        labels.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == fingerprint &&
        state.getValue("Running").jsonPrimitive.content == "false" &&
        (neverStarted || (status == "exited" && exit in
            (if (process.oneShot) (-1..255) else setOf(0, 143))))) {
        "Unacknowledged CID has no exact stopped native identity"
    }
    return QuadletUnacknowledgedCid(cid, image, exit,
        if (neverStarted) "native-created-never-started-read-only" else "native-read-only")
}

/** Bind the original guardian's fsynced, exact-CID readback of a container that
 * was CREATED but never ran. Neither this result nor its native state is a launch ACK.
 */
internal fun createdOwnerLossIntentSha256(root: Path, member: String, process: String,
    launchIntentSha256: String, cid: String): String {
    require(launchIntentSha256.matches(Regex("[a-f0-9]{64}")) && cid.matches(Regex("[a-f0-9]{64}")))
    val stem = "quadlet-owner-loss-$member-$process"
    val original = ReleasePrivateFiles.read(root.resolve("$stem.intent.json"), 8192)
    require(original.decodeToString(throwOnInvalidSequence = true) ==
        "quadlet-owner-loss-v1\n$launchIntentSha256\n$cid\n") { "Created CID lacks its original exact guardian intent" }
    val sha = ReleaseLocks.sha256(original)
    require(ReleasePrivateFiles.read(root.resolve("$stem.result.json"), 8192)
        .decodeToString(throwOnInvalidSequence = true) == "quadlet-owner-loss-stopped-v1\n$sha\n$cid\n") {
        "Created CID lacks its original exact guardian readback"
    }
    return sha
}

/** Separate terminal readback for a failed original StartUnit. It never grants
 * stage, launch, stop, isolation, backup, or qualification success. */
@Serializable internal data class QuadletStageTerminalObservation(val schemaVersion: Int = 1,
    val generation: String, val member: String, val bundleSha256: String, val originalStageIntentSha256: String,
    val originalInstallResultSha256: String, val fenceId: String, val observedPolicy: Map<String, String>,
    val observedStoppedCids: Map<String, String> = emptyMap(),
    val observedUnacknowledgedCids: Map<String, QuadletUnacknowledgedCid> = emptyMap(),
    /** ONLY exit -1: exact uncertain emergency intent, not an original stop ACK. */
    val uncertainEmergencyIntentSha256: Map<String, String> = emptyMap(),
    /** Exact guardian result for a never-started created CID, not a launch ACK. */
    val createdOwnerLossIntentSha256: Map<String, String> = emptyMap(),
    val disposition: String = "terminal-failed-before-native-launch", val startAuthorized: Boolean = false)

internal class RuntimeQuadletStageReconcile(
    private val generationBase: Path = GenerationRuntime.BASE,
    private val runtimeBase: Path = PrivateDeployment.BASE,
    private val audit: (PrivateDeploymentSpec, RuntimeProcess) -> String = { spec, p ->
        RuntimeQuadletInstalledAudit().audit(spec, p)
    },
    private val stoppedUnit: (String) -> Boolean = ::quadletTerminalUnit,
    private val nativeInspect: (PrivateDeploymentSpec, RuntimeProcess, String) -> QuadletUnacknowledgedCid =
        ::inspectUnacknowledged,
    private val namespaceStopped: (PrivateDeploymentSpec, String, Map<String, String>) -> Boolean = { spec, fp, stopped ->
        val result = PrivateRootfulCommands(45, spec.store).run(listOf("ps", "-a", "--no-trunc", "--format",
            "{{.ID}}\t{{.Names}}\t{{.State}}\t{{.Label \"io.p0v3.private-deployment\"}}\t{{.Label \"io.p0v3.runtime-fingerprint\"}}"))
        if (result.exitCode != 0 || result.output.toByteArray().size > 2_000_000) false else {
            val found = mutableSetOf<String>()
            val exact = stopped.mapKeys { (p, _) -> "p0v3-live-${spec.name}-$p" }
            result.output.lineSequence().filter { it.isNotBlank() }.all { line ->
                val parts = line.split('\t')
                require(parts.size == 5) { "Unknown native terminal container census" }
                val (cid, name, state, owner, fingerprint) = parts
                if (!name.startsWith("p0v3-live-${spec.name}-") && owner != spec.name) true
                else cid.matches(Regex("[a-f0-9]{64}")) && name in exact && found.add(name) &&
                    exact[name] == cid && owner == spec.name && fingerprint == fp &&
                    state in setOf("created", "exited")
            } && found == exact.keys
        }
    }) {
    private val json = Json { encodeDefaults = true }
    fun terminal(generation: String, expected: String, spec: PrivateDeploymentSpec): QuadletStageTerminalObservation {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) && spec.name.startsWith("$generation-") &&
            expected.matches(Regex("[a-f0-9]{64}")))
        val root = generationBase.resolve(generation)
        ReleasePrivateFiles.directory(root)
        val terminal = root.resolve("quadlet-stage.terminal.json")
        require(!Files.exists(terminal, NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("stage.result.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("quadlet-serve.result.json"), NOFOLLOW_LINKS))
        val sealed = ReleasePrivateFiles.read(root.resolve("bundle.json"), 1048576)
        val bundle = json.decodeFromString<GenerationBundle>(sealed.decodeToString(throwOnInvalidSequence = true))
        val pin = bundle.members.single()
        require(ReleaseLocks.sha256(sealed) == expected && pin.spec == spec && bundle.request.id == generation)
        val stage = ReleasePrivateFiles.read(root.resolve("stage.intent.json"), 8192)
        val intent = json.decodeFromString<GenerationIntent>(stage.decodeToString(throwOnInvalidSequence = true))
        require(intent.action == "stage" && intent.bundleSha256 == expected)
        val installed = ReleasePrivateFiles.read(root.resolve("quadlet-install-${spec.name}.result.json"), 8192)
        val original = ReleasePrivateFiles.read(root.resolve("quadlet-install-${spec.name}.intent.json"), 65536)
        val installedRecord = json.decodeFromString<QuadletInstallResult>(installed.decodeToString(throwOnInvalidSequence = true))
        require(installedRecord.intentSha256 == ReleaseLocks.sha256(original) &&
            spec.processes.any { p -> Files.exists(root.resolve(
                "quadlet-member-${spec.name}-${p.id}.intent.json"), NOFOLLOW_LINKS) })
        val fence = requireNotNull(RuntimeMaintenance.read(runtimeBase.resolve(spec.name), pin.runtimeFingerprint)) {
            "Failed original stage has no verified maintenance fence"
        }
        val stoppedCids = linkedMapOf<String, String>()
        val unacknowledged = linkedMapOf<String, QuadletUnacknowledgedCid>()
        val uncertainEmergency = linkedMapOf<String, String>()
        val createdOwnerLoss = linkedMapOf<String, String>()
        val policies = spec.processes.associate { p ->
            require(stoppedUnit("${RuntimeQuadlets.unit(spec, p)}.service")) {
                "An original member is still active or owns a MainPID"
            }
            val launchIntent = root.resolve("quadlet-launch-${spec.name}-${p.id}.intent.json")
            val launchResult = root.resolve("quadlet-launch-${spec.name}-${p.id}.result.json")
            val memberIntent = root.resolve("quadlet-member-${spec.name}-${p.id}.intent.json")
            val memberResult = root.resolve("quadlet-member-${spec.name}-${p.id}.result.json")
            val stopIntent = root.resolve("quadlet-stop-${spec.name}-${p.id}.intent.json")
            val stopResult = root.resolve("quadlet-stop-${spec.name}-${p.id}.result.json")
            if (Files.exists(launchIntent, NOFOLLOW_LINKS)) {
                val originalLaunch = ReleasePrivateFiles.read(launchIntent, 8192)
                val launchRequest = json.decodeFromString<QuadletLaunchIntent>(originalLaunch.decodeToString())
                val memberRequest = json.decodeFromString<QuadletDelegationIntent>(
                    ReleasePrivateFiles.read(memberIntent, 8192).decodeToString())
                require(memberRequest.action == "start" && memberRequest.member == spec.name &&
                    memberRequest.process == p.id && memberRequest.bundleSha256 == expected &&
                    memberRequest.fingerprint == pin.runtimeFingerprint &&
                    memberRequest.installedAuditSha256 == installedRecord.installedAuditSha256[p.id] &&
                    launchRequest.member == spec.name && launchRequest.process == p.id &&
                    launchRequest.fingerprint == pin.runtimeFingerprint &&
                    launchRequest.generatedArgvSha256.matches(Regex("[a-f0-9]{64}")) &&
                    launchRequest.delegationSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(
                        root.resolve("quadlet-delegate-${spec.name}-${p.id}-start.intent.json"), 8192))) {
                    "Unbound failed-stage original start or generated launch intent"
                }
                val launch = if (Files.exists(launchResult, NOFOLLOW_LINKS))
                    json.decodeFromString<QuadletLaunchResult>(ReleasePrivateFiles.read(launchResult, 8192)
                        .decodeToString(throwOnInvalidSequence = true)) else null
                if (launch != null) require(launch.nativeAcknowledged && launch.imageId == p.imageId &&
                    launch.intentSha256 == ReleaseLocks.sha256(originalLaunch) &&
                    launch.containerId.matches(Regex("[a-f0-9]{64}")))
                val stop = if (Files.exists(stopResult, NOFOLLOW_LINKS)) {
                    val originalStop = ReleasePrivateFiles.read(stopIntent, 8192)
                    json.decodeFromString<QuadletStopResult>(ReleasePrivateFiles.read(stopResult, 8192)
                        .decodeToString(throwOnInvalidSequence = true)).also {
                        require(it.stopped && it.intentSha256 == ReleaseLocks.sha256(originalStop))
                    }
                } else null
                when {
                    launch != null && stop != null -> {
                        require(launch.containerId == stop.containerId) { "Original stopped CID differs from launch" }
                        stoppedCids[p.id] = stop.containerId
                    }
                    else -> {
                        require(stop == null && !Files.exists(stopIntent, NOFOLLOW_LINKS) &&
                            Files.exists(root.resolve("quadlet-delegate-${spec.name}-${p.id}-stop.intent.json"), NOFOLLOW_LINKS) &&
                            (launch != null || !Files.exists(memberResult, NOFOLLOW_LINKS))) {
                            "Incomplete original failed-stage ACK cannot be treated as a terminal observation"
                        }
                        val observed = nativeInspect(spec, p, pin.runtimeFingerprint)
                        require(observed.cid.matches(Regex("[a-f0-9]{64}")) && observed.imageId == p.imageId &&
                            observed.reason in setOf("native-read-only", "native-created-never-started-read-only") &&
                            (launch == null || launch.containerId == observed.cid)) {
                            "Native stopped process cannot replace a missing original helper ACK"
                        }
                        if (observed.reason == "native-created-never-started-read-only") {
                            require(launch == null && !Files.exists(memberResult, NOFOLLOW_LINKS))
                            createdOwnerLoss[p.id] = createdOwnerLossIntentSha256(root, spec.name, p.id,
                                ReleaseLocks.sha256(originalLaunch), observed.cid)
                        } else if (observed.exitCode == -1) {
                            uncertainEmergency[p.id] = RuntimeQuadletEmergencyContainment.uncertainStoppedIntentSha256(
                                root, expected, spec, p, pin.runtimeFingerprint, fence.id, observed)
                        } else require(observed.exitCode in (if (p.oneShot) 0..255 else setOf(0, 143))) {
                            "Unacknowledged CID lacks original or bounded uncertain-stop evidence"
                        }
                        unacknowledged[p.id] = observed.copy(reason = when {
                            observed.reason == "native-created-never-started-read-only" -> "never-started-created-cid-missing-original-launch-and-stop-ack"
                            launch == null -> "missing-original-launch-and-stop-ack"
                            else -> "missing-original-stop-ack"
                        })
                    }
                }
            } else require(!Files.exists(launchResult, NOFOLLOW_LINKS) &&
                !Files.exists(memberResult, NOFOLLOW_LINKS) && !Files.exists(stopIntent, NOFOLLOW_LINKS) &&
                !Files.exists(stopResult, NOFOLLOW_LINKS)) {
                "Original result without launch intent"
            }
            p.id to audit(spec, p)
        }
        require(policies == installedRecord.installedAuditSha256 &&
            namespaceStopped(spec, pin.runtimeFingerprint, stoppedCids +
                unacknowledged.mapValues { it.value.cid }) &&
            !Files.exists(root.resolve("stage.result.json"), NOFOLLOW_LINKS)) {
            "Changed installed policy or native container after failed StartUnit"
        }
        val receipt = QuadletStageTerminalObservation(generation = generation, member = spec.name,
            bundleSha256 = expected, originalStageIntentSha256 = ReleaseLocks.sha256(stage),
            originalInstallResultSha256 = ReleaseLocks.sha256(installed), fenceId = fence.id,
            observedPolicy = policies, observedStoppedCids = stoppedCids,
            observedUnacknowledgedCids = unacknowledged, uncertainEmergencyIntentSha256 = uncertainEmergency,
            createdOwnerLossIntentSha256 = createdOwnerLoss,
            disposition = if (stoppedCids.isEmpty() && unacknowledged.isEmpty()) "terminal-failed-before-native-launch"
                else "terminal-fenced-stopped-after-partial-start")
        ReleasePrivateFiles.save(terminal, json.encodeToString(receipt).toByteArray())
        return receipt
    }
}

internal fun quadletTerminalUnit(unit: String): Boolean {
    require(unit.matches(Regex("p0v3-q-[a-f0-9]{12}-[a-z0-9-]+\\.service")))
    val child = ProcessBuilder("/usr/bin/systemctl", "show", "--no-pager",
        "--property=LoadState,ActiveState,MainPID,UnitFileState", unit)
        .redirectErrorStream(true).apply { environment().clear() }.start()
    try {
        require(child.waitFor(20, TimeUnit.SECONDS) && child.exitValue() == 0)
        val text = child.inputStream.use { it.readNBytes(8193) }.also { require(it.size in 1..8192) }
            .decodeToString(throwOnInvalidSequence = true)
        val fields = text.lineSequence().filter { it.contains('=') }
            .associate { it.substringBefore('=') to it.substringAfter('=') }
        return fields["LoadState"] == "loaded" && fields["ActiveState"] in setOf("failed", "inactive") &&
            fields["MainPID"] == "0" && fields["UnitFileState"] == "generated"
    } finally { if (child.isAlive) child.destroyForcibly() }
}
