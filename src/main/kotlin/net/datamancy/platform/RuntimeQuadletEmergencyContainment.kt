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

/** A NEW, explicitly separate owner-death containment effect. It is not an ACK for the
 * original StopUnit, launch, stage, isolation or capacity release. No second attempt is
 * permitted after its intent, even if the native command times out.
 */
@Serializable internal data class QuadletEmergencyContainment(val generation: String, val bundleSha256: String,
    val member: String, val process: String, val cid: String, val imageId: String, val fingerprint: String,
    val originalStopDelegationSha256: String, val fenceId: String, val disposition: String,
    val originalNativeStopNotIssued: Boolean = false, val systemdControlPid: Long? = null)

internal object RuntimeQuadletEmergencyContainment {
    private val json = Json { encodeDefaults = true }
    /** The sole original native stop helper fsyncs its intent before ANY stop command.
     * A prior original or owner-loss intent is uncertain even without its result.
     */
    internal fun originalNativeStopUnissued(root: Path, member: String, process: String): Boolean {
        val stem = "quadlet-stop-$member-$process"
        return listOf(".intent.json", ".result.json", ".reconciliation.json").none {
            Files.exists(root.resolve(stem + it), NOFOLLOW_LINKS)
        } && !Files.exists(root.resolve("quadlet-owner-loss-$member-$process.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("quadlet-owner-loss-$member-$process.result.json"), NOFOLLOW_LINKS)
    }
    /** Historical uncertain emergency command: bind its already-written intent to a
     * read-only exact stopped CID. An absent RESULT remains absent forever. This is
     * neither authorization of the old command nor an original helper ACK.
     */
    fun uncertainStoppedIntentSha256(root: Path, expected: String, spec: PrivateDeploymentSpec,
        process: RuntimeProcess, fingerprint: String, fenceId: String,
        observed: QuadletUnacknowledgedCid): String {
        require(process.oneShot && observed.exitCode == -1 && observed.imageId == process.imageId &&
            observed.reason == "native-read-only" && originalNativeStopUnissued(root, spec.name, process.id))
        val intentPath = root.resolve("quadlet-emergency-${spec.name}-${process.id}.intent.json")
        require(!Files.exists(root.resolve("quadlet-emergency-${spec.name}-${process.id}.result.json"), NOFOLLOW_LINKS)) {
            "Uncertain emergency effect must not acquire a fabricated result"
        }
        val original = ReleasePrivateFiles.read(intentPath, 8192)
        val binding = json.decodeFromString<QuadletEmergencyContainment>(original.decodeToString())
        val delegatedStop = ReleasePrivateFiles.read(root.resolve(
            "quadlet-delegate-${spec.name}-${process.id}-stop.intent.json"), 8192)
        require(binding.generation == root.fileName.toString() && binding.bundleSha256 == expected &&
            binding.member == spec.name && binding.process == process.id && binding.cid == observed.cid &&
            binding.imageId == process.imageId && binding.fingerprint == fingerprint &&
            binding.fenceId == fenceId &&
            binding.originalStopDelegationSha256 == ReleaseLocks.sha256(delegatedStop) &&
            binding.disposition == "independent-owner-death-emergency-stop-not-original-stop-ack") {
            "Uncertain independent intent is not bound to original CID, stop delegation and fence"
        }
        return ReleaseLocks.sha256(original)
    }
    fun contain(generation: String, expected: String, spec: PrivateDeploymentSpec, fingerprint: String,
        generationBase: Path = GenerationRuntime.BASE, runtimeBase: Path = PrivateDeployment.BASE,
        native: RuntimeCommands = PrivateRootfulCommands(90, spec.store)): QuadletEmergencyContainment {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) && expected.matches(Regex("[a-f0-9]{64}")) &&
            spec.name.startsWith("$generation-") && fingerprint.matches(Regex("[a-f0-9]{64}")))
        val root = generationBase.resolve(generation)
        val memberRoot = runtimeBase.resolve(spec.name)
        val source = ReleasePrivateFiles.read(root.resolve("bundle.json"), 1048576)
        val bundle = json.decodeFromString<GenerationBundle>(source.decodeToString())
        require(ReleaseLocks.sha256(source) == expected && bundle.request.id == generation &&
            bundle.members.single().spec == spec && bundle.members.single().runtimeFingerprint == fingerprint &&
            bundle.ownership != null && spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
            !Files.exists(root.resolve("stage.result.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("quadlet-serve.result.json"), NOFOLLOW_LINKS))
        val failed = json.decodeFromString<QuadletStageFailureObservation>(ReleasePrivateFiles.read(
            root.resolve("quadlet-stage-failure.observation.json"), 8192).decodeToString())
        require(failed.bundleSha256 == expected && failed.member == spec.name &&
            failed.phase.endsWith(":systemd-startunit") && failed.failureClass.isNotBlank())
        val process = spec.processes.single { failed.phase == "${it.id}:systemd-startunit" }
        val lease = json.decodeFromString<QuadletDelegationIntent>(ReleasePrivateFiles.read(root.resolve(
            "quadlet-delegate-${spec.name}-${process.id}-start.intent.json"), 8192).decodeToString())
        require(lease.bundleSha256 == expected && lease.member == spec.name &&
            lease.process == process.id && lease.fingerprint == fingerprint &&
            lease.ownerPid > 1 && !Files.exists(Path.of("/proc/${lease.ownerPid}"), NOFOLLOW_LINKS)) {
            "Only a dead original owner permits independent containment"
        }
        val fence = requireNotNull(RuntimeMaintenance.read(memberRoot, fingerprint))
        val unit = "${RuntimeQuadlets.unit(spec, process)}.service"
        require(quadletTerminalUnit(unit) &&
            Files.exists(root.resolve("quadlet-member-${spec.name}-${process.id}.intent.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("quadlet-member-${spec.name}-${process.id}.result.json"), NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("quadlet-stop-${spec.name}-${process.id}.result.json"), NOFOLLOW_LINKS)) {
            "Original failed StartUnit or missing stop ACK must remain distinct"
        }
        val originalStop = root.resolve("quadlet-delegate-${spec.name}-${process.id}-stop.intent.json")
        val stopBytes = ReleasePrivateFiles.read(originalStop, 8192)
        val stopping = json.decodeFromString<QuadletDelegationIntent>(stopBytes.decodeToString())
        require(stopping.action == "stop" && stopping.member == spec.name && stopping.process == process.id &&
            stopping.bundleSha256 == expected && stopping.fingerprint == fingerprint &&
            RuntimeQuadletInstalledAudit().audit(spec, process) == stopping.installedAuditSha256) {
            "Cannot prove original sole native ExecStop helper or installed unit closure"
        }
        // The original ExecStop helper fsyncs its native stop intent BEFORE issuing Podman stop.
        // A delegated StopUnit alone is NOT proof no stop happened. Exclude every original
        // native/owner-loss attempt and any in-flight systemd control helper under this lock.
        require(originalNativeStopUnissued(root, spec.name, process.id)) {
            "Original native stop or owner-loss effect is uncertain; independent stop forbidden"
        }
        val show = ProcessBuilder("/usr/bin/systemctl", "show", "--no-pager",
            "--property=ActiveState,MainPID,ControlPID,Job", unit)
            .redirectErrorStream(true).apply { environment().clear() }.start()
        val fields = try {
            require(show.waitFor(20, TimeUnit.SECONDS) && show.exitValue() == 0)
            val bytes = show.inputStream.use { it.readNBytes(8193) }
            require(bytes.size in 1..8192)
            bytes.decodeToString().lineSequence().filter { '=' in it }.associate {
                it.substringBefore('=') to it.substringAfter('=')
            }
        } finally { if (show.isAlive) show.destroyForcibly() }
        require(fields["ActiveState"] in setOf("failed", "inactive") &&
            fields["MainPID"] == "0" && fields["ControlPID"] == "0" &&
            fields["Job"] in setOf("0", "")) {
            "Original systemd stop helper may still be in flight"
        }
        val intent = root.resolve("quadlet-emergency-${spec.name}-${process.id}.intent.json")
        val result = root.resolve("quadlet-emergency-${spec.name}-${process.id}.result.json")
        require(!Files.exists(intent, NOFOLLOW_LINKS) && !Files.exists(result, NOFOLLOW_LINKS)) {
            "Prior independent containment may be uncertain; never replay"
        }
        val name = "p0v3-live-${spec.name}-${process.id}"
        fun inspect() = native.run(listOf("container", "inspect", name)).also {
            require(it.exitCode == 0 && it.output.toByteArray().size in 1..65536)
        }.output.let { json.parseToJsonElement(it).jsonArray.single().jsonObject }
        val before = inspect()
        val labels = before.getValue("Config").jsonObject.getValue("Labels").jsonObject
        val cid = before.getValue("Id").jsonPrimitive.content
        val state = before.getValue("State").jsonObject
        require(cid.matches(Regex("[a-f0-9]{64}")) && before.getValue("Name").jsonPrimitive.content == name &&
            before.getValue("Image").jsonPrimitive.content.removePrefix("sha256:") == process.imageId &&
            labels.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
            labels.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == fingerprint &&
            state.getValue("Status").jsonPrimitive.content == "running" &&
            state.getValue("Running").jsonPrimitive.content == "true") {
            "Unacknowledged failed unit has no exact running original CID"
        }
        val binding = QuadletEmergencyContainment(generation, expected, spec.name, process.id, cid,
            process.imageId, fingerprint, ReleaseLocks.sha256(stopBytes), fence.id,
            "independent-owner-death-emergency-stop-not-original-stop-ack", true, 0)
        ReleasePrivateFiles.save(intent, json.encodeToString(binding).toByteArray())
        val stopped = native.run(listOf("container", "stop", "--time=30", cid))
        require(stopped.exitCode == 0 && stopped.output.toByteArray().size <= 4096) {
            "Independent emergency stop uncertain; retain original intent and fence"
        }
        val after = inspect()
        val terminal = after.getValue("State").jsonObject
        require(after.getValue("Id").jsonPrimitive.content == cid &&
            after.getValue("Image").jsonPrimitive.content.removePrefix("sha256:") == process.imageId &&
            terminal.getValue("Status").jsonPrimitive.content == "exited" &&
            terminal.getValue("Running").jsonPrimitive.content == "false") {
            "Independent emergency stop has no exact stopped CID readback"
        }
        ReleasePrivateFiles.save(result, json.encodeToString(binding).toByteArray())
        return binding
    }
}
