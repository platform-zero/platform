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

@Serializable internal data class QuadletStopIntent(val schemaVersion: Int = 1, val delegationSha256: String,
    val member: String, val process: String, val containerId: String, val fingerprint: String)
@Serializable internal data class QuadletStopResult(val schemaVersion: Int = 1, val intentSha256: String,
    val containerId: String, val stopped: Boolean, val nativeStopAcknowledged: Boolean)
@Serializable internal data class QuadletStopReconciliation(val schemaVersion: Int = 1, val intentSha256: String,
    val containerId: String, val observedStopped: Boolean)

/** The *sole* effective systemd ExecStop/Post actor. Podman stop is addressed to the
 * inspected original CID, never --rm or --replace. A missing native ACK is never replayed.
 * A later stop-post may independently observe a stopped container, but records a separate
 * reconciliation, not a fabricated original result.
 */
internal class RuntimeQuadletStop(private val generationRoot: Path,
    private val delegation: RuntimeQuadletDelegation,
    private val commands: RuntimeCommands = PrivateRootfulCommands(45, RuntimeStore.CANONICAL_V2)) {
    private val json = Json { encodeDefaults = true }
    private val hash = Regex("[a-f0-9]{64}")
    private fun paths(member: String, process: String): Triple<Path, Path, Path> {
        val stem = "quadlet-stop-$member-$process"
        return Triple(NotebookEpisodePaths.path(generationRoot,"$stem.intent",member,process),
            NotebookEpisodePaths.path(generationRoot,"$stem.result",member,process),
            NotebookEpisodePaths.path(generationRoot,"$stem.reconciliation",member,process))
    }
    private data class Observed(val cid: String, val running: Boolean, val stopped: Boolean)
    private fun observe(member: String, process: String, fingerprint: String, image: String, imageId: String): Observed {
        val name = "p0v3-live-$member-$process"
        val reply = commands.run(listOf("container", "inspect", name))
        require(reply.exitCode == 0 && reply.output.toByteArray().size in 1..65536) {
            "Original Quadlet container unavailable; do not infer stopped state"
        }
        val item = json.parseToJsonElement(reply.output).jsonArray.single().jsonObject
        val state = item.getValue("State").jsonObject
        val labels = item.getValue("Config").jsonObject.getValue("Labels").jsonObject
        val cid = item.getValue("Id").jsonPrimitive.content
        val status = state.getValue("Status").jsonPrimitive.content
        val running = state.getValue("Running").jsonPrimitive.content.toBooleanStrict()
        require(cid.matches(hash) && item.getValue("Name").jsonPrimitive.content == name &&
            item.getValue("Image").jsonPrimitive.content.removePrefix("sha256:") == imageId &&
            item.getValue("Config").jsonObject.getValue("Image").jsonPrimitive.content == image &&
            labels.getValue("io.p0v3.private-deployment").jsonPrimitive.content == member &&
            labels.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == fingerprint &&
            status in setOf("running", "exited") && running == (status == "running")) {
            "Original Quadlet CID, image, label or state changed"
        }
        return Observed(cid, running, !running)
    }
    fun stop(generation: String, member: String, process: String): QuadletStopResult {
        val lease = delegation.authorize(generation, member, process, "stop")
        val bundleBytes = ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"), 1048576)
        require(ReleaseLocks.sha256(bundleBytes) == lease.bundleSha256)
        val spec = json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
            .members.single { it.spec.name == member }.spec
        val p = spec.processes.single { it.id == process }
        val (intentPath, resultPath, reconciliationPath) = paths(member, process)
        val prior = Files.exists(intentPath, NOFOLLOW_LINKS)
        val original = if (prior) {
            val bytes = ReleasePrivateFiles.read(intentPath, 8192)
            val old = json.decodeFromString<QuadletStopIntent>(bytes.decodeToString(throwOnInvalidSequence = true))
            require(old.schemaVersion == 1 && old.member == member && old.process == process &&
                old.fingerprint == lease.fingerprint && old.delegationSha256 ==
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(NotebookEpisodePaths.path(generationRoot,
                        "quadlet-delegate-$member-$process-stop.intent",member,process), 8192)) &&
                old.containerId.matches(hash) && json.encodeToString(old).toByteArray().contentEquals(bytes)) {
                "Foreign original Quadlet stop"
            }
            old
        } else null
        if (Files.exists(resultPath, NOFOLLOW_LINKS)) {
            val bytes = ReleasePrivateFiles.read(resultPath, 8192)
            val result = json.decodeFromString<QuadletStopResult>(bytes.decodeToString(throwOnInvalidSequence = true))
            require(original != null && result.schemaVersion == 1 && result.intentSha256 ==
                ReleaseLocks.sha256(ReleasePrivateFiles.read(intentPath, 8192)) &&
                result.containerId == original.containerId && result.stopped &&
                json.encodeToString(result).toByteArray().contentEquals(bytes) &&
                observe(member, process, lease.fingerprint, p.image, p.imageId).let { it.cid == result.containerId && it.stopped }) {
                "Original stop result or retained container changed"
            }
            delegation.acknowledge(generation, member, process, "stop")
            return result
        }
        if (prior) {
            val observed = observe(member, process, lease.fingerprint, p.image, p.imageId)
            require(observed.cid == original!!.containerId) { "Changed CID after uncertain stop" }
            if (!Files.exists(reconciliationPath, NOFOLLOW_LINKS)) {
                ReleasePrivateFiles.save(reconciliationPath, json.encodeToString(QuadletStopReconciliation(
                    intentSha256 = ReleaseLocks.sha256(ReleasePrivateFiles.read(intentPath, 8192)),
                    containerId = observed.cid, observedStopped = observed.stopped)).toByteArray())
            }
            error("Original stop ACK missing; reconciled observation retained, do not replay")
        }
        require(!Files.exists(reconciliationPath, NOFOLLOW_LINKS))
        val before = observe(member, process, lease.fingerprint, p.image, p.imageId)
        if (NotebookEpisodePaths.suffix(generationRoot,member,process).isNotEmpty()) {
            val launchPath = NotebookEpisodePaths.path(generationRoot,
                "quadlet-launch-$member-$process.result",member,process)
            val launch = json.decodeFromString<QuadletLaunchResult>(ReleasePrivateFiles.read(launchPath,8192)
                .decodeToString(throwOnInvalidSequence=true))
            require(launch.nativeAcknowledged && launch.containerId == before.cid && launch.imageId == p.imageId) {
                "Episode StopUnit did not address the original acknowledged CID"
            }
        }
        val stopIntent = QuadletStopIntent(delegationSha256 = ReleaseLocks.sha256(ReleasePrivateFiles.read(
            NotebookEpisodePaths.path(generationRoot,
                "quadlet-delegate-$member-$process-stop.intent",member,process), 8192)),
            member = member, process = process, containerId = before.cid, fingerprint = lease.fingerprint)
        val intentBytes = json.encodeToString(stopIntent).toByteArray()
        ReleasePrivateFiles.save(intentPath, intentBytes)
        if (before.running) {
            val reply = commands.run(listOf("container", "stop", "--time=30", before.cid))
            require(reply.exitCode == 0 && reply.output.toByteArray().size <= 4096) {
                "Original stop acknowledgment unavailable; reconcile, do not replay"
            }
        }
        val after = observe(member, process, lease.fingerprint, p.image, p.imageId)
        require(after.cid == before.cid && after.stopped) { "Original Quadlet container not stopped" }
        val result = QuadletStopResult(intentSha256 = ReleaseLocks.sha256(intentBytes),
            containerId = before.cid, stopped = true, nativeStopAcknowledged = before.running)
        ReleasePrivateFiles.save(resultPath, json.encodeToString(result).toByteArray())
        delegation.acknowledge(generation, member, process, "stop")
        return result
    }
}
