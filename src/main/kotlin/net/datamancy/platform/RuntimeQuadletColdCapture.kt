package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Read-only, stopped native Quadlet observation plus audited volume EXPORT.
 * It cannot call PrivateDeployment.apply/isolate, synthesize runtime.jobs or
 * start/stop any application process. Kopia alone snapshots the exported bytes.
 */
internal class RuntimeQuadletColdCapture(private val root: Path, private val bundle: GenerationBundle,
    private val expected: String, private val runtimeRoot: Path = PrivateDeployment.BASE,
    private val census: RuntimeCapacityCensus = RuntimeCapacityCensus(),
    private val native: RuntimeCommands = PrivateRootfulCommands(45, RuntimeStore.CANONICAL_V2)) :
    GenerationBackend, ColdGenerationBackend {
    private val json = Json { ignoreUnknownKeys = false }
    private val pin = bundle.members.single()
    private val spec = pin.spec
    private fun observed(): FrozenRuntimeObservation {
        require(spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 && root.fileName.toString() == bundle.request.id &&
            runtimeRoot == PrivateDeployment.BASE && expected == ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"), 1048576)))
        val terminal = requireNotNull(RuntimeQuadletCapacityTerminal.read(root, bundle, expected)) {
            "Quadlet cold capture requires a separate verified terminal observation"
        }
        val fence = requireNotNull(RuntimeMaintenance.read(runtimeRoot.resolve(spec.name), pin.runtimeFingerprint))
        require(fence.id == terminal.fenceId)
        val rows = census.snapshot(spec.store)
        require(census.quiescent(listOf(RuntimeCapacityCensus.Member(spec, pin.runtimeFingerprint)), rows) &&
            RuntimeQuadletCapacityTerminal.matchesOriginalCids(spec.name, terminal.stoppedCids, rows)) {
            "Quadlet cold source has a running, foreign or changed native process"
        }
        val statuses = spec.processes.map { process ->
            val cid = terminal.stoppedCids.getValue(process.id)
            val result = native.run(listOf("container", "inspect", cid))
            require(result.exitCode == 0 && result.output.toByteArray().size in 1..65536)
            val item = json.parseToJsonElement(result.output).jsonArray.single().jsonObject
            val state = item.getValue("State").jsonObject
            val labels = item.getValue("Config").jsonObject.getValue("Labels").jsonObject
            val code = state.getValue("ExitCode").jsonPrimitive.content.toInt()
            require(item.getValue("Id").jsonPrimitive.content == cid &&
                item.getValue("Name").jsonPrimitive.content == "p0v3-live-${spec.name}-${process.id}" &&
                item.getValue("Image").jsonPrimitive.content.removePrefix("sha256:") == process.imageId &&
                labels.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
                labels.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == pin.runtimeFingerprint &&
                state.getValue("Running").jsonPrimitive.content == "false" &&
                code in (if (process.oneShot) setOf(0) else setOf(0, 143))) {
                "Quadlet original stopped CID or native exit differs"
            }
            RuntimeStatus(process.id, if (process.oneShot) "completed" else "exited", code)
        }
        return FrozenRuntimeObservation(spec.name, pin.runtimeFingerprint, fence.id,
            QuadletColdEvidence.ledgerHash(spec, terminal), spec.processes.filter { it.oneShot }.map { it.id }.toSet(), statuses)
    }
    override fun audit(spec: PrivateDeploymentSpec, pristine: Boolean): RuntimeAudit {
        require(this.spec == spec && !pristine)
        val proof = observed()
        return RuntimeAudit(spec.name, proof.fingerprint, spec.volumes.size + spec.networks.size,
            proof.fenceId, proof.statuses)
    }
    override fun <T> withFrozen(spec: PrivateDeploymentSpec, fence: String,
        action: (FrozenRuntimeObservation) -> T): T {
        require(this.spec == spec && fence.matches(Regex("[0-9a-f-]{36}")))
        return PrivateDeployment.withOrderedNativeLocks(listOf(spec.name), runtimeRoot) {
            val before = observed()
            require(before.fenceId == fence)
            val result = action(before)
            require(observed() == before) { "Quadlet original CID, initializer or fence changed during capture" }
            result
        }
    }
    override fun exportVolume(spec: PrivateDeploymentSpec, volume: RuntimeVolume, output: Path) =
        error("Quadlet capture requires bounded native volume export")
    override fun exportVolume(spec: PrivateDeploymentSpec, volume: RuntimeVolume, output: Path,
        maximumBytes: Long) {
        require(this.spec == spec && volume in spec.volumes)
        ColdVolumeExport.export(spec, volume, output, maximumBytes = maximumBytes)
    }
    override fun apply(spec: PrivateDeploymentSpec): List<RuntimeStatus> =
        error("Quadlet process lifecycle is exclusively systemd-owned")
    override fun isolate(spec: PrivateDeploymentSpec): String =
        error("Quadlet cold capture cannot invent an original isolation result")
}
