package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.Serializable

internal interface BackupGenerationFactory {
    fun forBackup(access: RuntimeBackupAccess): BackupGenerationBackend
}
internal interface BackupGenerationBackend : GenerationBackend, ColdGenerationBackend {
    fun claim(spec: PrivateDeploymentSpec)
    fun quiesce(spec: PrivateDeploymentSpec): String
    fun resume(spec: PrivateDeploymentSpec, fence: String): List<RuntimeStatus>
    fun finish(spec: PrivateDeploymentSpec)
}
@Serializable internal data class GenerationBackupOutcome(val access: RuntimeBackupAccess, val passed: Boolean,
    val snapshot: KopiaSnapshotReceipt? = null, val sourceResumed: Boolean = false, val failureType: String? = null)

/** Uses the same audited runtime for staging, capture, import and operation-bound routine backup. */
internal class NativeGenerationBackend(private val bindings: Map<String, String>, private val access: RuntimeBackupAccess? = null) :
    GenerationBackend, ColdGenerationBackend, GenerationImportBackend, GenerationRestoreStartupBackend, BackupGenerationFactory, BackupGenerationBackend {
    private val runtime = PrivateDeployment.real(bindings, access)
    override fun forBackup(access: RuntimeBackupAccess) = NativeGenerationBackend(bindings, access)
    override fun audit(spec: PrivateDeploymentSpec, pristine: Boolean) = runtime.audit(spec, pristine)
    override fun apply(spec: PrivateDeploymentSpec) = runtime.apply(spec, pristine = true)
    override fun isolate(spec: PrivateDeploymentSpec): String {
        if (access != null) return runtime.isolateBackup(spec)
        val fence = runtime.maintenanceStatus(spec)
        return runtime.enterMaintenance(spec, fence?.reason ?: "update", fence?.stageTarget).id
    }
    override fun importCold(spec: PrivateDeploymentSpec, archives: Map<String, Path>, sourceArchiveSha256: String, verificationRoot: Path, expectedHashes: Map<String, String>) =
        runtime.importCold(spec, archives, sourceArchiveSha256, verificationRoot, expectedHashes)
    override fun startImported(spec: PrivateDeploymentSpec, fence: String) = runtime.startImported(spec, fence)
    override fun <T> withFrozen(spec: PrivateDeploymentSpec, fence: String, action: (FrozenRuntimeObservation) -> T): T =
        runtime.withFrozen(spec, fence, action)
    override fun exportVolume(spec: PrivateDeploymentSpec, volume: RuntimeVolume, output: Path) = ColdVolumeExport.export(spec, volume, output)
    override fun claim(spec: PrivateDeploymentSpec) = runtime.claimBackup(spec)
    override fun quiesce(spec: PrivateDeploymentSpec) = runtime.enterMaintenance(spec, "backup").id
    override fun resume(spec: PrivateDeploymentSpec, fence: String): List<RuntimeStatus> {
        runtime.leaveMaintenance(spec, fence)
        // The separate operation lease still blocks ordinary startup across this boundary.
        return runtime.apply(spec)
    }
    override fun finish(spec: PrivateDeploymentSpec) = runtime.finishBackup(spec)
}
