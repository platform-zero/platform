package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable

internal interface ColdGenerationBackend {
    fun <T> withFrozen(spec: PrivateDeploymentSpec, fence: String, action: (FrozenRuntimeObservation) -> T): T
    fun exportVolume(spec: PrivateDeploymentSpec, volume: RuntimeVolume, output: Path)
}
@Serializable internal data class GenerationCaptureIntent(val id: String, val generation: String, val bundleSha256: String,
    val fences: Map<String, String>, val expectedPayloads: Set<String>)
@Serializable internal data class GenerationCaptureOutcome(val id: String, val bundleSha256: String, val passed: Boolean,
    val verification: CapsuleVerification? = null, val failureType: String? = null)

/** Read-only export from an already ownership-audited, stopped, locked member.
 * The kernel file-size limit bounds plaintext output, and the privileged timeout bounds its CLI.
 * Neither this helper nor a successful export establishes functional restorability.
 */
internal object ColdVolumeExport {
    fun rootMetadata(spec: PrivateDeploymentSpec, volume: RuntimeVolume, home: Path): VolumeRootMetadata =
        ColdVolumeMetadata().observe(spec, volume, home)
    fun export(spec: PrivateDeploymentSpec, volume: RuntimeVolume, output: Path) {
        PrivateDeployment.validate(spec)
        require(volume in spec.volumes && output.isAbsolute && output.normalize() == output &&
            output.parent.toRealPath() == output.parent && !Files.exists(output, NOFOLLOW_LINKS)) { "Invalid cold volume export" }
        val root = rootMetadata(spec, volume, output.parent)
        Files.createFile(output, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        val maximum = RecoveryCapsule.MAX_TOTAL - VolumeTar.MAX_ROOT_PREFIX
        val command = listOf("/usr/bin/sudo", "-n", "/usr/bin/prlimit", "--fsize=$maximum:$maximum",
            "--", "/usr/bin/timeout", "--signal=TERM", "--kill-after=10s", "120s") + spec.store.prefix().drop(2) + listOf("volume", "export", "--output=$output",
            "p0v3-live-${spec.name}-volume-${volume.id}")
        if (Thread.currentThread().isInterrupted) throw InterruptedException("Cold export interrupted before effect")
        val process = ProcessBuilder(command).redirectOutput(ProcessBuilder.Redirect.DISCARD)
            .redirectError(ProcessBuilder.Redirect.DISCARD).apply {
                environment().clear(); environment().putAll(mapOf("PATH" to "/usr/bin:/bin", "LANG" to "C.UTF-8", "HOME" to output.parent.toString()))
            }.start()
        try {
            check(process.waitFor(150, TimeUnit.SECONDS) && process.exitValue() == 0) { "Cold volume export failed or timed out; retain partial capture" }
            RecoveryCapsule.guard(output, RecoveryCapsule.MAX_TOTAL)
            require(rootMetadata(spec, volume, output.parent) == root) { "Volume root changed during capture" }
            VolumeTar.prependRoot(output, root.uid, root.gid, root.mode, root.modified.seconds, root.modified.nanos)
        } catch (failure: InterruptedException) {
            Thread.currentThread().interrupt(); throw failure
        } finally {
            if (process.isAlive) {
                process.descendants().use { children -> children.forEach { it.destroyForcibly() } }
                process.destroyForcibly()
            }
        }
    }
}
