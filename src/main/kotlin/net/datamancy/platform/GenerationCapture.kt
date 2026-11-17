package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import java.time.Instant
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable

/** Thread-scoped monotonic recovery budget. Nested controller/runtime calls inherit the smaller
 * remaining interval; a native subprocess cannot reset the clock for each volume or phase.
 * An UTC projection is diagnostic only and never overrules the monotonic deadline.
 */
internal object RecoveryDeadline {
    const val MAX_MILLIS = 8 * 60 * 60 * 1000L
    private val bound = ThreadLocal<Long?>()
    fun <T> within(maxMillis: Long = MAX_MILLIS, effect: () -> T): T {
        require(maxMillis in 1..MAX_MILLIS)
        val previous = bound.get()
        val now = System.nanoTime()
        val desired = java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(maxMillis)
        val inherited = previous?.let { it - now }
        require(inherited == null || inherited > 0L) { "Recovery deadline expired; retain isolation" }
        val nanos = if (inherited == null) desired else minOf(desired, inherited)
        bound.set(now + nanos)
        try { return effect() } finally { if (previous == null) bound.remove() else bound.set(previous) }
    }
    fun remainingMillis(): Long {
        val remaining = (bound.get() ?: error("Recovery operation missing monotonic deadline")) - System.nanoTime()
        check(remaining > 0) { "Recovery deadline expired; retain isolation" }
        val millis = java.util.concurrent.TimeUnit.NANOSECONDS.toMillis(remaining)
        check(millis > 0) { "Recovery deadline lacks a complete millisecond" }
        return millis
    }
    fun remainingSeconds(): Long = (remainingMillis() / 1000).also {
        check(it > 0) { "Recovery deadline lacks a complete native second" }
    }
    fun remainingSecondsIfBound(): Long? = if (bound.get() == null) null else remainingSeconds()
    fun observedUtcDeadline(): Instant = Instant.now().plusMillis(remainingMillis())
}

internal interface ColdGenerationBackend {
    fun <T> withFrozen(spec: PrivateDeploymentSpec, fence: String, action: (FrozenRuntimeObservation) -> T): T
    fun exportVolume(spec: PrivateDeploymentSpec, volume: RuntimeVolume, output: Path)
    /** Unit-only injected transports retain the historic method with a postwrite guard.
     * The native implementation MUST override this and enforce maximumBytes before writes.
     */
    fun exportVolume(spec: PrivateDeploymentSpec, volume: RuntimeVolume, output: Path, maximumBytes: Long) {
        require(maximumBytes in (VolumeTar.MAX_METADATA_PREFIX + 1024L)..RecoveryCapsule.MAX_TOTAL)
        exportVolume(spec, volume, output)
        RecoveryCapsule.guard(output, maximumBytes)
    }
}
@Serializable internal data class GenerationCaptureIntent(val id: String, val generation: String, val bundleSha256: String,
    val fences: Map<String, String>, val expectedPayloads: Set<String>,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val credentialHeadSha256: String? = null)
@Serializable internal data class GenerationCaptureOutcome(val id: String, val bundleSha256: String, val passed: Boolean,
    val verification: CapsuleVerification? = null, val failureType: String? = null)

/** Read-only export from an already ownership-audited, stopped, locked member.
 * The kernel file-size limit bounds plaintext output, and the privileged timeout bounds its CLI.
 * Neither this helper nor a successful export establishes functional restorability.
 */
internal object ColdVolumeExport {
    fun rootMetadata(spec: PrivateDeploymentSpec, volume: RuntimeVolume, home: Path): VolumeRootMetadata =
        ColdVolumeMetadata().observeFull(spec, volume, home)
    fun export(spec: PrivateDeploymentSpec, volume: RuntimeVolume, output: Path,
        deadline: Instant = Instant.now().plusSeconds(WeeklyRestoreSchedule.BUDGET_SECONDS),
        maximumBytes: Long = RecoveryCapsule.MAX_TOTAL) {
        PrivateDeployment.validate(spec)
        require(maximumBytes in (VolumeTar.MAX_METADATA_PREFIX + 1024L)..RecoveryCapsule.MAX_TOTAL) {
            "Insufficient original-state payload allowance before cold export"
        }
        require(volume in spec.volumes && output.isAbsolute && output.normalize() == output &&
            output.parent.toRealPath() == output.parent && !Files.exists(output, NOFOLLOW_LINKS)) { "Invalid cold volume export" }
        val root = rootMetadata(spec, volume, output.parent)
        val remaining = minOf(Duration.between(Instant.now(), deadline).seconds,
            RecoveryDeadline.remainingSeconds())
        require(remaining in 1..WeeklyRestoreSchedule.BUDGET_SECONDS) { "Cold export operation deadline expired" }
        Files.createFile(output, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        // Reserve the entire root PAX prefix BEFORE the native writer starts. RLIMIT_FSIZE
        // prevents even an uncertain/crashed exporter from overrunning the admitted release
        // budget; a post-export size check alone would be too late to protect host headroom.
        val nativeMaximum = maximumBytes - VolumeTar.MAX_METADATA_PREFIX
        val command = listOf("/usr/bin/sudo", "-n", "/usr/bin/prlimit", "--fsize=$nativeMaximum:$nativeMaximum",
            "--", "/usr/bin/timeout", "--signal=KILL", "--kill-after=1s", "${remaining}s") + spec.store.prefix().drop(2) + listOf("volume", "export", "--output=$output",
            "p0v3-live-${spec.name}-volume-${volume.id}")
        if (Thread.currentThread().isInterrupted) throw InterruptedException("Cold export interrupted before effect")
        val process = ProcessBuilder(command).redirectOutput(ProcessBuilder.Redirect.DISCARD)
            .redirectError(ProcessBuilder.Redirect.DISCARD).apply {
                environment().clear(); environment().putAll(mapOf("PATH" to "/usr/bin:/bin", "LANG" to "C.UTF-8", "HOME" to output.parent.toString()))
            }.start()
        try {
            check(process.waitFor(remaining + 15, TimeUnit.SECONDS) && process.exitValue() == 0) { "Cold volume export failed or timed out; retain partial capture" }
            require(Instant.now() < deadline) { "Cold export exceeded the operation deadline; retain isolation" }
            RecoveryCapsule.guard(output, nativeMaximum)
            require(rootMetadata(spec, volume, output.parent) == root) { "Volume root changed during capture" }
            VolumeTar.prependRoot(output, root.uid, root.gid, root.mode, root.modified.seconds, root.modified.nanos,
                root.accessAcl, root.defaultAcl, root.userXattrs)
            RecoveryCapsule.guard(output, maximumBytes)
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
