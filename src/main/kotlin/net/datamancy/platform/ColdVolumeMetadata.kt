package net.datamancy.platform

import java.nio.file.Path
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

internal data class VolumeRootMetadata(val uid: Int, val gid: Int, val mode: Int, val modified: VolumeTimestamp) {
    init { require(uid in 0..65534 && gid in 0..65534 && mode in 0..4095) }
    companion object {
        fun parse(text: String): VolumeRootMetadata {
            val fields = text.split('\n')
            require(fields.size == 6 && fields[5] == "directory") { "Volume root must be an actual directory" }
            require(fields.take(2).all { it.matches(Regex("[0-9]{1,5}")) } && fields[2].matches(Regex("[0-7]{1,4}")))
            require(fields[3].matches(Regex("-?[0-9]{1,10}")) &&
                fields[4].matches(Regex("[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{9} \\+0000"))) { "Precise UTC root timestamp required" }
            val time = Instant.parse(fields[4].substringBefore(" +0000").replace(' ', 'T') + "Z")
            require(time.epochSecond == fields[3].toLong()) { "Inconsistent root timestamps" }
            return VolumeRootMetadata(fields[0].toInt(), fields[1].toInt(), fields[2].toInt(8), VolumeTimestamp(time.epochSecond, time.nano))
        }
    }
}

/** Only observes or restores the exact owned volume root. No shell, dereferencing, recursive chmod or host trust changes. */
internal class ColdVolumeMetadata(private val execute: (List<String>, Path) -> String = ColdMetadataProcess::run) {
    private fun root(spec: PrivateDeploymentSpec, volume: RuntimeVolume): Path {
        PrivateDeployment.validate(spec); require(volume in spec.volumes); spec.store.verifyConfiguration()
        return Path.of("${spec.store.graph}/volumes/p0v3-live-${spec.name}-volume-${volume.id}/_data")
    }
    private val prefix = listOf("/usr/bin/sudo", "-n", "/usr/bin/timeout", "--kill-after=5s", "15s")
    fun observe(spec: PrivateDeploymentSpec, volume: RuntimeVolume, home: Path): VolumeRootMetadata {
        val root = root(spec, volume)
        return VolumeRootMetadata.parse(execute(prefix + listOf("/usr/bin/stat", "--printf=%u\\n%g\\n%a\\n%Y\\n%y\\n%F", "--", root.toString()), home))
    }
    fun restore(spec: PrivateDeploymentSpec, volume: RuntimeVolume, entry: VolumeTarEntry) {
        require(spec.name.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,23}")) && spec.processes.none { it.oneShot } &&
            entry.directory && entry.path == "." && entry.uid == volume.userId && entry.gid == volume.userId && entry.mode in 0..511)
        val expected = VolumeRootMetadata(entry.uid, entry.gid, entry.mode, VolumeTimestamp(entry.modifiedSeconds, entry.modifiedNanos))
        val root = root(spec, volume)
        observe(spec, volume, root.parent) // A symlink or non-directory root must fail before metadata writes.
        for (args in listOf(
            listOf("/usr/bin/chown", "--no-dereference", "${entry.uid}:${entry.gid}", "--", root.toString()),
            listOf("/usr/bin/chmod", entry.mode.toString(8), "--", root.toString()),
            listOf("/usr/bin/touch", "--no-dereference", "--date=@${expected.modified.decimal()}", "--", root.toString())
        )) execute(prefix + args, root.parent)
        require(observe(spec, volume, root.parent) == expected) { "Restored volume-root metadata mismatch" }
    }
}

/** Bounded diagnostics with a clean environment. Tests exercise this using synthetic subprocesses, never sudo/Podman. */
internal object ColdMetadataProcess {
    fun run(argv: List<String>, home: Path): String = execute(argv, home, 25000)
    internal fun execute(argv: List<String>, home: Path, timeoutMillis: Long): String {
        require(argv.isNotEmpty() && home.isAbsolute && timeoutMillis in 1..25000)
        if (Thread.currentThread().isInterrupted) throw InterruptedException("Metadata operation interrupted before effect")
        val process = ProcessBuilder(argv).redirectError(ProcessBuilder.Redirect.DISCARD).apply {
            environment().clear()
            environment().putAll(mapOf("PATH" to "/usr/bin:/bin", "LANG" to "C", "LC_ALL" to "C", "TZ" to "UTC", "HOME" to home.toString()))
        }.start()
        val reader = Executors.newSingleThreadExecutor { task -> Thread(task, "volume-metadata-output").apply { isDaemon = true } }
        try {
            process.outputStream.close()
            val output = reader.submit<ByteArray> { process.inputStream.use { it.readNBytes(1025) } }
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
            check(process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)) { "Volume metadata operation timed out; retain isolation" }
            check(process.exitValue() == 0) { "Volume metadata operation failed; retain isolation" }
            val remaining = deadline - System.nanoTime()
            check(remaining > 0) { "Volume metadata output timed out; retain isolation" }
            val bytes = output.get(remaining, TimeUnit.NANOSECONDS)
            require(bytes.size <= 1024) { "Oversized volume metadata output" }
            return bytes.decodeToString(throwOnInvalidSequence = true)
        } catch (failure: InterruptedException) {
            Thread.currentThread().interrupt(); throw failure
        } finally {
            // Only this invocation's process tree; timeout is never authority to resume a source.
            if (process.isAlive) {
                process.descendants().use { children -> children.forEach { it.destroyForcibly() } }
                process.destroyForcibly()
            }
            reader.shutdownNow()
        }
    }
}
