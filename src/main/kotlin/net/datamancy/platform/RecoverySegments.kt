package net.datamancy.platform

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import kotlinx.serialization.Serializable

/** Segmentation is transport framing, not an alternate backup engine. Kopia stores/encrypts each part. */
@Serializable internal data class RecoveryVolume(val name: String, val bytes: Long, val sha256: String,
    val segments: List<String>)

internal object RecoverySegments {
    private val mode = PosixFilePermissions.fromString("rw-------")
    private val hash = Regex("[a-f0-9]{64}")
    private val volume = Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,23}/volumes/[a-z][a-z0-9-]*\\.tar")
    private val managed = Regex("managed/(home|workspace|manifests|transcripts)/tree\\.tar")
    private fun interrupted() { if (Thread.currentThread().isInterrupted) throw InterruptedException("Recovery framing interrupted; retain isolation") }

    fun validate(manifest: CapsuleManifest) {
        require(manifest.volumes.size <= 256 && manifest.volumes.map { it.name }.distinct().size == manifest.volumes.size)
        val files = manifest.files.associateBy { it.name }
        val claimed = mutableSetOf<String>()
        for (item in manifest.volumes) {
            require((volume.matches(item.name) && item.name.startsWith(manifest.generation + "-") || managed.matches(item.name)) &&
                item.name !in files &&
                item.bytes in 1024..RecoveryCapsule.MAX_TOTAL && item.bytes % 512 == 0L && hash.matches(item.sha256) &&
                item.segments.size in 2..512) { "Invalid segmented volume" }
            require(item.segments == item.segments.indices.map { "${item.name}.part-${it.toString().padStart(4, '0')}" }) { "Noncanonical segment order" }
            val parts = item.segments.map { name ->
                require(claimed.add(name)) { "Shared recovery segment" }
                requireNotNull(files[name]) { "Missing recovery segment" }.also {
                    require(it.bytes in 1..RecoveryCapsule.MAX_FILE && hash.matches(it.sha256))
                }
            }
            require(parts.sumOf { it.bytes } == item.bytes &&
                (!managed.matches(item.name) || manifest.managedFiles.containsAll(item.segments))) { "Segment size or managed ownership mismatch" }
        }
    }

    /** Called while source locks remain held. Leaves original exports for controller-owned cleanup. */
    fun prepare(payloads: MutableMap<String, Path>, segmentBytes: Long = RecoveryCapsule.MAX_FILE): List<RecoveryVolume> {
        require(segmentBytes in 512..RecoveryCapsule.MAX_FILE && segmentBytes % 512 == 0L)
        val result = mutableListOf<RecoveryVolume>()
        for ((name, path) in payloads.toMap()) {
            if (!(volume.matches(name) || managed.matches(name)) || Files.size(path) <= segmentBytes) continue
            RecoveryCapsule.guard(path, RecoveryCapsule.MAX_TOTAL)
            val size = Files.size(path)
            require(size % 512 == 0L && (size + segmentBytes - 1) / segmentBytes <= 512)
            val originalHash = RecoveryCapsule.fileHash(path)
            val parts = mutableListOf<String>()
            Files.newInputStream(path, READ, NOFOLLOW_LINKS).use { input ->
                var remaining = size
                while (remaining > 0) {
                    interrupted()
                    val suffix = ".part-${parts.size.toString().padStart(4, '0')}"
                    val target = path.resolveSibling(path.fileName.toString() + suffix)
                    val length = minOf(remaining, segmentBytes)
                    FileChannel.open(target, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(mode)).use { output ->
                        var left = length
                        val buffer = ByteArray(65536)
                        while (left > 0) {
                            interrupted()
                            val count = input.read(buffer, 0, minOf(left, buffer.size.toLong()).toInt())
                            require(count > 0) { "Truncated volume export" }
                            val bytes = ByteBuffer.wrap(buffer, 0, count)
                            while (bytes.hasRemaining()) output.write(bytes)
                            left -= count
                        }
                        output.force(true)
                    }
                    payloads[name + suffix] = target; parts += name + suffix; remaining -= length
                }
                require(input.read() == -1) { "Volume export grew" }
            }
            require(RecoveryCapsule.fileHash(path) == originalHash) { "Volume export changed during segmentation" }
            FileChannel.open(path.parent, READ).use { it.force(true) }
            payloads.remove(name)
            result += RecoveryVolume(name, size, originalHash, parts)
        }
        return result
    }

    /** Only after the physical manifest set and every part hash were authenticated. Exclusive output, no retry of partial writes. */
    fun materialize(root: Path, manifest: CapsuleManifest,
        availableBytes: (Path) -> Long = { Files.getFileStore(it).usableSpace }) {
        validate(manifest)
        if (manifest.volumes.isEmpty()) return
        val missing = manifest.volumes.filterNot { Files.exists(root.resolve(it.name), NOFOLLOW_LINKS) }
        require(availableBytes(root) >= missing.sumOf { it.bytes } + 10737418240L + 536870912L) { "Insufficient reassembly headroom" }
        val files = manifest.files.associateBy { it.name }
        for (item in manifest.volumes) {
            interrupted()
            val target = root.resolve(item.name)
            require(target.parent.toRealPath() == target.parent)
            if (!Files.exists(target, NOFOLLOW_LINKS)) {
                FileChannel.open(target, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(mode)).use { output ->
                    for (name in item.segments) {
                        val expected = files.getValue(name)
                        val path = root.resolve(name)
                        RecoveryCapsule.guard(path)
                        require(Files.size(path) == expected.bytes)
                        val digest = MessageDigest.getInstance("SHA-256")
                        Files.newInputStream(path, READ, NOFOLLOW_LINKS).use { input ->
                            var left = expected.bytes
                            val buffer = ByteArray(65536)
                            while (left > 0) {
                                interrupted()
                                val count = input.read(buffer, 0, minOf(left, buffer.size.toLong()).toInt())
                                require(count > 0) { "Truncated recovery segment" }
                                digest.update(buffer, 0, count)
                                val bytes = ByteBuffer.wrap(buffer, 0, count)
                                while (bytes.hasRemaining()) output.write(bytes)
                                left -= count
                            }
                            require(input.read() == -1)
                        }
                        require(java.util.HexFormat.of().formatHex(digest.digest()) == expected.sha256) { "Recovery segment changed" }
                    }
                    output.force(true)
                }
                FileChannel.open(target.parent, READ).use { it.force(true) }
            }
            RecoveryCapsule.guard(target, RecoveryCapsule.MAX_TOTAL)
            require(Files.size(target) == item.bytes && RecoveryCapsule.fileHash(target) == item.sha256) { "Reassembled volume mismatch; retain partial recovery" }
        }
    }
}
