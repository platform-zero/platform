package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class RecoverySegmentsTest {
    private val name = "q-123456789abc-foundation/volumes/postgres.tar"
    private fun fixture(block: (Path, Path, MutableMap<String, Path>) -> Unit) {
        val root = Files.createTempDirectory("segmented-recovery-unit-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val source = root.resolve("export.tar")
        Files.write(source, VolumeTarTest.tar(VolumeTarTest.root(), VolumeTarTest.member("data", data = ByteArray(4000) { it.toByte() })))
        Files.setPosixFilePermissions(source, PosixFilePermissions.fromString("rw-------"))
        try { block(root, source, linkedMapOf(name to source)) }
        finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private fun manifest(payloads: Map<String, Path>, volumes: List<RecoveryVolume>) = CapsuleManifest(
        id = "cap-123456789abc", generation = "q-123456789abc", bundleSha256 = "a".repeat(64), members = emptyList(),
        files = RecoveryCapsule.describe(payloads), volumes = volumes)
    private fun restored(root: Path, payloads: Map<String, Path>): Path {
        val destination = Files.createDirectory(root.resolve("recovered"))
        for ((name, path) in payloads) {
            val target = destination.resolve(name)
            Files.createDirectories(target.parent)
            Files.copy(path, target)
            Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"))
        }
        return destination
    }
    @Test fun `bounded segments reconstruct byte exact archive including nanosecond metadata`() = fixture { root, source, payloads ->
        Files.write(source, VolumeTarTest.tar(VolumeTarTest.root(),
            VolumeTarTest.member("pax", 'x', VolumeTarTest.pax("mtime", "-0.000000001")),
            VolumeTarTest.member("data", data = ByteArray(4000) { it.toByte() })))
        val original = Files.readAllBytes(source)
        val volumes = RecoverySegments.prepare(payloads, 1024)
        assertEquals(1, volumes.size)
        assertFalse(name in payloads)
        assertTrue(payloads.values.all { Files.size(it) <= 1024 })
        val manifest = manifest(payloads, volumes)
        val destination = restored(root, payloads)
        RecoverySegments.materialize(destination, manifest) { Long.MAX_VALUE }
        assertContentEquals(original, Files.readAllBytes(destination.resolve(name)))
        assertEquals(VolumeTar.inspect(source, 999), VolumeTar.inspect(destination.resolve(name), 999))
        assertEquals(999999999, VolumeTar.inspect(destination.resolve(name), 999).last().modifiedNanos)
        RecoverySegments.materialize(destination, manifest) { Long.MAX_VALUE } // Exact existing reassembly is idempotent observation.
        Files.write(destination.resolve(name), byteArrayOf(1))
        assertFails { RecoverySegments.materialize(destination, manifest) { Long.MAX_VALUE } }
    }
    @Test fun `no segments changes no legacy wire representation or payload map`() = fixture { _, source, payloads ->
        val volumes = RecoverySegments.prepare(payloads)
        assertTrue(volumes.isEmpty())
        assertEquals(mapOf(name to source), payloads)
        val wire = Json { encodeDefaults = true }.encodeToString(manifest(payloads, volumes))
        assertFalse("\"volumes\"" in wire)
    }
    @Test fun `malformed segment ordering bounds identity and collision are refused`() = fixture { _, _, payloads ->
        val volumes = RecoverySegments.prepare(payloads, 1024)
        val manifest = manifest(payloads, volumes)
        val item = volumes.single()
        for (bad in listOf(item.copy(name = "../escape.tar"), item.copy(bytes = item.bytes + 512),
            item.copy(segments = item.segments.reversed()), item.copy(sha256 = "wrong"), item.copy(segments = listOf(item.segments.first()))))
            assertFails { RecoverySegments.validate(manifest.copy(volumes = listOf(bad))) }
        assertFails { RecoverySegments.validate(manifest.copy(volumes = volumes + volumes)) }
        assertFails { RecoverySegments.validate(manifest.copy(files = manifest.files.drop(1))) }
        assertFails { RecoverySegments.prepare(payloads, 513) }
    }
    @Test fun `headroom tampering and interrupted framing leave no success or overwrite`() = fixture { root, _, payloads ->
        val volumes = RecoverySegments.prepare(payloads, 1024)
        val manifest = manifest(payloads, volumes)
        val destination = restored(root, payloads)
        assertFails { RecoverySegments.materialize(destination, manifest) { 10737418240L } }
        assertFalse(Files.exists(destination.resolve(name)))
        Thread.currentThread().interrupt()
        try { assertFailsWith<InterruptedException> { RecoverySegments.materialize(destination, manifest) { Long.MAX_VALUE } } }
        finally { assertTrue(Thread.interrupted()) }
        val first = destination.resolve(volumes.single().segments.first())
        val data = Files.readAllBytes(first); data[0] = (data[0].toInt() xor 1).toByte(); Files.write(first, data)
        assertFails { RecoverySegments.materialize(destination, manifest) { Long.MAX_VALUE } }
        assertTrue(Files.exists(destination.resolve(name))) // Partial output is retained, not silently retried.
        assertFails { RecoverySegments.materialize(destination, manifest) { Long.MAX_VALUE } }
    }
    @Test fun `exclusive segment creation cannot overwrite an earlier attempt`() = fixture { _, source, payloads ->
        Files.write(source.resolveSibling("export.tar.part-0000"), byteArrayOf(42))
        assertFails { RecoverySegments.prepare(payloads, 1024) }
        assertContentEquals(byteArrayOf(42), Files.readAllBytes(source.resolveSibling("export.tar.part-0000")))
    }
}
