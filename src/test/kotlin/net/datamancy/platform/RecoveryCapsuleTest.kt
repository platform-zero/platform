package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

class RecoveryCapsuleTest {
    private val generation = "q-123456789abc"
    private val snapshot = "cap-123456789abc"
    private val hash = "a".repeat(64)
    private fun privateFile(path: Path, bytes: ByteArray): Path {
        Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        Files.write(path, bytes); return path
    }
    private fun fixture(test: (Path, Path, Path, Map<String, Path>, CapsuleManifest) -> Unit) {
        val root = Files.createTempDirectory("capsule-unit-")
        val permissions = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
        val archive = Files.createDirectory(root.resolve("data"), permissions).resolve("state.cap")
        val key = Files.createDirectory(root.resolve("custody"), permissions).resolve("key")
        val payloads = mapOf("member/config.json" to privateFile(root.resolve("config"), "synthetic private configuration".toByteArray()),
            "member/volume.tar" to privateFile(root.resolve("volume"), ByteArray(200000) { (it % 251).toByte() }))
        val member = FrozenRuntimeObservation("$generation-member", hash, "unit-fence", hash,
            setOf("init"), listOf(RuntimeStatus("init", "completed", 0), RuntimeStatus("daemon", "exited", 143)))
        val manifest = CapsuleManifest(id = snapshot, generation = generation, bundleSha256 = hash, members = listOf(member),
            files = RecoveryCapsule.describe(payloads))
        try { test(root, archive, key, payloads, manifest) }
        finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `encrypted capsule authenticates complete data and never claims functional restoration`() = fixture { _, archive, key, payloads, manifest ->
        val result = RecoveryCapsule.create(archive, key, manifest, payloads)
        assertTrue(result.authenticated)
        assertFalse(result.functionalRestoreVerified)
        assertEquals(2, result.files)
        assertEquals(manifest.files.sumOf { it.bytes }, result.plaintextBytes)
        assertEquals(64L, Files.size(key))
        assertEquals(result, RecoveryCapsule.verify(archive, key, snapshot, generation, hash))
        assertFalse(Files.readAllBytes(archive).decodeToString().contains("synthetic private configuration"))
        assertFailsWith<Exception> { RecoveryCapsule.create(archive, key, manifest, payloads) }
    }
    @Test fun `wrong key corruption truncation appended bytes and wrong scope all fail`() = fixture { root, archive, key, payloads, manifest ->
        RecoveryCapsule.create(archive, key, manifest, payloads)
        val original = Files.readAllBytes(archive)
        val wrong = privateFile(root.resolve("wrong-key"), ByteArray(64) { 7 })
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.verify(archive, wrong, snapshot, generation, hash) }
        for (position in listOf(0, 10, 100, original.lastIndex)) {
            val corrupt = original.clone(); corrupt[position] = (corrupt[position].toInt() xor 1).toByte(); Files.write(archive, corrupt)
            assertFailsWith<Exception> { RecoveryCapsule.verify(archive, key, snapshot, generation, hash) }
        }
        for (data in listOf(original.copyOf(20), original.copyOf(original.size - 1), original + byteArrayOf(0))) {
            Files.write(archive, data)
            assertFailsWith<Exception> { RecoveryCapsule.verify(archive, key, snapshot, generation, hash) }
        }
        Files.write(archive, original)
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.verify(archive, key, "cap-aaaaaaaaaaaa", generation, hash) }
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.verify(archive, key, snapshot, "q-aaaaaaaaaaaa", hash) }
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.verify(archive, key, snapshot, generation, "b".repeat(64)) }
    }
    @Test fun `unsafe payload names links modes budgets and stale declarations cannot be captured`() = fixture { root, archive, key, payloads, manifest ->
        val source = payloads.values.first()
        for (name in listOf("../escape", "/absolute", "a//b", "a/./b", "manifest.json", "manifest.json/child", "bad\\path"))
            assertFailsWith<IllegalArgumentException> { RecoveryCapsule.describe(mapOf(name to source)) }
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.describe(emptyMap()) }
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.describe(mapOf("parent" to source, "parent/child" to source)) }
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.describe(mapOf("a/b/c/d/e/f/g/h/i" to source)) }
        val link = root.resolve("link"); Files.createSymbolicLink(link, source)
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.describe(mapOf("safe" to link)) }
        Files.delete(link); Files.createLink(link, source)
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.describe(mapOf("safe" to source)) }
        Files.delete(link)
        Files.setPosixFilePermissions(source, PosixFilePermissions.fromString("rw-r--r--"))
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.describe(payloads) }
        Files.setPosixFilePermissions(source, PosixFilePermissions.fromString("rw-------"))
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.create(archive, archive.parent.resolve("key"), manifest, payloads) }
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.create(archive, key, manifest.copy(schemaVersion = 2), payloads) }
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.create(archive, key, manifest.copy(files = manifest.files + manifest.files.first()), payloads) }
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.create(archive, key, manifest.copy(files = manifest.files.map { it.copy(bytes = RecoveryCapsule.MAX_FILE + 1) }), payloads) }
        Files.writeString(source, "changed after declaration")
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.create(archive, key, manifest, payloads) }
        assertFalse(Files.exists(key))
    }
    @Test fun `extraction authenticates first preserves bytes and refuses destination reuse`() = fixture { root, archive, key, payloads, manifest ->
        RecoveryCapsule.create(archive, key, manifest, payloads)
        val destination = root.resolve("extracted")
        val wrong = privateFile(root.resolve("wrong"), ByteArray(64))
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.extract(archive, wrong, snapshot, generation, hash, destination) }
        assertFalse(Files.exists(destination))
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.extract(archive, key, snapshot, generation, hash, destination) { 0 } }
        assertFalse(Files.exists(destination))
        assertEquals(manifest, RecoveryCapsule.extract(archive, key, snapshot, generation, hash, destination) { Long.MAX_VALUE })
        payloads.forEach { (name, source) ->
            assertContentEquals(Files.readAllBytes(source), Files.readAllBytes(destination.resolve(name)))
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(destination.resolve(name)))
        }
        assertFailsWith<Exception> { RecoveryCapsule.extract(archive, key, snapshot, generation, hash, destination) { Long.MAX_VALUE } }
        assertContentEquals(Files.readAllBytes(payloads.values.first()), Files.readAllBytes(destination.resolve(payloads.keys.first())))
    }
    @Test fun `fresh capsules use distinct ciphertext and keys for identical payloads`() = fixture { root, archive, key, payloads, manifest ->
        RecoveryCapsule.create(archive, key, manifest, payloads)
        val otherArchive = archive.parent.resolve("other.cap"); val otherKey = key.parent.resolve("other.key")
        RecoveryCapsule.create(otherArchive, otherKey, manifest.copy(id = "cap-aaaaaaaaaaaa"), payloads)
        assertFalse(Files.readAllBytes(key).contentEquals(Files.readAllBytes(otherKey)))
        assertNotEquals(RecoveryCapsule.fileHash(archive), RecoveryCapsule.fileHash(otherArchive))
        val short = privateFile(root.resolve("short-key"), ByteArray(2))
        assertFailsWith<IllegalArgumentException> { RecoveryCapsule.verify(archive, short, snapshot, generation, hash) }
    }
}
