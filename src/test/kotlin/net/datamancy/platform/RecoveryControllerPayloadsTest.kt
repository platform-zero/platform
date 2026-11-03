package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

class RecoveryControllerPayloadsTest {
    private fun directory(path: Path) = Files.createDirectory(path,
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    private fun file(path: Path, text: String) {
        Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        Files.writeString(path, text)
    }
    private fun fixture(block: (Path) -> Unit) {
        val root = Files.createTempDirectory("controller-payload-unit-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try { block(root) } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `only declared nonauthority fixture subtree is captured and imported without replay`() = fixture { root ->
        val source = directory(root.resolve("source"))
        val fixture = directory(directory(source.resolve("rss-qualification")).resolve("invocation-1"))
        val state = directory(fixture.resolve("state"))
        file(state.resolve("rss-state.json"), "{\"original\":true}")
        file(state.resolve("rss-state.lock"), "rss-state-lock-v1\n")
        file(fixture.resolve("feed-items.json"), "{\"fixture\":\"original\"}")
        file(source.resolve("activation.permit"), "must never restore")
        val payloads = linkedMapOf<String, Path>()
        val names = RecoveryControllerPayloads.capture(source, payloads)
        assertEquals(3, names.size)
        assertTrue(names.all { it.startsWith("controller/rss-qualification/invocation-1/") })
        val manifest = CapsuleManifest(id = "cap-123456789abc", generation = "q-123456789abc", bundleSha256 = "a".repeat(64),
            members = emptyList(), files = RecoveryCapsule.describe(payloads), controllerFiles = names)
        RecoveryControllerPayloads.validate(manifest)
        val recoveredRoot = directory(root.resolve("recovered"))
        for ((name, original) in payloads) {
            var parent = recoveredRoot
            for (part in name.split('/').dropLast(1)) {
                parent = parent.resolve(part)
                if (!Files.exists(parent)) directory(parent)
            }
            file(recoveredRoot.resolve(name), Files.readString(original))
        }
        val bundle = GenerationBundle(GenerationRequest(id = manifest.generation, candidateSha256 = "b".repeat(64), members = emptyList(), diskReservationMiB = 1024), emptyList(), 0)
        val recovered = RecoveredGeneration(bundle, manifest, recoveredRoot,
            GenerationRecoveryCheck(manifest.generation, manifest.id, manifest.bundleSha256, "", emptyList()))
        val target = directory(root.resolve("target"))
        RecoveryControllerPayloads.restore(recovered, target)
        assertEquals("{\"original\":true}", Files.readString(target.resolve("rss-qualification/invocation-1/state/rss-state.json")))
        assertFalse(Files.exists(target.resolve("activation.permit")))
        assertFails { RecoveryControllerPayloads.restore(recovered, target) }
        assertFails { RecoveryControllerPayloads.validate(manifest.copy(controllerFiles = names + names.first())) }
        assertFails { RecoveryControllerPayloads.validate(manifest.copy(controllerFiles = listOf("controller/schedule/enabled.json"))) }
        val fresh = directory(root.resolve("fresh"))
        Files.writeString(recoveredRoot.resolve(names.first()), "changed")
        assertFails { RecoveryControllerPayloads.restore(recovered, fresh) }
    }
    @Test fun `missing subtree is legacy compatible and unsafe trees are rejected`() = fixture { root ->
        val payloads = linkedMapOf<String, Path>()
        assertTrue(RecoveryControllerPayloads.capture(root, payloads).isEmpty())
        val subtree = directory(root.resolve("rss-qualification"))
        val invocation = directory(subtree.resolve("invocation-1"))
        file(root.resolve("outside"), "private original")
        Files.createSymbolicLink(invocation.resolve("feed-items.json"), root.resolve("outside"))
        assertFails { RecoveryControllerPayloads.capture(root, payloads) }
        Files.delete(invocation.resolve("feed-items.json"))
        file(invocation.resolve("feed-items.json"), "original")
        Thread.currentThread().interrupt()
        try { assertFailsWith<InterruptedException> { RecoveryControllerPayloads.capture(root, payloads) } }
        finally { assertTrue(Thread.interrupted()) }
        Files.setPosixFilePermissions(invocation, PosixFilePermissions.fromString("rwxr-xr-x"))
        assertFails { RecoveryControllerPayloads.capture(root, payloads) }
    }
}
