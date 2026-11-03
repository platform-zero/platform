package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class RecoveryReferencesTest {
    private val hash = "a".repeat(64)
    private fun receipt(n: Int) = KopiaSnapshotReceipt(id = "cap-" + n.toString().padStart(12, '0'), generation = "q-abcdef123456", bundleSha256 = hash,
        snapshotId = n.toString().padStart(32, 'b'), rootObjectId = "k" + n.toString().padStart(32, 'b'), manifestSha256 = hash,
        files = 1, plaintextBytes = 10, image = "example.test/kopia@sha256:$hash", imageId = hash)
    private fun verified(receipt: KopiaSnapshotReceipt): WeeklyRestoreResult {
        val target = "q-111111111111"; val assertions = setOf("fixture:readback")
        return WeeklyRestoreResult(receipt.id, target, hash, receipt,
            WeeklyFunctionalResult(receipt.id, target, hash, receipt.snapshotId, assertions, true), assertions,
            GenerationOutcome("isolate", hash, true, fences = mapOf("$target-core" to "22222222-2222-2222-2222-222222222222")), true)
    }
    private fun fixture(existing: List<KopiaSnapshotReceipt> = emptyList(), action: (RecoveryReferences, Path) -> Unit) {
        val base = Files.createTempDirectory("reference-unit-")
        try { action(RecoveryReferences.initialize(base.resolve("refs"), existing), base.resolve("refs")) }
        finally { Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private fun retained(protection: KopiaRetentionProtection, deleted: Set<String> = emptySet()) = KopiaRetentionResult(
        KopiaRetentionPlan(id = "r-111111111111", generation = "q-abcdef123456", referenceHeadSha256 = protection.referenceHeadSha256,
            beforeSha256 = hash, retain = (protection.receipts.map { it.snapshotId }.toSet() - deleted).sorted(), delete = deleted.sorted()), hash)
    @Test fun `two functional points mandatory and bootstrap protects all legacy snapshots`() = fixture(listOf(receipt(1), receipt(2))) { refs, _ ->
        assertFails { refs.withProtection { error("must not run") } }
        refs.verified(verified(receipt(1))); assertFails { refs.withProtection { error("must not run") } }
        refs.verified(verified(receipt(2)))
        refs.withProtection {
            assertEquals(setOf(receipt(1).snapshotId, receipt(2).snapshotId), it.referencedSnapshotIds)
            assertEquals(2, it.functionallyVerifiedSnapshotIds.size); retained(it)
        }
    }
    @Test fun `rollback import qualification activation unknown references survive failed effects`() = fixture { refs, _ ->
        refs.register(receipt(1)); refs.register(receipt(1)); refs.register(receipt(2))
        for (kind in listOf("rollback", "import", "qualification", "activation", "unknown", "weekly")) {
            assertFailsWith<IllegalStateException> { refs.withReference(kind, kind, setOf(receipt(1).snapshotId)) { error("lost response") } }
        }
        assertFails { refs.protect("permissive", "x", setOf(receipt(1).snapshotId)) }
        assertFails { refs.protect("rollback", "x", setOf("foreign")) }
        assertFails { refs.register(receipt(1).copy(files = 2)) }
        refs.verified(verified(receipt(1))); refs.verified(verified(receipt(2)))
        refs.withProtection { assertEquals(setOf(receipt(1).snapshotId), it.referencedSnapshotIds); retained(it) }
    }
    @Test fun `successful native deletion tombstones ID and unknown deletion freezes later writers`() = fixture { refs, root ->
        (1..3).forEach { refs.register(receipt(it)) }
        refs.verified(verified(receipt(1))); refs.verified(verified(receipt(2)))
        refs.withProtection { retained(it, setOf(receipt(3).snapshotId)) }
        assertFalse(Files.exists(root.resolve("retention.pending")))
        assertFails { refs.register(receipt(3)) }
        assertFails { refs.protect("import", "restore", setOf(receipt(3).snapshotId)) }
        assertFails { refs.withProtection { error("native acknowledgement lost") } }
        assertTrue(Files.exists(root.resolve("retention.pending")))
        assertFails { refs.register(receipt(4)) }; assertFails { refs.withProtection { error("must not retry") } }
    }
    @Test fun `corrupt chain and partial bootstrap cannot become authority`() = fixture { refs, root ->
        refs.register(receipt(1))
        Files.delete(root.resolve("00000001.json"))
        // A later event cannot hide a missing predecessor.
        Files.writeString(root.resolve("00000002.json"), "{}")
        assertFails { refs.register(receipt(2)) }
        Files.delete(root.resolve("ready"))
        assertFails { refs.protect("unknown", "pending", setOf(receipt(1).snapshotId)) }
        assertFails { RecoveryReferences.initialize(root, emptyList()) }
    }
    @Test fun `false functional reports never qualify retention`() = fixture { refs, _ ->
        refs.register(receipt(1))
        assertFails { refs.verified(verified(receipt(1)).copy(sourceResumed = false)) }
        assertFails { refs.verified(verified(receipt(1)).copy(functional = verified(receipt(1)).functional.copy(passed = false))) }
        assertFails { refs.verified(verified(receipt(1)).copy(targetIsolation = GenerationOutcome("isolate", hash, false))) }
    }
}
