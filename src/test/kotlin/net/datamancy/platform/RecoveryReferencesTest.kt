package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
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
            GenerationOutcome("isolate", hash, true, fences = mapOf("$target-core" to "22222222-2222-2222-2222-222222222222")), true,
            WeeklyCompletionProof(hash, hash, hash, hash))
    }
    private fun fixture(existing: List<KopiaSnapshotReceipt> = emptyList(), action: (RecoveryReferences, Path) -> Unit) {
        val base = Files.createTempDirectory("reference-unit-")
        try { action(RecoveryReferences.initialize(base.resolve("refs"), existing), base.resolve("refs")) }
        finally { Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private fun retained(protection: KopiaRetentionProtection, deleted: Set<String> = emptySet()) = KopiaRetentionResult(
        KopiaRetentionPlan(id = "r-111111111111", generation = "q-abcdef123456", referenceHeadSha256 = protection.referenceHeadSha256,
            beforeSha256 = hash, retain = (protection.receipts.map { it.snapshotId }.toSet() - deleted).sorted(), delete = deleted.sorted()), hash)
    @Test fun `standalone bootstrap requires externally pinned anchor and existing custody without fabricating proof`(): Unit {
        val base = Files.createTempDirectory("external-bootstrap-")
        try {
            val fresh = Files.createDirectory(base.resolve("q-abcdef123456"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val secret = base.resolve("custody.env")
            val anchorFile = base.resolve("operator-anchor.json")
            Files.writeString(secret, "KOPIA_PASSWORD=original-external-custody\n")
            Files.setPosixFilePermissions(secret, PosixFilePermissions.fromString("rw-------"))
            val anchor = RecoveryBootstrapAnchor(fresh.fileName.toString(), listOf(receipt(1), receipt(2)),
                RecoveryCapsule.fileHash(secret), hash)
            Files.writeString(anchorFile, Json { encodeDefaults = true }.encodeToString(anchor))
            Files.setPosixFilePermissions(anchorFile, PosixFilePermissions.fromString("rw-------"))
            val expected = RecoveryCapsule.fileHash(anchorFile)
            assertFails { RecoveryReferenceOperations.bootstrapStandalone(fresh.resolve("recovery-references"), anchorFile, "0".repeat(64), secret) }
            assertFalse(Files.exists(fresh.resolve("recovery-references")))
            val refs = RecoveryReferenceOperations.bootstrapStandalone(fresh.resolve("recovery-references"), anchorFile, expected, secret)
            assertFalse(refs.retentionReady())
            assertFails { RecoveryReferenceOperations.bootstrapStandalone(fresh.resolve("recovery-references"), anchorFile, expected, secret) }
            assertFails { refs.withProtection { error("fabricated functional authority") } }
        } finally { Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `foreign site claim cannot authorize successor retirement or fabricated protection`(): Unit = fixture { refs, _ ->
        val old = receipt(1)
        refs.register(old)
        refs.protect("site-selection", "unit-${"b".repeat(64)}", setOf(old.snapshotId))
        assertFails { refs.siteSelectionEvent("unit", "b".repeat(64), old) }
        val fake = ActivationInput("/mnt/media/p0-v3/release-transactions/unit/false", hash)
        val newer = receipt(2).copy(generation = "q-111111111111", bundleSha256 = "c".repeat(64))
        val terminal = SiteSuccessionTerminal("owned-trial", "unit",
            ReleaseGeneration(old.generation, old.bundleSha256),
            ReleaseGeneration(newer.generation, newer.bundleSha256),
            "b".repeat(64), "d".repeat(64), old, newer, fake, fake,
            ReleasePublication("/mnt/media/p0-v3/release-generations/${old.generation}/rss/schedule", hash), fake, fake)
        assertFails { refs.retireSupersededSite(terminal) }
        assertFails { refs.siteSelectionEvent("unit", "d".repeat(64), newer) }
    }
    @Test fun `terminal daily operation indexes while snapshot protection remains in ledger`(): Unit = fixture { refs, root ->
        val snapshot = receipt(1)
        refs.register(snapshot)
        refs.protect("unknown", "uncertain-native-import", setOf(snapshot.snapshotId))
        val outcome = GenerationBackupOutcome(RuntimeBackupAccess(snapshot.generation, snapshot.id, snapshot.bundleSha256),
            true, snapshot, true)
        val privateDir = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
        val backups = Files.createDirectory(root.parent.resolve("backups"), privateDir)
        val attempt = Files.createDirectory(backups.resolve(snapshot.id), privateDir)
        ReleasePrivateFiles.save(attempt.resolve("result.json"), Json { encodeDefaults = true }.encodeToString(outcome).toByteArray())
        refs.requireTerminalDaily(outcome)
        refs.register(receipt(2)); refs.register(receipt(3))
        refs.verified(verified(receipt(2))); refs.verified(verified(receipt(3)))
        refs.withProtection {
            assertTrue(snapshot.snapshotId in it.referencedSnapshotIds)
            retained(it)
        }
    }
    @Test fun `two functional points mandatory and bootstrap protects all legacy snapshots`(): Unit = fixture(listOf(receipt(1), receipt(2))) { refs, _ ->
        assertFails { refs.withProtection { error("must not run") } }
        refs.verified(verified(receipt(1))); assertFails { refs.withProtection { error("must not run") } }
        refs.verified(verified(receipt(2)))
        refs.withProtection {
            assertEquals(setOf(receipt(1).snapshotId, receipt(2).snapshotId), it.referencedSnapshotIds)
            assertEquals(2, it.functionallyVerifiedSnapshotIds.size); retained(it)
        }
    }
    @Test fun `rollback import qualification activation unknown references survive failed effects`(): Unit = fixture { refs, _ ->
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
    @Test fun `successful native deletion tombstones ID and unknown deletion freezes later writers`(): Unit = fixture { refs, root ->
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
    @Test fun `only durable weekly terminal can close its own claim and bootstrap remains protected`(): Unit = fixture(listOf(receipt(1))) { refs, _ ->
        refs.register(receipt(2))
        refs.protect("weekly", receipt(2).id, setOf(receipt(2).snapshotId))
        refs.protect("unknown", "unacknowledged", setOf(receipt(1).snapshotId))
        assertFails { refs.retireWeekly(verified(receipt(1))) }
        assertFails { refs.retireWeekly(verified(receipt(2)).copy(sourceResumed = false)) }
        assertFails { refs.retireWeekly(verified(receipt(2)).copy(
            completionProof = WeeklyCompletionProof("c".repeat(64), hash, hash, hash))) }
        refs.verified(verified(receipt(2)))
        refs.retireWeekly(verified(receipt(2)))
        assertFails { refs.retireWeekly(verified(receipt(2))) }
        refs.protect("rollback", "separate", setOf(receipt(2).snapshotId))
        refs.requireTerminalWeekly(verified(receipt(2))) // Index the weekly OPERATION; do not retire rollback's snapshot hold.
        refs.verified(verified(receipt(1)))
        refs.withProtection {
            assertEquals(setOf(receipt(1).snapshotId, receipt(2).snapshotId), it.referencedSnapshotIds)
            retained(it)
        }
    }
    @Test fun `reference checkpoint binds original event chain and protected active state without erasing evidence`(): Unit = fixture { refs, root ->
        refs.register(receipt(1))
        for (n in 1 until 128) refs.protect("qualification", "entry$n", setOf(receipt(1).snapshotId))
        assertTrue(Files.exists(root.resolve("checkpoint-00000128.intent.json")))
        assertTrue(Files.exists(root.resolve("checkpoint-00000128.json")))
        assertFalse(Files.readString(root.resolve("checkpoint-00000128.json")).contains("pendingOperations"),
            "Historical checkpoint bytes must not acquire default-empty operation fields")
        assertTrue(Files.exists(root.resolve("checkpoint-00000128.complete.json")))
        assertTrue(Files.exists(root.resolve("00000001.json")))
        refs.register(receipt(2))
        Files.writeString(root.resolve("00000001.json"), "tampered")
        assertFails { refs.register(receipt(3)) }
        assertTrue(Files.exists(root.resolve("checkpoint-00000128.complete.json")))
    }
    @Test fun `partial immutable ledger checkpoint blocks new claims and never rewrites source evidence`(): Unit = fixture { refs, root ->
        refs.register(receipt(1))
        val original = Files.readAllBytes(root.resolve("00000001.json"))
        Files.writeString(root.resolve("checkpoint-00000128.intent.json"), "unfinished")
        Files.setPosixFilePermissions(root.resolve("checkpoint-00000128.intent.json"), PosixFilePermissions.fromString("rw-------"))
        assertFails { refs.protect("unknown", "uncertain", setOf(receipt(1).snapshotId)) }
        assertContentEquals(original, Files.readAllBytes(root.resolve("00000001.json")))
    }
    @Test fun `corrupt chain and partial bootstrap cannot become authority`(): Unit = fixture { refs, root ->
        refs.register(receipt(1))
        Files.delete(root.resolve("00000001.json"))
        // A later event cannot hide a missing predecessor.
        Files.writeString(root.resolve("00000002.json"), "{}")
        assertFails { refs.register(receipt(2)) }
        Files.delete(root.resolve("ready"))
        assertFails { refs.protect("unknown", "pending", setOf(receipt(1).snapshotId)) }
        assertFails { RecoveryReferences.initialize(root, emptyList()) }
    }
    @Test fun `false functional reports never qualify retention`(): Unit = fixture { refs, _ ->
        refs.register(receipt(1))
        assertFails { refs.verified(verified(receipt(1)).copy(sourceResumed = false)) }
        assertFails { refs.verified(verified(receipt(1)).copy(completionProof = null)) }
        assertFails { refs.verified(verified(receipt(1)).copy(functional = verified(receipt(1)).functional.copy(passed = false))) }
        assertFails { refs.verified(verified(receipt(1)).copy(targetIsolation = GenerationOutcome("isolate", hash, false))) }
    }
}
