package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Source-only definitions: no native repository, no product startup, no tests run in this phase. */
class RecoveryReferenceOperationsTest {
    private val json = Json { encodeDefaults = true }
    private val generation = "q-abcdef123456"
    private fun receipt(n: Int, bundle: String): KopiaSnapshotReceipt = KopiaSnapshotReceipt(
        id = "cap-" + n.toString().padStart(12, '0'), generation = generation, bundleSha256 = bundle,
        snapshotId = n.toString().padStart(32, 'a'), rootObjectId = "k" + n.toString().padStart(32, 'b'),
        manifestSha256 = "f".repeat(64), files = 1, plaintextBytes = 10,
        image = "example.test/kopia@sha256:" + "d".repeat(64), imageId = "e".repeat(64))
    private fun dir(path: Path): Path = Files.createDirectory(path,
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    private fun fixture(action: (Path, RecoveryReferences, String) -> Unit) {
        val base = Files.createTempDirectory("references-operation-")
        try {
            val source = dir(base.resolve(generation))
            val bundleBytes = "sealed private test source".toByteArray()
            val digest = ReleaseLocks.sha256(bundleBytes)
            val refs = RecoveryReferences.initialize(source.resolve("recovery-references"), emptyList())
            ReleasePrivateFiles.save(source.resolve("bundle.json"), bundleBytes)
            action(base, refs, digest)
        } finally {
            Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
    @Test fun `pending native capture before repository effects forbids duplicate and unknown retention`(): Unit = fixture { base, refs, digest ->
        val access = RuntimeBackupAccess(generation, "cap-000000000001", digest)
        val pin = PendingRecoveryOperation("rollback", "owned-trial", access)
        refs.protectPending(pin)
        assertFalse(refs.retentionReady())
        assertFails { refs.protectPending(pin) } // No implicit replay of lost acknowledgment.
        assertFails { refs.withProtection { error("Must never run native retention") } }
        assertFails { refs.bindCaptured(pin, receipt(1, digest)) } // No native result yet.
        assertTrue(Files.exists(base.resolve("$generation/recovery-references/00000001.json")))
        assertEquals("operation-pending", json.decodeFromString<RecoveryReferenceEvent>(ReleasePrivateFiles.read(
            base.resolve("$generation/recovery-references/00000001.json")).decodeToString()).kind)
    }
    @Test fun `pending operation binds only actual native receipt and protects exact new snapshot`(): Unit = fixture { base, refs, digest ->
        val access = RuntimeBackupAccess(generation, "cap-000000000001", digest)
        val pin = PendingRecoveryOperation("import", "owned-trial", access)
        refs.protectPending(pin)
        val snapshot = receipt(1, digest)
        val capture = dir(base.resolve("$generation/kopia-captures"))
        val attempt = dir(capture.resolve(snapshot.id))
        ReleasePrivateFiles.save(attempt.resolve("capture.result.json"), json.encodeToString(
            KopiaCaptureOutcome(snapshot.id, digest, true, snapshot)).toByteArray())
        assertFails { refs.bindCaptured(pin, snapshot.copy(files = 2)) }
        refs.bindCaptured(pin, snapshot)
        val root = base.resolve("$generation/recovery-references")
        val events = (1..3).map { json.decodeFromString<RecoveryReferenceEvent>(ReleasePrivateFiles.read(
            root.resolve("%08d.json".format(it))).decodeToString()) }
        assertEquals(listOf("operation-pending", "snapshot", "operation-bound"), events.map { it.kind })
        assertEquals(setOf(snapshot.snapshotId), events.last().snapshots)
        assertFails { refs.bindCaptured(pin, snapshot) }
        assertFails { refs.protect("import", "owned-trial", setOf(snapshot.snapshotId)) }
        assertFails { PendingRecoveryOperation("held", "caller-alias", access).validate() }
    }
    @Test fun `owned rollback claim cannot retire on caller-authored terminal without native isolation and resume`(): Unit = fixture { base, refs, digest ->
        val access = RuntimeBackupAccess(generation, "cap-000000000001", digest)
        val pin = PendingRecoveryOperation("rollback", "owned-trial", access)
        refs.protectPending(pin)
        val snapshot = receipt(1, digest)
        val capture = dir(base.resolve("$generation/kopia-captures"))
        ReleasePrivateFiles.save(dir(capture.resolve(snapshot.id)).resolve("capture.result.json"),
            json.encodeToString(KopiaCaptureOutcome(snapshot.id, digest, true, snapshot)).toByteArray())
        refs.bindCaptured(pin, snapshot)
        val attempt = OwnedUpdateReferenceTerminal(kind = "rollback", transactionId = "owned-trial",
            intentSha256 = "a".repeat(64), original = snapshot, source = ReleaseGeneration(generation, digest),
            targetGeneration = "q-222222222222", targetBundleSha256 = "b".repeat(64),
            sitePolicySha256 = "c".repeat(64), importResult = ActivationInput(
                base.resolve("q-222222222222/stage.result.json").toString(), "d".repeat(64)))
        assertFails { refs.retireOwned(attempt) }
        assertFalse(Files.exists(base.resolve("release-transactions/owned-trial/reference-rollback.terminal.json")))
    }
    @Test fun `generic backup remains protected without native resume audit`(): Unit = fixture { base, refs, digest ->
        val access = RuntimeBackupAccess(generation, "cap-000000000001", digest)
        val pin = PendingRecoveryOperation("backup", access.operation, access)
        refs.protectPending(pin)
        val snapshot = receipt(1, digest)
        val capture = dir(base.resolve("$generation/kopia-captures"))
        ReleasePrivateFiles.save(dir(capture.resolve(snapshot.id)).resolve("capture.result.json"),
            json.encodeToString(KopiaCaptureOutcome(snapshot.id, digest, true, snapshot)).toByteArray())
        refs.bindCaptured(pin, snapshot)
        val backups = dir(base.resolve("$generation/backups"))
        val attempt = dir(backups.resolve(access.operation))
        ReleasePrivateFiles.save(attempt.resolve("result.json"), json.encodeToString(
            GenerationBackupOutcome(access, true, snapshot, true)).toByteArray())
        ReleasePrivateFiles.save(attempt.resolve("resume.verified.json"), json.encodeToString(access).toByteArray())
        assertFails { refs.completeBackup(access) }
        val ledgerRoot = base.resolve("$generation/recovery-references")
        assertFalse(Files.exists(ledgerRoot.resolve("00000004.json")),
            "No callback/Boolean can retire a backup without native member audit")
    }
    @Test fun `no empty bootstrap over orphan held operation even with missing capture receipt`(): Unit {
        val base = Files.createTempDirectory("orphan-legacy-")
        try {
            val source = dir(base.resolve(generation))
            val bytes = "independent sealed bundle".toByteArray()
            val digest = ReleaseLocks.sha256(bytes)
            ReleasePrivateFiles.save(source.resolve("bundle.json"), bytes)
            val backups = dir(source.resolve("backups"))
            dir(backups.resolve("cap-000000000001"))
            assertFails { RecoveryReferenceOperations.authority(base, generation, digest) }
            assertFalse(Files.exists(source.resolve("recovery-references")))
            Files.delete(backups.resolve("cap-000000000001")); Files.delete(backups)
            val store = dir(source.resolve("kopia-store")); dir(store.resolve("repository"))
            assertFails { RecoveryReferenceOperations.authority(base, generation, digest) }
            assertFalse(Files.exists(source.resolve("recovery-references")))
        } finally {
            Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}
