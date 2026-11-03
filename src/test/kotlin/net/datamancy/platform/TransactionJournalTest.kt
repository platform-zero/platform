package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class TransactionJournalTest {
    private fun temporary(action: (java.nio.file.Path) -> Unit) {
        val dir = Files.createTempDirectory("journal-private")
        Files.setPosixFilePermissions(dir, setOf(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE))
        try { action(dir) } finally {
            Files.list(dir).use { it.forEach(Files::delete) }
            Files.delete(dir)
        }
    }
    private val digest = "a".repeat(64)
    @Test fun `owned update binds once after snapshot and legacy records cannot gain authority`() = temporary { dir ->
        val path = dir.resolve("journal")
        val update = ReleaseUpdateBinding("q-111111111111", digest, "q-222222222222", "b".repeat(64), "c".repeat(64), "d".repeat(64))
        val deployment = ReleaseDeploymentBinding(update.targetGeneration, "e".repeat(64), update.sitePolicySha256, "f".repeat(64))
        assertFailsWith<IllegalArgumentException> { TransactionJournal.append(path, "tx", digest, Phase.PREPARED, update.sourceGeneration, null, deployment, update) }
        TransactionJournal.append(path, "tx", digest, Phase.PREPARED, update.sourceGeneration, null, update = update)
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.FROZEN, null, deployment = deployment) }
        TransactionJournal.appendExisting(path, Phase.FROZEN, null)
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.SNAPSHOT_VERIFIED, "cap-111111111111", deployment = deployment) }
        TransactionJournal.appendExisting(path, Phase.SNAPSHOT_VERIFIED, "cap-111111111111")
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.STAGED, "cap-111111111111") }
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.STAGED, "cap-111111111111", deployment = deployment.copy(generationId = update.sourceGeneration)) }
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.STAGED, "cap-111111111111", deployment = deployment.copy(sitePolicySha256 = digest)) }
        TransactionJournal.appendExisting(path, Phase.STAGED, "cap-111111111111", deployment = deployment)
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.CUTOVER_RESTRICTED, "cap-111111111111", deployment = deployment.copy(bundleSha256 = digest)) }
        TransactionJournal.appendExisting(path, Phase.CUTOVER_RESTRICTED, "cap-111111111111")
        assertEquals(deployment, TransactionJournal.verify(path).last().deployment)
        assertEquals(update, TransactionJournal.verify(path).last().update)
        val legacy = dir.resolve("legacy")
        TransactionJournal.append(legacy, "tx-old", digest, Phase.PREPARED, null, null)
        TransactionJournal.appendExisting(legacy, Phase.FROZEN, null)
        TransactionJournal.appendExisting(legacy, Phase.SNAPSHOT_VERIFIED, "cap-222222222222")
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(legacy, Phase.STAGED, "cap-222222222222", deployment = deployment) }
    }
    @Test fun `clean install progresses but cannot skip cutover or append after commit`() = temporary { dir ->
        val path = dir.resolve("journal")
        assertFailsWith<IllegalArgumentException> { TransactionJournal.append(path, "tx", digest, Phase.STAGED, null, null) }
        assertEquals(Phase.PREPARED, TransactionJournal.append(path, "tx", digest, Phase.PREPARED, null, null).phase)
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.COMMITTED, null) }
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.STAGED, null) }
        TransactionJournal.appendExisting(path, Phase.FROZEN, null)
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.SNAPSHOT_VERIFIED, null) }
        listOf(Phase.SNAPSHOT_VERIFIED, Phase.STAGED, Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED, Phase.COMMITTED).forEach {
            TransactionJournal.appendExisting(path, it, "backup-one")
        }
        assertEquals(7, TransactionJournal.verify(path).size)
        val output = mutableListOf<String>()
        assertEquals(0, runCommand(arrayOf("release", "status", path.toString()), output::add, { }))
        kotlin.test.assertTrue(output.single().contains("COMMITTED"))
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.FROZEN, null) }
        assertEquals(7, TransactionJournal.verify(path).size)
    }
    @Test fun `update requires snapshot and rejects changing its identity`() = temporary { dir ->
        val path = dir.resolve("journal")
        TransactionJournal.append(path, "tx", digest, Phase.PREPARED, "old-release", null)
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.STAGED, null) }
        TransactionJournal.appendExisting(path, Phase.FROZEN, null)
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.SNAPSHOT_VERIFIED, null) }
        TransactionJournal.appendExisting(path, Phase.SNAPSHOT_VERIFIED, "backup-one")
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.STAGED, "backup-two") }
        TransactionJournal.appendExisting(path, Phase.RECOVERY_REQUIRED, "backup-one")
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.STAGED, "backup-one") }
    }
    @Test fun `partial write tampering public permissions and symlinks fail closed`() = temporary { dir ->
        val path = dir.resolve("journal")
        TransactionJournal.append(path, "tx", digest, Phase.PREPARED, null, null)
        val pristine = Files.readAllBytes(path)
        Files.write(path, pristine.dropLast(1).toByteArray())
        assertFailsWith<IllegalArgumentException> { TransactionJournal.verify(path) }
        Files.write(path, pristine)
        Files.write(path, pristine + "broken\n".toByteArray())
        assertFailsWith<Exception> { TransactionJournal.verify(path) }
        Files.write(path, pristine)
        Files.setPosixFilePermissions(path, setOf(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.OTHERS_READ))
        assertFailsWith<IllegalArgumentException> { TransactionJournal.verify(path) }
        val link = dir.resolve("link")
        Files.createSymbolicLink(link, path)
        assertFailsWith<IllegalArgumentException> { TransactionJournal.verify(link) }
    }
}
