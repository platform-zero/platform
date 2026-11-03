package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ReleaseTransactionTest {
    private val hash = "a".repeat(64)
    private val deployment = ReleaseDeploymentBinding("q-abcdef123456", "b".repeat(64), "c".repeat(64), "d".repeat(64))
    private fun temporary(block: (Path) -> Unit) {
        val dir = Files.createTempDirectory("transaction-private-")
        Files.setPosixFilePermissions(dir, setOf(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE))
        try { block(dir.resolve("tx.journal")) } finally {
            Files.list(dir).use { it.forEach(Files::delete) }
            Files.delete(dir)
        }
    }
    private class Fake(var failAt: String? = null) : ReleaseEffects {
        val calls = mutableListOf<String>()
        var failAlso: String? = null
        private fun call(name: String) {
            calls += name
            if (name == failAt || name == failAlso) throw IllegalStateException("injected $name")
            if ("interrupt-$name" == failAt) throw InterruptedException("unit interruption")
        }
        fun authorization(path: Path) = object : ReleaseActivationAuthorization {
            override fun verify(binding: ReleaseActivationBinding): String {
                assertEquals(Phase.ACCEPTED, TransactionJournal.verify(path).last().phase)
                call("verify-permit")
                return "f".repeat(64)
            }
            override fun consume(binding: ReleaseActivationBinding, permitSha256: String, activationJournalHead: String) {
                val record = TransactionJournal.verify(path).last()
                assertEquals(Phase.ACTIVATION_STARTED, record.phase)
                assertEquals(binding.deployment, record.deployment)
                assertEquals(permitSha256, record.activationPermitSha256)
                assertEquals(activationJournalHead, record.hash)
                call("consume-permit")
            }
        }
        fun reviewer() = object : ReleaseQualification {
            override fun verifyStagedJourneys() = call("staged-journeys")
            override fun verifyRealDomainJourneys() = call("domain-journeys")
        }
        override fun preflight() = call("preflight")
        override fun stageImmutableCandidate() = call("stage")
        override fun checkPrivateReadinessAndIntegrations() = call("readiness")
        override fun freezeNonTestWrites() = call("freeze")
        override fun pauseOutbound() = call("pause")
        override fun quiesceQueues() = call("quiesce")
        override fun snapshotCoordinated(): String { call("snapshot"); return "snapshot-one" }
        override fun verifySnapshotAndIsolatedFunctionalRestore(snapshotId: String) = call("restore-test")
        override fun migrateStaged() = call("migrate")
        override fun restrictPublicWritesToAcceptance() = call("restrict")
        override fun loadAllApprovedHostsOnce() = call("load-caddy")
        override fun openPublicWrites() = call("open-writes")
        override fun releaseOutbound() = call("release-outbound")
        override fun reloadPreviousCaddyConfig() = call("reload-old-caddy")
        override fun isolateCandidate() = call("isolate")
        override fun restoreOldSnapshot(snapshotId: String) = call("restore-old")
        override fun verifyOldStack() = call("verify-old")
    }
    private fun ReleaseTransaction(path: Path, fake: Fake) = ReleaseTransaction(path, fake, fake.reviewer())
    @Test fun `clean install keeps public closed until backup restore and real journeys pass`() = temporary { path ->
        val fake = Fake()
        val last = ReleaseTransaction(path, fake).execute("tx-one", hash, null)
        assertEquals(Phase.ACCEPTED, last.phase)
        assertEquals("snapshot-one", last.snapshotId)
        assertTrue(fake.calls.indexOf("staged-journeys") < fake.calls.indexOf("freeze"))
        assertTrue(fake.calls.indexOf("freeze") < fake.calls.indexOf("quiesce"))
        assertTrue(fake.calls.indexOf("quiesce") < fake.calls.indexOf("snapshot"))
        assertTrue(fake.calls.indexOf("pause") < fake.calls.indexOf("stage"))
        assertEquals(listOf(Phase.PREPARED, Phase.FROZEN, Phase.SNAPSHOT_VERIFIED, Phase.STAGED,
            Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED), TransactionJournal.verify(path).map { it.phase })
        assertFalse("migrate" in fake.calls)
        assertTrue(fake.calls.indexOf("restore-test") < fake.calls.indexOf("load-caddy"))
        assertFalse("open-writes" in fake.calls || "release-outbound" in fake.calls)
        assertEquals("domain-journeys", fake.calls.last())
        assertFailsWith<IllegalArgumentException> { ReleaseTransaction(path, fake).activate("tx-one", hash, last.hash, fake.authorization(path)) }
        assertFailsWith<IllegalArgumentException> { ReleaseTransaction(path, Fake()).execute("tx-two", hash, null) }
    }
    @Test fun `update freezes before coordinated backup and migration`() = temporary { path ->
        val fake = Fake()
        val result = ReleaseTransaction(path, fake).execute("tx-two", hash, "old-release")
        assertEquals(Phase.ACCEPTED, result.phase)
        assertTrue(fake.calls.indexOf("freeze") < fake.calls.indexOf("snapshot"))
        assertTrue(fake.calls.indexOf("pause") < fake.calls.indexOf("snapshot"))
        assertTrue(fake.calls.indexOf("restore-test") < fake.calls.indexOf("migrate"))
        assertTrue(fake.calls.indexOf("migrate") < fake.calls.indexOf("load-caddy"))
        assertEquals(listOf(Phase.PREPARED, Phase.FROZEN, Phase.SNAPSHOT_VERIFIED, Phase.STAGED,
            Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED), TransactionJournal.verify(path).map { it.phase })
    }
    @Test fun `failures before opening writes isolate candidate restore old snapshot and never release outward jobs`() {
        for (step in listOf("stage", "readiness", "migrate", "staged-journeys", "restrict", "load-caddy", "domain-journeys")) {
            temporary { path ->
                val fake = Fake(step)
                assertFailsWith<IllegalStateException> { ReleaseTransaction(path, fake).execute("tx-two", hash, "old-release") }
                assertEquals(Phase.RECOVERY_REQUIRED, TransactionJournal.verify(path).last().phase, step)
                assertTrue("isolate" in fake.calls, step)
                assertTrue("restore-old" in fake.calls && "verify-old" in fake.calls, step)
                assertFalse("open-writes" in fake.calls || "release-outbound" in fake.calls, step)
                if (step in setOf("load-caddy", "domain-journeys")) assertTrue("reload-old-caddy" in fake.calls, step)
            }
        }
    }
    @Test fun `failed backup or quiesce cannot proceed to migration or public cutover`() {
        for (step in listOf("freeze", "pause", "quiesce", "snapshot", "restore-test")) temporary { path ->
            val fake = Fake(step)
            assertFailsWith<IllegalStateException> { ReleaseTransaction(path, fake).execute("tx-two", hash, "old-release") }
            assertFalse("migrate" in fake.calls || "load-caddy" in fake.calls)
            assertFalse("restore-old" in fake.calls || "verify-old" in fake.calls, "Unverified snapshots cannot drive rollback")
            assertEquals(Phase.RECOVERY_REQUIRED, TransactionJournal.verify(path).last().phase)
        }
    }
    @Test fun `clean install freeze quiesce or snapshot failure never exposes or resumes the candidate`() {
        for (step in listOf("freeze", "quiesce", "snapshot", "restore-test")) temporary { path ->
            val fake = Fake(step)
            assertFailsWith<IllegalStateException> { ReleaseTransaction(path, fake).execute("new-release", hash, null) }
            assertTrue("isolate" in fake.calls)
            assertFalse("load-caddy" in fake.calls || "open-writes" in fake.calls || "release-outbound" in fake.calls)
            assertFalse("restore-old" in fake.calls || "verify-old" in fake.calls)
            if (step in setOf("freeze", "quiesce")) assertFalse("snapshot" in fake.calls)
            assertEquals(Phase.RECOVERY_REQUIRED, TransactionJournal.verify(path).last().phase)
        }
    }
    @Test fun `possible external writes forbid blind rollback after commitment starts`() {
        for (step in listOf("open-writes", "release-outbound")) temporary { path ->
            val fake = Fake(step)
            val tx = ReleaseTransaction(path, fake)
            val ready = tx.execute("tx-two", hash, "old-release", deployment)
            val error = assertFailsWith<IllegalStateException> {
                tx.activate("tx-two", hash, ready.hash, fake.authorization(path))
            }
            assertTrue(error.message.orEmpty().contains("reconcile authoritative state"))
            assertTrue("restrict" in fake.calls && "pause" in fake.calls)
            assertFalse("restore-old" in fake.calls || "reload-old-caddy" in fake.calls)
            assertEquals(Phase.RECOVERY_REQUIRED, TransactionJournal.verify(path).last().phase)
        }
    }
    @Test fun `a corrected candidate can qualify in a fresh transaction without rewriting the failure`() = temporary { path ->
        val failed = Fake("readiness")
        val failure = assertFailsWith<IllegalStateException> {
            ReleaseTransaction(path, failed).execute("failed-trial", hash, "old-release")
        }
        assertTrue(failure.message.orEmpty().contains("diagnose, correct and qualify a fresh attempt"))
        assertTrue("verify-old" in failed.calls) // Injected recovery observation, not a live restore claim.
        val original = Files.readAllBytes(path)
        val replay = Fake()
        assertFailsWith<IllegalArgumentException> { ReleaseTransaction(path, replay).execute("retry", hash, "old-release") }
        assertTrue(replay.calls.isEmpty())
        val repaired = Fake()
        val result = ReleaseTransaction(path.resolveSibling("corrected.journal"), repaired)
            .execute("corrected-trial", "b".repeat(64), "old-release")
        assertEquals(Phase.ACCEPTED, result.phase)
        assertTrue(original.contentEquals(Files.readAllBytes(path)))
        assertEquals(Phase.RECOVERY_REQUIRED, TransactionJournal.verify(path).last().phase)
    }

    @Test fun `activation needs exact deployment authority and durable single use before writes`() = temporary { path ->
        val fake = Fake(); val tx = ReleaseTransaction(path, fake)
        val ready = tx.execute("tx", hash, null, deployment)
        assertEquals(deployment, ready.deployment)
        assertFalse("open-writes" in fake.calls)
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.COMMITTED, ready.snapshotId) }
        assertFailsWith<IllegalArgumentException> { tx.activate("foreign", hash, ready.hash, fake.authorization(path)) }
        assertFailsWith<IllegalArgumentException> { tx.activate("tx", "b".repeat(64), ready.hash, fake.authorization(path)) }
        assertFailsWith<IllegalArgumentException> { tx.activate("tx", hash, "0".repeat(64), fake.authorization(path)) }
        assertFalse("verify-permit" in fake.calls)
        val committed = tx.activate("tx", hash, ready.hash, fake.authorization(path))
        assertEquals(Phase.COMMITTED, committed.phase)
        assertEquals(listOf("verify-permit", "consume-permit", "open-writes", "release-outbound"), fake.calls.takeLast(4))
        assertEquals("f".repeat(64), committed.activationPermitSha256)
        assertFailsWith<IllegalArgumentException> { tx.activate("tx", hash, committed.hash, fake.authorization(path)) }
    }

    @Test fun `failed or interrupted permit consumption leaves writes closed and forbids replay`() {
        for (failure in listOf("verify-permit", "consume-permit", "interrupt-consume-permit", "interrupt-verify-permit")) temporary { path ->
            val fake = Fake(); val tx = ReleaseTransaction(path, fake)
            val ready = tx.execute("tx", hash, null, deployment)
            fake.failAt = failure
            try {
                if (failure == "interrupt-verify-permit") {
                    assertFailsWith<InterruptedException> { tx.activate("tx", hash, ready.hash, fake.authorization(path)) }
                } else assertFailsWith<IllegalStateException> { tx.activate("tx", hash, ready.hash, fake.authorization(path)) }
                assertEquals(failure.startsWith("interrupt"), Thread.currentThread().isInterrupted)
            } finally { Thread.interrupted() }
            assertFalse("open-writes" in fake.calls || "release-outbound" in fake.calls)
            assertEquals(if (failure.endsWith("verify-permit")) Phase.ACCEPTED else Phase.RECOVERY_REQUIRED,
                TransactionJournal.verify(path).last().phase)
        }
    }

    @Test fun `activation compare and append rejects races and retains incomplete claims`() = temporary { path ->
        val fake = Fake(); val tx = ReleaseTransaction(path, fake)
        val ready = tx.execute("tx", hash, null, deployment)
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.ACTIVATION_STARTED,
            ready.snapshotId, "0".repeat(64), "f".repeat(64)) }
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.ACTIVATION_STARTED, ready.snapshotId, ready.hash, "bad") }
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.ACTIVATION_STARTED, ready.snapshotId, ready.hash) }
        val claim = TransactionJournal.appendExisting(path, Phase.ACTIVATION_STARTED, ready.snapshotId, ready.hash, "f".repeat(64))
        assertFailsWith<IllegalArgumentException> { tx.activate("tx", hash, claim.hash, fake.authorization(path)) }
        assertFailsWith<IllegalArgumentException> { TransactionJournal.appendExisting(path, Phase.COMMITTED, ready.snapshotId, claim.hash, "e".repeat(64)) }
        assertEquals(claim, TransactionJournal.verify(path).last())
        assertFalse("open-writes" in fake.calls)
    }

    @Test fun `isolation or ingress rollback failure forbids source restoration`() {
        for (recovery in listOf("isolate", "reload-old-caddy")) temporary { path ->
            val fake = Fake("domain-journeys").also { it.failAlso = recovery }
            assertFailsWith<IllegalStateException> { ReleaseTransaction(path, fake).execute("tx", hash, "old-release") }
            assertFalse("restore-old" in fake.calls || "verify-old" in fake.calls)
            assertEquals(Phase.RECOVERY_REQUIRED, TransactionJournal.verify(path).last().phase)
        }
    }

    @Test fun `failed source restore cannot be reported verified`() = temporary { path ->
        val fake = Fake("stage").also { it.failAlso = "restore-old" }
        assertFailsWith<IllegalStateException> { ReleaseTransaction(path, fake).execute("tx", hash, "old-release") }
        assertTrue("restore-old" in fake.calls)
        assertFalse("verify-old" in fake.calls)
    }

    @Test fun `invalid deployment fails before preflight or journal creation`() = temporary { path ->
        val fake = Fake()
        assertFailsWith<IllegalArgumentException> { ReleaseTransaction(path, fake).execute("tx", hash, null,
            deployment.copy(generationId = "foreign")) }
        assertTrue(fake.calls.isEmpty()); assertFalse(Files.exists(path))
    }

    @Test fun `crash at every journal phase requires recovery instead of guessing`() {
        for (phase in listOf(Phase.PREPARED, Phase.FROZEN, Phase.SNAPSHOT_VERIFIED, Phase.STAGED,
            Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED, Phase.COMMITTED, Phase.RECOVERY_REQUIRED)) temporary { path ->
            TransactionJournal.append(path, "tx-two", hash, Phase.PREPARED, "old-release", null)
            var snapshot: String? = null
            for (next in listOf(Phase.FROZEN, Phase.SNAPSHOT_VERIFIED, Phase.STAGED,
                Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED, Phase.COMMITTED)) {
                if (phase == Phase.PREPARED) break
                if (next == Phase.SNAPSHOT_VERIFIED) snapshot = "snapshot-one"
                if (phase == Phase.RECOVERY_REQUIRED && next == Phase.COMMITTED) break
                TransactionJournal.appendExisting(path, next, snapshot)
                if (next == phase) break
            }
            if (phase == Phase.RECOVERY_REQUIRED) TransactionJournal.appendExisting(path, phase, snapshot)
            val fake = Fake()
            assertFailsWith<IllegalArgumentException> { ReleaseTransaction(path, fake).execute("tx-two", hash, "old-release") }
            assertTrue(fake.calls.isEmpty())
            assertEquals(phase, TransactionJournal.verify(path).last().phase)
        }
    }
}
