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
    private val update = ReleaseUpdateBinding("q-111111111111", hash, deployment.generationId,
        "e".repeat(64), deployment.sitePolicySha256, "f".repeat(64))
    private class Fake(var failAt: String? = null) : ReleaseEffects, ReleaseUpdateEffects, ReleaseQualificationSnapshotEffects {
        val calls = mutableListOf<String>()
        var failAlso: String? = null
        var ownedJournal: Path? = null
        private fun call(name: String) {
            calls += name
            if (name == failAt || name == failAlso) throw IllegalStateException("injected $name")
            if ("interrupt-$name" == failAt) throw InterruptedException("unit interruption")
        }
        fun authorization(path: Path) = object : ReleaseActiveSiteAuthorization {
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
            override fun select(binding: ReleaseActivationBinding, permitSha256: String,
                activationJournalHead: String, qualificationSnapshotId: String): String {
                assertEquals(Phase.ACTIVATION_STARTED, TransactionJournal.verify(path).last().phase)
                assertEquals("cap-222222222222", qualificationSnapshotId)
                assertEquals("f".repeat(64), permitSha256)
                call("select-site")
                return "e".repeat(64)
            }
            override fun finalize(binding: ReleaseActivationBinding, committed: JournalRecord, selectionSha256: String) {
                assertEquals(Phase.COMMITTED, committed.phase)
                assertEquals(committed, TransactionJournal.verify(path).last())
                assertEquals("e".repeat(64), selectionSha256)
                call("finalize-site")
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
        override fun bindStagedDeployment(snapshotId: String): ReleaseDeploymentBinding {
            call("bind-staged")
            return ReleaseDeploymentBinding("q-abcdef123456", "b".repeat(64), "c".repeat(64), "d".repeat(64))
        }
        override fun verifyQualificationSnapshot(): String = "cap-222222222222"
        override fun restrictPublicWritesToAcceptance() = call("restrict")
        override fun loadAllApprovedHostsOnce() = call("load-caddy")
        override fun openPublicWrites() = call("open-writes")
        override fun releaseOutbound() = call("release-outbound")
        override fun retirePreviousAfterCommittedSite() = call("retire-old")
        override fun retireInstalledAfterCommittedSite() = call("retire-install-site")
        override fun reloadPreviousCaddyConfig() = call("reload-old-caddy")
        override fun isolateCandidate() = call("isolate")
        override fun restoreOldSnapshot(snapshotId: String) = call("restore-old")
        override fun verifyOldStack() {
            ownedJournal?.let { require(TransactionJournal.verify(it).last().phase == Phase.RECOVERY_REQUIRED) {
                "Source resume occurred before durable rollback journal terminal"
            } }
            call("verify-old")
        }
    }
    private fun ReleaseTransaction(path: Path, fake: Fake) = ReleaseTransaction(path, fake, fake.reviewer())
    private fun owned(path: Path, fake: Fake, id: String = "tx-two", digest: String = hash): JournalRecord {
        fake.ownedJournal = path
        return ReleaseTransaction(path, fake).execute(id, digest, update.sourceGeneration, update = update)
    }
    @Test fun `clean install keeps public closed until backup restore and real journeys pass`(): Unit = temporary { path ->
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
    @Test fun `untyped legacy update cannot freeze or acquire deployment authority`(): Unit = temporary { path ->
        val fake = Fake()
        assertFailsWith<IllegalArgumentException> {
            ReleaseTransaction(path, fake).execute("tx", hash, update.sourceGeneration, deployment)
        }
        assertFailsWith<IllegalArgumentException> {
            ReleaseTransaction(path, fake).execute("tx", hash, update.sourceGeneration)
        }
        assertTrue(fake.calls.isEmpty())
        assertFalse(Files.exists(path))
    }
    @Test fun `update freezes before coordinated backup and migration`(): Unit = temporary { path ->
        val fake = Fake()
        val result = owned(path, fake)
        assertEquals(Phase.ACCEPTED, result.phase)
        assertTrue(fake.calls.indexOf("freeze") < fake.calls.indexOf("snapshot"))
        assertTrue(fake.calls.indexOf("pause") < fake.calls.indexOf("snapshot"))
        assertTrue(fake.calls.indexOf("restore-test") < fake.calls.indexOf("migrate"))
        assertTrue(fake.calls.indexOf("migrate") < fake.calls.indexOf("load-caddy"))
        assertEquals(listOf(Phase.PREPARED, Phase.FROZEN, Phase.SNAPSHOT_VERIFIED, Phase.STAGED,
            Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED), TransactionJournal.verify(path).map { it.phase })
    }
    @Test fun `failures before opening writes isolate candidate restore old snapshot and never release outward jobs`(): Unit {
        for (step in listOf("stage", "readiness", "migrate", "staged-journeys", "restrict", "load-caddy", "domain-journeys")) {
            temporary { path ->
                val fake = Fake(step)
                assertFailsWith<IllegalStateException> { owned(path, fake) }
                assertEquals(Phase.RECOVERY_REQUIRED, TransactionJournal.verify(path).last().phase, step)
                assertTrue("isolate" in fake.calls, step)
                assertEquals(1, fake.calls.count { it == "pause" }, "A held original cannot be re-claimed on rollback")
                assertTrue("restore-old" in fake.calls && "verify-old" in fake.calls, step)
                assertFalse("open-writes" in fake.calls || "release-outbound" in fake.calls, step)
                if (step in setOf("load-caddy", "domain-journeys")) assertTrue("reload-old-caddy" in fake.calls, step)
            }
        }
    }
    @Test fun `failed backup or quiesce cannot proceed to migration or public cutover`(): Unit {
        for (step in listOf("freeze", "pause", "quiesce", "snapshot", "restore-test")) temporary { path ->
            val fake = Fake(step)
            assertFailsWith<IllegalStateException> { owned(path, fake) }
            assertFalse("migrate" in fake.calls || "load-caddy" in fake.calls)
            assertFalse("restore-old" in fake.calls || "verify-old" in fake.calls, "Unverified snapshots cannot drive rollback")
            assertEquals(Phase.RECOVERY_REQUIRED, TransactionJournal.verify(path).last().phase)
        }
    }
    @Test fun `clean install freeze quiesce or snapshot failure never exposes or resumes the candidate`(): Unit {
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
    @Test fun `owned site selection precedes public writes and metadata follows committed outbound`(): Unit = temporary { path ->
        val fake = Fake(); val tx = ReleaseTransaction(path, fake)
        val accepted = owned(path, fake)
        val committed = tx.activate("tx-two", hash, accepted.hash, fake.authorization(path))
        assertEquals(Phase.COMMITTED, committed.phase)
        assertTrue(fake.calls.indexOf("consume-permit") < fake.calls.indexOf("select-site"))
        assertTrue(fake.calls.indexOf("select-site") < fake.calls.indexOf("open-writes"))
        assertTrue(fake.calls.indexOf("open-writes") < fake.calls.indexOf("release-outbound"))
        assertEquals(listOf("release-outbound", "finalize-site", "retire-old"), fake.calls.takeLast(3))
    }
    @Test fun `lost global site finalization after COMMITTED never restores stale original state`(): Unit = temporary { path ->
        val fake = Fake("finalize-site"); val tx = ReleaseTransaction(path, fake)
        val accepted = owned(path, fake)
        assertFailsWith<IllegalStateException> { tx.activate("tx-two", hash, accepted.hash, fake.authorization(path)) }
        assertEquals(Phase.COMMITTED, TransactionJournal.verify(path).last().phase)
        assertTrue("release-outbound" in fake.calls)
        assertFalse("restore-old" in fake.calls || "reload-old-caddy" in fake.calls || "retire-old" in fake.calls)
    }
    @Test fun `owned activation refuses callback-only authority before consuming permit`(): Unit = temporary { path ->
        val fake = Fake(); val tx = ReleaseTransaction(path, fake)
        val accepted = owned(path, fake)
        val callbackOnly = object : ReleaseActivationAuthorization {
            override fun verify(binding: ReleaseActivationBinding) = "f".repeat(64)
            override fun consume(binding: ReleaseActivationBinding, permitSha256: String, activationJournalHead: String) = Unit
        }
        assertFailsWith<IllegalStateException> { tx.activate("tx-two", hash, accepted.hash, callbackOnly) }
        assertEquals(Phase.ACCEPTED, TransactionJournal.verify(path).last().phase)
        assertFalse("open-writes" in fake.calls || "release-outbound" in fake.calls)
    }
    @Test fun `possible external writes forbid blind rollback after commitment starts`(): Unit {
        for (step in listOf("open-writes", "release-outbound")) temporary { path ->
            val fake = Fake(step)
            val tx = ReleaseTransaction(path, fake)
            val ready = tx.execute("tx-two", hash, update.sourceGeneration, update = update)
            val error = assertFailsWith<IllegalStateException> {
                tx.activate("tx-two", hash, ready.hash, fake.authorization(path))
            }
            assertTrue(error.message.orEmpty().contains("reconcile authoritative state"))
            assertTrue("restrict" in fake.calls && "pause" in fake.calls)
            assertFalse("restore-old" in fake.calls || "reload-old-caddy" in fake.calls)
            assertEquals(Phase.RECOVERY_REQUIRED, TransactionJournal.verify(path).last().phase)
        }
    }
    @Test fun `a corrected candidate can qualify in a fresh transaction without rewriting the failure`(): Unit = temporary { path ->
        val failed = Fake("readiness")
        val failure = assertFailsWith<IllegalStateException> {
            owned(path, failed, "failed-trial")
        }
        assertTrue(failure.message.orEmpty().contains("diagnose, correct and qualify a fresh attempt"))
        assertTrue("verify-old" in failed.calls) // Injected recovery observation, not a live restore claim.
        val original = Files.readAllBytes(path)
        val replay = Fake()
        assertFailsWith<IllegalArgumentException> { owned(path, replay, "retry") }
        assertTrue(replay.calls.isEmpty())
        val repaired = Fake()
        val result = owned(path.resolveSibling("corrected.journal"), repaired, "corrected-trial", "b".repeat(64))
        assertEquals(Phase.ACCEPTED, result.phase)
        assertTrue(original.contentEquals(Files.readAllBytes(path)))
        assertEquals(Phase.RECOVERY_REQUIRED, TransactionJournal.verify(path).last().phase)
    }

    @Test fun `activation needs exact deployment authority and durable single use before writes`(): Unit = temporary { path ->
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
        assertEquals(listOf("verify-permit", "consume-permit", "select-site", "open-writes", "release-outbound",
            "finalize-site", "retire-install-site"), fake.calls.takeLast(7))
        assertEquals("f".repeat(64), committed.activationPermitSha256)
        assertFailsWith<IllegalArgumentException> { tx.activate("tx", hash, committed.hash, fake.authorization(path)) }
    }

    @Test fun `failed or interrupted permit consumption leaves writes closed and forbids replay`(): Unit {
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

    @Test fun `activation compare and append rejects races and retains incomplete claims`(): Unit = temporary { path ->
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

    @Test fun `isolation or ingress rollback failure forbids source restoration`(): Unit {
        for (recovery in listOf("isolate", "reload-old-caddy")) temporary { path ->
            val fake = Fake("domain-journeys").also { it.failAlso = recovery }
            assertFailsWith<IllegalStateException> { owned(path, fake, "tx") }
            assertFalse("restore-old" in fake.calls || "verify-old" in fake.calls)
            assertEquals(Phase.RECOVERY_REQUIRED, TransactionJournal.verify(path).last().phase)
        }
    }

    @Test fun `failed source restore cannot be reported verified`(): Unit = temporary { path ->
        val fake = Fake("stage").also { it.failAlso = "restore-old" }
        assertFailsWith<IllegalStateException> { owned(path, fake, "tx") }
        assertTrue("restore-old" in fake.calls)
        assertFalse("verify-old" in fake.calls)
    }

    @Test fun `invalid deployment fails before preflight or journal creation`(): Unit = temporary { path ->
        val fake = Fake()
        assertFailsWith<IllegalArgumentException> { ReleaseTransaction(path, fake).execute("tx", hash, null,
            deployment.copy(generationId = "foreign")) }
        assertTrue(fake.calls.isEmpty()); assertFalse(Files.exists(path))
    }

    @Test fun `crash at every journal phase requires recovery instead of guessing`(): Unit {
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
            assertFailsWith<IllegalArgumentException> { owned(path, fake) }
            assertTrue(fake.calls.isEmpty())
            assertEquals(phase, TransactionJournal.verify(path).last().phase)
        }
    }
}
