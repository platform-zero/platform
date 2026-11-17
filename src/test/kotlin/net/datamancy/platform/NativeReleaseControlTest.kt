package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.encodeToString
import kotlin.test.*

class NativeReleaseControlTest {
    @Test fun `native install refuses absent RESTORE bridge before startup or source hold`(): Unit =
        ReleaseControlTestFixture().use { f ->
            val control = NativeReleaseControl(f.request, f.runtime, f.acceptance, f::restore,
                f.operations, f.base, restoredJourneys = null)
            assertFails { control.preflight() }
            assertFalse(f.calls.any { it == "stage" || it.startsWith("hold:") })
        }
    private fun fixture(action: (ReleaseControlTestFixture) -> Unit) = ReleaseControlTestFixture().use(action)
    private fun staged(f: ReleaseControlTestFixture): ReleaseGenerationControl = f.control().also {
        it.preflight(); it.stage(); it.readiness(); it.freeze(); it.verifyQuiesced()
        assertEquals(f.capture, it.capture()); it.restoreTest(f.capture); it.resumeRestrictedCandidate()
    }
    @Test fun `native orchestration preserves distinct snapshots and isolates targets before source resume`(): Unit = fixture { f ->
        val control = staged(f)
        assertEquals(f.qualifiedCapture, control.qualificationSnapshot())
        assertEquals(listOf("hold:${f.capture}", "hold:${f.qualifiedCapture}"), f.calls.filter { it.startsWith("hold:") })
        for ((capture, target) in listOf(f.capture to f.stagedTarget, f.qualifiedCapture to f.qualifiedTarget))
            {
                assertTrue(f.calls.indexOf("start-restored:$target") >= 0)
                assertTrue(f.calls.indexOf("start-restored:$target") < f.calls.indexOf("isolate:$target"))
                assertTrue(f.calls.indexOf("isolate:$target") < f.calls.indexOf("resume:$capture"))
            }
        assertFalse(f.frozen)
        val ledger = f.sourceRoot.resolve("recovery-references")
        val events = Files.list(ledger).use { it.filter { p -> p.fileName.toString().matches(Regex("[0-9]{8}\\.json")) }.toList() }
        val records = events.map { f.json.decodeFromString<RecoveryReferenceEvent>(Files.readString(it)) }
        assertTrue(records.any { it.kind == "operation-bound" && it.id == "rollback:${f.request.transactionId}" &&
            it.snapshots == setOf(f.snapshot(f.capture).snapshotId) })
        assertTrue(records.any { it.kind == "operation-bound" && it.id == "qualification:${f.request.transactionId}" &&
            it.snapshots == setOf(f.snapshot(f.qualifiedCapture).snapshotId) })
        control.isolateCandidate()
        assertTrue("isolate:${f.source}" in f.calls)
        assertFails { control.migrate() }; assertFails { control.restorePrevious(f.capture) }; assertFails { control.verifyPrevious() }
    }
    @Test fun `production restored verifier rejects changed original invocation before native scope lookup`(): Unit = fixture { f ->
        val changed = f.request.restore.copy(input = f.request.restore.input.copy(sha256 = "0".repeat(64)))
        assertFailsWith<IllegalArgumentException> {
            RestoredReleaseVerifier.NATIVE.verify(f.pin("not-evidence.json", "{\"unitFixture\":true}"),
                changed, "execute-staged", ReleaseGeneration(f.source, f.sourceHash),
                ReleaseGeneration(f.stagedTarget, f.targetHash), false)
        }
        assertTrue(f.calls.isEmpty())
    }
    @Test fun `production runtime adapter cannot bypass immutable generation input admission`(): Unit = fixture { f ->
        var nativeCalls = 0
        val runtime = GenerationRuntime(f.base, f.root, { nativeCalls++; error("must not allocate native backend") },
            { nativeCalls++; error("must not inspect native capacity") })
        val operations = NativeReleaseRuntime(runtime)
        // A valid bundle exists, but the supplied identity differs and no retained operation
        // authorizes resume/reconciliation. No operation may act merely on a declared name.
        val changed = "0".repeat(64)
        assertFails { operations.stage(f.source, changed) }
        assertFails { operations.startRestored(f.inventory, f.source, changed) }
        assertFails { operations.inspect(f.source, changed) }
        assertFails { operations.holdKopiaForRestore(f.inventory, f.source, changed, f.capture) }
        assertFails { operations.backupKopia(f.inventory, f.source, changed, f.capture) }
        assertFails { operations.resumeHeldSourceAfterIsolation(f.inventory, f.source, changed, f.capture,
            "a".repeat(64), f.stagedTarget, f.targetHash) }
        assertFails { operations.isolate(f.source, changed) }
        assertFails { operations.reconcileBackup(f.source, changed, f.capture, "r-999999999999", "a".repeat(64)) }
        assertFails { operations.reconcileIsolation(f.source, changed, "r-999999999999", "a".repeat(64)) }
        assertEquals(0, nativeCalls)
    }
    @Test fun `preflight never bootstraps references over historical captures or accepts mismatched restore bindings`(): Unit {
        fixture { f ->
            val captures = f.dir(f.sourceRoot.resolve("kopia-captures")); f.dir(captures.resolve(f.capture))
            assertFails { f.control().preflight() }
            assertFalse(Files.exists(f.sourceRoot.resolve("recovery-references")))
        }
        fixture { f ->
            val controls = listOf(
                f.request.copy(previous = ReleaseGeneration(f.source, f.sourceHash)),
                f.request.copy(qualifiedRestore = null),
                f.request.copy(restoreTarget = f.source),
                f.request.copy(qualifiedRestore = f.request.qualifiedRestore!!.copy(captureId = f.capture)),
                f.request.copy(qualifiedRestore = f.request.qualifiedRestore!!.copy(targetGeneration = f.stagedTarget)),
                f.request.copy(qualifiedRestore = f.request.qualifiedRestore!!.copy(acceptance = f.request.qualifiedRestore!!.acceptance.copy(
                    input = f.request.qualifiedRestore!!.acceptance.input.copy(sha256 = "0".repeat(64))))),
                f.request.copy(restore = f.request.staged),
                f.request.copy(inventory = f.request.inventory.copy(sha256 = "0".repeat(64))),
                f.request.copy(deployment = requireNotNull(f.request.deployment).copy(bundleSha256 = "0".repeat(64))))
            for (request in controls) assertFails { f.control(request).preflight() }
            assertTrue(f.calls.none { it == "stage" || it.startsWith("hold:") })
            f.control().preflight(); f.control().preflight() // Existing complete reference census is retained.
        }
    }
    @Test fun `readiness and freeze require exact cohort fingerprints states and fences`(): Unit = fixture { f ->
        val control = f.control(); control.preflight()
        f.failure = "stage"; assertFails { control.stage() }; f.failure = null
        for (bad in listOf<(GenerationInspection) -> GenerationInspection>(
            { it.copy(members = emptyList()) },
            { it.copy(members = it.members.map { member -> member.copy(fingerprint = "0".repeat(64)) }) },
            { it.copy(members = it.members.map { member -> member.copy(maintenanceId = f.fence) }) },
            { it.copy(members = it.members.map { member -> member.copy(statuses = emptyList()) }) })) {
            f.auditOverride = bad; assertFails { control.readiness() }
        }
        f.auditOverride = null; control.readiness()
        assertFails { control.verifyQuiesced() }; assertFails { control.resumeRestrictedCandidate() }; assertFails { control.qualificationSnapshot() }
        control.freeze(); assertFails { control.freeze() }
        f.auditOverride = { it.copy(members = it.members.map { member -> member.copy(maintenanceId = null) }) }
        assertFails { control.capture() }
        f.auditOverride = null; assertEquals(f.capture, control.capture())
        assertFails { control.restoreTest("cap-999999999999") }
    }
    @Test fun `failed or interrupted functional journeys never resume source and still attempt target isolation`(): Unit {
        for (mode in listOf("failure", "interrupt", "isolate", "import", "startup")) fixture { f ->
            val control = f.control(); control.preflight(); control.freeze(); control.capture()
            f.failedAcceptance = mode == "failure"; f.interruptedAcceptance = mode == "interrupt"
            f.failure = mode.takeIf { it in setOf("isolate", "startup") }; f.importPassed = mode != "import"
            try {
                if (mode == "interrupt") {
                    assertFailsWith<InterruptedException> { control.restoreTest(f.capture) }
                    assertTrue(Thread.currentThread().isInterrupted)
                } else assertFails { control.restoreTest(f.capture) }
            } finally { Thread.interrupted() }
            assertTrue(f.calls.none { it.startsWith("resume:") })
            if (mode != "import") assertTrue("isolate:${f.stagedTarget}" in f.calls)
            control.isolateCandidate()
            assertTrue("reconcile-backup:${f.capture}" in f.calls)
        }
    }
    @Test fun `qualified restoration failures retain newest held capture and cannot resume on timeout`(): Unit {
        for (mode in listOf("failure", "interrupt", "import", "isolate", "resume", "startup")) fixture { f ->
            val control = staged(f)
            f.calls.clear(); f.failedAcceptance = mode == "failure"; f.interruptedAcceptance = mode == "interrupt"
            f.importPassed = mode != "import"; f.failure = mode.takeIf { it in setOf("isolate", "resume", "startup") }
            try { assertFails { control.qualificationSnapshot() } } finally { Thread.interrupted() }
            if (mode != "resume") assertTrue(f.calls.none { it.startsWith("resume:") })
            assertTrue(f.frozen)
            f.failure = null; control.isolateCandidate()
            assertTrue("reconcile-backup:${f.qualifiedCapture}" in f.calls)
        }
    }
    @Test fun `isolation reconciliation observes previous intent and refuses failed isolation`(): Unit = fixture { f ->
        val control = f.control()
        ReleasePrivateFiles.save(f.sourceRoot.resolve("isolate.intent.json"), "unit-original-intent".toByteArray())
        control.isolateCandidate(); assertTrue("reconcile-isolation:${f.source}" in f.calls)
        f.failure = "reconcile-isolation"; assertFails { control.isolateCandidate() }
        Files.delete(f.sourceRoot.resolve("isolate.intent.json"))
        f.failure = "isolate"; assertFails { control.isolateCandidate() }
    }
    @Test fun `held-source failed resume and failed backup reconciliation remain fenced`(): Unit = fixture { f ->
        val control = f.control(); control.preflight(); control.freeze(); control.capture()
        f.failure = "resume"
        assertFails { control.restoreTest(f.capture) }
        assertFails { control.resumeRestrictedCandidate() }
        assertTrue(f.frozen)
        f.failure = "reconcile-backup"; assertFails { control.isolateCandidate() }
    }
    @Test fun `restricted continuation revalidates restored evidence without a second source resume`(): Unit = fixture { f ->
        val control = f.control(); control.preflight(); control.freeze(); control.capture(); control.restoreTest(f.capture)
        assertEquals(1, f.calls.count { it == "resume:${f.capture}" })
        f.failedRestoredVerification = true
        assertFails { control.resumeRestrictedCandidate() }
        assertFails { control.qualificationSnapshot() }
        assertEquals(1, f.calls.count { it == "resume:${f.capture}" })
        assertEquals(2, f.calls.count { it == "verify-restored:execute-staged:${f.stagedTarget}" })
    }
    @Test fun `complete backup record is not misclassified as an uncertain hold after controller restart`(): Unit = fixture { f ->
        staged(f)
        // A fresh controller has no in-memory resumed flag: durable successful outcome decides.
        f.control().isolateCandidate()
        assertTrue("isolate:${f.source}" in f.calls)
        assertTrue(f.calls.none { it.startsWith("reconcile-backup:") })
    }
    private fun schedule(f: ReleaseControlTestFixture, name: String, journal: Path): ReleasePublication {
        val root = f.dir(f.root.resolve(name))
        val binding = RssScheduleBinding(deployment = requireNotNull(f.request.deployment), transactionJournal = journal.toString(),
            stateDirectory = f.root.resolve("state").toString(), tokenDirectory = f.root.resolve("tokens").toString(),
            mastodonOrigin = "https://social.datamancy.net", controllerSha256 = "a".repeat(64), artifactClosure = f.inventoryPin,
            userId = UnixSystem().uid.toInt())
        val bytes = f.json.encodeToString(binding).toByteArray(); val hash = ReleaseLocks.sha256(bytes)
        ReleasePrivateFiles.save(root.resolve("binding.json"), bytes); ReleasePrivateFiles.save(root.resolve("enrolled"), hash.toByteArray())
        return ReleasePublication(root.toString(), hash)
    }
    @Test fun `publication stays unenabled during staging then release and permanent failure suspension are distinct`(): Unit = fixture { f ->
        val journal = f.root.resolve("transaction.jsonl")
        val publication = schedule(f, "publication", journal)
        val previous = schedule(f, "previous", journal)
        val observed = mutableListOf<Boolean>()
        val scheduler = RssSchedule({ _, committed -> observed += committed }, { }, RssHttp { _, _, _, _ -> error("No outbound requests in unit test") })
        val request = f.request.copy(publication = publication, previousPublication = previous)
        TransactionJournal.append(journal, request.transactionId, request.lockDigest, Phase.PREPARED, null, null, request.deployment)
        // Unit fixture has no systemd timer; production construction retains
        // SystemdRssTimerControl and cannot claim a synthetic native ACK.
        val fixtureTimer = object : NativeRssTimerControl {
            override fun start(root: Path, expected: String) = Unit
            override fun stopIfOwned(root: Path, expected: String) = Unit
        }
        val control = NativeReleasePublication(request, journal, scheduler, timer = fixtureTimer)
        control.pause()
        assertFalse(Files.exists(Path.of(publication.root).resolve("enabled")))
        assertTrue(Files.exists(Path.of(previous.root).resolve("suspended")))
        assertFails { NativeReleasePublication(request.copy(publication = publication.copy(bindingSha256 = "0".repeat(64))), journal, scheduler, timer = fixtureTimer).pause() }
        for (phase in listOf(Phase.FROZEN, Phase.SNAPSHOT_VERIFIED, Phase.STAGED, Phase.CUTOVER_RESTRICTED, Phase.ACCEPTED))
            TransactionJournal.appendExisting(journal, phase, if (phase == Phase.FROZEN) null else f.capture)
        val accepted = TransactionJournal.verify(journal).last()
        TransactionJournal.appendExisting(journal, Phase.ACTIVATION_STARTED, f.capture, accepted.hash, "f".repeat(64))
        control.release(); assertEquals(listOf(false), observed)
        assertTrue(Files.exists(Path.of(publication.root).resolve("enabled")))
        control.pause(); assertTrue(Files.exists(Path.of(publication.root).resolve("suspended")))
        assertFails { control.release() }
    }
}
