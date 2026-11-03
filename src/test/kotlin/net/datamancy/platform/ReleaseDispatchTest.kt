package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class ReleaseDispatchTest {
    @Test fun `install dispatch drives native control boundaries then explicit single use activation`() = ReleaseControlTestFixture().use { f ->
        val dispatcher = f.dispatcher()
        val accepted = Json.decodeFromString<JournalRecord>(dispatcher.execute(ReleaseRequest.Install(f.request)))
        assertEquals(Phase.ACCEPTED, accepted.phase)
        assertEquals(f.capture, accepted.snapshotId); assertEquals(f.qualifiedCapture, accepted.qualificationSnapshotId)
        assertFalse("release" in f.calls)
        val activation = ReleaseRequest.Activate(f.request, accepted.hash, f.evidence())
        assertFails { dispatcher.execute(activation.copy(expectedHead = "0".repeat(64))) }
        assertFails { dispatcher.execute(activation.copy(transaction = f.request.copy(lockDigest = "0".repeat(64)))) }
        val committed = Json.decodeFromString<JournalRecord>(dispatcher.execute(activation))
        assertEquals(Phase.COMMITTED, committed.phase)
        assertTrue(f.calls.indexOf("consume-permit") < f.calls.indexOf("release"))
        assertFails { dispatcher.execute(activation) }
        assertFails { dispatcher.execute(ReleaseRequest.Install(f.request)) }
        assertFails { dispatcher.execute(ReleaseRequest.Reconcile(f.request, committed.hash, "r-999999999999", "a".repeat(64))) }
        assertEquals("install", ReleaseDispatch.operation(ReleaseRequest.Install(f.request)))
        assertEquals("activate", ReleaseDispatch.operation(activation))
    }

    @Test fun `backup and restoration dispatch preserve failures target identity and interruption`() {
        ReleaseControlTestFixture().use { f ->
            val dispatcher = f.dispatcher(); val generation = ReleaseGeneration(f.source, f.sourceHash)
            val backup = ReleaseRequest.Backup(generation, f.inventoryPin, f.capture)
            assertTrue(Json.decodeFromString<GenerationBackupOutcome>(dispatcher.execute(backup)).sourceResumed)
            f.failure = "backup"; assertFails { dispatcher.execute(backup) }; f.failure = null
            assertFails { dispatcher.execute(backup.copy(inventory = f.inventoryPin.copy(sha256 = "0".repeat(64)))) }
            val restore = ReleaseRequest.RestoreTest(generation, f.inventoryPin, f.capture, f.stagedTarget, f.request.restore)
            assertEquals("unit-only semantic runner response", dispatcher.execute(restore))
            assertTrue("isolate:${f.stagedTarget}" in f.calls)
            assertFails { dispatcher.execute(restore.copy(target = f.source)) }
            assertFails { dispatcher.execute(restore.copy(acceptance = f.request.staged)) }
            f.importPassed = false; assertFails { dispatcher.execute(restore) }; f.importPassed = true
            f.failedAcceptance = true; assertFails { dispatcher.execute(restore) }; f.failedAcceptance = false
            f.failure = "isolate"; assertFails { dispatcher.execute(restore) }; f.failure = null
            f.interruptedAcceptance = true
            try {
                assertFailsWith<InterruptedException> { dispatcher.execute(restore) }
                assertTrue(Thread.currentThread().isInterrupted)
            } finally { Thread.interrupted() }
            assertEquals("restore-test", ReleaseDispatch.operation(restore))
        }
    }

    private class RecordingControl(private val calls: MutableList<String>) : ReleaseGenerationControl {
        override fun preflight() { calls += "preflight" }
        override fun stage() { calls += "stage" }
        override fun readiness() { calls += "ready" }
        override fun freeze() { calls += "freeze" }
        override fun verifyQuiesced() { calls += "quiesce" }
        override fun capture(): String { calls += "capture"; return "cap-111111111111" }
        override fun restoreTest(snapshot: String) { calls += "restore-test" }
        override fun migrate() { calls += "migrate" }
        override fun resumeRestrictedCandidate() { calls += "resume" }
        override fun isolateCandidate() { calls += "isolate" }
        override fun restorePrevious(snapshot: String) { calls += "restore-old:$snapshot" }
        override fun verifyPrevious() { calls += "verify-old" }
        override fun qualificationSnapshot() = "cap-222222222222"
    }
    @Test fun `typed update dispatch and separately invoked rollback retain durable caddy result and terminal claim`() = ReleaseControlTestFixture().use { f ->
        // Unit routing contract, NOT native owned-update creation or promotion evidence.
        val calls = mutableListOf<String>()
        val dispatcher = f.dispatcher { _, _ -> RecordingControl(calls) }
        val app = f.bundle.members.single().spec.processes.single { it.id == "planka" }
        val migration = PlankaMigrationRequest(operation = "r-555555555555", transition = PlankaVersionTransition("2.2.0", "2.2.1"),
            generation = f.source, bundleSha256 = f.sourceHash, snapshotId = f.capture, manifest = f.inventoryPin,
            migrationEnvironment = f.inventoryPin, image = ActivationImagePin(app.image, app.imageId), fenceId = f.fence)
        val request = f.request.copy(previous = ReleaseGeneration("q-444444444444", "4".repeat(64)),
            previousPublication = ReleasePublication(f.root.resolve("old-publication").toString(), "5".repeat(64)), migration = migration)
        assertFails { dispatcher.execute(ReleaseRequest.Install(request)) }
        assertFails { dispatcher.execute(ReleaseRequest.Update(f.request)) }
        assertFails { dispatcher.execute(ReleaseRequest.Update(request.copy(migration = migration.copy(transition = PlankaVersionTransition("2.2.1", "2.2.0"))))) }
        val accepted = Json.decodeFromString<JournalRecord>(dispatcher.execute(ReleaseRequest.Update(request)))
        assertTrue(calls.indexOf("migrate") < calls.indexOf("ready"))
        val rollback = ReleaseRequest.Rollback(request, accepted.hash)
        val recovered = Json.decodeFromString<JournalRecord>(dispatcher.execute(rollback))
        assertEquals(Phase.RECOVERY_REQUIRED, recovered.phase)
        assertTrue(calls.indexOf("isolate") < calls.indexOf("restore-old:${f.capture}"))
        assertEquals("verify-old", calls.last())
        assertFails { dispatcher.execute(rollback) }
        assertEquals("update", ReleaseDispatch.operation(ReleaseRequest.Update(request)))
        assertEquals("rollback", ReleaseDispatch.operation(rollback))
    }

    @Test fun `reconcile observes lost caddy acknowledgement without resending or opening writes`(): Unit = ReleaseControlTestFixture().use { f ->
        val txRoot = f.dir(f.transactions.resolve("unit"))
        val head = TransactionJournal.append(txRoot.resolve("transaction.jsonl"), f.request.transactionId, f.request.lockDigest,
            Phase.PREPARED, null, null, f.request.deployment)
        f.lostCaddyAck = true
        assertFails { f.caddy.replace(f.request.ingress.cutover, f.request.ingress.expectedConfigurationSha256, null,
            f.source, f.request.ingress.upstreams, "a".repeat(64)) }
        f.lostCaddyAck = false
        val intent = ReleaseLocks.sha256(Files.readAllBytes(f.caddyRoot.resolve("${f.request.ingress.cutover}.intent.json")))
        val reconcile = ReleaseRequest.Reconcile(f.request, head.hash, "r-999999999999", "a".repeat(64), intent)
        val dispatcher = f.dispatcher()
        assertTrue(Json.decodeFromString<GenerationOutcome>(dispatcher.execute(reconcile)).passed)
        assertEquals(1, f.calls.count { it == "caddy:PATCH" })
        assertTrue(f.calls.none { it.startsWith("resume:") || it == "release" })
        f.failure = "reconcile-isolation"
        assertFails { dispatcher.execute(reconcile.copy(caddyIntentSha256 = null)) }
        assertEquals("reconcile", ReleaseDispatch.operation(reconcile))
        assertFails { dispatcher.execute(ReleaseRequest.Rollback(f.request, head.hash)) }
    }

    @Test fun `invalid transaction definitions fail before effect construction`() = ReleaseControlTestFixture().use { f ->
        val dispatcher = f.dispatcher { _, _ -> error("Must not construct native controls") }
        for (request in listOf(f.request.copy(schemaVersion = 9), f.request.copy(transactionId = "../foreign"),
            f.request.copy(snapshotId = "bad"), f.request.copy(restoreTarget = f.source),
            f.request.copy(previousPublication = ReleasePublication("/foreign", "a".repeat(64))))) {
            assertFails { dispatcher.execute(ReleaseRequest.Install(request)) }
        }
        assertTrue(f.calls.none { it == "stage" })
    }

    private fun temporary(block: (Path) -> Unit) {
        val root = Files.createTempDirectory("release-dispatch-unit-")
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try { block(root) } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private fun pin(root: Path, name: String, text: String): ActivationInput {
        val path = root.resolve(name); ReleasePrivateFiles.save(path, text.toByteArray())
        return ActivationInput(path.toString(), ReleaseLocks.sha256(text.toByteArray()))
    }
    private fun invocation(root: Path): ReleaseAcceptanceInvocation = ReleaseAcceptanceInvocation("a".repeat(64),
        pin(root, "products.json", "{}"), pin(root, "manifest.json", "{}"), pin(root, "input.json", "{}"),
        pin(root, "journal.jsonl", "private unit journal\n").path, "b".repeat(64), root.resolve("artifacts").toString(),
        pin(root, "contexts.json", "{}"))
    @Test fun `pinned acceptance command has fixed executable and exact independent input hashes`() = temporary { root ->
        val request = invocation(root); var verified = 0; val calls = mutableListOf<List<String>>()
        val acceptance = ReleaseAcceptance(root, AcceptanceControllerProcess { argv, directory ->
            assertEquals(root, directory); calls += argv; RuntimeCommandResult(0, "verified")
        }) { path, hash -> assertEquals(request.controllerSha256, hash); assertTrue(path.endsWith(hash)); verified++ }
        assertEquals("verified", acceptance.run("execute-staged", request))
        assertEquals("execute-staged", calls.single()[1]); assertEquals(request.contexts!!.path, calls.single().last())
        assertEquals("verified", acceptance.run("execute-qualified", request.copy(contexts = null)))
        assertEquals(request.artifacts, calls.last().last())
        assertEquals("verified", acceptance.run("finish-qualified", request.copy(artifacts = null, contexts = null)))
        assertEquals("verified", acceptance.run("assess-qualified", request.copy(artifacts = null, contexts = null)))
        assertEquals(4, verified)
        assertFails { acceptance.run("sh", request) }
        assertFails { acceptance.run("finish-qualified", request) }
        assertFails { acceptance.run("execute-qualified", request.copy(artifacts = null)) }
        assertFails { acceptance.run("execute-qualified", request.copy(products = request.products.copy(sha256 = "0".repeat(64)))) }
        Files.createDirectory(Path.of(request.artifacts!!), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        assertFails { acceptance.run("execute-qualified", request) }
        assertEquals(4, calls.size)
    }
    @Test fun `pinned verifier refusal and interruption propagate without fallback`() = temporary { root ->
        val request = invocation(root)
        assertFails { ReleaseAcceptance(root, AcceptanceControllerProcess { _, _ -> RuntimeCommandResult(1, "no") }) { _, _ -> }
            .run("execute-qualified", request) }
        try {
            assertFailsWith<InterruptedException> { ReleaseAcceptance(root, AcceptanceControllerProcess { _, _ -> throw InterruptedException("unit") }) { _, _ -> }
                .run("execute-qualified", request) }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
        assertFails { ReleaseAcceptance(root, AcceptanceControllerProcess { _, _ -> error("must not execute") }) { _, _ -> error("changed distribution") }
            .run("execute-qualified", request) }
    }
    @Test fun `strict typed wire selects backup and rejects unknown action or fields`() = temporary { root ->
        val inventory = pin(root, "inventory.json", "{}")
        val request: ReleaseRequest = ReleaseRequest.Backup(ReleaseGeneration("q-111111111111", "a".repeat(64)), inventory, "cap-111111111111")
        val json = Json { classDiscriminator = "operation" }
        val file = root.resolve("request.json"); ReleasePrivateFiles.save(file, json.encodeToString(request).toByteArray())
        assertEquals(request, ReleaseDispatch.read(file)); assertEquals("backup", ReleaseDispatch.operation(request))
        val invalid = root.resolve("bad.json")
        ReleasePrivateFiles.save(invalid, "{\"operation\":\"shell\",\"command\":\"true\"}".toByteArray())
        assertFails { ReleaseDispatch.read(invalid) }
        assertFails { ReleaseGeneration("q-foreign", "a".repeat(64)).validate() }
        assertFails { ReleaseGeneration("q-111111111111", "bad").validate() }
    }
    @Test fun `legacy qualification dispatch refuses invalid journal before launching controller`() = temporary { root ->
        val base = invocation(root).copy(artifacts = null, contexts = null)
        val assess = base.copy(expectedHead = "c".repeat(64))
        val calls = mutableListOf<List<String>>()
        val acceptance = ReleaseAcceptance(root, AcceptanceControllerProcess { args, _ -> calls += args; RuntimeCommandResult(0, "unit output") }) { _, _ -> }
        val runtime = GenerationRuntime(root, root, { error("no runtime in qualification") }, { error("no capacity observation") })
        val dispatcher = ReleaseDispatch(root, runtime, { _, _ -> error("no effects") }, acceptance,
            { _, _, _, _ -> error("no restore") }, { _, _ -> error("no publication") })
        assertFails { dispatcher.execute(ReleaseRequest.Qualify(base, assess)) }
        assertTrue(calls.isEmpty())
        assertFails { dispatcher.execute(ReleaseRequest.QualifyBound(base, assess.input)) }
        assertEquals("qualify", ReleaseDispatch.operation(ReleaseRequest.QualifyBound(base, assess.input)))
        assertFails { dispatcher.execute(ReleaseRequest.Qualify(base, assess.copy(controllerSha256 = "d".repeat(64)))) }
    }
}
