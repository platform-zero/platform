package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class ReleaseDispatchTest {
    @Test fun `install dispatch drives native control boundaries then explicit single use activation`(): Unit = ReleaseControlTestFixture().use { f ->
        val dispatcher = f.dispatcher()
        val originalWire = Json { encodeDefaults = true }.encodeToString(f.request)
        assertFalse(originalWire.contains("updatePreparation"))
        assertTrue(originalWire.contains("\"deployment\""))
        assertTrue(originalWire.contains("\"publication\""))
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

    @Test fun `RESTORE refuses absent original-host bridge before import or UI effect`(): Unit =
        ReleaseControlTestFixture().use { f ->
            val withoutBridge = f.dispatcher(bridge = false)
            val restore = ReleaseRequest.RestoreTest(ReleaseGeneration(f.source, f.sourceHash),
                f.inventoryPin, f.capture, f.stagedTarget, f.request.restore)
            assertFails { withoutBridge.execute(restore) }
            assertFalse(f.calls.any { it.startsWith("import:") || it.startsWith("acceptance:execute-qualified") })
        }
    @Test fun `backup and restoration dispatch preserve failures target identity and interruption`(): Unit {
        ReleaseControlTestFixture().use { f ->
            val dispatcher = f.dispatcher(); val generation = ReleaseGeneration(f.source, f.sourceHash)
            val backup = ReleaseRequest.Backup(generation, f.inventoryPin, f.capture)
            assertTrue(Json.decodeFromString<GenerationBackupOutcome>(dispatcher.execute(backup)).sourceResumed)
            f.failure = "backup"; assertFails { dispatcher.execute(backup) }; f.failure = null
            assertFails { dispatcher.execute(backup.copy(inventory = f.inventoryPin.copy(sha256 = "0".repeat(64)))) }
            val restore = ReleaseRequest.RestoreTest(generation, f.inventoryPin, f.capture, f.stagedTarget, f.request.restore)
            assertTrue(dispatcher.execute(restore).matches(Regex("[a-f0-9]{64}")),
                "RESTORE returns immutable removed-bridge/source-resume evidence, not a runner callback")
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

    @Test fun `owned update refuses caller future deployment migration and missing original source pins`() : Unit = ReleaseControlTestFixture().use { f ->
        val dispatcher = f.dispatcher(controls = { _, _ -> error("Invalid update must not construct native controls") })
        val source = ReleaseGeneration(f.source, f.sourceHash)
        val intent = ReleaseUpdateIntent(source, f.stagedTarget, "c".repeat(64), f.inventoryPin.sha256,
            f.inventoryPin.sha256, f.inventoryPin.sha256, PlankaVersionTransition("2.2.0", "2.2.1"))
        val original = ActivationInput(f.sourceRoot.resolve("bundle.json").toString(), f.sourceHash)
        val preparation = ReleaseUpdatePreparation(intent = intent, previousInventory = f.inventoryPin,
            candidateInventory = f.inventoryPin, sourceBundle = original, sitePolicy = f.inventoryPin,
            migrationOperation = "r-555555555555")
        val request = f.request.copy(previous = source, previousPublication =
            ReleasePublication(f.root.resolve("old-publication").toString(), "5".repeat(64)),
            deployment = null, publication = null, migration = null, updatePreparation = preparation)
        val preparedWire = Json { encodeDefaults = true }.encodeToString(request)
        assertFalse(preparedWire.contains("\"deployment\""))
        assertFalse(preparedWire.contains("\"publication\""))
        assertTrue(preparedWire.contains("\"updatePreparation\""))
        assertFails { dispatcher.execute(ReleaseRequest.Update(f.request)) }
        assertFails { dispatcher.execute(ReleaseRequest.Install(request)) }
        assertFails { dispatcher.execute(ReleaseRequest.Update(request.copy(deployment = f.request.deployment))) }
        assertFails { dispatcher.execute(ReleaseRequest.Update(request.copy(publication = f.request.publication))) }
        assertFails { dispatcher.execute(ReleaseRequest.Update(request.copy(updatePreparation = null))) }
        assertFails { dispatcher.execute(ReleaseRequest.Update(request.copy(migration = f.request.migration ?: PlankaMigrationRequest(
            operation = "r-555555555555", transition = intent.transition, generation = f.stagedTarget,
            bundleSha256 = "a".repeat(64), snapshotId = f.capture, manifest = f.inventoryPin,
            migrationEnvironment = f.inventoryPin, image = ActivationImagePin("pinned", "b".repeat(64)), fenceId = f.fence)))) }
        assertFails { dispatcher.execute(ReleaseRequest.Update(request.copy(updatePreparation = preparation.copy(
            sourceBundle = original.copy(sha256 = "0".repeat(64)))))) }
        assertFails { dispatcher.execute(ReleaseRequest.Update(request.copy(updatePreparation = preparation.copy(
            migrationOperation = "bad")))) }
        assertTrue(f.calls.none { it == "stage" || it.startsWith("hold:") })
        assertEquals("update", ReleaseDispatch.operation(ReleaseRequest.Update(request)))
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

    @Test fun `invalid transaction definitions fail before effect construction`(): Unit = ReleaseControlTestFixture().use { f ->
        val dispatcher = f.dispatcher(controls = { _, _ -> error("Must not construct native controls") })
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
    @Test fun `pinned acceptance command has fixed executable and exact independent input hashes`(): Unit = temporary { root ->
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
    @Test fun `pinned verifier refusal and interruption propagate without fallback`(): Unit = temporary { root ->
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
    @Test fun `controlled execution cannot fall back to legacy child on refusal`(): Unit = temporary { root ->
        val invocation = invocation(root)
        var legacy = 0
        var controlled = 0
        val acceptance = ReleaseAcceptance(root, AcceptanceControllerProcess { _, _ ->
            legacy++; RuntimeCommandResult(0, "legacy")
        }, controlledExecution = { operation, pinned, argv, directory ->
            controlled++
            assertEquals("execute-qualified", operation)
            assertEquals(invocation, pinned)
            assertEquals(root, directory)
            assertEquals(invocation.input.path, argv[4])
            RuntimeCommandResult(1, "retained refusal")
        }, verifyDistribution = { _, _ -> })
        assertFails { acceptance.run("execute-qualified", invocation) }
        assertEquals(1, controlled)
        assertEquals(0, legacy)
        assertEquals("legacy", acceptance.run("finish-qualified", invocation.copy(artifacts = null, contexts = null)))
        assertEquals(1, legacy)
    }
    @Test fun `strict typed wire selects backup and rejects unknown action or fields`(): Unit = temporary { root ->
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
    @Test fun `legacy qualification dispatch refuses invalid journal before launching controller`(): Unit = temporary { root ->
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
