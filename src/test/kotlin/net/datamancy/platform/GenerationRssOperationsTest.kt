package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class GenerationRssOperationsTest {
    private fun fixture(block: (Path) -> Unit) {
        val root = Files.createTempDirectory("rss-op-unit-", PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------")))
        try { block(root) } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `global lock is injected, same-thread nested scope is safe and other entrypoints cannot interleave`(): Unit = fixture { root ->
        val scope = GenerationRssOperations(root.resolve("generations"))
        val generationBase = Files.createDirectory(root.resolve("generations"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val generation = Files.createDirectory(generationBase.resolve("q-123456789abc"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        assertFails { scope.requireWritableGeneration(generation) }
        var reached = false
        scope.withExclusion {
            scope.withExclusion { reached = true; scope.requireWritableGeneration(generation) }
            val failure = java.util.concurrent.atomic.AtomicReference<Throwable?>()
            val competing = Thread {
                try { assertFailsWith<OverlappingFileLockException> { scope.withExclusion { error("Interleaved writer") } } }
                catch (error: Throwable) { failure.set(error) }
            }
            competing.start(); competing.join()
            assertNull(failure.get())
        }
        assertTrue(reached)
        assertTrue(Files.exists(root.resolve("rss-controller.lock")))
        assertEquals("rss-controller.lock", root.resolve("rss-controller.lock").fileName.toString())
    }
    @Test fun `whole-case qualification claim blocks unrelated writer and completes only from durable native oracle and result`(): Unit = fixture { root ->
        val generations = Files.createDirectory(root.resolve("generations"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val generation = Files.createDirectory(generations.resolve("q-123456789abc"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        GenerationRssPlan.prepare(generation)
        val plan = GenerationRssPlan(controllerSha256 = "a".repeat(64),
            artifactClosure = ActivationInput(root.resolve("closure").toString(), "b".repeat(64)),
            mastodonOrigin = "https://social.datamancy.net")
        val bundle = GenerationBundle(GenerationRequest(id = "q-123456789abc", candidateSha256 = "c".repeat(64),
            members = emptyList(), diskReservationMiB = 128, store = RuntimeStore.CANONICAL_V2,
            rssPlan = plan), emptyList(), 0)
        val bundleBytes = Json.encodeToString(bundle).toByteArray()
        ReleasePrivateFiles.save(generation.resolve("bundle.json"), bundleBytes)
        val caseId = "case-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        val artifacts = Files.createDirectory(root.resolve("artifacts"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val caseDirectory = Files.createDirectory(artifacts.resolve("rss-pack-us--workflow--headless--native"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val context = "{\"bundleSha256\":\"${ReleaseLocks.sha256(bundleBytes)}\"}"
        ReleasePrivateFiles.save(caseDirectory.resolve("context.json"), context.toByteArray())
        val intent = "{\"invocationId\":\"$caseId\",\"binding\":{\"trialId\":\"trial-test\",\"generationId\":\"q-123456789abc\",\"phase\":\"INSTALL\"}," +
            "\"serviceId\":\"rss-pack-us\",\"journey\":\"workflow\",\"surface\":\"HEADLESS\",\"variant\":\"NATIVE\"," +
            "\"requiredAssertions\":[\"checkpoint-preservation\"],\"contextSha256\":\"${ReleaseLocks.sha256(context.toByteArray())}\"}"
        ReleasePrivateFiles.save(caseDirectory.resolve("intent.json"), intent.toByteArray())
        val scope = GenerationRssOperations(generations)
        val phaseIntent = "{\"binding\":{\"trialId\":\"trial-test\",\"generationId\":\"q-123456789abc\",\"phase\":\"INSTALL\"}," +
            "\"artifactRoot\":\"$artifacts\",\"journalHead\":\"${"a".repeat(64)}\"}"
        val phaseRequest = RssQualificationPhaseRequest(trialId = "trial-test", generationId = "q-123456789abc",
            phase = "INSTALL", stagedOnly = false, bundleSha256 = ReleaseLocks.sha256(bundleBytes),
            inventorySha256 = "b".repeat(64), manifestSha256 = "c".repeat(64),
            intentSha256 = ReleaseLocks.sha256(phaseIntent.toByteArray()), journalHead = "a".repeat(64),
            artifactRoot = artifacts.toString(), phaseIntentPath = root.resolve("phase-trial-test-install.intent.json").toString(),
            phaseResultPath = root.resolve("phase-trial-test-install.result.json").toString())
        val requestPath = root.resolve("phase-request.json")
        ReleasePrivateFiles.save(requestPath, Json.encodeToString(phaseRequest).toByteArray())
        val phaseClaim = scope.withExclusion { RssQualificationIntents.beginPhase(generation, requestPath) }
        scope.withExclusion { assertFails { scope.requireWritableGeneration(generation) } }
        ReleasePrivateFiles.save(Path.of(phaseRequest.phaseIntentPath), phaseIntent.toByteArray())
        val claim = scope.withExclusion { RssQualificationIntents.begin(generation, caseDirectory, phaseClaim.phaseClaimSha256) }
        assertEquals(ReleaseLocks.sha256(intent.toByteArray()), claim.intentSha256)
        scope.withExclusion {
            assertFails { scope.requireWritableGeneration(generation) }
            scope.requireWritableGeneration(generation, caseId, claim.claimSha256, phaseClaim.phaseClaimSha256)
            assertFails { scope.requireWritableGeneration(generation, "case-ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee",
                claim.claimSha256, phaseClaim.phaseClaimSha256) }
        }
        assertFails { RssQualificationIntents.complete(generation, caseDirectory, claim.claimSha256, "d".repeat(64),
            phaseClaim.phaseClaimSha256) }
        ReleasePrivateFiles.save(caseDirectory.resolve("adapter-request.json"), "{\"invocation\":$intent}".toByteArray())
        val oracle = "{\"originalId\":\"rss-1\"}"
        ReleasePrivateFiles.save(caseDirectory.resolve("oracle.json"), oracle.toByteArray())
        val oracleHash = ReleaseLocks.sha256(oracle.toByteArray())
        val native = "{\"schemaVersion\":2,\"invocationId\":\"$caseId\",\"serviceId\":\"rss-pack-us\",\"generationId\":\"q-123456789abc\"," +
            "\"phase\":\"INSTALL\",\"assertions\":{\"checkpoint-preservation\":true},\"artifacts\":{\"oracle.json\":\"$oracleHash\"}}"
        ReleasePrivateFiles.save(caseDirectory.resolve("native-result.json"), native.toByteArray())
        val result = "{\"passed\":true,\"finished\":true,\"exitCode\":0,\"failureType\":null,\"invocation\":$intent," +
            "\"artifactHashes\":{\"oracle.json\":\"$oracleHash\"},\"observationSha256\":\"${ReleaseLocks.sha256(native.toByteArray())}\"}"
        ReleasePrivateFiles.save(caseDirectory.resolve("result.json"), result.toByteArray())
        assertFails { RssQualificationIntents.complete(generation, caseDirectory, claim.claimSha256, "f".repeat(64),
            phaseClaim.phaseClaimSha256) }
        val complete = scope.withExclusion { RssQualificationIntents.complete(generation, caseDirectory,
            claim.claimSha256, ReleaseLocks.sha256(result.toByteArray()), phaseClaim.phaseClaimSha256) }
        assertEquals(caseId, complete.invocationId)
        assertEquals(ReleaseLocks.sha256(result.toByteArray()), complete.resultSha256)
        scope.withExclusion { assertFails { scope.requireWritableGeneration(generation) } } // Whole phase remains held.
        assertFails { RssQualificationIntents.begin(generation, caseDirectory, phaseClaim.phaseClaimSha256) }
        assertFails { RssQualificationIntents.completePhase(generation, requestPath, phaseClaim.phaseClaimSha256,
            "e".repeat(64)) } // Eleven case proofs AND final phase result are required.
        Files.writeString(caseDirectory.resolve("oracle.json"), "{\"originalId\":\"changed\"}")
        scope.withExclusion { assertFails { scope.requireWritableGeneration(generation) } }
    }
    @Test fun `held intent blocks replay and normal tick until an exact proof completes`(): Unit = fixture { root ->
        val generations = Files.createDirectory(root.resolve("generations"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val generation = Files.createDirectory(generations.resolve("q-123456789abc"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val rss = Files.createDirectory(generation.resolve("rss"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val state = Files.createDirectory(rss.resolve("state"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        RssStateStore(state).initializeFresh()
        val tokens = Files.createDirectory(rss.resolve("tokens"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val closure = root.resolve("closure.json")
        ReleasePrivateFiles.save(closure, "synthetic".toByteArray())
        val id = "q-123456789abc"
        val binding = RssScheduleBinding(deployment = ReleaseDeploymentBinding(id, "a".repeat(64), "b".repeat(64), "c".repeat(64)),
            transactionJournal = root.resolve("journal.jsonl").toString(), stateDirectory = state.toString(), tokenDirectory = tokens.toString(),
            mastodonOrigin = "https://social.datamancy.net", controllerSha256 = "d".repeat(64),
            artifactClosure = ActivationInput(closure.toString(), ReleaseLocks.sha256(Files.readAllBytes(closure))),
            userId = UnixSystem().uid.toInt())
        val native = GenerationRuntime(generations, root.resolve("runtime"),
            { error("No native backend before actual held snapshot") }, { error("No capacity operation") })
        val priorProof = RssKopiaOperationProof(generations, native, id, binding.deployment.bundleSha256,
            "cap-123456789abc", heldRestore = true)
        priorProof.bind(binding, "cap-123456789abc", true) // No future target hash at hold admission.
        assertFails { priorProof.verifyAfter() } // Cannot complete before snapshot and actual target exist.
        assertFails { priorProof.bind(binding, "cap-123456789abc", false) }
        val schedule = RssSchedule({ _, _ -> }, {}, RssHttp { _, _, _, _ -> error("No real network") })
        val scheduleRoot = rss.resolve("schedule")
        val hash = schedule.enroll(scheduleRoot, binding)
        var ready = false
        val proof = object : RssDurableOperationProof {
            override fun verifyBefore() { require(!ready) }
            override fun verifyAfter() { require(ready) }
        }
        val claim = schedule.beginHeld(scheduleRoot, hash, "cap-123456789abc", proof)
        assertFails { schedule.tick(scheduleRoot, hash) }
        assertFails { schedule.requireWritable(scheduleRoot, hash) }
        assertFails { schedule.beginHeld(scheduleRoot, hash, "cap-222222222222", proof) }
        assertFails { schedule.completeHeld(claim, proof) }
        assertTrue(Files.exists(scheduleRoot.resolve("maintenance-cap-123456789abc.intent")))
        assertFalse(Files.exists(scheduleRoot.resolve("maintenance-cap-123456789abc.complete")))
        ready = true
        schedule.completeHeld(claim, proof)
        assertFails { schedule.completeHeld(claim, proof) }
        schedule.requireWritable(scheduleRoot, hash)
        assertNull(schedule.tick(scheduleRoot, hash)) // Still disabled; maintenance completion never grants publication.
    }
    @Test fun `early owned no-target rollback is completion-only and cannot start a new RSS hold`(): Unit {
        val proof = RssEarlyUpdateRollbackProof(GenerationRuntime.BASE, GenerationRuntime.real(),
            "tx-unit", "q-123456789abc", "a".repeat(64), "cap-123456789abc", "q-abcdef012345")
        assertFailsWith<IllegalStateException> { proof.verifyBefore() }
    }
    @Test fun `release-bound original schedule cannot be permanently retired before activation proof`(): Unit = fixture { root ->
        val generation = Files.createDirectory(root.resolve("q-123456789abc"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val rss = Files.createDirectory(generation.resolve("rss"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val state = Files.createDirectory(rss.resolve("state"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        RssStateStore(state).initializeFresh()
        val tokens = Files.createDirectory(rss.resolve("tokens"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val closure = root.resolve("closure")
        ReleasePrivateFiles.save(closure, "synthetic-controller-closure".toByteArray())
        val binding = RssScheduleBinding(deployment = ReleaseDeploymentBinding("q-123456789abc", "a".repeat(64),
            "b".repeat(64), "c".repeat(64)), transactionJournal = root.resolve("transaction.jsonl").toString(),
            stateDirectory = state.toString(), tokenDirectory = tokens.toString(), mastodonOrigin = "https://social.datamancy.net",
            controllerSha256 = "d".repeat(64),
            artifactClosure = ActivationInput(closure.toString(), ReleaseLocks.sha256(Files.readAllBytes(closure))),
            userId = UnixSystem().uid.toInt())
        val release = RssSchedule({ _, _ -> error("No activation permit") }, {}, RssHttp { _, _, _, _ -> error("No outbound HTTP") },
            enrollment = object : RssEnrollmentAuthority {
                override fun preflight(root: Path, binding: RssScheduleBinding) {}
                override fun claim(root: Path, binding: RssScheduleBinding, digest: String) {}
                override fun complete(root: Path, binding: RssScheduleBinding, digest: String) {}
                override fun verify(root: Path, binding: RssScheduleBinding, digest: String) {}
            })
        val scheduleRoot = rss.resolve("schedule")
        val digest = release.enroll(scheduleRoot, binding)
        assertFails { release.pause(scheduleRoot, digest) }
        assertFalse(Files.exists(scheduleRoot.resolve("suspended")))
        assertFails { release.release(scheduleRoot, digest) } // No activation permit exists.
    }
}
