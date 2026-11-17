package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class NativeRestoredJourneysTest {
    private val caseOne = ActivationInput("/protected/case-one/safety.json", "a".repeat(64))
    private val caseTwo = ActivationInput("/protected/case-two/safety.json", "b".repeat(64))
    private val isolated = GenerationOutcome("isolate", "c".repeat(64), passed = true)

    @Test fun `failed second case still audits both safety receipts and isolates target, never resumes source`(): Unit {
        val events = mutableListOf<String>()
        var sourceResumed = false
        val attempt = RestoredLifecycleDriver().settle<List<ActivationInput>>(
            run = { events += "first case"; events += "second case fails"; error("acceptance failed") },
            safety = { events += "original case teardown receipts"; listOf(caseOne, caseTwo) },
            isolate = { events += "isolate restored target"; isolated })
        assertNotNull(attempt.failure)
        assertNull(attempt.completion)
        assertEquals(listOf(caseOne, caseTwo), attempt.safety)
        assertEquals(isolated, attempt.isolation)
        assertFailsWith<IllegalStateException> {
            attempt.requireForSourceDisposition()
            sourceResumed = true
        }
        assertEquals(false, sourceResumed)
        assertEquals(listOf("first case", "second case fails", "original case teardown receipts",
            "isolate restored target"), events)
    }

    @Test fun `unknown client stop still attempts target isolation but cannot authorize disposition`(): Unit {
        val events = mutableListOf<String>()
        assertFailsWith<IllegalStateException> {
            RestoredLifecycleDriver().settle(
                run = { events += "acceptance fails"; error("case lost ACK") },
                safety = { events += "stop uncertain"; error("original client stop unknown") },
                isolate = { events += "isolate target"; isolated })
        }
        assertEquals(listOf("acceptance fails", "stop uncertain", "isolate target"), events)
    }

    @Test fun `target isolation failure blocks source disposition after nominal passing cases`(): Unit {
        val attempt = RestoredLifecycleDriver().settle(
            run = { listOf(caseOne, caseTwo) }, safety = { listOf(caseOne, caseTwo) },
            isolate = { GenerationOutcome("isolate", "c".repeat(64), passed = false, failureType = "uncertain") })
        assertFailsWith<IllegalArgumentException> { attempt.requireForSourceDisposition() }
    }

    @Test fun `owned update keeps original rollback source held after safe staged journey`(): Unit {
        val attempt = RestoredLifecycleDriver().settle(
            run = { listOf(caseOne, caseTwo) }, safety = { listOf(caseOne, caseTwo) }, isolate = { isolated })
        assertEquals(RestoredSourceDisposition.RETAINED_FOR_OWNED_UPDATE,
            RestoredSourceDispositionPolicy.select(attempt,
                ActivationInput("/protected/source/held.json", "d".repeat(64)),
                ActivationInput("/protected/owned/update.json", "e".repeat(64))))
        assertFailsWith<IllegalArgumentException> {
            RestoredSourceDispositionPolicy.select(attempt, null,
                ActivationInput("/protected/owned/update.json", "e".repeat(64)))
        }
        val noProof = attempt.copy(safety = listOf(caseOne))
        assertFailsWith<IllegalArgumentException> {
            RestoredSourceDispositionPolicy.select(noProof, null, null)
        }
    }

    @Test fun `independent case refusal after isolation precedes every source or aggregate effect`(): Unit {
        val events = mutableListOf<String>()
        val driver = RestoredLifecycleDriver()
        val attempt = driver.settle(run = { events += "accepted cases"; listOf(caseOne, caseTwo) },
            safety = { events += "protected teardown"; listOf(caseOne, caseTwo) },
            isolate = { events += "target isolated"; isolated })
        var sourceResume = false
        var retainedSuccess = false
        var aggregateWritten = false
        assertFailsWith<IllegalStateException> {
            driver.verifiedCasesBeforeDisposition(attempt) { originals ->
                assertEquals(listOf(caseOne, caseTwo), originals)
                events += "independent C2V refusal"
                error("raw case closure rejected")
            }
            sourceResume = true; retainedSuccess = true; aggregateWritten = true
        }
        assertEquals(false, sourceResume)
        assertEquals(false, retainedSuccess)
        assertEquals(false, aggregateWritten)
        assertEquals(listOf("accepted cases", "protected teardown", "target isolated",
            "independent C2V refusal"), events)
    }

    private data class OriginalEffects(val scope: QualificationControlScope,
        val files: MutableMap<Path, ByteArray>, val caseDirectory: String,
        val completionResult: Path, val completionReply: QualificationControlReplyBody)
    private fun originalEffects(kind: String): OriginalEffects {
        val json = QualificationOwnerControl.json
        val hash = "a".repeat(64)
        val phase = "b".repeat(64)
        val root = Path.of("/fixture/requests")
        val caseDirectory = "/fixture/cases/rss-native"
        val scope = QualificationControlScope(suiteId = "0".repeat(24), generationId = "q-000000000001",
            bundleSha256 = hash, operation = "execute-staged", controllerSha256 = hash,
            products = ActivationInput("/fixture/products", hash), manifest = ActivationInput("/fixture/manifest", hash),
            binding = ActivationInput("/fixture/binding", hash), journalFile = "/fixture/journal",
            journalHeadSha256 = hash, artifactRoot = "/fixture/cases", contexts = null)
        val scopeSha = ReleaseLocks.sha256(json.encodeToString(scope).encodeToByteArray())
        val invocation = "case-00000000-0000-0000-0000-000000000001"
        fun body(sequence: Int, operation: String, payload: JsonElement) = QualificationControlRequestBody(
            suiteId = scope.suiteId, scopeSha256 = scopeSha, sequence = sequence,
            operation = operation, payload = payload)
        fun reply(sequence: Int, operation: String, payload: JsonElement) = QualificationControlReplyBody(
            suiteId = scope.suiteId, scopeSha256 = scopeSha, sequence = sequence,
            operation = operation, status = "OK", payload = payload, errorCode = null)
        val begin = if (kind == "RSS") json.encodeToJsonElement(RssQualificationBeginReceipt(
            invocation, scope.generationId, "rss-jobs", hash, hash, hash, hash, phase))
            else json.encodeToJsonElement(NativeCaseClaimEnvelope(invocation, scope.generationId,
                "opensearch", "trial", buildJsonObject { }, hash, "q-000000000001-v2", hash,
                "RESTORE", hash, hash, hash))
        val finishRequest = if (kind == "RSS") json.encodeToJsonElement(
            QualificationControlRssCaseFinish(caseDirectory, hash, phase, hash))
            else json.encodeToJsonElement(NativeCaseCompletionRequest(caseDirectory, hash, hash))
        val finishResult = if (kind == "RSS") json.encodeToJsonElement(
            RssQualificationCaseCompletionReceipt(invocation, hash, hash))
            else json.encodeToJsonElement(NativeCaseCompletionEnvelope(invocation, hash, hash))
        val files = mutableMapOf<Path, ByteArray>()
        fun add(sequence: Int, operation: String, payload: JsonElement, response: JsonElement?) {
            files[root.resolve("$sequence.intent.json")] = json.encodeToString(body(sequence, operation, payload)).encodeToByteArray()
            if (response != null) files[root.resolve("$sequence.result.json")] =
                json.encodeToString(reply(sequence, operation, response)).encodeToByteArray()
        }
        add(2, "${kind}_CASE_BEGIN", buildJsonObject { put("caseDirectory", caseDirectory) }, begin)
        add(3, "${kind}_CASE_COMPLETE", finishRequest, finishResult)
        add(4, "CASE_START", buildJsonObject { put("caseDirectory", caseDirectory) }, null)
        return OriginalEffects(scope, files, caseDirectory, root.resolve("3.result.json"),
            reply(3, "${kind}_CASE_COMPLETE", finishResult))
    }
    private fun census(fixture: OriginalEffects): Set<String> =
        RestoredFailureSafetyEvidence.originalEffectCensus(fixture.scope, fixture.files.keys.toList()) { path, maximum ->
            requireNotNull(fixture.files[path]).also { require(it.size in 1..maximum) }
        }

    @Test fun `failure native and RSS census requires original matching OK result not just COMPLETE intent`(): Unit {
        for (kind in listOf("NATIVE", "RSS")) {
            val exact = originalEffects(kind)
            assertEquals(setOf(exact.caseDirectory), census(exact))
            val lost = originalEffects(kind)
            lost.files.remove(lost.completionResult)
            assertFailsWith<IllegalArgumentException> { census(lost) }
            val refused = originalEffects(kind)
            refused.files[refused.completionResult] = QualificationOwnerControl.json.encodeToString(
                refused.completionReply.copy(status = "REFUSED", payload = null, errorCode = "UNCERTAIN"))
                .encodeToByteArray()
            assertFailsWith<IllegalArgumentException> { census(refused) }
            val foreign = originalEffects(kind)
            foreign.files[foreign.completionResult] = QualificationOwnerControl.json.encodeToString(
                foreign.completionReply.copy(sequence = 5)).encodeToByteArray()
            assertFailsWith<IllegalArgumentException> { census(foreign) }
            val wrongClaim = originalEffects(kind)
            val wrong = if (kind == "RSS") QualificationOwnerControl.json.encodeToJsonElement(
                RssQualificationCaseCompletionReceipt("case-00000000-0000-0000-0000-000000000001",
                    "f".repeat(64), "a".repeat(64))) else QualificationOwnerControl.json.encodeToJsonElement(
                NativeCaseCompletionEnvelope("case-00000000-0000-0000-0000-000000000001",
                    "f".repeat(64), "a".repeat(64)))
            wrongClaim.files[wrongClaim.completionResult] = QualificationOwnerControl.json.encodeToString(
                wrongClaim.completionReply.copy(payload = wrong)).encodeToByteArray()
            assertFailsWith<IllegalArgumentException> { census(wrongClaim) }
        }
    }

    @Test fun `successful journey permits disposition only after native target isolation`(): Unit {
        val events = mutableListOf<String>()
        val attempt = RestoredLifecycleDriver().settle(
            run = { events += "case closure"; listOf(caseOne, caseTwo) },
            safety = { events += "protected teardown"; listOf(caseOne, caseTwo) },
            isolate = { events += "target isolated"; isolated })
        val closures = attempt.requireForSourceDisposition()
        assertEquals(2, closures.size)
        events += "authorized source disposition"
        assertEquals(listOf("case closure", "protected teardown", "target isolated",
            "authorized source disposition"), events)
    }
}
