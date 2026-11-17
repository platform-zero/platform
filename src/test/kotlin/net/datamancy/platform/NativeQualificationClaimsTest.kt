package net.datamancy.platform

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class NativeQualificationClaimsTest {
    private val sha = "a".repeat(64)

    @Test fun `begin refuses case-controlled paths before claim publication or native effects`(): Unit {
        val request = NativeCaseBeginRequest("/tmp/case-authored", ActivationInput("/tmp/phase.intent.json", sha),
            "/tmp/journal.jsonl", sha, sha, "q-000000000001-opensearch", sha)
        assertFailsWith<IllegalArgumentException> { NativeQualificationCasePublisher.begin(request) }
        assertFailsWith<IllegalArgumentException> {
            NativeQualificationCasePublisher.begin(request.copy(caseDirectory = "../relative-case"))
        }
    }

    @Test fun `claim response has its digest only outside the independently hashed claim record`(): Unit {
        val typed = NativeCaseClaimEnvelope("case-00000000-0000-0000-0000-000000000001",
            "q-000000000001", "opensearch", "trial-original",
            kotlinx.serialization.json.buildJsonObject { put("implementationSha256", sha) },
            sha, "q-000000000001-opensearch", sha, "INSTALL", sha, sha, sha)
        val envelope = Json.encodeToString(typed)
        assertTrue("claimSha256" in envelope)
        val request = NativeCaseBeginRequest("/private/original-case",
            ActivationInput("/private/phase.intent.json", sha), "/private/journal", sha,
            sha, "q-000000000001-opensearch", sha)
        assertFalse("claimSha256" in Json.encodeToString(request))
        assertFalse("futureResultSha256" in Json.encodeToString(request))
    }

    @Test fun `active RSS phase is trusted controller argument not a field in native claim request`(): Unit {
        val request = NativeCaseBeginRequest("/tmp/case-authored", ActivationInput("/tmp/phase.intent.json", sha),
            "/tmp/journal.jsonl", sha, sha, "q-000000000001-opensearch", sha)
        val wire = Json.encodeToString(request)
        assertFalse("activePhaseClaimSha256" in wire)
        assertFailsWith<IllegalArgumentException> { NativeQualificationCasePublisher.begin(request, sha) }
        assertFailsWith<IllegalArgumentException> { NativeQualificationCasePublisher.begin(request) }
    }
    @Test fun `native continuation matches only its actual phase receipt request`(): Unit {
        val dir = java.nio.file.Path.of("/private/trial/cases")
        val intent = ActivationInput("/private/trial/phase-trial-install.intent.json", sha)
        val phase = RssQualificationPhaseRequest(trialId = "trial", generationId = "q-000000000001",
            phase = "INSTALL", stagedOnly = false, bundleSha256 = sha, inventorySha256 = sha,
            manifestSha256 = sha, intentSha256 = sha, journalHead = sha, artifactRoot = dir.toString(),
            phaseIntentPath = intent.path, phaseResultPath = "/private/trial/phase-trial-install.result.json")
        assertTrue(RssQualificationIntents.matchesNativePhase(phase, "trial", "INSTALL", dir, intent))
        assertFalse(RssQualificationIntents.matchesNativePhase(phase, "other", "INSTALL", dir, intent))
        assertFalse(RssQualificationIntents.matchesNativePhase(phase, "trial", "RESTORE", dir, intent))
        assertFalse(RssQualificationIntents.matchesNativePhase(phase, "trial", "INSTALL",
            java.nio.file.Path.of("/private/another/cases"), intent))
        assertFalse(RssQualificationIntents.matchesNativePhase(phase, "trial", "INSTALL", dir,
            intent.copy(sha256 = "b".repeat(64))))
        assertFails {
            RssQualificationIntents.requireNativePhase(java.nio.file.Path.of("/missing/q-000000000001"),
                sha, "trial", "INSTALL", dir, intent)
        }
    }
    @Test fun `completion cannot accept caller success without protected original case`(): Unit {
        assertFailsWith<IllegalArgumentException> {
            NativeQualificationCasePublisher.complete(NativeCaseCompletionRequest("/tmp/case-authored", sha, sha))
        }
    }
}
