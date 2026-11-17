package net.datamancy.platform

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ForgejoCiOriginalJobSourceTest {
    @Test fun `protected native job schema carries trusted original and rootless terminal identity`() {
        val hash = "a".repeat(64)
        val intent = ForgejoCiJobIntent(generation = "q-111111111111", bundleSha256 = hash,
            nativeStartSha256 = hash, repository = "private/trusted-repo", trustedCommit = "b".repeat(40),
            workflowPath = ".forgejo/workflows/reviewed-fixture.yml", workflowSha256 = hash,
            runnerId = 19, jobImageId = "sha256:$hash")
        val result = ForgejoCiJobResult(intentSha256 = hash, generation = intent.generation,
            repository = intent.repository, trustedCommit = intent.trustedCommit,
            workflowPath = intent.workflowPath, workflowSha256 = intent.workflowSha256,
            runId = 101, jobId = 102, runnerId = intent.runnerId,
            jobImageId = intent.jobImageId, rootlessJobCid = hash,
            guardCreateSha256 = hash, guardStartSha256 = hash, guardWaitSha256 = hash,
            nativeRunSha256 = hash, nativeJobSha256 = hash)
        val keys = Json.encodeToString(result).let { Json.parseToJsonElement(it).jsonObject.keys }
        assertEquals(1, result.schemaVersion)
        assertTrue(result.terminalSuccess)
        assertTrue(setOf("runId", "jobId", "runnerId", "jobImageId", "rootlessJobCid",
            "guardCreateSha256", "guardStartSha256", "guardWaitSha256", "nativeRunSha256",
            "nativeJobSha256", "trustedCommit", "workflowSha256").all { it in keys })
    }
}
