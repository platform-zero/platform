package net.datamancy.platform

import kotlin.test.*

class CrowdsecNativeQualificationTest {
    private val pinned = "example.org/crowdsec@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf(AcquiredImage("crowdsec", "upstream",
        "example.org/crowdsec:1", pinned, "b".repeat(64), emptyList(), pinned.substringAfter('@'), "amd64", "linux")))
    private val generation = "q-111111111111"
    private val target = CrowdsecRuntime.canonicalFragment(inventory, "$generation-crowdsec").spec
    private val original = CrowdsecNativeIntent("cnq-111111111111", generation, target.name,
        "crowdsec-original-1", "INSTALL", CrowdsecNativeAction.APPEND_SYNTHETIC_LOG)

    @Test fun `only fixed original target may accept synthetic detector log`(): Unit {
        CrowdsecNativeQualification.requireIntent(original, target)
        val sample = CrowdsecNativeQualification.line("2026-11-09T03:00:00Z")
        assertEquals(3, sample.lineSequence().count { it.isNotBlank() })
        assertTrue(sample.lines().filter { it.isNotBlank() }.all { it.contains("198.51.100.18 401 GET") })
        assertFails { CrowdsecNativeQualification.line("2026-11-09T03:00:00Z;curl") }
        assertFails { CrowdsecNativeQualification.requireIntent(original, target.copy(
            processes = target.processes.filterNot { it.id == "guard" })) }
        assertFails { CrowdsecNativeQualification.requireIntent(original, target.copy(store = RuntimeStore.LEGACY)) }
        assertFails { CrowdsecNativeQualification.requireIntent(original.copy(memberName = "other-guard"), target) }
    }

    @Test fun `cold original history permits observation but never a second append or decision`(): Unit {
        val restored = original.copy(phase = "RESTORE", sourceOracleSha256 = "a".repeat(64),
            action = CrowdsecNativeAction.READ_ORIGINAL_HISTORY, originalAlertId = 42)
        CrowdsecNativeQualification.requireIntent(restored, target)
        CrowdsecNativeQualification.requireIntent(restored.copy(action = CrowdsecNativeAction.DENY_BOUNCER), target)
        for (action in listOf(CrowdsecNativeAction.APPEND_SYNTHETIC_LOG,
            CrowdsecNativeAction.ADD_EXPIRING_DECISION, CrowdsecNativeAction.ADD_REVOCABLE_DECISION,
            CrowdsecNativeAction.REVOKE_DECISION))
            assertFails { CrowdsecNativeQualification.requireIntent(restored.copy(action = action), target) }
        assertFails { CrowdsecNativeQualification.requireIntent(restored.copy(sourceOracleSha256 = "b"), target) }
        assertFails { CrowdsecNativeQualification.requireIntent(original.copy(
            action = CrowdsecNativeAction.REVOKE_DECISION), target) }
    }

    @Test fun `native detector result binds actual target CID PID netns and isolation`(): Unit {
        val result = CrowdsecNativeResult(original.operation, generation, original.invocationId,
            original.action, "c".repeat(64), 123, 456, "d".repeat(64), "e".repeat(64),
            12, null, null, false, "f".repeat(64))
        CrowdsecNativeQualification.requireResult(original, result, "c".repeat(64), 123, 456, "d".repeat(64))
        assertFails { CrowdsecNativeQualification.requireResult(original,
            result.copy(targetPid = 124), "c".repeat(64), 123, 456, "d".repeat(64)) }
        assertFails { CrowdsecNativeQualification.requireResult(original,
            result.copy(targetContainerId = "x".repeat(64)), "c".repeat(64), 123, 456, "d".repeat(64)) }
        assertFails { CrowdsecNativeQualification.requireResult(original,
            result.copy(targetIsolationProofSha256 = "x".repeat(64)), "c".repeat(64), 123, 456, "d".repeat(64)) }
    }
}
