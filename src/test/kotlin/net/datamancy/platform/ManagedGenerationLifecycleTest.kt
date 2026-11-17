package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertEquals
import java.util.UUID

/** Pure receipt regressions; these fixtures do not stand in for native startup evidence. */
class ManagedGenerationLifecycleTest {
    private val generation = "q-012345abcdef"
    private val hash = "a".repeat(64)
    private val lane = UUID.randomUUID().toString()
    private val specs = ManagedLaneKind.entries.map { kind ->
        ManagedLaneSpec(kind, lane, "8d345319-3dbc-436e-a609-1584dd08ec35", "managed-test",
            "home", "home/workspace", if (kind == ManagedLaneKind.WORKLANE) 512 else 0,
            if (kind == ManagedLaneKind.WORKLANE) 1024 else 0)
    }
    private val plan = ManagedLanePlan(generation, specs, ManagedLaneHostBinding(
        ActivationInput("/usr/local/bin/worklane", hash), ActivationInput("/usr/bin/podman", hash),
        ActivationInput("/sandbox/$generation/managed/inputs/target-lane.toml", hash),
        ActivationInput("/sandbox/$generation/managed/control/storage.conf", hash),
        ManagedBrokerServiceBinding(hash, hash,
            ActivationInput("/sandbox/$generation/managed/inputs/broker.json", hash))))
    private fun evidence(kind: ManagedLaneKind, operation: ManagedLaneOperation,
        isolated: Boolean) = ManagedLaneEvidence(generation, lane, operation,
        if (operation == ManagedLaneOperation.START) "managed-start" else "cap-abcdef012345",
        hash, hash, hash, isolated, 100)
    private val imported = ManagedImportResult(hash,
        ManagedLaneKind.entries.associateWith { evidence(it, ManagedLaneOperation.IMPORT, true) },
        ManagedLaneKind.entries.associateWith { evidence(it, ManagedLaneOperation.PREPARE, true) })
    private val intent = ManagedGenerationStartIntent(generation, hash, hash, "recovered-private", hash, hash, hash)
    private val result = ManagedGenerationStartResult(hash, generation, "recovered-private", hash, hash,
        hash, 123L, "inode-123", ManagedLaneKind.entries.associateWith {
            evidence(it, ManagedLaneOperation.START, false)
        }, promotable = false)
    @Test fun privateNativeReceiptsCannotConferPromotionOrAdoptSourceLane(): Unit {
        ManagedGenerationLifecycle.validateReceipt(intent, result, imported, plan)
        assertFalse(result.promotable)
        assertEquals(ManagedLaneKind.entries.toSet(), result.lanes.keys)
        for (bad in listOf(result.copy(promotable = true), result.copy(brokerMainPid = 0),
            result.copy(identityHeadSha256 = "b".repeat(64)),
            result.copy(lanes = result.lanes - ManagedLaneKind.PI),
            result.copy(lanes = result.lanes + (ManagedLaneKind.PI to
                evidence(ManagedLaneKind.PI, ManagedLaneOperation.START, true))))) {
            assertFailsWith<IllegalArgumentException> {
                ManagedGenerationLifecycle.validateReceipt(intent, bad, imported, plan)
            }
        }
    }
    @Test fun originalPreparationHasDistinctTypedPrivateModeNotRecoveryPromotion(): Unit {
        val initial = ManagedInitialPreparation(generation, hash, hash, imported.preparations)
        val originalIntent = intent.copy(mode = "original-private", importResultSha256 = null)
        val originalResult = result.copy(mode = "original-private")
        ManagedGenerationLifecycle.validateReceipt(originalIntent, originalResult, null, plan, initial)
        assertFailsWith<IllegalArgumentException> {
            ManagedGenerationLifecycle.validateReceipt(originalIntent, originalResult.copy(promotable = true),
                null, plan, initial)
        }
        assertFailsWith<IllegalArgumentException> {
            ManagedGenerationLifecycle.validateReceipt(originalIntent, originalResult, imported, plan, initial)
        }
    }
    @Test fun isolationAndResumeHaveDistinctNativeProofTypesNotSitePromotion(): Unit {
        val isolated = ManagedGenerationIsolationResult(generation, hash, "held-first", hash, hash,
            brokerSocketAbsent = true, ManagedLaneKind.entries.associateWith {
                evidence(it, ManagedLaneOperation.ISOLATE, true)
            })
        val resumed = ManagedGenerationResumeResult(generation, hash, isolated.operationId,
            "resume-first", hash, 123, "inode-123", ManagedLaneKind.entries.associateWith {
                evidence(it, ManagedLaneOperation.START, false)
            })
        assertTrue(isolated.brokerSocketAbsent)
        assertEquals(isolated.operationId, resumed.isolatedOperationId)
        assertFalse(resumed.lanes.values.any { it.isolated })
        assertFalse(result.promotable)
    }

    @Test fun frozenImportAndPreparationMustRemainIsolated(): Unit {
        assertFailsWith<IllegalArgumentException> {
            ManagedGenerationLifecycle.validateReceipt(intent, result,
                imported.copy(preparations = imported.preparations + (ManagedLaneKind.WORKLANE to
                    evidence(ManagedLaneKind.WORKLANE, ManagedLaneOperation.PREPARE, false))), plan)
        }
        assertFailsWith<IllegalArgumentException> {
            ManagedGenerationLifecycle.validateReceipt(intent.copy(mode = "site-active"), result, imported, plan)
        }
    }
}
