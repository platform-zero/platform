package net.datamancy.platform

import java.nio.file.Path
import kotlin.test.*
import org.junit.jupiter.api.Test
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

class PendingR10ColdRestoreProjectionTest {
    @Test fun `cold recompile preserves exact selected r10 Planka serving graph without reenrollment`() {
        if (System.getenv("P0V3_VERIFY_R10_GRAPH_ONLY") != "1") return
        val source = "q-5712d9335843"; val target = "q-000000000078"
        val inventory = Json.decodeFromString<AcquiredInventory>(ReleasePrivateFiles.read(Path.of(
            "/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$source/inventory.json"),2097152)
            .decodeToString(throwOnInvalidSequence=true))
        val name = "$source-v2"
        val spec = CanonicalSharedYamlGraph.pendingR10Spec(inventory,name,
            controllerSha256="c".repeat(64),controllerUid=1000,controllerGid=1000)
        val member = GenerationMember(name,emptyList())
        val inputs = PrivateDeployment.inputNames(spec).associateWith { "a".repeat(64) }
        val pin = GenerationPin(member,"b".repeat(64),inputs,
            PrivateDeployment.expectedFingerprint(spec,inputs),spec)
        val original = GenerationBundle(GenerationRequest(id=source,candidateSha256="b".repeat(64),
            members=listOf(member),diskReservationMiB=262144,store=RuntimeStore.CANONICAL_V2),listOf(pin),98304)
        val restored = FoundationRestore.bundle(original,inventory,target,"e".repeat(64),
            cohort=ColdRestoreCohort.WHOLE_RELEASE,targetStore=RuntimeStore.CANONICAL_V2,
            targetControllerSha256="d".repeat(64))
        val selected = restored.members.single().spec
        assertEquals(FragmentPhase.RESTORE.name,selected.fragmentBinding?.phase)
        assertEquals("d".repeat(64),selected.fragmentBinding?.controllerSha256)
        assertTrue(selected.fragmentBinding?.resources?.containsKey("fragments/v3/canonical/r10/index.yaml") == true)
        assertFalse(selected.fragmentBinding?.resources?.containsKey("fragments/v3/canonical/r9/index.yaml") == true)
        assertTrue(selected.processes.none { it.oneShot })
        assertEquals(spec.processes.count { !it.oneShot },selected.processes.size)
        assertTrue(selected.processes.any { it.id == "planka" })
        assertFalse(selected.processes.any { it.id == "planka-enroll" })
        assertNull(restored.request.freshPlankaActorGrant)
        assertEquals(target,restored.request.id)
    }
}
