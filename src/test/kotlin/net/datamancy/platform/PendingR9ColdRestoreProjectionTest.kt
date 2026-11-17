package net.datamancy.platform

import java.nio.file.Path
import kotlin.test.*
import org.junit.jupiter.api.Test
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

class PendingR9ColdRestoreProjectionTest {
    @Test fun `cold compile uses exact selected r9 source rather than active r7 and retains late keeper input`() {
        if (System.getenv("P0V3_VERIFY_R9_FULL_SOURCE")!="1") return
        val source="q-5962a9fda75b";val target="q-000000000077"
        val inventory=Json.decodeFromString<AcquiredInventory>(ReleasePrivateFiles.read(Path.of(
            "/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$source/inventory.json"),2097152)
            .decodeToString(throwOnInvalidSequence=true))
        val name="$source-v2"
        val spec=CanonicalSharedYamlGraph.pendingR9Spec(inventory,name,controllerSha256="c".repeat(64),
            controllerUid=1000,controllerGid=1000)
        val member=GenerationMember(name,emptyList())
        val hashes=PrivateDeployment.inputNames(spec).associateWith { "a".repeat(64) }
        val pin=GenerationPin(member,"b".repeat(64),hashes,
            PrivateDeployment.expectedFingerprint(spec,hashes),spec)
        val request=GenerationRequest(id=source,candidateSha256="b".repeat(64),
            members=listOf(member),diskReservationMiB=262144,store=RuntimeStore.CANONICAL_V2)
        val original=GenerationBundle(request,listOf(pin),98304)
        val restored=FoundationRestore.bundle(original,inventory,target,"e".repeat(64),
            cohort=ColdRestoreCohort.WHOLE_RELEASE,targetStore=RuntimeStore.CANONICAL_V2)
        val selected=restored.members.single().spec
        assertEquals(FragmentPhase.RESTORE.name,selected.fragmentBinding?.phase)
        assertTrue(selected.fragmentBinding?.resources?.containsKey("fragments/v3/canonical/r9/index.yaml")==true)
        assertEquals("keeper-bao-late.env",selected.processes.single { it.id=="keeper" }.lateEnvironmentFile)
        assertTrue(selected.processes.none { it.oneShot })
        assertEquals(target,restored.request.id)
    }
}
