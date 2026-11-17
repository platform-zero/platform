package net.datamancy.platform

import java.nio.file.Path
import kotlin.test.*
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import org.junit.jupiter.api.Test

class GenerationFreshBaoStageSourceTest {
    @Test fun `complete selected r9 graph and frozen Quadlet require separate late keeper token`() {
        if (System.getenv("P0V3_VERIFY_R9_FULL_SOURCE") != "1") return
        val generation="q-5962a9fda75b"
        val inventory=Json.decodeFromString<AcquiredInventory>(ReleasePrivateFiles.read(
            Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$generation/inventory.json"),2097152)
            .decodeToString(throwOnInvalidSequence=true))
        val spec=CanonicalSharedYamlGraph.pendingR9Spec(inventory,"$generation-v2",
            controllerSha256="c".repeat(64),controllerUid=1000,controllerGid=1000)
        val keeper=spec.processes.single { it.id=="keeper" }
        val bao=spec.processes.single { it.id=="bao" }
        assertTrue("bao" in keeper.dependencies)
        val ordered=PrivateDeployment.validate(spec).map { it.id }
        assertTrue(ordered.indexOf("bao") in 0 until ordered.indexOf("keeper"))
        assertTrue("bao-web" in bao.networks)
        assertEquals("keeper-bao-late.env",keeper.lateEnvironmentFile)
        val unit=RuntimeQuadlets.render(spec).files.getValue("${RuntimeQuadlets.unit(spec,keeper)}.container")
        assertTrue(unit.contains("EnvironmentFile=${PrivateDeployment.BASE.resolve(spec.name)}/keeper.env\n"))
        assertTrue(unit.contains("EnvironmentFile=${PrivateDeployment.BASE.resolve(spec.name)}/keeper-bao-late.env\n"))
        val projected=CanonicalR9LateKeeperInputs.project(generation,"a".repeat(64),
            setOf("5656263b-b9ef-4ab7-95bc-037384f02f9e"),mapOf("ca.pem" to "CA", "web.pem" to "LEAF",
                "web-key.pem" to "KEY"),"IDENTITY","BAO")
        assertTrue(projected.getValue("keeper.env").contains("KEYKEEPER_BAO_URL=https://bao:8200"))
        assertFalse(projected.getValue("keeper.env").contains("KEYKEEPER_BAO_TOKEN"))
        assertEquals(setOf("keeper.env","identity-ca.pem","bao-ca.pem","keeper-ca.pem",
            "keeper-web.pem","keeper-web-key.pem"),projected.keys)
        assertEquals("BAO",projected.getValue("bao-ca.pem"))
    }
}
