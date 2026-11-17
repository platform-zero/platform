package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class HomeAssistantRecoveryTest {
    private val inventory = Json.decodeFromString<AcquiredInventory>(Files.readString(Path.of("release/downloaded-candidate-inventory.json")))
    @Test fun `whole-release projection keeps original volume and image but refuses initialization and schema bootstrap`(): Unit {
        val name = "q-111111111111-homeassistant"
        val spec = HomeAssistantRuntime.spec(inventory, name)
        val inputs = PrivateDeployment.inputNames(spec).associateWith { "a".repeat(64) }
        val member = GenerationMember(name)
        val source = GenerationBundle(GenerationRequest(id = "q-111111111111", candidateSha256 = "b".repeat(64),
            members = listOf(member), diskReservationMiB = 1024), listOf(GenerationPin(member,
            ReleaseLocks.sha256(Json.encodeToString(spec).toByteArray()), inputs,
            PrivateDeployment.expectedFingerprint(spec, inputs), spec)), spec.processes.sumOf { it.memoryMiB.toLong() })
        val result = FoundationRestore.bundle(source, inventory, "q-222222222222", "c".repeat(64), ColdRestoreCohort.WHOLE_RELEASE,
            RuntimeStore.CANONICAL_V2)
        val target = result.members.single()
        assertEquals(spec.volumes, target.spec.volumes)
        assertEquals(spec.networks, target.spec.networks)
        val daemon = target.spec.processes.single()
        assertFalse(daemon.oneShot); assertTrue(daemon.dependencies.isEmpty())
        assertEquals(spec.processes.last().image, daemon.image)
        assertTrue(target.inputHashes.isEmpty()); assertNull(daemon.environmentFile)
        assertEquals(listOf("-c"), daemon.command.take(1))
        assertTrue(daemon.command.last().contains("MAX(schema_version)"))
        assertTrue(daemon.command.last().contains("os.execve"))
        assertNull(result.ownership); assertNull(target.spec.ingress)
        assertFails { HomeAssistantRuntime.coldRestoreSpec(spec.copy(processes = spec.processes.filterNot { it.oneShot })) }
        assertFails { HomeAssistantRuntime.coldRestoreSpec(spec.copy(processes = spec.processes.map {
            it.copy(image = "example.org/unreviewed@sha256:" + "d".repeat(64))
        })) }
        assertFails { HomeAssistantRuntime.coldRestoreSpec(spec.copy(processes = spec.processes.map {
            if (it.oneShot) it else it.copy(command = listOf("-m", "foreign"))
        })) }
    }
    @Test fun `canonical Home Assistant cold projects exact original owner guard without rerunning config bootstrap`(): Unit {
        val graph = HomeAssistantRuntime.canonicalFragment(inventory, "q-111111111111-homeassistant")
        val inputs = HomeAssistantRuntime.canonicalInputs()
        assertEquals(PrivateDeployment.inputNames(graph.spec).toSet(), inputs.keys)
        assertContains(inputs.getValue("homeassistant-configuration.yaml"), "persistent_notification:")
        assertFalse(HomeAssistantRuntime.inputs().getValue("configuration.yaml").contains("persistent_notification:"))
        assertEquals(setOf("home-data", "home-web"), graph.spec.networks.toSet())
        val cold = HomeAssistantRuntime.coldRestoreFragment(graph)
        assertEquals(graph.spec.volumes, cold.spec.volumes)
        assertEquals(listOf("homeassistant"), cold.spec.processes.map { it.id })
        assertContains(cold.spec.processes.single().command.last(), "onboarding")
        assertContains(cold.spec.processes.single().command.last(), "schema_changes")
        assertFalse("homeassistant-config-init" in cold.spec.processes.map { it.id })
        assertNull(cold.spec.processes.single().environmentFile)
        assertFails { HomeAssistantRuntime.coldRestoreFragment(graph.copy(spec = graph.spec.copy(processes = graph.spec.processes.drop(1)))) }
    }
}
