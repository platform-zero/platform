package net.datamancy.platform

import org.junit.jupiter.api.Test
import kotlin.test.*

class GenerationR9InventoryTest {
    @Test fun `complete r9 image inventory is distinct and maps to one pinned physical v2 member`() {
        val inventory = GenerationR9Inventory.assemble()
        assertEquals(66, inventory.images.size)
        assertEquals(66, inventory.images.map { it.product }.distinct().size)
        assertEquals("q-000000000099-v2", GenerationAssembly.memberName(
            "q-000000000099", CanonicalSharedYamlGraph.R9_ASSEMBLY_RECIPE))
        assertEquals("q-000000000099-canonical-shared-core-v3", GenerationAssembly.memberName(
            "q-000000000099", CanonicalSharedYamlGraph.RECIPE))
        val recipe = GenerationAssembly.catalog.single { it.id == CanonicalSharedYamlGraph.R9_ASSEMBLY_RECIPE }
        assertTrue(GenerationAssembly.requiredCapabilities.containsAll(recipe.capabilities),
            "Unrepresented selected source capabilities: ${recipe.capabilities - GenerationAssembly.requiredCapabilities}")
        val spec = recipe.spec(inventory, "q-000000000099-v2")
        assertEquals(133, spec.processes.size)
        assertEquals(79, spec.processes.count { !it.oneShot })
        assertTrue("fragments/v3/canonical/r9/index.yaml" in requireNotNull(spec.fragmentBinding).resources)
        assertTrue(NotebookSelectedGraph.selected(GenerationRuntime.BASE.resolve("q-000000000099"), spec))
        assertEquals(spec.processes.size, GenerationWorkingEnvelopeIssuer.forecastRows(spec).size)
        assertEquals(spec.processes.size, CanonicalSharedYamlGraph.processOwnersFor(spec).size)
        assertEquals(PrivateDeployment.inputNames(spec).size, CanonicalSharedYamlGraph.inputOwnersFor(spec).size)
    }
}
