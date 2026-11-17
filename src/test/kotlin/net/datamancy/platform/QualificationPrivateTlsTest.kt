package net.datamancy.platform

import kotlin.test.*

class QualificationPrivateTlsTest {
    @Test fun `selected r10 closure is exact and cannot borrow an r9 issuer`() {
        val selected = PackagedGraphFragment.pendingV3R10()
        val resources = selected.second.mapKeys { (path, _) ->
            if (path.startsWith("v2/")) "fragments/$path" else "fragments/v3/$path"
        }
        val binding = RuntimeFragmentBinding(CanonicalSharedYamlGraph.RECIPE,"INSTALL",resources)
        assertEquals(selected.first,QualificationPrivateTls.selectedManifest(binding))
        assertEquals(selected.first,QualificationPrivateTls.selectedManifest(binding.copy(phase="RESTORE")))
        assertFails { QualificationPrivateTls.selectedManifest(binding.copy(resources=resources +
            ("fragments/v3/canonical/r10/index.yaml" to "0".repeat(64)))) }
        assertFails { QualificationPrivateTls.selectedManifest(binding.copy(resources=resources +
            ("fragments/v3/canonical/r9/index.yaml" to "0".repeat(64)))) }
    }
    @Test fun `only exact sealed full r9 resource graph selects qualification issuers`() {
        val packaged = PackagedGraphFragment.pendingV3R9()
        val resources = packaged.second.mapKeys { (path, _) ->
            if (path.startsWith("v2/")) "fragments/$path" else "fragments/v3/$path"
        }
        val binding = RuntimeFragmentBinding(CanonicalSharedYamlGraph.RECIPE, FragmentPhase.INSTALL.name, resources)
        val selected = QualificationPrivateTls.selectedManifest(binding)
        assertEquals(9, selected.revision)
        assertEquals("full-private", selected.scope)
        assertEquals(packaged.first, selected)
        assertEquals(selected, QualificationPrivateTls.selectedManifest(binding.copy(phase = FragmentPhase.RESTORE.name)))
        for (name in listOf("fragments/v3/canonical/r9/index.yaml",
            "fragments/v3/canonical/r9/manifest.yaml",
            "fragments/v3/canonical/r9/generated-caddy.json",
            resources.keys.first { it.startsWith("fragments/v2/") },
            resources.keys.first { it.startsWith("fragments/v3/") && "/canonical/" !in it })) {
            assertTrue(name in resources)
            assertFails { QualificationPrivateTls.selectedManifest(binding.copy(
                resources = resources + (name to "0".repeat(64)))) }
            assertFails { QualificationPrivateTls.selectedManifest(binding.copy(
                resources = resources - name)) }
        }
        assertFails { QualificationPrivateTls.selectedManifest(binding.copy(recipe = "historical-v2")) }
        assertFails { QualificationPrivateTls.selectedManifest(binding.copy(phase = "unspecified")) }
        assertFails { QualificationPrivateTls.selectedManifest(binding.copy(
            resources = resources + ("fragments/v3/fixture-root.pem" to "f".repeat(64)))) }
    }
}
