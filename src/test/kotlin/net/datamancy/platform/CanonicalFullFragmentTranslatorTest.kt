package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.Json
import kotlin.test.*

class CanonicalFullFragmentTranslatorTest {
    private fun inventory(): AcquiredInventory {
        val broad = Json.decodeFromString<AcquiredInventory>(
            GenerationAssembly.readInventory(Path.of("release/downloaded-candidate-inventory.json")).decodeToString())
        val development = Json.decodeFromString<AcquiredInventory>(
            GenerationAssembly.readInventory(Path.of("release/forgejo-pg-v2-development-inventory.json")).decodeToString())
        return broad.copy(images = broad.images + development.images.single { it.product == "postgres-timescale" })
    }

    @Test fun `adapter translation retains exact private process and never resumes saved ingress`() {
        val images = inventory()
        val member = "q-123456abcdef-v3"
        val caddy = CaddyRuntime.spec(images, member).copy(store = RuntimeStore.CANONICAL_V2,
            processes = CaddyRuntime.spec(images, member).processes.map {
                it.copy(command = listOf("run", "--config", "/run/secrets/caddy.json"),
                    apparmorProfile = "p0v3-private-v1")
            })
        val frontend = CanonicalProviderFragment("caddy", caddy)
        val inputs = mapOf("caddy.env" to "caddy", "caddy.json" to "caddy")
        val translated = CanonicalFullFragmentTranslator.translate(frontend, frontend, images,
            mapOf("caddy" to "caddy"), inputs, "private-caddy")
        assertEquals(setOf("caddy"), translated.processes.map { it.id }.toSet())
        assertFalse(translated.processes.single().command.contains("--resume"))
        assertEquals(listOf("caddy"), translated.restore.processes)
        assertFailsWith<IllegalArgumentException> {
            CanonicalFullFragmentTranslator.translate(frontend, frontend.copy(spec = caddy.copy(processes =
                caddy.processes.map { it.copy(networks = it.networks + "unexpected-egress") })), images,
                mapOf("caddy" to "caddy"), inputs, "private-caddy")
        }
    }

    @Test fun `no input custody or cold projection can be synthesized for Donetick`() {
        val images = inventory()
        val fresh = DonetickRuntime.canonicalFragment(images, "q-123456abcdef-v3")
        val cold = DonetickRuntime.canonicalColdFragment(fresh)
        val inputs = mapOf("donetick-runtime.env" to "donetick", "selfhosted.yaml" to "donetick")
        val translated = CanonicalFullFragmentTranslator.translate(fresh, cold, images,
            mapOf("donetick" to "donetick"), inputs, "private-donetick")
        assertEquals(setOf("donetick"), translated.processes.map { it.id }.toSet())
        assertFailsWith<IllegalArgumentException> {
            CanonicalFullFragmentTranslator.translate(fresh, cold, images,
                mapOf("donetick" to "donetick"), inputs - "selfhosted.yaml", "private-donetick")
        }
    }
}
