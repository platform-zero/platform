package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class ReleaseCaddyEndpointTest {
    private val site = CaddySiteBinding("unit", "owned", "http://127.0.0.1:2019", setOf("web.datamancy.net"))
    private fun ingress() = ReleaseIngress(site, "/mnt/media/p0-v3/caddy-transactions/unit", emptyList(),
        ActivationInput("/private/token", "a".repeat(64)), "b".repeat(64), null,
        "r-000000000001", "r-000000000002", "r-000000000003", "r-000000000004")

    @Test fun `runtime endpoint is mandatory without changing historical ingress bytes`() {
        val ingress = ingress()
        val encoded = Json { encodeDefaults = true }.encodeToString(ingress)
        assertFalse("runtime" in encoded)
        assertEquals(ingress, Json.decodeFromString<ReleaseIngress>(encoded))
        assertFailsWith<IllegalArgumentException> { ReleaseCaddyEndpoints.real(ingress) }
    }

    @Test fun `only exact published canonical runtime manifests may select admin transport`() {
        val root = Files.createTempDirectory("release-caddy-endpoint-unit-")
        try {
            val inventory = Json.decodeFromString<AcquiredInventory>(Files.readString(Path.of("release/downloaded-candidate-inventory.json")))
            val spec = CaddyRuntime.publish(CaddyRuntime.spec(inventory, "q-012345abcdef-caddy").copy(store = RuntimeStore.CANONICAL_V2),
                RuntimeIngressPublication(site.site, site.approvedHosts, "0.0.0.0"))
            val path = root.resolve("${spec.name}.json")
            fun bound(value: PrivateDeploymentSpec): ReleaseIngress {
                Files.deleteIfExists(path)
                val bytes = Json.encodeToString(value).toByteArray()
                ReleasePrivateFiles.save(path, bytes)
                return ingress().copy(runtime = ReleaseCaddyEndpoint(ActivationInput(path.toString(), ReleaseLocks.sha256(bytes)), "c".repeat(64)))
            }
            val request = bound(spec)
            assertEquals(spec, ReleaseCaddyEndpoints.spec(request, root))
            for (changed in listOf(
                request.copy(site = site.copy(site = "foreign")),
                request.copy(site = site.copy(approvedHosts = setOf("other.datamancy.net"))),
                request.copy(site = site.copy(endpoint = "http://127.0.0.1:2020")),
                request.copy(runtime = request.runtime!!.copy(runtimeFingerprint = "bad")),
                request.copy(runtime = request.runtime!!.copy(manifest = request.runtime.manifest.copy(sha256 = "d".repeat(64)))),
                request.copy(runtime = request.runtime!!.copy(manifest = request.runtime.manifest.copy(path = root.resolve("../foreign.json").toString()))))) {
                assertFailsWith<IllegalArgumentException> { ReleaseCaddyEndpoints.spec(changed, root) }
            }
            assertFailsWith<IllegalArgumentException> { ReleaseCaddyEndpoints.spec(request, root.resolve("other-registry")) }
            for (changed in listOf(spec.copy(ingress = null, networks = listOf("net"),
                processes = spec.processes.map { it.copy(networks = listOf("net")) }),
                spec.copy(name = "q-111111111111-caddy"))) {
                val altered = bound(changed)
                assertFailsWith<IllegalArgumentException> { ReleaseCaddyEndpoints.spec(altered, root) }
            }
            val exact = bound(spec)
            Files.delete(path)
            Files.createSymbolicLink(path, root.resolve("absent"))
            assertFails { ReleaseCaddyEndpoints.spec(exact, root) }
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
