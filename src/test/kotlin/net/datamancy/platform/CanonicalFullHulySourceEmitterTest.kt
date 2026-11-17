package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE_NEW
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals

/** Source materialization only. The current r7 index is never modified; full-batch
 * packaging must explicitly review this output together with every other family.
 */
class CanonicalFullHulySourceEmitterTest {
    @Test fun `materialize pinned existing Huly native provider and cold projection as restricted source YAML`() {
        val broad = Json.decodeFromString<AcquiredInventory>(
            GenerationAssembly.readInventory(Path.of("release/downloaded-candidate-inventory.json")).decodeToString())
        val development = Json.decodeFromString<AcquiredInventory>(
            GenerationAssembly.readInventory(Path.of("release/forgejo-pg-v2-development-inventory.json")).decodeToString())
        // Offline source conversion only: the separate historical local plugin build has
        // a retained pinned receipt, but is NOT in the current native store/inventory.
        fun localBuild(product: String, prefix: String, image: String, id: String): AcquiredImage {
            val receipt = Json.parseToJsonElement(Files.readString(Path.of(
                "/mnt/media/p0-v3/image-acquisition-receipts/$prefix/receipt.json")))
                as kotlinx.serialization.json.JsonObject
            val recordedDigest = (receipt["imageDigest"] ?: receipt.getValue("digest")).toString().trim('"')
            require(receipt.getValue("passed").toString() == "true" &&
                receipt.getValue("imageId").toString().trim('"') == id &&
                recordedDigest == image.substringAfter('@'))
            return AcquiredImage(product, "historical-local-build-receipt", image.substringBefore('@') + ":source-only",
                image, id, emptyList(), image.substringAfter('@'), "amd64", "linux")
        }
        val local = listOf(
            localBuild("huly-elasticsearch-adapted", "p0v3-huly-search-build-6d582630bc3e",
                HulyRuntime.SEARCH_IMAGE, HulyRuntime.SEARCH_ID),
            localBuild("huly-kvs-adapted", "p0v3-huly-kvs-build-1f55c14434e9",
                HulyRuntime.KVS_IMAGE, HulyRuntime.KVS_ID),
            localBuild("huly-caddy-adapted", "p0v3-huly-caddy-build-1a587d36647d",
                HulyRuntime.CADDY_IMAGE, HulyRuntime.CADDY_ID))
        val images = broad.copy(status = "source-only-not-acquired",
            images = broad.images + development.images.single { it.product == "postgres-timescale" } + local)
        val fresh = HulyRuntime.canonicalFragment(images, "q-123456abcdef-v3")
        val cold = HulyRuntime.coldRestoreFragment(fresh)
        val owners = fresh.spec.processes.associate { it.id to "huly" }
        val inputs = PrivateDeployment.inputNames(fresh.spec).associateWith { "huly" }
        val translated = CanonicalFullFragmentTranslator.translate(fresh, cold, images, owners, inputs, "private-huly")
        // OLD's private Huly gateway is upstream of the single shared ingress owner.
        // Its browser path must not be a disconnected per-family private island.
        val dto = translated.copy(
            exportedInputs = listOf("huly-ca.pem"),
            providers = listOf("caddy"), providerProcesses = mapOf("caddy" to listOf("caddy")),
            networks = translated.networks + "ingress-control",
            providerNetworks = mapOf("caddy" to listOf("ingress-control")),
            processes = translated.processes.map { if (it.id == "huly")
                it.copy(networks = it.networks + "ingress-control") else it },
            install = translated.install.copy(dependencies = translated.install.dependencies.mapValues { (id, deps) ->
                if (id == "huly") deps + "caddy" else deps
            }),
            restore = translated.restore.copy(dependencies = translated.restore.dependencies.mapValues { (id, deps) ->
                if (id == "huly") deps + "caddy" else deps
            }))
        dto.validate()
        assertEquals("huly", dto.product)
        val bytes = Json.encodeToString(GraphFragment.serializer(), dto).toByteArray()
        val parsed = GraphFragment.lint(bytes)
        assertEquals(dto, parsed)
        val target = Path.of("src/main/resources/fragments/v3/huly/r1/fragment.yaml")
        if (Files.exists(target)) {
            assertEquals(dto, GraphFragment.lint(Files.readAllBytes(target)))
        } else {
            Files.createDirectories(target.parent)
            Files.write(target, bytes, CREATE_NEW)
        }
    }
}
