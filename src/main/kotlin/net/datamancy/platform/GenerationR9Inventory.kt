package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Preserve exact already-acquired image evidence as one generation-local,
 * whole-family source inventory. This does not import images, establish store
 * presence or claim any native readiness. No development credentials/state are
 * imported: only immutable image IDs, digests and reference names are copied.
 */
internal object GenerationR9Inventory {
    private val json = Json { ignoreUnknownKeys = false }
    private val source = Path.of("/mnt/media/p0-v3/image-acquisition-receipts")
    private val anchor = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly")
    private val directoryMode = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))

    fun assemble(): AcquiredInventory {
        val development = source.resolve(
            "canonical-private-assembled-stack-images/combined-private-development-keycloak-optimized-inventory.json")
        val baseline = json.decodeFromString<AcquiredInventory>(Files.readString(development))
        require(baseline.images.size == 56 && baseline.images.map { it.product }.distinct().size == 56 &&
            baseline.status == "private-development-derived-offline-keycloak-optimized-not-reviewed-release")
        val archiveRoot = source.resolve("full-private-adapted-oci-archives-r1")
        val adapted = listOf("huly-caddy-adapted", "huly-elasticsearch-adapted", "huly-kvs-adapted",
            "keykeeper-adapted", "mail-bootstrap-adapted", "mailserver-adapted").map { product ->
            val path = archiveRoot.resolve("$product.export.result.json")
            require(Files.isRegularFile(path, NOFOLLOW_LINKS))
            val receipt = json.parseToJsonElement(Files.readString(path)).jsonObject
            val manifest = receipt.getValue("ociManifestDigest").jsonPrimitive.content
            require(manifest.matches(Regex("sha256:[a-f0-9]{64}")))
            AcquiredImage(product, "authenticated-local-build-archive", "localhost/p0v3-$product:sealed",
                "localhost/p0v3-$product@$manifest", receipt.getValue("imageId").jsonPrimitive.content,
                listOf("localhost/p0v3-$product@$manifest"), manifest, "amd64", "linux")
        }
        val independent = listOf(
            "keycloak-auth-gateway" to source.resolve(
                "full-private-auth-gateway-independent-archive-r1/archive-export.result.json"),
            "portal" to source.resolve("full-private-portal-image-r2/portal.pull.result.json")
        ).map { (product, path) ->
            require(Files.isRegularFile(path, NOFOLLOW_LINKS))
            val receipt = json.parseToJsonElement(Files.readString(path)).jsonObject
            val manifest = receipt.getValue(if (product == "portal") "manifestDigest" else "ociManifestDigest")
                .jsonPrimitive.content
            require(manifest.matches(Regex("sha256:[a-f0-9]{64}")))
            val pinned = if (product == "portal") receipt.getValue("image").jsonPrimitive.content
                else "localhost/p0v3-$product@$manifest"
            AcquiredImage(product, "pinned-support-observation", pinned, pinned,
                receipt.getValue("imageId").jsonPrimitive.content, listOf(pinned), manifest, "amd64", "linux")
        }
        val images = baseline.images + adapted + independent +
            listOf(FreshFinanceImporterArtifact.acquired(), FreshFinanceImporterArtifact.acquiredSso())
        require(images.size == 66 && images.map { it.product }.distinct().size == images.size &&
            images.all { it.imageId.matches(Regex("[a-f0-9]{64}")) &&
                it.selectedManifestDigest.matches(Regex("sha256:[a-f0-9]{64}")) })
        return AcquiredInventory(1, "r9-complete-private-source-inventory-native-image-store-unverified", images)
    }
    /** One-use, 0600 inventory for the SAME fresh generation request. */
    fun issue(generation: String): ActivationInput {
        require(generation.matches(Regex("q-[a-f0-9]{12}")))
        GenerationPreparationTerminalDisposition.requireClosedForNewSource(generation)
        GenerationAfterNativeImportLineage.beforeSourceIssue(generation)
        GenerationAfterCapacityRefusalLineage.beforeSourceIssue(generation)
        GenerationAfterQ273Lineage.beforeSourceIssue(generation)
        GenerationAfterQ583Lineage.beforeSourceIssue(generation)
        GenerationAfterQ9bLineage.beforeSourceIssue(generation)
        GenerationAfterQ07Lineage.beforeSourceIssue(generation)
        val bytes = json.encodeToString(assemble()).toByteArray()
        return ReleasePrivateFiles.locked(anchor.parent) {
            if (!Files.exists(anchor, NOFOLLOW_LINKS)) {
                Files.createDirectory(anchor, directoryMode); ReleasePrivateFiles.sync(anchor.parent)
            }
            ReleasePrivateFiles.directory(anchor)
            val root = anchor.resolve(generation)
            require(!Files.exists(root, NOFOLLOW_LINKS)) { "Original generation inventory exists; no replacement" }
            Files.createDirectory(root, directoryMode); ReleasePrivateFiles.sync(anchor)
            val file = root.resolve("inventory.json")
            ReleasePrivateFiles.save(file, bytes)
            ActivationInput(file.toString(), ReleaseLocks.sha256(bytes))
        }
    }
}
