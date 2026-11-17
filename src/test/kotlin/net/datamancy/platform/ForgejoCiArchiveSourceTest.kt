package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.*
import kotlin.test.*

/** Pure local archive verification, explicitly opt-in because it hashes every
 * compressed layer. Does not touch Podman, user managers or Forgejo.
 */
class ForgejoCiArchiveSourceTest {
    @Test fun `sealed rootless CI trio is admitted by exact OCI archive verifier`() {
        if (System.getenv("P0V3_VERIFY_CI_ARCHIVES") != "1") return
        val root = Path.of("/mnt/media/p0-v3/image-acquisition-receipts/forgejo-ci-minimal-bound-r2")
        for (kind in listOf("job", "transport", "runner")) {
            val result = Json.parseToJsonElement(Files.readString(root.resolve("$kind.normalize.result.json"))).jsonObject
            val archive = root.resolve("$kind.oci.tar")
            val bytes = result.getValue("archiveBytes").jsonPrimitive.long
            val image = result.getValue("imageId").jsonPrimitive.content
            val manifest = result.getValue("ociManifestDigest").jsonPrimitive.content
            val source = result.getValue("sourceImageReference").jsonPrimitive.content
            val diff = result.getValue("diffIds").jsonArray.map { it.jsonPrimitive.content }
            val binding = ManagedLaneImageBinding(ActivationInput(archive.toString(),
                result.getValue("archiveSha256").jsonPrimitive.content), bytes,
                8L * 1024 * 1024 * 1024, "sha256:$image", source, manifest, diff)
            ManagedLaneOciArchive.inspect(archive, binding, System.currentTimeMillis() + 1200000L)
            assertEquals(ReleaseLocks.sha256(Files.readAllBytes(archive)), binding.archive.sha256)
        }
    }
}
