package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.json.*

/** Acquired immutable OLD-pinned image identity, NOT permission to select an
 * importer without its native subject, cookie, SSO and storage policy sources.
 * The original pull ACK must exist; a read-only image observation cannot replace it.
 */
internal object FreshFinanceImporterArtifact {
    const val IMAGE = "docker.io/fireflyiii/data-importer@sha256:2627644321afdcb52b49b258126bfe98312c2f93a709cc3a07c90327854e6aa2"
    const val OLD_SOURCE_SHA256 = "0a5ee8c35ddd4662d13e9ca46c8499a4c0e7bfd520b164745f5083683e20f0b6"
    const val SSO_IMAGE = "quay.io/oauth2-proxy/oauth2-proxy@sha256:8caf464e485b9cad9ff02aaed4a48e6aef358cc968065e1b1716e920c1ac5f5c"
    private val root = Path.of("/mnt/media/p0-v3/image-acquisition-receipts")
    fun acquired(): AcquiredImage = read("fresh-r9-firefly-importer-image-r1", IMAGE, "firefly-importer")
    fun acquiredSso(): AcquiredImage = read("fresh-r9-firefly-sso-image-r1", SSO_IMAGE, "firefly-sso")
    private fun read(directory: String, image: String, product: String): AcquiredImage {
        val receiptRoot = root.resolve(directory)
        val intent = receiptRoot.resolve("firefly-iii.pull.intent.json")
        val result = receiptRoot.resolve("firefly-iii.pull.result.json")
        require(listOf(root, receiptRoot, intent, result).none(Files::isSymbolicLink) &&
            Files.isRegularFile(intent, NOFOLLOW_LINKS) && Files.isRegularFile(result, NOFOLLOW_LINKS))
        val claim = Json.parseToJsonElement(Files.readString(intent)).jsonObject
        val receipt = Json.parseToJsonElement(Files.readString(result)).jsonObject
        require(claim.getValue("sourceSha256").jsonPrimitive.content == OLD_SOURCE_SHA256 &&
            claim.getValue("image").jsonPrimitive.content == image &&
            claim.getValue("effect").jsonPrimitive.content == "pinned-artifact-pull-only" &&
            receipt.getValue("originalPullAcknowledged").jsonPrimitive.boolean &&
            !receipt.getValue("applicationStarted").jsonPrimitive.boolean &&
            receipt.getValue("intentSha256").jsonPrimitive.content ==
                ReleaseLocks.sha256(Files.readAllBytes(intent)) &&
            receipt.getValue("image").jsonPrimitive.content == image &&
            receipt.getValue("manifestDigest").jsonPrimitive.content == image.substringAfter('@')) {
            "No original immutable importer acquisition ACK"
        }
        val id = receipt.getValue("imageId").jsonPrimitive.content
        require(id.matches(Regex("(?:sha256:)?[a-f0-9]{64}")))
        return AcquiredImage(product, "old-pinned-independent-original-pull-ack", image,
            image, id, listOf(image), image.substringAfter('@'), "amd64", "linux")
    }
}
