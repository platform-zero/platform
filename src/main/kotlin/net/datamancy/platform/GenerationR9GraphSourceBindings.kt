package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Independent source projections. These records are *not* RSS enrollment,
 * a content-review approval, image-store readback or a signed release lock. */
internal object GenerationR9GraphSourceBindings {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    fun issue(generation: String): Map<String,ActivationInput> {
        require(generation.matches(Regex("q-[a-f0-9]{12}")))
        val dir = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$generation")
        ReleasePrivateFiles.directory(dir)
        val inventoryPath = dir.resolve("inventory.json")
        val inventory = json.decodeFromString<AcquiredInventory>(ReleasePrivateFiles.read(inventoryPath,2097152)
            .decodeToString(throwOnInvalidSequence=true))
        require(inventory.images.size == 66 && inventory.status ==
            "r9-complete-private-source-inventory-native-image-store-unverified")
        val selected = PackagedGraphFragment.pendingV3R9()
        val spec = CanonicalSharedYamlGraph.pendingR9Spec(inventory,"$generation-v2")
        val routes = CanonicalGraphCaddyfile.siteRoutes(selected.first,spec)
        require(routes.size >= 30 && routes.map { it.host }.distinct().size == routes.size &&
            routes.any { it.host == "social.datamancy.net" && it.product == "mastodon" } &&
            routes.any { it.host == "donetick.datamancy.net" && it.product == "donetick" } &&
            routes.any { it.host == "forgejo.datamancy.net" && it.product == "forgejo" })
        val feeds = RssPacks.load()
        require(feeds.size == 47 && feeds.map { it.feed.account }.distinct().size == 47)
        val manifestBytes = requireNotNull(javaClass.getResourceAsStream("/rss-packs/v1/manifest.json"))
            .use { it.readBytes() }
        val packs = json.decodeFromString<FeedPackManifest>(manifestBytes.decodeToString(throwOnInvalidSequence=true))
        require(packs.packs.size == 9)
        val closure = buildJsonObject {
            put("schemaVersion",1); put("generation",generation)
            put("scope","unqualified-selected-artifact-and-pinned-feed-source-closure-no-native-enrollment")
            put("selectedIndexSha256",selected.second.getValue("canonical/r9/index.yaml"))
            put("selectedManifestSha256",selected.second.getValue("canonical/r9/manifest.yaml"))
            put("inventorySha256",ReleaseLocks.sha256(ReleasePrivateFiles.read(inventoryPath,2097152)))
            put("feedManifestSha256",ReleaseLocks.sha256(manifestBytes))
            put("feedReviewStatus",packs.reviewStatus)
            put("feedCount",feeds.size)
            put("imagePins",buildJsonObject {
                inventory.images.sortedBy { it.product }.forEach { put(it.product,it.imageId) }
            })
            put("feedPackPins",buildJsonObject {
                packs.packs.sortedBy { it.name }.forEach { put(it.name,it.sha256) }
            })
        }
        val files = linkedMapOf("graph-portal-routes.json" to json.encodeToString(routes).toByteArray(),
            "rss-source-artifact-closure.json" to json.encodeToString(closure).toByteArray())
        require(files.keys.all { !Files.exists(dir.resolve(it),NOFOLLOW_LINKS) }) {
            "Graph/RSS source projection already exists; do not replace a previous issued record"
        }
        return files.mapValues { (name,bytes) ->
            val path=dir.resolve(name)
            ReleasePrivateFiles.save(path,bytes)
            ActivationInput(path.toString(),ReleaseLocks.sha256(bytes))
        }
    }
}
