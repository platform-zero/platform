package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** NEW original source projection. Never mutate or alias the issued r9 records.
 * Source closure and enrollment grant pins do not assert any native ACK. */
internal object GenerationR10GraphSourceBindings {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    fun issue(generation: String, actorPin: ActivationInput): Map<String, ActivationInput> {
        require(generation in setOf("q-5712d9335843", "q-dd36ebcf43ef", "q-4d3c1cb287e5",
                GenerationAfterNativeImportLineage.generation,
                GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation) &&
            !Files.exists(GenerationRuntime.BASE.resolve(generation), NOFOLLOW_LINKS))
        GenerationAfterNativeImportLineage.beforeSourceIssue(generation)
        GenerationAfterCapacityRefusalLineage.beforeSourceIssue(generation)
        GenerationAfterQ273Lineage.beforeSourceIssue(generation)
        GenerationAfterQ583Lineage.beforeSourceIssue(generation)
        GenerationAfterQ9bLineage.beforeSourceIssue(generation)
        GenerationAfterQ07Lineage.beforeSourceIssue(generation)
        GenerationFreshPlankaGrant.original(generation, actorPin)
        val dir = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$generation")
        ReleasePrivateFiles.directory(dir)
        val bytes = ReleasePrivateFiles.read(dir.resolve("inventory.json"), 2097152)
        val inventory = json.decodeFromString<AcquiredInventory>(bytes.decodeToString(throwOnInvalidSequence = true))
        require(inventory.images.size == 66 && inventory.status ==
            "r9-complete-private-source-inventory-native-image-store-unverified")
        val selected = PackagedGraphFragment.pendingV3R10()
        val spec = CanonicalSharedYamlGraph.pendingR10Spec(inventory, "$generation-v2")
        require(spec.processes.size == 134 && spec.processes.single { it.id == "planka-enroll" }.oneShot &&
            "planka-enroll" !in CanonicalSharedYamlGraph.pendingR10Spec(inventory, "$generation-v2",
                FragmentPhase.RESTORE).processes.map { it.id })
        val routes = CanonicalGraphCaddyfile.siteRoutes(selected.first, spec)
        require(routes.size >= 30 && routes.map { it.host }.distinct().size == routes.size &&
            routes.any { it.host == "social.datamancy.net" && it.product == "mastodon" } &&
            routes.any { it.host == "donetick.datamancy.net" && it.product == "donetick" })
        val manifest = requireNotNull(javaClass.getResourceAsStream("/rss-packs/v1/manifest.json")).use { it.readBytes() }
        val packs = json.decodeFromString<FeedPackManifest>(manifest.decodeToString(throwOnInvalidSequence = true))
        val feeds = RssPacks.load()
        require(feeds.size == 47 && packs.packs.size == 9)
        val closure = buildJsonObject {
            put("schemaVersion", 2); put("generation", generation)
            put("scope", "unqualified-r10-artifact-closure-original-planka-grant-no-native-ack")
            put("selectedIndexSha256", selected.second.getValue("canonical/r10/index.yaml"))
            put("selectedManifestSha256", selected.second.getValue("canonical/r10/manifest.yaml"))
            put("plankaR2FragmentSha256", selected.second.getValue("planka/r2/fragment.yaml"))
            put("plankaActorGrantSha256", actorPin.sha256)
            put("inventorySha256", ReleaseLocks.sha256(bytes))
            put("feedManifestSha256", ReleaseLocks.sha256(manifest))
            put("feedReviewStatus", packs.reviewStatus)
            put("feedCount", feeds.size)
            put("imagePins", buildJsonObject { inventory.images.sortedBy { it.product }.forEach {
                put(it.product, it.imageId) } })
            put("feedPackPins", buildJsonObject { packs.packs.sortedBy { it.name }.forEach {
                put(it.name, it.sha256) } })
        }
        val files = linkedMapOf("graph-portal-routes.r10-v2.json" to json.encodeToString(routes).encodeToByteArray(),
            "rss-source-artifact-closure.r10-v2.json" to json.encodeToString(closure).encodeToByteArray())
        require(files.keys.all { !Files.exists(dir.resolve(it), NOFOLLOW_LINKS) }) {
            "r10 graph/RSS source projection already attempted; do not replace it"
        }
        return files.mapValues { (name, value) ->
            val file = dir.resolve(name)
            ReleasePrivateFiles.save(file, value)
            ActivationInput(file.toString(), ReleaseLocks.sha256(value))
        }
    }
}
