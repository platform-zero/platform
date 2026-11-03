package net.datamancy.platform

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable data class FeedDefinition(val id: String, val account: String, val display_name: String,
    val source: String, val url: String)
@Serializable data class FeedPack(val feeds: List<FeedDefinition>)
@Serializable data class FeedPackHash(val name: String, val sha256: String)
@Serializable data class FeedPackManifest(val schemaVersion: Int, val reviewStatus: String, val packs: List<FeedPackHash>)

data class ReviewedFeed(val pack: String, val feed: FeedDefinition)

/** Content is pinned but remains disabled until independently reviewed and explicitly enabled. */
object RssPacks {
    private val json = Json { ignoreUnknownKeys = false }
    private val expected = setOf("analysis", "aus-state", "aus", "china-state", "china", "tas", "us-state", "us", "world")
    fun load(): List<ReviewedFeed> {
        val manifest = json.decodeFromString<FeedPackManifest>(resource("manifest.json"))
        require(manifest.schemaVersion == 1 && manifest.packs.map { it.name }.toSet() == expected &&
            manifest.packs.size == expected.size) { "All nine pinned feed packs required" }
        val feeds = manifest.packs.flatMap { pack ->
            val bytes = resourceBytes("${pack.name}.json")
            require(ReleaseLocks.sha256(bytes) == pack.sha256) { "Feed pack changed: ${pack.name}" }
            json.decodeFromString<FeedPack>(bytes.toString(Charsets.UTF_8)).feeds.map { ReviewedFeed(pack.name, it) }
        }
        val slug = Regex("[a-z0-9][a-z0-9-]{0,63}")
        val account = Regex("rss_[a-z0-9_]{1,60}")
        require(feeds.isNotEmpty() && feeds.map { it.feed.id }.distinct().size == feeds.size &&
            feeds.map { it.feed.account }.distinct().size == feeds.size && feeds.all {
                val uri = java.net.URI(it.feed.url)
                slug.matches(it.feed.id) && account.matches(it.feed.account) && it.feed.source.isNotBlank() &&
                    it.feed.display_name.isNotBlank() && uri.scheme == "https" && uri.host != null &&
                    uri.userInfo == null && uri.fragment == null
            }) { "Unsafe or duplicate feed identity" }
        return feeds
    }
    fun reviewedForPublication(): Boolean = json.decodeFromString<FeedPackManifest>(resource("manifest.json"))
        .reviewStatus == "independently-reviewed"
    private fun resource(name: String): String = resourceBytes(name).toString(Charsets.UTF_8)
    private fun resourceBytes(name: String) = requireNotNull(RssPacks::class.java.getResourceAsStream("/rss-packs/v1/$name")) {
        "Missing RSS pack: $name"
    }.use { it.readBytes() }
}
