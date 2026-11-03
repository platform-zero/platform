package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class RssPackFixture(val schemaVersion: Int = 1, val pack: String,
    val items: Map<String, List<FeedItem>>)
@Serializable internal data class RssPackFeedObservation(val feed: FeedDefinition, val items: List<FeedItem>, val previews: List<DraftPost>)
@Serializable internal data class RssPackObservation(val schemaVersion: Int = 1, val pack: String,
    val fixtureSha256: String, val checkpointSha256: String, val feeds: List<RssPackFeedObservation>, val pending: Int)

/** Native read-only pack qualification, using separate original fixtures, never the installed publication state.
 * Preview uses the actual attributed draft engine but has no sender, token or publication effect attached.
 */
internal class RssPackObserver(private val fetch: (ReviewedFeed) -> List<FeedItem>) {
    fun observe(pack: String, stateRoot: Path, fixturePath: Path, restoring: Boolean): RssPackObservation {
        val feeds = RssPacks.load().filter { it.pack == pack }
        require(feeds.isNotEmpty()) { "Unknown pinned RSS pack" }
        val store = RssStateStore(stateRoot)
        val before = store.read()
        val fixture: RssPackFixture
        val bytes: ByteArray
        if (restoring) {
            bytes = ReleasePrivateFiles.read(fixturePath, 1048576)
            fixture = Json.decodeFromString<RssPackFixture>(bytes.decodeToString())
        } else {
            require(before.publisher.checkpoints.isEmpty() && before.pending.isEmpty() && before.reconciled.isEmpty()) {
                "Native first-poll observation requires fresh dedicated fixture state; never reset installed state"
            }
            // Fetch the entire pack before writing anything. An unresolved publisher cannot advance its checkpoint.
            fixture = RssPackFixture(pack = pack, items = feeds.associate { it.feed.id to fetch(it) })
            require(fixture.items.values.all { it.isNotEmpty() }) { "Empty feed cannot prove native attribution" }
            bytes = Json.encodeToString(fixture).toByteArray()
            require(bytes.size <= 1048576) { "Original RSS fixture exceeds authenticated recovery payload bound" }
            ReleasePrivateFiles.save(fixturePath, bytes) // Preserve original native items for restore; never refetch then relabel.
            feeds.forEach { feed -> store.checkpoint(feed, fixture.items.getValue(feed.feed.id), PollGate.STAGING, 0) }
        }
        require(fixture.schemaVersion == 1 && fixture.pack == pack && fixture.items.keys == feeds.map { it.feed.id }.toSet())
        val after = store.read()
        require(after.pending.isEmpty() && after.reconciled.isEmpty() &&
            after.publisher.checkpoints.associate { it.feedId to it.seen } == fixture.items.mapValues { it.value.map { item -> item.id }.toSet() }) {
            "First-poll checkpoint differs from original feed fixture"
        }
        if (restoring) require(before == after) { "Restore observation changed original checkpoint" }
        val observations = feeds.map { feed ->
            val items = fixture.items.getValue(feed.feed.id)
            require(items.isNotEmpty())
            val preview = RssPublisher.pollWithReview(PublisherState(checkpoints = listOf(FeedCheckpoint(feed.feed.id, emptySet()))),
                feed, items, PollGate.ACTIVE, true).drafts
            RssPackFeedObservation(feed.feed, items, preview)
        }
        return RssPackObservation(pack = pack, fixtureSha256 = ReleaseLocks.sha256(bytes),
            checkpointSha256 = ReleaseLocks.sha256(ReleasePrivateFiles.read(stateRoot.resolve("rss-state.json"))),
            feeds = observations, pending = after.pending.size)
    }
}
