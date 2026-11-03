package net.datamancy.platform

import kotlinx.serialization.Serializable

@Serializable data class FeedItem(val id: String, val title: String, val link: String)
@Serializable data class FeedCheckpoint(val feedId: String, val seen: Set<String>)
@Serializable data class PublisherState(val schemaVersion: Int = 1, val checkpoints: List<FeedCheckpoint> = emptyList())
enum class PollGate { STAGING, RESTORING, ACTIVE }
@Serializable data class DraftPost(val pack: String, val feedId: String, val account: String, val itemId: String,
    val idempotencyKey: String, val text: String)
data class PollResult(val state: PublisherState, val drafts: List<DraftPost>)

/** Pure draft engine; the separate worker must durably claim and remotely confirm delivery. */
object RssPublisher {
    fun poll(state: PublisherState, feed: ReviewedFeed, items: List<FeedItem>, gate: PollGate): PollResult {
        require(feed in RssPacks.load()) { "Unpinned feed" }
        return pollWithReview(state, feed, items, gate, RssPacks.reviewedForPublication())
    }

    internal fun pollWithReview(state: PublisherState, feed: ReviewedFeed, items: List<FeedItem>, gate: PollGate,
                                reviewed: Boolean): PollResult {
        require(state.schemaVersion == 1 && state.checkpoints.map { it.feedId }.distinct().size == state.checkpoints.size)
        require(items.size <= 200 && items.map { it.id }.distinct().size == items.size && items.all {
            it.id.isNotBlank() && it.id.length <= 512 && it.title.isNotBlank() && it.title.length <= 1000 &&
                it.link.length <= 2048 && runCatching {
                    java.net.URI(it.link).let { uri -> uri.scheme == "https" && uri.host != null && uri.userInfo == null }
                }.getOrDefault(false)
        }) { "Malformed feed items" }
        val existing = state.checkpoints.find { it.feedId == feed.feed.id }
        if (gate == PollGate.RESTORING) return PollResult(state, emptyList())
        val observed = items.map { it.id }.toSet()
        if (existing == null) {
            // First poll is a checkpoint, never a replay of historic articles.
            return PollResult(state.copy(checkpoints = state.checkpoints + FeedCheckpoint(feed.feed.id, observed)), emptyList())
        }
        if (gate == PollGate.STAGING) {
            return PollResult(state.copy(checkpoints = state.checkpoints.map {
                if (it.feedId == feed.feed.id) it.copy(seen = it.seen + observed) else it
            }), emptyList())
        }
        // No publication while content review is pending, even when a caller asks for ACTIVE.
        if (!reviewed) return PollResult(state, emptyList())
        val drafts = items.filter { it.id !in existing.seen }.map { item ->
            val key = ReleaseLocks.sha256("${feed.feed.account}\u0000${item.id}".toByteArray(Charsets.UTF_8))
            val suffix = " — ${feed.feed.source.trim()}\n${item.link}"
            val available = 500 - suffix.codePointCount(0, suffix.length)
            require(available >= 2) { "Attribution and link exceed the conservative status limit" }
            val title = item.title.trim()
            val bounded = if (title.codePointCount(0, title.length) <= available) title
                else title.substring(0, title.offsetByCodePoints(0, available - 1)).trimEnd() + "…"
            DraftPost(feed.pack, feed.feed.id, feed.feed.account, item.id, key, bounded + suffix)
        }
        return PollResult(state, drafts)
    }
    /** Call only after a remote post is confirmed under its stable idempotency key. */
    fun acknowledge(result: PollResult, confirmed: Set<String>): PublisherState {
        require(confirmed.size <= result.drafts.size && confirmed.all { id -> result.drafts.any { it.itemId == id } }) {
            "Cannot acknowledge an item that was not proposed"
        }
        val byFeed = result.drafts.filter { it.itemId in confirmed }.groupBy { it.feedId }
        return result.state.copy(checkpoints = result.state.checkpoints.map { checkpoint ->
            checkpoint.copy(seen = checkpoint.seen + byFeed[checkpoint.feedId].orEmpty().map { it.itemId })
        })
    }
}
