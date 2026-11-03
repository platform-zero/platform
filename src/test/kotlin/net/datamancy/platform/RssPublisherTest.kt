package net.datamancy.platform

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class RssPublisherTest {
    private val items = listOf(FeedItem("old", "First", "https://example.org/old"))
    private val new = FeedItem("new", "Second", "https://example.org/new")
    @Test fun `nine pinned archives include 47 separate bot accounts and cannot publish pending review`() {
        val feeds = RssPacks.load()
        assertEquals(9, feeds.map { it.pack }.toSet().size)
        assertEquals(47, feeds.size)
        assertEquals(47, feeds.map { it.feed.account }.toSet().size)
        assertTrue(feeds.any { it.pack == "analysis" })
        assertTrue(feeds.any { it.pack == "china-state" })
        assertTrue(feeds.any { it.pack == "us-state" })
        assertTrue(feeds.any { it.pack == "aus-state" })
        assertTrue(!RssPacks.reviewedForPublication())
        val feed = feeds.first()
        val first = RssPublisher.poll(PublisherState(), feed, items, PollGate.ACTIVE)
        assertTrue(first.drafts.isEmpty())
        assertTrue(RssPublisher.poll(first.state, feed, items + new, PollGate.ACTIVE).drafts.isEmpty())
    }
    @Test fun `first fetch silent then one attributed proposal and restart dedup after acknowledgement`() {
        val feed = RssPacks.load().first()
        val state = RssPublisher.pollWithReview(PublisherState(), feed, items, PollGate.ACTIVE, true).state
        val proposals = RssPublisher.pollWithReview(state, feed, items + new, PollGate.ACTIVE, true)
        assertEquals(1, proposals.drafts.size)
        assertEquals(feed.feed.account, proposals.drafts.single().account)
        assertTrue(proposals.drafts.single().text.contains(feed.feed.source))
        assertTrue(proposals.drafts.single().text.contains(new.link))
        assertEquals(proposals.drafts.single().idempotencyKey,
            RssPublisher.pollWithReview(state, feed, items + new, PollGate.ACTIVE, true).drafts.single().idempotencyKey)
        assertFailsWith<IllegalArgumentException> { RssPublisher.acknowledge(proposals, setOf("unseen")) }
        val persisted = Json.decodeFromString<PublisherState>(Json.encodeToString(RssPublisher.acknowledge(proposals, setOf(new.id))))
        assertTrue(RssPublisher.pollWithReview(persisted, feed, items + new, PollGate.ACTIVE, true).drafts.isEmpty())
    }
    @Test fun `staging checkpoints new items without posting and restore does not change state`() {
        val feed = RssPacks.load().first()
        val state = RssPublisher.pollWithReview(PublisherState(), feed, items, PollGate.STAGING, true).state
        val staged = RssPublisher.pollWithReview(state, feed, items + new, PollGate.STAGING, true)
        assertTrue(staged.drafts.isEmpty())
        assertTrue(RssPublisher.pollWithReview(staged.state, feed, items + new, PollGate.ACTIVE, true).drafts.isEmpty())
        val restored = RssPublisher.pollWithReview(state, feed, items + new, PollGate.RESTORING, true)
        assertTrue(restored.drafts.isEmpty())
        assertEquals(state, restored.state)
    }
    @Test fun `malformed feed item refuses without advancing checkpoint`() {
        val feed = RssPacks.load().first()
        assertFailsWith<IllegalArgumentException> { RssPublisher.poll(PublisherState(), feed,
            listOf(FeedItem("bad", "hi", "http://example.org")), PollGate.STAGING) }
        assertFailsWith<IllegalArgumentException> { RssPublisher.poll(PublisherState(), feed,
            items + items, PollGate.ACTIVE) }
    }
}
