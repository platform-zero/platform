package net.datamancy.platform

import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Instant
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

class RssReconciliationTest {
    private val feed = RssPacks.load().first()
    private val article = FeedItem("new-unit-item", "Synthetic article", "https://example.org/unit-article")
    private val attempted = 1_000_000L
    private fun fixture(block: (RssStateStore, PendingRssPost) -> Unit) {
        val root = Files.createTempDirectory("rss-reconcile-unit-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            val store = RssStateStore(root); store.initializeFresh()
            store.checkpointWithReview(feed, emptyList(), PollGate.ACTIVE, attempted - 1000, true)
            val pending = store.checkpointWithReview(feed, listOf(article), PollGate.ACTIVE, attempted, true).single()
            block(store, pending)
        } finally { Files.list(root).use { it.forEach(Files::delete) }; Files.delete(root) }
    }
    private fun sender(pending: PendingRssPost, failure: String = "", calls: MutableList<String> = mutableListOf()) = MastodonRssSender(
        URI("https://social.datamancy.net"), { "unit-token-that-is-not-a-real-secret" }, RssHttp { method, uri, _, body ->
            assertEquals("GET", method); assertTrue(body.isEmpty()); calls += uri.path
            val text = when {
                uri.path.endsWith("verify_credentials") -> buildJsonObject {
                    put("id", "17"); put("acct", if (failure == "account") "wrong" else feed.feed.account); put("bot", true)
                }
                uri.path.endsWith("/source") -> buildJsonObject {
                    put("id", "123"); put("text", if (failure == "text") "different" else pending.draft.text); put("spoiler_text", "")
                }
                else -> buildJsonObject {
                    put("id", if (failure == "id") "456" else "123")
                    put("account", buildJsonObject { put("id", if (failure == "owner") "18" else "17") })
                    put("visibility", if (failure == "private") "private" else "public")
                    put("created_at", Instant.ofEpochMilli(if (failure == "time") attempted - 120001 else attempted).toString())
                }
            }
            val status = when {
                failure == "absent" && uri.path.endsWith("/123") -> 404
                failure == "scope" && uri.path.endsWith("/source") -> 403
                failure == "server" && uri.path.endsWith("/123") -> 503
                else -> 200
            }
            RssHttpReply(status, text.toString().toByteArray())
        })
    @Test fun `matching author owned source confirms once with durable reconciliation evidence and no POST`() = fixture { store, pending ->
        assertFalse("reconciled" in Json.encodeToString(RssStoreDocument())) // legacy wire/checksum unchanged
        assertTrue(store.claim(pending, attempted))
        val before = store.read(); val calls = mutableListOf<String>()
        val proof = assertNotNull(sender(pending, calls = calls).reconcile(store, before.checksum, feed.feed.id, article.id, "123", attempted + 1000, PollGate.ACTIVE))
        assertEquals(listOf("/api/v1/accounts/verify_credentials", "/api/v1/statuses/123", "/api/v1/statuses/123/source"), calls)
        assertEquals(pending.draft.idempotencyKey, proof.idempotencyKey); assertEquals("123", proof.remoteStatusId)
        val after = store.read(); assertTrue(after.pending.isEmpty()); assertEquals(listOf(proof), after.reconciled)
        assertTrue(article.id in after.publisher.checkpoints.single().seen)
        assertFails { sender(pending).reconcile(store, after.checksum, feed.feed.id, article.id, "123", attempted + 1000, PollGate.ACTIVE) }
    }
    @Test fun `absence wrong account source time or identity leaves uncertain sends and checkpoints unchanged`() {
        for (failure in listOf("absent", "account", "text", "owner", "private", "time", "id", "scope", "server")) fixture { store, pending ->
            assertTrue(store.claim(pending, attempted)); val before = store.read()
            if (failure == "absent") assertNull(sender(pending, failure).reconcile(store, before.checksum, feed.feed.id, article.id, "123", attempted + 1000, PollGate.ACTIVE))
            else assertFails { sender(pending, failure).reconcile(store, before.checksum, feed.feed.id, article.id, "123", attempted + 1000, PollGate.ACTIVE) }
            assertEquals(before, store.read())
            assertTrue(store.checkpointWithReview(feed, listOf(article), PollGate.ACTIVE, attempted + 2000, true).isEmpty())
        }
    }
    @Test fun `interrupted send preserves interruption and durable uncertainty without acknowledgement`() = fixture { store, _ ->
        val worker = RssWorker(store, { if (it == feed) listOf(article) else emptyList() }, { throw InterruptedException("synthetic send interruption") }, { attempted + 1 })
        try {
            assertFailsWith<InterruptedException> { worker.pollReviewed(PollGate.ACTIVE, true) }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
        assertEquals(attempted + 1, store.read().pending.single().attemptedAtMillis)
        assertFalse(article.id in store.read().publisher.checkpoints.single().seen)
    }

    @Test fun `staging never silently acknowledges pending or uncertain delivery`() = fixture { store, pending ->
        val unclaimed = store.read()
        assertTrue(store.checkpointWithReview(feed, listOf(article), PollGate.STAGING, attempted, true).isEmpty())
        assertEquals(unclaimed, store.read())
        assertTrue(store.claim(pending, attempted))
        val uncertain = store.read()
        for (gate in PollGate.entries) {
            assertTrue(store.checkpointWithReview(feed, listOf(article), gate, attempted + 1, true).isEmpty())
            assertEquals(uncertain, store.read())
        }
    }

    @Test fun `unclaimed posts stale state and restore gates cannot be reconciled or retried`() = fixture { store, pending ->
        val remote = sender(pending); val before = store.read()
        assertFails { remote.reconcile(store, before.checksum, feed.feed.id, article.id, "123", attempted, PollGate.ACTIVE) }
        assertTrue(store.claim(pending, attempted)); val claimed = store.read()
        assertFails { remote.reconcile(store, before.checksum, feed.feed.id, article.id, "123", attempted, PollGate.ACTIVE) }
        for (gate in listOf(PollGate.STAGING, PollGate.RESTORING)) assertFails {
            remote.reconcile(store, claimed.checksum, feed.feed.id, article.id, "123", attempted, gate)
        }
        assertFails { remote.reconcile(store, claimed.checksum, feed.feed.id, article.id, "../foreign", attempted, PollGate.ACTIVE) }
        assertFails { remote.reconcile(store, claimed.checksum, feed.feed.id, article.id, "123", attempted - 1, PollGate.ACTIVE) }
        assertFails { store.reconcileConfirmed(claimed.checksum, feed.feed.id, article.id) {
            RssReconciledDelivery("foreign", article.id, pending.draft.idempotencyKey, feed.feed.account, "123", attempted, "a".repeat(64))
        } }
        assertEquals(claimed, store.read())
    }
}
