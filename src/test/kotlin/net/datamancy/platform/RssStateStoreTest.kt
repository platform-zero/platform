package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RssStateStoreTest {
    private fun temporary(block: (Path) -> Unit) {
        val dir = Files.createTempDirectory("v3-rss-state-")
        Files.setPosixFilePermissions(dir, setOf(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE))
        try { block(dir) } finally {
            Files.list(dir).use { it.forEach(Files::delete) }
            Files.delete(dir)
        }
    }
    @Test fun `direct managed checkpoint and confirm writer cannot bypass enrolled scheduler or global exclusion`(): Unit {
        val root = Files.createTempDirectory("rss-managed-state-")
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        fun dir(parent: Path, name: String): Path = Files.createDirectory(parent.resolve(name),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            val generations = dir(root, "generations")
            val generation = dir(generations, "q-123456789abc")
            val rss = dir(generation, "rss")
            val state = dir(rss, "state")
            val scope = GenerationRssOperations(generations)
            val store = RssStateStore(state, generations, scope)
            store.initializeFresh()
            val feed = RssPacks.load().first()
            store.checkpointWithReview(feed, listOf(old), PollGate.STAGING, 1000, true)
            val original = Files.readAllBytes(state.resolve("rss-state.json"))
            var fetchAttempted = false
            store.withWriteAdmission { fetchAttempted = true; assertEquals(store.read(), store.read()) }
            assertTrue(fetchAttempted)
            dir(rss, "schedule") // Incomplete enrollment is not a license to write or reset.
            fetchAttempted = false
            assertFailsWith<Exception> { store.withWriteAdmission { fetchAttempted = true } }
            assertFalse(fetchAttempted) // Outer admission fails BEFORE even a read-only network fetch.
            assertFailsWith<Exception> { store.checkpointWithReview(feed, listOf(old, next), PollGate.STAGING, 2000, true) }
            assertFailsWith<Exception> { store.claim(PendingRssPost(DraftPost(feed.pack, feed.feed.id,
                feed.feed.account, "new", "a".repeat(64), "Synthetic"), 1000), 2000) }
            assertFailsWith<Exception> { store.initializeFresh() }
            assertTrue(original.contentEquals(Files.readAllBytes(state.resolve("rss-state.json"))))
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private val old = FeedItem("old", "Old article", "https://example.org/old")
    private val next = FeedItem("new", "New article", "https://example.org/new")
    @Test fun `first fetch stays silent and durable state survives restart and acknowledges only once`() = temporary { dir ->
        val feed = RssPacks.load().first()
        val store = RssStateStore(dir)
        store.initializeFresh()
        assertTrue(store.checkpointWithReview(feed, listOf(old), PollGate.ACTIVE, 1000, true).isEmpty())
        val pending = store.checkpointWithReview(feed, listOf(old, next), PollGate.ACTIVE, 2000, true)
        assertEquals(1, pending.size)
        assertEquals(feed.feed.account, pending.single().draft.account)
        val reopened = RssStateStore(dir)
        assertFailsWith<IllegalArgumentException> { reopened.initializeFresh() }
        assertEquals(pending, reopened.checkpointWithReview(feed, listOf(old, next), PollGate.ACTIVE, 3000, true))
        assertFailsWith<IllegalArgumentException> { reopened.confirm(feed.feed.id, next.id, pending.single().draft.idempotencyKey, "123456") }
        assertTrue(reopened.claim(pending.single(), 3000))
        reopened.confirm(feed.feed.id, next.id, pending.single().draft.idempotencyKey, "123456")
        assertTrue(RssStateStore(dir).checkpointWithReview(feed, listOf(old, next), PollGate.ACTIVE, 4000, true).isEmpty())
        assertTrue(Files.isRegularFile(dir.resolve("rss-state.previous")))
        assertFailsWith<IllegalArgumentException> {
            reopened.confirm(feed.feed.id, next.id, pending.single().draft.idempotencyKey, "123456")
        }
    }
    @Test fun `restore and staging do not generate public drafts and old uncertain posts stop retrying`() = temporary { dir ->
        val feed = RssPacks.load().first()
        val store = RssStateStore(dir)
        store.initializeFresh()
        store.checkpointWithReview(feed, listOf(old), PollGate.STAGING, 1000, true)
        val before = store.read()
        assertTrue(store.checkpointWithReview(feed, listOf(old, next), PollGate.RESTORING, 2000, true).isEmpty())
        assertEquals(before, store.read())
        assertTrue(store.checkpointWithReview(feed, listOf(old, next), PollGate.STAGING, 2000, true).isEmpty())
        assertTrue(store.checkpointWithReview(feed, listOf(old, next), PollGate.ACTIVE, 3000, true).isEmpty())
        val later = FeedItem("third", "Third", "https://example.org/third")
        val pending = store.checkpointWithReview(feed, listOf(old, next, later), PollGate.ACTIVE, 4000, true)
        assertEquals(1, pending.size)
        assertTrue(store.claim(pending.single(), 4000))
        assertTrue(store.checkpointWithReview(feed, listOf(old, next, later), PollGate.ACTIVE, 3_604_000, true).isEmpty())
        assertEquals(1, store.read().pending.size) // no blind retry after Mastodon's 1h idempotency window
        store.confirm(feed.feed.id, later.id, pending.single().draft.idempotencyKey, "42")
    }
    @Test fun `content remains disabled for public API pending review`() = temporary { dir ->
        val feed = RssPacks.load().first()
        val store = RssStateStore(dir)
        store.initializeFresh()
        assertTrue(store.checkpoint(feed, listOf(old), PollGate.ACTIVE, 1000).isEmpty())
        assertTrue(store.checkpoint(feed, listOf(old, next), PollGate.ACTIVE, 2000).isEmpty())
        assertTrue(store.read().pending.isEmpty())
    }
    @Test fun `unknown entries cannot be mistaken for a fresh v3 RSS state root`() = temporary { dir ->
        val unrelated = dir.resolve("unrelated.txt")
        Files.writeString(unrelated, "do not touch")
        assertFailsWith<IllegalArgumentException> { RssStateStore(dir).initializeFresh() }
        assertEquals("do not touch", Files.readString(unrelated))
    }
    @Test fun `corruption symlinks and exposed parent fail without resetting state`() = temporary { dir ->
        val store = RssStateStore(dir)
        store.initializeFresh()
        val state = dir.resolve("rss-state.json")
        val bytes = Files.readAllBytes(state)
        Files.write(state, bytes.dropLast(2).toByteArray())
        assertFailsWith<Exception> { store.read() }
        Files.write(state, bytes)
        val link = dir.resolve("linked")
        Files.createSymbolicLink(link, dir)
        assertFailsWith<IllegalArgumentException> { RssStateStore(link).read() }
        Files.setPosixFilePermissions(dir, setOf(PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE, PosixFilePermission.OTHERS_READ))
        assertFailsWith<IllegalArgumentException> { store.read() }
    }
}
