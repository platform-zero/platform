package net.datamancy.platform

import java.net.URI
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.Flow
import kotlin.test.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class RssTransportTest {
    private val source = URI("https://example.org/feed")
    private val feed = RssPacks.load().first()
    private fun rss(id: String = "one", link: String = "https://example.org/story") =
        "<rss><channel><item><guid>$id</guid><title>Headline</title><link>$link</link></item></channel></rss>".toByteArray()
    private fun draft(): DraftPost = RssPublisher.pollWithReview(
        PublisherState(checkpoints = listOf(FeedCheckpoint(feed.feed.id, emptySet()))), feed,
        listOf(FeedItem("article", "Headline", "https://example.org/article")), PollGate.ACTIVE, true).drafts.single()
    private fun store(): RssStateStore {
        val dir = Files.createTempDirectory("rss-worker-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        return RssStateStore(dir).also { it.initializeFresh() }
    }
    @Test fun `native fixture transport rejects production origin and arbitrary ports before reading private CA`(): Unit {
        val missing = java.nio.file.Path.of("/nonexistent/rss-fixture-ca.pem")
        for (origin in listOf("https://social.datamancy.net", "https://127.0.0.1:443",
            "http://127.0.0.1:19447", "https://user@127.0.0.1:19447", "https://127.0.0.1:19447/feed/")) {
            assertFailsWith<IllegalArgumentException> { PinnedRssFixtureHttp(URI(origin), missing, "a".repeat(64)) }
        }
    }
    @Test fun `canonical synthetic Mastodon transport refuses duplicate public origin or foreign status before CA`(): Unit {
        val missing = Path.of("/nonexistent/rss-canonical-ca.pem")
        for (foreign in listOf("https://127.0.0.1:49152", "https://social.datamancy.net:444",
            "https://social2.datamancy.net", "http://social.datamancy.net"))
            assertFailsWith<IllegalArgumentException> {
                PinnedRssMastodonHttp(URI(foreign), missing, "a".repeat(64))
            }
    }
    @Test fun `original synthetic Mastodon refuses public DNS and foreign private destination before CA`(): Unit {
        val missing = Path.of("/nonexistent/rss-canonical-ca.pem")
        val origin = URI("https://social.datamancy.net")
        assertFailsWith<IllegalArgumentException> { PinnedRssMastodonHttp(origin,missing,"a".repeat(64)) }
        for (address in listOf("8.8.8.8","127.0.0.1","169.254.1.1","192.168.1.999","social.datamancy.net")) {
            assertFailsWith<IllegalArgumentException> {
                PinnedRssMastodonHttp(origin,missing,"a".repeat(64),address,"b".repeat(64))
            }
        }
        assertFailsWith<IllegalArgumentException> {
            PinnedRssMastodonHttp(origin,missing,"a".repeat(64),"10.7.2.4","invalid")
        }
    }
    @Test fun `restored original RSS source remains a distinct generation member`(): Unit {
        val original="q-123456789abc"
        val restored="q-abcdef123456"
        assertEquals("$original-v2",rssOriginalMemberName(original,restored))
        assertNotEquals("$restored-v2",rssOriginalMemberName(original,restored))
        assertFailsWith<IllegalArgumentException> { rssOriginalMemberName(restored,restored) }
        assertFailsWith<IllegalArgumentException> { rssOriginalMemberName("q-1234",restored) }
    }
    @Test fun `restored native RSS cannot create an unowned host bridge client`(): Unit {
        val foreign = Path.of("/tmp/foreign-restored-rss")
        assertFailsWith<IllegalArgumentException> {
            RssRestoredMastodonHttp(foreign, foreign, "a".repeat(64), foreign, "b".repeat(64),
                foreign, "rssq_123456789abc")
        }
    }
    @Test fun `existing loopback server selects only current pack for all 47 synthetic feed ids`(): Unit {
        val reviewed=RssPacks.load()
        assertEquals(47,reviewed.size)
        assertEquals(9,reviewed.map { it.pack }.toSet().size)
        for(feed in reviewed) {
            assertEquals(feed,RssNativeFixtureServer.selectedPackFeed(feed.pack,feed.feed.id))
            for(otherPack in reviewed.map { it.pack }.toSet()-feed.pack)
                assertNull(RssNativeFixtureServer.selectedPackFeed(otherPack,feed.feed.id))
        }
        assertNull(RssNativeFixtureServer.selectedPackFeed("analysis","unknown"))
        assertFailsWith<IllegalArgumentException> {
            RssNativeFixtureServer.selectedPackFeed("analysis","../../public")
        }
    }
    @Test fun `native fixture server rejects absent live phase and case claim before binding a listener`(): Unit {
        val root = Files.createTempDirectory("rss-fixture-plan-unit-", PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------")))
        try {
            val configuration = root.resolve("fixture-server.json")
            ReleasePrivateFiles.save(configuration, Json.encodeToString(RssNativeFixtureServerPlan(
                generation = "q-123456789abc", fixtureId = "fixture", pack = "analysis", port = 55000,
                serverRoot = root.toString(), certificateAuthority = root.resolve("ca.pem").toString(),
                caSha256 = "a".repeat(64), keyStore = root.resolve("fixture-keystore.p12").toString(),
                keyStorePasswordFile = root.resolve("fixture-keystore.pass").toString(),
                keyStoreSha256 = "b".repeat(64), keyStorePasswordSha256 = "c".repeat(64))).toByteArray())
            assertFailsWith<IllegalArgumentException> { RssNativeFixtureServer.serve(configuration) }
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `read only bot verification works before publication review without enabling sends`() {
        var calls = 0
        val sender = MastodonRssSender(URI("https://social.example"), { "a".repeat(32) }, RssHttp { method, uri, headers, body ->
            calls++
            assertEquals("GET", method); assertEquals("/api/v1/accounts/verify_credentials", uri.path)
            assertEquals("", body); assertEquals("Bearer " + "a".repeat(32), headers["Authorization"])
            RssHttpReply(200, """{"id":"123","acct":"${feed.feed.account}","bot":true}""".toByteArray())
        })
        assertEquals("123", sender.verifyAccount(feed.feed.account)); assertEquals(1, calls)
        assertFails { sender.verifyAccount("not-a-selected-feed") }; assertEquals(1, calls)
        assertFailsWith<IllegalArgumentException> { sender.send(draft()) }; assertEquals(1, calls)
    }
    @Test fun `long titles are bounded without splitting surrogate pairs or truncating attribution`() {
        val item = FeedItem("long", "😀".repeat(400), "https://example.org/article")
        val result = RssPublisher.pollWithReview(PublisherState(checkpoints = listOf(FeedCheckpoint(feed.feed.id, emptySet()))),
            feed, listOf(item), PollGate.ACTIVE, true)
        val text = result.drafts.single().text
        assertTrue(text.codePointCount(0, text.length) <= 500)
        assertTrue(text.endsWith(" — ${feed.feed.source.trim()}\n${item.link}"))
        val longer = item.copy(title = "a".repeat(1000))
        assertTrue(RssPublisher.pollWithReview(result.state, feed, listOf(longer), PollGate.ACTIVE, true).drafts.single().text.contains("…"))
        assertFails { RssPublisher.pollWithReview(result.state, feed, listOf(item.copy(link = "https://example.org/" + "x".repeat(600))), PollGate.ACTIVE, true) }
    }
    @Test fun `RSS and Atom preserve attribution identity and resolve relative links`() {
        assertEquals(listOf(FeedItem("one", "Headline", "https://example.org/story")), RssXml.parse(rss(), source))
        val atom = """<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>urn:article:one</id>
            <title>&lt;b&gt;Atom&lt;/b&gt;</title><link rel="self" href="/api/one"/>
            <link rel="alternate" type="text/html" href="/one"/></entry></feed>"""
        assertEquals(FeedItem("urn:article:one", "Atom", "https://example.org/one"), RssXml.parse(atom.toByteArray(), source).single())
        assertEquals("https://example.org/story", RssXml.parse(rss(""), source).single().id)
    }
    @Test fun `RDF gzip and explicitly bounded feed redirects are supported`() {
        val rdf = """<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/">
            <item rdf:about="urn:article"><title>Research</title><link>https://example.org/article</link></item></rdf:RDF>"""
        assertEquals("urn:article", RssXml.parse(rdf.toByteArray(), source).single().id)
        fun gzip(bytes: ByteArray): ByteArray {
            val out = java.io.ByteArrayOutputStream()
            java.util.zip.GZIPOutputStream(out).use { it.write(bytes) }
            return out.toByteArray()
        }
        var calls = 0
        val npr = RssPacks.load().single { it.feed.id == "npr-world" }
        val fetcher = RssFetcher { _, uri, _, _ ->
            calls++
            if (calls == 1) RssHttpReply(301, byteArrayOf(), mapOf("location" to "https://feeds.npr.org/1004/rss.xml"))
            else {
                assertEquals("feeds.npr.org", uri.host)
                RssHttpReply(200, gzip(rss()), mapOf("content-encoding" to "gzip"))
            }
        }
        assertEquals(1, fetcher.fetch(npr).size)
        assertEquals(2, calls)
        val broken = """<rss><channel><item><title><![CDATA[A & B]]></title><link>https://example.org/?x=1&amp;y=2</link>
            <thumbnail url="https://example.org/image?a=1&b=2"/><!-- keep & literal --></item></channel></rss>"""
        val repaired = fetcher.repairPublisherAmpersands(broken.toByteArray())
        assertTrue(repaired.decodeToString().contains("a=1&amp;b=2"))
        assertTrue(repaired.decodeToString().contains("<!-- keep & literal -->"))
        assertEquals("A & B", RssXml.parse(repaired, source).single().title)
        assertFails { fetcher.decodeBody(RssHttpReply(200, gzip(ByteArray(2_097_153)), mapOf("content-encoding" to "gzip"))) }
        assertFails { fetcher.decodeBody(RssHttpReply(200, byteArrayOf(), mapOf("content-encoding" to "br"))) }
        for (location in listOf("https://evil.example/rss", "http://www.npr.org/rss", "https://user@www.npr.org/rss")) {
            assertFails { RssFetcher { _, _, _, _ -> RssHttpReply(301, byteArrayOf(), mapOf("location" to location)) }.fetch(npr) }
        }
        assertFails { RssFetcher { _, uri, _, _ -> RssHttpReply(301, byteArrayOf(), mapOf("location" to uri.toString())) }.fetch(npr) }
    }
    @Test fun `untrusted XML cannot read external files or expand entities`() {
        val malicious = """<!DOCTYPE rss [<!ENTITY leak SYSTEM "file:///etc/passwd">]><rss><channel><item><title>&leak;</title></item></channel></rss>"""
        listOf(malicious, "<rss>", "<html/>", "<rss><channel/><channel/></rss>",
            "<rss><channel><item><title>No link</title></item></channel></rss>",
            "<rss><channel><item><title></title><link>https://example.org</link></item></channel></rss>").forEach {
            assertFails { RssXml.parse(it.toByteArray(), source) }
        }
        assertFails { RssXml.parse(rss(link = "http://example.org"), source) }
        assertFails { RssXml.parse(rss(link = "https://user@example.org"), source) }
        assertFails { RssXml.parse(ByteArray(0), source) }
        assertFails { RssXml.parse(ByteArray(2_097_153), source) }
        val item = "<item><guid>duplicate</guid><title>A</title><link>https://example.org/a</link></item>"
        assertFails { RssXml.parse("<rss><channel>$item$item</channel></rss>".toByteArray(), source) }
        assertFails { RssXml.parse(("<rss><channel>" + item.repeat(201) + "</channel></rss>").toByteArray(), source) }
    }
    @Test fun `bounded HTTP subscriber handles chunks failures and cancellation`() {
        var canceled = false
        val subscription = object : Flow.Subscription {
            override fun request(n: Long) {}
            override fun cancel() { canceled = true }
        }
        val valid = BoundedRssBody(4)
        valid.onSubscribe(subscription)
        valid.onNext(listOf(ByteBuffer.wrap(byteArrayOf(1, 2)), ByteBuffer.wrap(byteArrayOf(3))))
        valid.onComplete()
        assertContentEquals(byteArrayOf(1, 2, 3), valid.body.toCompletableFuture().get())
        val large = BoundedRssBody(1)
        large.onSubscribe(subscription)
        large.onNext(listOf(ByteBuffer.wrap(byteArrayOf(1, 2))))
        assertTrue(canceled)
        assertFails { large.body.toCompletableFuture().get() }
        val failed = BoundedRssBody(1)
        failed.onSubscribe(subscription)
        failed.onError(IllegalStateException("network error"))
        assertFails { failed.body.toCompletableFuture().get() }
    }
    @Test fun `fetch uses pinned URL and rejects redirects instead of following untrusted locations`() {
        var calls = 0
        val fetcher = RssFetcher { method, uri, headers, body ->
            calls++
            assertEquals("GET", method)
            assertEquals(URI(feed.feed.url), uri)
            assertTrue(headers.getValue("Accept").contains("application/atom+xml"))
            assertEquals("", body)
            RssHttpReply(200, rss())
        }
        assertEquals(1, fetcher.fetch(feed).size)
        assertEquals(1, calls)
        assertFails { fetcher.fetch(feed.copy(feed = feed.feed.copy(url = "https://evil.example/feed"))) }
        assertFails { RssFetcher { _, _, _, _ -> RssHttpReply(302, byteArrayOf()) }.fetch(feed) }
    }
    @Test fun `Mastodon sender verifies per-feed bot identity before posting and keeps idempotency key`() {
        val draft = draft()
        val requests = mutableListOf<String>()
        val sender = MastodonRssSender(URI("https://social.example"), { account ->
            assertEquals(feed.feed.account, account); "t".repeat(32)
        }) { method, uri, headers, body ->
            requests += method
            assertEquals("Bearer " + "t".repeat(32), headers["Authorization"])
            if (method == "GET") {
                assertEquals("/api/v1/accounts/verify_credentials", uri.path)
                RssHttpReply(200, """{"id":"123","acct":"${draft.account}","bot":true}""".toByteArray())
            } else {
                assertEquals("/api/v1/statuses", uri.path)
                assertEquals(draft.idempotencyKey, headers["Idempotency-Key"])
                assertTrue(body.contains("visibility=public"))
                assertTrue(body.contains("status=Headline"))
                RssHttpReply(201, """{"id":"456","account":{"id":"123"}}""".toByteArray())
            }
        }
        assertFailsWith<IllegalArgumentException> { sender.send(draft) }
        assertTrue(requests.isEmpty())
        assertEquals("456", sender.sendReviewed(draft))
        assertEquals(listOf("GET", "POST"), requests)
        assertFails { sender.sendReviewed(draft.copy(account = "wrong")) }
        assertFails { sender.sendReviewed(draft.copy(text = "a".repeat(501))) }
    }
    @Test fun `revoked publication authority is rechecked after bot identity verification before POST`() {
        val calls = mutableListOf<String>()
        val sender = MastodonRssSender(URI("https://social.example"), { "t".repeat(32) }) { method, _, _, _ ->
            calls += method
            RssHttpReply(200, """{"id":"123","acct":"${feed.feed.account}","bot":true}""".toByteArray())
        }
        assertFails { sender.sendReviewed(draft()) { error("revoked release") } }
        assertEquals(listOf("GET"), calls)
    }

    @Test fun `wrong account HTTP errors and malformed acknowledgements never confirm delivery`() {
        val draft = draft()
        for (verify in listOf(RssHttpReply(401, byteArrayOf()), RssHttpReply(200,
            """{"id":"123","acct":"wrong","bot":true}""".toByteArray()))) {
            var calls = 0
            val sender = MastodonRssSender(URI("https://social.example"), { "t".repeat(32) }) { _, _, _, _ -> calls++; verify }
            assertFails { sender.sendReviewed(draft) }
            assertEquals(1, calls)
        }
        for (reply in listOf(RssHttpReply(503, byteArrayOf()), RssHttpReply(200,
            """{"id":"456","account":{"id":"wrong"}}""".toByteArray()))) {
            val sender = MastodonRssSender(URI("https://social.example"), { "t".repeat(32) }) { method, _, _, _ ->
                if (method == "GET") RssHttpReply(200, """{"id":"123","acct":"${draft.account}","bot":true}""".toByteArray()) else reply
            }
            assertFails { sender.sendReviewed(draft) }
        }
    }
    @Test fun `token file is private and origin cannot downgrade HTTPS`() {
        assertFails { MastodonRssSender(URI("http://social.example"), { "" }) { _, _, _, _ -> error("unused") } }
        assertFails { MastodonRssSender(source, { "" }) { _, _, _, _ -> error("unused") } }
        val token = Files.createTempFile("rss-token", ".txt", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        Files.writeString(token, "x".repeat(32))
        assertEquals("x".repeat(32), MastodonRssSender.privateToken(token))
        Files.setPosixFilePermissions(token, PosixFilePermissions.fromString("rw-r--r--"))
        assertFails { MastodonRssSender.privateToken(token) }
        Files.setPosixFilePermissions(token, PosixFilePermissions.fromString("rw-------"))
        Files.writeString(token, "invalid token with spaces" )
        assertFails { MastodonRssSender.privateToken(token) }
        Files.delete(token)
    }
    @Test fun `worker baselines all nine packs silently and restores make no network calls`() {
        val store = store()
        var fetched = 0
        val worker = RssWorker(store, { fetched++; listOf(FeedItem("old", "Old", "https://example.org/old")) },
            { error("No posting allowed") }, { 1000 })
        assertEquals(RssPollSummary(0, 0, 0), worker.poll(PollGate.RESTORING))
        assertEquals(0, fetched)
        assertFails { worker.poll(PollGate.ACTIVE) }
        val first = worker.poll(PollGate.STAGING)
        assertEquals(RssPacks.load().size, first.feeds)
        assertEquals(first.feeds, first.observed)
        assertEquals(0, first.confirmed)
        assertEquals(first.feeds, store.read().publisher.checkpoints.size)
        assertTrue(store.read().pending.isEmpty())
    }
    @Test fun `feed failures remain visible without preventing other first-poll baselines`() {
        val store = store()
        val worker = RssWorker(store, { source ->
            if (source == feed) throw IllegalArgumentException("bad XML")
            emptyList()
        }, { error("publishing disabled") })
        val result = worker.poll(PollGate.STAGING)
        assertEquals(listOf(feed.feed.id), result.failedFeeds)
        assertEquals(RssPacks.load().size - 1, store.read().publisher.checkpoints.size)
        assertFailsWith<InterruptedException> {
            RssWorker(store, { throw InterruptedException() }, { "" }).poll(PollGate.STAGING)
        }
        assertTrue(Thread.interrupted())
    }
    @Test fun `RSS CLI initialization is non-destructive and restore and active guards do no HTTP`() {
        val parent = Files.createTempDirectory("rss-cli")
        val state = parent.resolve("state")
        val output = mutableListOf<String>()
        val errors = mutableListOf<String>()
        assertEquals(0, runCommand(arrayOf("rss", "initialize", state.toString()), output::add, errors::add))
        assertEquals(1, runCommand(arrayOf("rss", "initialize", state.toString()), output::add, errors::add))
        assertEquals(0, runCommand(arrayOf("rss", "poll", "restoring", state.toString()), output::add, errors::add))
        assertEquals(1, runCommand(arrayOf("rss", "poll", "active", state.toString(), "https://social.example", parent.toString()), output::add, errors::add))
        assertTrue(RssStateStore(state).read().pending.isEmpty())
    }
    @Test fun `durable claim prevents replay after timeout crash or concurrent worker`() {
        val store = store()
        var article = "old"
        var attempts = 0
        val fetch: (ReviewedFeed) -> List<FeedItem> = { listOf(FeedItem(article, "Headline", "https://example.org/article")) }
        val worker = RssWorker(store, fetch, { attempts++; throw IllegalStateException("timeout") }, { 1000 })
        worker.pollReviewed(PollGate.ACTIVE, true)
        article = "new"
        assertFails { worker.pollReviewed(PollGate.ACTIVE, true) }
        val claimed = store.read().pending.single()
        assertEquals(1000L, claimed.attemptedAtMillis)
        assertFalse(store.claim(claimed.copy(attemptedAtMillis = null), 1001))
        assertEquals(1, attempts)
        // Keep only this feed active on retry; other feeds' new items are successfully delivered.
        val retry = RssWorker(store, fetch, { "123" }, { 1002 }).pollReviewed(PollGate.ACTIVE, true)
        assertEquals(RssPacks.load().size - 1, retry.confirmed)
        assertEquals(listOf(claimed), store.read().pending)
        store.confirm(claimed.draft.feedId, claimed.draft.itemId, claimed.draft.idempotencyKey, "456")
        assertTrue(store.read().pending.isEmpty())
        assertEquals(0, RssWorker(store, fetch, { error("duplicate") }, { 1003 }).pollReviewed(PollGate.ACTIVE, true).confirmed)
    }
}
