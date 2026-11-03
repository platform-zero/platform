package net.datamancy.platform

import java.io.ByteArrayInputStream
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.time.Duration
import java.util.concurrent.Flow
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.w3c.dom.Element
import org.xml.sax.ErrorHandler
import org.xml.sax.SAXParseException

internal data class RssHttpReply(val status: Int, val body: ByteArray, val headers: Map<String, String> = emptyMap())
internal fun interface RssHttp { fun request(method: String, uri: URI, headers: Map<String, String>, body: String): RssHttpReply }

/** Streaming size cap applies even when Content-Length is absent or dishonest. */
internal class BoundedRssBody(private val maximum: Int) : HttpResponse.BodySubscriber<ByteArray> {
    private val delegate = HttpResponse.BodySubscribers.ofByteArray()
    private var subscription: Flow.Subscription? = null
    private var received = 0L
    override fun getBody() = delegate.body
    override fun onSubscribe(value: Flow.Subscription) { subscription = value; delegate.onSubscribe(value) }
    override fun onNext(items: List<ByteBuffer>) {
        received += items.sumOf { it.remaining().toLong() }
        if (received > maximum) {
            subscription?.cancel()
            delegate.onError(IllegalArgumentException("RSS HTTP body exceeds limit"))
        } else delegate.onNext(items)
    }
    override fun onError(error: Throwable) = delegate.onError(error)
    override fun onComplete() = delegate.onComplete()
}

internal class JdkRssHttp : RssHttp {
    private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15))
        .version(HttpClient.Version.HTTP_1_1).followRedirects(HttpClient.Redirect.NEVER).build()
    override fun request(method: String, uri: URI, headers: Map<String, String>, body: String): RssHttpReply {
        require(uri.scheme == "https" && uri.host != null && uri.userInfo == null && uri.fragment == null)
        val builder = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30))
            .header("User-Agent", "Mozilla/5.0 (compatible; PlatformZero-RSS/1.0)")
        headers.forEach { (key, value) -> builder.header(key, value) }
        val request = if (method == "GET") {
            require(body.isEmpty())
            builder.GET().build()
        } else builder.method(method, HttpRequest.BodyPublishers.ofString(body)).build()
        val pending = client.sendAsync(request, HttpResponse.BodyHandler { BoundedRssBody(2_097_152) })
        try {
            val reply = pending.get(30, java.util.concurrent.TimeUnit.SECONDS)
            return RssHttpReply(reply.statusCode(), reply.body(), reply.headers().map().mapValues { it.value.singleOrNull().orEmpty() })
        } catch (interrupted: InterruptedException) {
            pending.cancel(true); Thread.currentThread().interrupt(); throw interrupted
        } catch (error: Exception) {
            pending.cancel(true); throw IllegalStateException("RSS HTTP exchange incomplete; do not retry an attempted send", error)
        }
    }
}

/** XML is untrusted. No DTD, external entities, XInclude, schemas or network access during parsing. */
internal object RssXml {
    fun parse(bytes: ByteArray, source: URI): List<FeedItem> {
        require(bytes.size in 1..2_097_152) { "Empty or oversized feed" }
        val factory = DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = true
            isXIncludeAware = false
            isExpandEntityReferences = false
            setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            setFeature("http://xml.org/sax/features/external-general-entities", false)
            setFeature("http://xml.org/sax/features/external-parameter-entities", false)
            setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
            setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "")
        }
        val builder = factory.newDocumentBuilder().apply {
            setErrorHandler(object : ErrorHandler {
                override fun warning(e: SAXParseException) { throw IllegalArgumentException("Invalid feed XML") }
                override fun error(e: SAXParseException) { throw IllegalArgumentException("Invalid feed XML") }
                override fun fatalError(e: SAXParseException) { throw IllegalArgumentException("Invalid feed XML") }
            })
        }
        val root = builder.parse(ByteArrayInputStream(bytes)).documentElement
        val atom = root.localName == "feed" && root.namespaceURI == "http://www.w3.org/2005/Atom"
        val rdf = root.localName == "RDF" && root.namespaceURI == "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
        val entries = when {
            atom -> children(root, "entry", "http://www.w3.org/2005/Atom")
            rdf -> children(root, "item", "http://purl.org/rss/1.0/")
            root.tagName == "rss" -> children(children(root, "channel", null).single(), "item", null)
            else -> throw IllegalArgumentException("Unsupported feed format")
        }
        require(entries.size <= 200) { "Too many feed items" }
        val items = entries.map { entry ->
            val ns = when { atom -> "http://www.w3.org/2005/Atom"; rdf -> "http://purl.org/rss/1.0/"; else -> null }
            fun text(name: String) = children(entry, name, ns).singleOrNull()?.textContent?.trim().orEmpty()
            val title = text("title").replace(Regex("<[^>]*>"), "").trim()
            val href = if (atom) children(entry, "link", ns).filter {
                it.getAttribute("rel") in setOf("", "alternate") && it.getAttribute("type") in setOf("", "text/html")
            }.singleOrNull()?.getAttribute("href").orEmpty() else text("link")
            require(href.isNotBlank()) { "Missing or ambiguous article link" }
            val link = source.resolve(href)
            val id = (if (rdf) entry.getAttributeNS("http://www.w3.org/1999/02/22-rdf-syntax-ns#", "about")
                else text(if (atom) "id" else "guid")).ifBlank { link.toString() }
            require(id.length in 1..512 && title.length in 1..1000 && link.toString().length <= 2048 &&
                link.scheme == "https" && link.host != null && link.userInfo == null) { "Unsafe feed item" }
            FeedItem(id, title, link.toString())
        }
        require(items.map { it.id }.distinct().size == items.size) { "Duplicate article identity" }
        return items
    }
    private fun children(element: Element, name: String, namespace: String?): List<Element> =
        (0 until element.childNodes.length).mapNotNull { element.childNodes.item(it) as? Element }
            .filter { it.localName == name && it.namespaceURI == namespace }
}

internal class RssFetcher(private val http: RssHttp) {
    fun fetch(feed: ReviewedFeed): List<FeedItem> {
        require(feed in RssPacks.load()) { "Unpinned feed source" }
        var uri = URI(feed.feed.url)
        val origin = uri
        repeat(4) { hop ->
            val result = http.request("GET", uri, mapOf("Accept" to "application/atom+xml, application/rss+xml, application/xml, text/xml",
                "Accept-Encoding" to "gzip"), "")
            if (result.status in setOf(301, 302, 303, 307, 308)) {
                require(hop < 3) { "Too many feed redirects" }
                val target = uri.resolve(requireNotNull(result.headers["location"]) { "Missing redirect target" })
                val allowedHosts = setOf(origin.host) + if (feed.feed.id == "npr-world") setOf("feeds.npr.org") else emptySet()
                require(target.scheme == "https" && target.host in allowedHosts && target.port == origin.port &&
                    target.userInfo == null && target.fragment == null) { "Unapproved feed redirect" }
                uri = target
            } else {
                require(result.status == 200) { "Feed HTTP request failed: ${result.status}" }
                val bytes = decodeBody(result)
                return RssXml.parse(if (feed.feed.id == "rest-of-world") repairPublisherAmpersands(bytes) else bytes, uri)
            }
        }
        error("Feed redirect loop")
    }
    /** Rest of World's thumbnail URLs contain unescaped query separators. Preserve CDATA/comments and entities. */
    internal fun repairPublisherAmpersands(bytes: ByteArray): ByteArray {
        val text = Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString()
        val pattern = Regex("<!\\[CDATA\\[[\\s\\S]*?]]>|<!--[\\s\\S]*?-->|&(?!amp;|lt;|gt;|quot;|apos;|#[0-9]+;|#x[0-9a-fA-F]+;)")
        return pattern.replace(text) { if (it.value == "&") "&amp;" else it.value }.toByteArray(Charsets.UTF_8)
    }
    internal fun decodeBody(reply: RssHttpReply): ByteArray {
        require(reply.body.size <= 2_097_152)
        return when (reply.headers["content-encoding"]?.lowercase()) {
            null, "", "identity" -> reply.body
            "gzip" -> java.util.zip.GZIPInputStream(ByteArrayInputStream(reply.body)).use {
                it.readNBytes(2_097_153).also { bytes -> require(bytes.size <= 2_097_152) { "Expanded feed exceeds limit" } }
            }
            else -> throw IllegalArgumentException("Unsupported feed compression")
        }
    }
}

internal class MastodonRssSender(private val origin: URI, private val token: (String) -> String, private val http: RssHttp) {
    init {
        require(origin.scheme == "https" && origin.host != null && origin.userInfo == null &&
            origin.rawQuery == null && origin.rawFragment == null && origin.path in setOf("", "/")) { "HTTPS Mastodon origin required" }
    }
    companion object {
        fun privateToken(path: Path): String {
            require(path.isAbsolute && Files.isRegularFile(path, NOFOLLOW_LINKS) && path.toRealPath() == path &&
                Files.size(path) in 20..512 &&
                (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == com.sun.security.auth.module.UnixSystem().uid &&
                (Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong() == 1L && Files.getPosixFilePermissions(path).none {
                    it.name.startsWith("GROUP_") || it.name.startsWith("OTHERS_")
                }) { "Private per-account token file required" }
            return Files.readString(path).trim().also {
                require(it.matches(Regex("[A-Za-z0-9_.-]{20,256}"))) { "Invalid token encoding" }
            }
        }
    }
    fun send(draft: DraftPost, authority: RssPublicationAuthority? = null): String {
        require(RssPacks.reviewedForPublication()) { "RSS publication review pending" }
        val permit = requireNotNull(authority) { "Release-bound RSS publication authority required" }
        permit.verify()
        return sendReviewed(draft, permit::verify)
    }
    /** Read-only readiness check; deliberately usable before publication authorization. */
    fun verifyAccount(account: String): String {
        require(RssPacks.load().any { it.feed.account == account }) { "Unpinned RSS account" }
        return verifiedIdentity(account, bearer(account))
    }
    private fun bearer(account: String): String = token(account).also {
        require(it.matches(Regex("[A-Za-z0-9_.-]{20,256}"))) { "Invalid token encoding" }
    }
    private fun verifiedIdentity(expectedAccount: String, bearer: String): String {
        val verify = http.request("GET", origin.resolve("/api/v1/accounts/verify_credentials"),
            mapOf("Authorization" to "Bearer $bearer", "Accept" to "application/json"), "")
        require(verify.status == 200) { "RSS account verification failed" }
        val account = Json.parseToJsonElement(verify.body.decodeToString()).jsonObject
        val accountId = account.getValue("id").jsonPrimitive.content
        require(accountId.matches(Regex("[0-9]{1,32}")) && account.getValue("acct").jsonPrimitive.content == expectedAccount &&
            account.getValue("bot").jsonPrimitive.content == "true") { "RSS token belongs to wrong account or non-bot" }
        return accountId
    }
    /** Explicit, read-only reconciliation. A 404 never clears the claim or permits a retry; no POST occurs here.
     * Requires read:statuses in addition to the existing account verification scope. No token/scope fallback.
     */
    fun reconcile(store: RssStateStore, expectedChecksum: String, feedId: String, itemId: String,
        statusId: String, nowMillis: Long, gate: PollGate): RssReconciledDelivery? {
        require(gate == PollGate.ACTIVE && statusId.matches(Regex("[0-9]{1,32}")) && nowMillis in 0..253402300799999L)
        return store.reconcileConfirmed(expectedChecksum, feedId, itemId) { pending ->
            val attempted = requireNotNull(pending.attemptedAtMillis)
            require(nowMillis >= attempted && attempted <= 253402300679999L) { "RSS reconciliation clock rollback" }
            val draft = pending.draft
            val feed = RssPacks.load().single { it.feed.id == draft.feedId }
            require(draft.account == feed.feed.account && draft.pack == feed.pack &&
                draft.idempotencyKey == ReleaseLocks.sha256("${draft.account}\u0000${draft.itemId}".toByteArray()))
            val bearer = bearer(draft.account)
            val accountId = verifiedIdentity(draft.account, bearer)
            val headers = mapOf("Authorization" to "Bearer $bearer", "Accept" to "application/json")
            val remote = http.request("GET", origin.resolve("/api/v1/statuses/$statusId"), headers, "")
            if (remote.status == 404) return@reconcileConfirmed null
            require(remote.status == 200) { "RSS status observation failed; claim remains uncertain" }
            val status = Json.parseToJsonElement(remote.body.decodeToString()).jsonObject
            require(status.getValue("id").jsonPrimitive.content == statusId &&
                status.getValue("account").jsonObject.getValue("id").jsonPrimitive.content == accountId &&
                status.getValue("visibility").jsonPrimitive.content == "public" &&
                status["reblog"] in listOf(null, kotlinx.serialization.json.JsonNull)) { "Foreign or non-public RSS status" }
            val created = java.time.Instant.parse(status.getValue("created_at").jsonPrimitive.content).toEpochMilli()
            require(created in maxOf(0, attempted - 120000)..minOf(nowMillis + 120000, attempted + 120000)) { "Status does not match attempted-send time window" }
            val source = http.request("GET", origin.resolve("/api/v1/statuses/$statusId/source"), headers, "")
            require(source.status == 200) { "Author-owned status source is required; no HTML guessing" }
            val text = Json.parseToJsonElement(source.body.decodeToString()).jsonObject
            require(text.getValue("id").jsonPrimitive.content == statusId && text.getValue("text").jsonPrimitive.content == draft.text &&
                text.getValue("spoiler_text").jsonPrimitive.content.isEmpty()) { "RSS status source differs from pending attributed draft" }
            val observation = remote.body.size.toString().toByteArray() + byteArrayOf(0) + remote.body + source.body
            RssReconciledDelivery(draft.feedId, draft.itemId, draft.idempotencyKey, draft.account, statusId, nowMillis, ReleaseLocks.sha256(observation))
        }
    }
    internal fun sendReviewed(draft: DraftPost, beforePost: () -> Unit = {}): String {
        val feed = RssPacks.load().single { it.feed.id == draft.feedId }
        require(draft.account == feed.feed.account && draft.pack == feed.pack &&
            draft.idempotencyKey == ReleaseLocks.sha256("${draft.account}\u0000${draft.itemId}".toByteArray()) &&
            draft.text.isNotBlank() && draft.text.codePointCount(0, draft.text.length) <= 500) { "Invalid RSS draft" }
        val bearer = bearer(draft.account)
        val auth = mapOf("Authorization" to "Bearer $bearer", "Accept" to "application/json")
        val accountId = verifiedIdentity(draft.account, bearer)
        val form = listOf("status" to draft.text, "visibility" to "public").joinToString("&") { (key, value) ->
            "$key=${URLEncoder.encode(value, Charsets.UTF_8)}"
        }
        beforePost() // Reobserve after account verification; revoked authority cannot authorize a POST.
        val reply = http.request("POST", origin.resolve("/api/v1/statuses"), auth + mapOf(
            "Content-Type" to "application/x-www-form-urlencoded", "Idempotency-Key" to draft.idempotencyKey), form)
        require(reply.status in setOf(200, 201)) { "RSS post not confirmed; reconcile pending outbox" }
        val status = Json.parseToJsonElement(reply.body.decodeToString()).jsonObject
        val id = status.getValue("id").jsonPrimitive.content
        require(id.matches(Regex("[0-9]{1,32}")) && status.getValue("account").jsonObject.getValue("id").jsonPrimitive.content == accountId) {
            "RSS response account mismatch; reconcile pending outbox"
        }
        return id
    }
}

internal data class RssPollSummary(val feeds: Int, val observed: Int, val confirmed: Int,
    val failedFeeds: List<String> = emptyList(), val failureTypes: Map<String, String> = emptyMap())
internal class RssWorker(private val store: RssStateStore, private val fetch: (ReviewedFeed) -> List<FeedItem>,
    private val send: (DraftPost) -> String, private val clock: () -> Long = System::currentTimeMillis) {
    fun poll(gate: PollGate, authority: RssPublicationAuthority? = null): RssPollSummary {
        val authorize: () -> Unit = if (gate == PollGate.ACTIVE) requireNotNull(authority) {
            "Release-bound RSS publication authority required"
        }::verify else ({})
        return pollReviewed(gate, RssPacks.reviewedForPublication(), authorize)
    }
    internal fun pollReviewed(gate: PollGate, reviewed: Boolean, authorize: () -> Unit = {}): RssPollSummary {
        if (gate == PollGate.RESTORING) return RssPollSummary(0, 0, 0)
        require(gate != PollGate.ACTIVE || reviewed) { "RSS publication review pending" }
        if (gate == PollGate.ACTIVE) authorize()
        var observed = 0
        var confirmed = 0
        val feeds = RssPacks.load()
        val failed = mutableListOf<String>()
        val failureTypes = mutableMapOf<String, String>()
        for (feed in feeds) {
            if (gate == PollGate.ACTIVE) authorize()
            val items = try { fetch(feed) } catch (e: Exception) {
                if (e is InterruptedException) { Thread.currentThread().interrupt(); throw e }
                failed += feed.feed.id
                failureTypes[feed.feed.id] = e.javaClass.simpleName
                continue
            }
            observed += items.size
            val pending = store.checkpointWithReview(feed, items, gate, clock(), reviewed)
            for (post in pending) {
                authorize()
                if (!store.claim(post, clock())) continue
                val id = try { send(post.draft) } catch (interrupted: InterruptedException) {
                    Thread.currentThread().interrupt(); throw interrupted
                }
                store.confirm(post.draft.feedId, post.draft.itemId, post.draft.idempotencyKey, id)
                confirmed++
            }
        }
        return RssPollSummary(feeds.size, observed, confirmed, failed, failureTypes)
    }
}
