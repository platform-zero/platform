package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertEquals

class RssQualificationPackSourceTest {
    private val feeds = RssPacks.load()
    private val hash = "a".repeat(64)
    private val generation = "q-" + "b".repeat(12)
    private val caseId = "case-" + "c".repeat(36)
    private fun binding() = RssQualificationPackBinding(generation = generation, bundleSha256 = hash,
        invocationId = caseId, phaseClaimSha256 = hash, host = "social.datamancy.net",
        privateAddress = "10.31.0.7", caSha256 = hash, servedLeafSha256 = hash,
        feeds = feeds.map { RssQualificationFeedSource(it.feed.id, it.feed.account, it.feed.url,
            "/feed/pack/${it.feed.id}", hash) }, originalManifestSha256 = hash)
    private fun check(source: RssQualificationPackBinding) = source.validate(feeds, generation,
        hash, caseId, hash, "10.31.0.7", hash, hash)

    @Test fun `exact nine packs and 47 reviewed sources preserve account and upstream provenance`() {
        assertEquals(47, feeds.size)
        assertEquals(9, feeds.map { it.pack }.toSet().size)
        check(binding())
        val original = binding()
        val first = original.feeds.first()
        for (changed in listOf(first.copy(account = "rss_foreign"),
            first.copy(originalUrl = "https://example.invalid/feed"),
            first.copy(path = "/api/v1/statuses"), first.copy(responseSha256 = "0"))) {
            assertFailsWith<IllegalArgumentException> {
                check(original.copy(feeds = listOf(changed) + original.feeds.drop(1)))
            }
        }
        assertFailsWith<IllegalArgumentException> { check(original.copy(feeds = original.feeds.dropLast(1))) }
        assertFailsWith<IllegalArgumentException> { check(original.copy(privateAddress = "8.8.8.8")) }
        assertFailsWith<IllegalArgumentException> { check(original.copy(invocationId = "case-foreign")) }
        assertFailsWith<IllegalArgumentException> { check(original.copy(phaseClaimSha256 = "0".repeat(64))) }
    }

    @Test fun `producer XML is deterministic labelled private test content for all 47 identities`() {
        assertEquals(47, feeds.map { it.feed.id }.toSet().size)
        for (feed in feeds) {
            val bytes = RssQualificationPackSource.xml(feed)
            assertContentEquals(bytes, RssQualificationPackSource.xml(feed))
            val text = bytes.toString(Charsets.UTF_8)
            kotlin.test.assertTrue(text.contains("TEST FIXTURE") && text.contains(feed.feed.account) &&
                text.contains("not external news") && text.contains("no upstream GET or publication"))
            val parsed = RssXml.parse(bytes, java.net.URI(feed.feed.url)).single()
            assertEquals("qualification-fixture-v1:${feed.feed.id}", parsed.id)
            kotlin.test.assertTrue(parsed.link.startsWith("https://fixture.invalid/qualification/"))
        }
    }

    @Test fun `production fetch without a real scoped phase case fails before network`() {
        assertFailsWith<IllegalArgumentException> { RssQualificationPackSource.fetch(feeds.first()) }
    }
}
