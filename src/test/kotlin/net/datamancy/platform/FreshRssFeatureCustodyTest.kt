package net.datamancy.platform

import kotlinx.serialization.json.*
import kotlin.test.*

/** Controller ledger acceptance is pure and has no SQL, Podman or token
 * issuance. Test-only token strings never become installation credentials. */
class FreshRssFeatureCustodyTest {
    private fun ledger(observerFeed: String = "observer", publication: Boolean = false,
        duplicateToken: Boolean = false): ByteArray {
        val feeds = RssPacks.load()
        val rows = feeds.mapIndexed { index, item -> buildJsonObject {
            put("account", item.feed.account); put("accountId", (index + 1).toString())
            put("feedId", item.feed.id); put("pack", item.pack)
            val tokenIndex = if (duplicateToken && index == 1) 0 else index
            put("token", "fixture-token-${tokenIndex.toString().padStart(3, '0')}-not-a-credential")
        } } + buildJsonObject {
            put("account", "rss_observer"); put("accountId", "48")
            put("feedId", observerFeed); put("pack", "observer")
            put("token", "fixture-observer-token-not-a-credential")
        }
        return buildJsonObject {
            put("schemaVersion", 1); put("publicationEnabled", publication)
            put("accounts", JsonArray(rows))
        }.toString().toByteArray()
    }
    @Test fun `post-one-shot controller adopts only the 47 fresh bots and separate observer`() {
        val accepted = FreshRssFeatureCustody.validateLedger(ledger())
        assertEquals(48, accepted.size)
        assertTrue("rss_observer.token" in accepted)
        assertFalse(accepted.values.any { it.contains("fixture-token") })
        assertFails { FreshRssFeatureCustody.validateLedger(ledger(observerFeed = "borrowed")) }
        assertFails { FreshRssFeatureCustody.validateLedger(ledger(publication = true)) }
        assertFails { FreshRssFeatureCustody.validateLedger(ledger(duplicateToken = true)) }
    }
}
