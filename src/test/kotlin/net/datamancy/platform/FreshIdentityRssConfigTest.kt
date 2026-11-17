package net.datamancy.platform

import kotlinx.serialization.json.*
import kotlin.test.*

/** Pure fresh INSTALL config closure. Does not issue credentials, start Rails,
 * import OLD subjects or claim native RSS follow/token acceptance. */
class FreshIdentityRssConfigTest {
    @Test fun `new realm subjects groups and exact operator client are bound without OLD accounts`() {
        val generation = "q-012345abcdef"
        val grant = FreshIdentityBootstrap(ownerUuid = "83953fbb-078e-4669-829d-bc99df4888fb",
            outsiderUuid = "e0922ea8-c04a-4c4d-97cb-684b896813fb",
            appNonMemberUuid = "00000000-0000-4000-8000-000000000004")
        grant.validate()
        var counter = 2
        val inputs = IdentityRuntime.canonicalInputs("1".repeat(64),
            pki = { mapOf("ca.pem" to "local-test-ca", "web.pem" to "local-test-leaf", "web-key.pem" to "local-test-key") },
            password = { (counter++).toString(16).padStart(64, '0') },
            clients = JsonArray(listOf(IdentityRuntime.canonicalOperatorClient(generation))),
            originalOwnerId = grant.ownerUuid, originalOutsiderId = grant.outsiderUuid,
            originalMemberships = grant.memberships(), originalAppNonMemberId = grant.appNonMemberUuid)
        val realm = Json.parseToJsonElement(inputs.getValue("identity-realm.json")).jsonObject
        val users = realm.getValue("users").jsonArray.map { it.jsonObject }
        assertEquals(setOf(grant.ownerUuid, grant.outsiderUuid, grant.appNonMemberUuid),
            users.map { it.getValue("id").jsonPrimitive.content }.toSet())
        assertEquals(grant.ownerGroups, users.single { it.getValue("username").jsonPrimitive.content == "owner" }
            .getValue("groups").jsonArray.map { it.jsonPrimitive.content }.toSet())
        assertEquals(emptySet<String>(), users.single { it.getValue("username").jsonPrimitive.content == "outsider" }
            .getValue("groups").jsonArray.map { it.jsonPrimitive.content }.toSet())
        assertEquals(setOf("users"), users.single { it.getValue("username").jsonPrimitive.content == "app-nonmember" }
            .getValue("groups").jsonArray.map { it.jsonPrimitive.content }.toSet())
        assertNotEquals(grant.outsiderUuid, grant.appNonMemberUuid)
        assertFails { grant.copy(appNonMemberUuid = grant.outsiderUuid).validate() }
        assertFails { grant.copy(appNonMemberGroups = setOf("operators", "users")).validate() }
        assertTrue(realm.getValue("registrationAllowed").jsonPrimitive.boolean.not())
        assertFails { grant.copy(outsiderGroups = setOf("admins")).validate() }
        assertFails { grant.copy(outsiderUuid = grant.ownerUuid).validate() }
    }

    @Test fun `fresh Mastodon feature mints 47 bot definitions and separate read-only follower`() {
        var counter = 11
        val source = CanonicalFreshMastodonSource.inputs("q-012345abcdef", "1".repeat(64),
            "2".repeat(64)) { (counter++).toString(16).padStart(64, '0') }
        val feeds = Json.parseToJsonElement(source.getValue("rss-accounts.json")).jsonArray
        val expected = RssPacks.load().map { it.feed.account }.toSet()
        assertEquals(47, feeds.size)
        assertEquals(expected, feeds.map { it.jsonObject.getValue("account").jsonPrimitive.content }.toSet())
        assertFalse("rss_observer" in expected)
        val script = source.getValue("rss-bootstrap.rb")
        assertContains(script, "Account.find_local('rss_observer')")
        assertContains(script, "Follow.create!(account: observer, target_account: bot)")
        assertContains(script, "scopes: 'read:accounts'")
        assertContains(script, "'publicationEnabled' => false")
        assertContains(script, "File::EXCL")
        assertContains(source.getValue("mastodon-fresh-users.rb"), "Pre-existing local user is not fresh bootstrap")
        assertContains(source.getValue("mastodon-migrate.env"), "P0V3_GENERATION=q-012345abcdef")
        assertFalse(source.getValue("mastodon.env").contains("REDIS_HOST=valkey"))
        val full = PackagedGraphFragment.pendingV3R9().first
        assertEquals(5, full.fragments.single { it.id == "private-mastodon-shared-redis-bridge" }.revision)
        val graph = PackagedGraphFragment.loadPendingV3("private-mastodon-shared-redis-bridge", 5, 9).definition
        assertEquals("mastodon-uploads", graph.volumes.single { it.id == "mastodon-uploads" }.id)
        assertTrue(graph.install.processes.containsAll(listOf("mastodon-fresh-users", "mastodon-rss-feature")))
        assertFalse(graph.restore.processes.contains("mastodon-rss-feature"))
    }
}
