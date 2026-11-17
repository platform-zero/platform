package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

/** Source-only tests: no assertion here is a native import or credential acquisition. */
class MastodonRecoveryTest {
    @Test fun `original social adoption refuses an unanchored caller authored capsule result`(): Unit {
        val root = Files.createTempDirectory("mastodon-original-unit-")
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            val generation = "q-" + "a".repeat(12)
            val digest = "b".repeat(64)
            val request = GenerationRequest(id = generation, candidateSha256 = digest,
                members = listOf(GenerationMember("mastodon")), diskReservationMiB = 10240)
            val bundle = GenerationBundle(request, emptyList(), memoryReservationMiB = 0)
            val manifest = CapsuleManifest(id = "cap-" + "c".repeat(12), generation = generation,
                bundleSha256 = digest, members = emptyList(), files = emptyList())
            val fake = RecoveredGeneration(bundle, manifest, root,
                GenerationRecoveryCheck(generation, manifest.id, digest, "d".repeat(64), emptyList()))
            val inventory = AcquiredInventory(1, "candidate", emptyList())
            assertFails { MastodonRecovery.canonicalSource(fake, inventory) }
            assertTrue(Files.list(root).use { !it.findAny().isPresent })
        } finally {
            Files.delete(root)
        }
    }

    @Test fun `only exact two disjoint synthetic accounts can be provisioned with generation bound intents`(): Unit {
        val generation = "q-" + "a".repeat(12)
        val ids = setOf("rssq-" + "1".repeat(12), "rssq-" + "2".repeat(12))
        val inputs = MastodonRecovery.syntheticRssqInputs(ids, generation, "b".repeat(64))
        val manifest = inputs.getValue("mastodon-rssq-fixtures.json")
        assertContains(manifest, generation)
        assertContains(manifest, "b".repeat(64))
        assertTrue(ids.all { it in manifest })
        val script = inputs.getValue("mastodon-rssq-provision.rb")
        assertContains(script, "File::WRONLY | File::CREAT | File::EXCL")
        assertContains(script, "'original47Sha256'")
        assertContains(script, "'accountId' => account.id.to_s")
        assertContains(script, "'read:accounts read:statuses write:statuses'")
        assertContains(script, "token.scopes.to_s == 'read:accounts write:statuses'")
        assertFalse(script.contains("Mastodon::CLI::Accounts.start"))
        assertFails { MastodonRecovery.syntheticRssqInputs(ids + ("rssq-" + "3".repeat(12)), generation, "b".repeat(64)) }
        assertFails { MastodonRecovery.syntheticRssqInputs(ids, "invalid", "b".repeat(64)) }
        assertFails { MastodonRecovery.syntheticRssqInputs(ids, generation, "invented") }
    }

    @Test fun `original47 SQL verification is read only and rejects foreign scope`(): Unit {
        val script = MastodonRecovery.canonicalOriginalCheckScript()
        assertContains(script, "Original SQL account/token ID/scope changed")
        assertContains(script, "token.scopes.to_s == 'read:accounts write:statuses'")
        assertContains(script, "account.id.to_s == row.fetch('accountId')")
        assertContains(script, "ORIGINAL_SQL47_SHA256")
        assertContains(script, "ORIGINAL_TOKEN_CUSTODY_SHA256")
        assertContains(script, "ORIGINAL_#{who.upcase}_ID")
        assertContains(script, "!token.revoked?")
        assertContains(script, "File::CREAT | File::EXCL")
        assertFalse(script.contains("Account.create!"))
        assertFalse(script.contains("db:migrate"))
        assertFalse(script.contains("Doorkeeper::AccessToken.create!"))
    }
}
