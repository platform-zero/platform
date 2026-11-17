package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class RssPackObservationTest {
    private fun fixture(block: (Path, Path) -> Unit) {
        val root = Files.createTempDirectory("rss-pack-unit", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val state = Files.createDirectory(root.resolve("state"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        RssStateStore(state).initializeFresh()
        try { block(state, root.resolve("fixture.json")) }
        finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `native pack observation retains original attributed items without sender and restore does not refetch`() = fixture { state, file ->
        var calls = 0
        val observer = RssPackObserver { calls++; listOf(FeedItem("synthetic-item", "Synthetic headline", "https://example.org/article")) }
        val install = observer.observe("aus", state, file, false)
        assertEquals(RssPacks.load().count { it.pack == "aus" }, calls)
        assertEquals(0, install.pending)
        install.feeds.forEach { row ->
            assertEquals("Synthetic headline — ${row.feed.source.trim()}\nhttps://example.org/article", row.previews.single().text)
        }
        assertEquals(install, RssPackObserver { error("Restore cannot fetch") }.observe("aus", state, file, true))
        assertFails { observer.observe("aus", state, file, false) }
        assertFails { observer.observe("world", state, file, true) }
        assertFails { observer.observe("unknown", state, file, true) }
    }
    @Test fun `registered observation command emits explicit schema and refuses unknown modes`() = fixture { state, file ->
        val output = mutableListOf<String>()
        val observer = RssPackObserver { listOf(FeedItem("unit", "Synthetic", "https://example.org/unit")) }
        assertTrue(RssScheduleCommands.run(arrayOf("rss", "pack-observe", "install", "aus", state.toString(), file.toString()),
            output::add, { error("No schedule created by read-only observation") }, { observer }, null))
        assertTrue(output.single().contains("\"schemaVersion\":1"))
        assertFails { RssScheduleCommands.run(arrayOf("rss", "pack-observe", "publish", "aus", state.toString(), file.toString()),
            output::add, operationScope = null) }
    }

    @Test fun `isolated publisher sends one synthetic POST loses ack and never replays before authenticated reconciliation`(): Unit = fixture { state, _ ->
        val root = state.parent
        val original = RssSyntheticQualification.observe("aus", root, false)
        assertEquals(0, original.firstPollPosts)
        assertEquals(1, original.attemptedPosts)
        assertEquals(0, original.replayPosts)
        assertEquals("777", original.reconciledStatusId)
        assertEquals(original, RssSyntheticQualification.observe("aus", root, true))
        assertFails { RssSyntheticQualification.observe("aus", root, false) }
        assertFails { RssSyntheticQualification.observe("analysis", root, true) }
        val originalState = state.resolve("rss-state.json")
        assertTrue(Files.exists(originalState))
        assertTrue(RssStateStore(root.resolve("synthetic-state")).read().pending.isEmpty())
        assertEquals(1, RssStateStore(root.resolve("synthetic-state")).read().reconciled.size)
    }
    @Test fun `real fixture enrollment refuses production origin before token network or timer writes`(): Unit {
        val root = Files.createTempDirectory("rss-native-fixture-unit", PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------")))
        try {
            val generation = Files.createDirectory(root.resolve("q-123456789abc"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val qualifier = Files.createDirectory(generation.resolve("rss-qualification"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val sample = Files.createDirectory(qualifier.resolve("sample"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val binding = RssNativeFixtureBinding(generation = "q-123456789abc", bundleSha256 = "a".repeat(64),
                pack = "analysis", origin = "https://social.datamancy.net", baselineUrl = "https://social.datamancy.net/feed/baseline",
                newItemUrl = "https://social.datamancy.net/feed/new", tokenFile = sample.resolve("synthetic-bot.token").toString(),
                caFile = sample.resolve("fixture-ca.pem").toString(), caSha256 = "b".repeat(64),
                controllerSha256 = "c".repeat(64), userId = com.sun.security.auth.module.UnixSystem().uid.toInt(),
                syntheticAccount = "rssq_123456789abc", mastodonOrigin = "https://social.datamancy.net",
                mastodonCaFile = sample.resolve("mastodon-ca.pem").toString(), mastodonCaSha256 = "d".repeat(64))
            val input = sample.resolve("native-fixture-binding.json")
            ReleasePrivateFiles.save(input, Json.encodeToString(binding).toByteArray())
            assertFails { RssNativeFixtureTimer.enroll(sample, input) }
            assertFalse(Files.exists(generation.resolve("rss/fixture-timers")))
            assertFalse(Files.exists(sample.resolve("native-state")))
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `unresolved or empty feed cannot advance a native checkpoint`() = fixture { state, file ->
        val before = RssStateStore(state).read()
        assertFails { RssPackObserver { if (it.feed.id == "washpost-politics") error("unresolved") else
            listOf(FeedItem("one", "Synthetic", "https://example.org/one")) }.observe("analysis", state, file, false) }
        assertEquals(before, RssStateStore(state).read()); assertFalse(Files.exists(file))
        assertFails { RssPackObserver { emptyList() }.observe("aus", state, file, false) }
        assertEquals(before, RssStateStore(state).read())
    }
}
