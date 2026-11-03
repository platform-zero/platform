package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

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
            output::add, { error("No schedule created by read-only observation") }, { observer }))
        assertTrue(output.single().contains("\"schemaVersion\":1"))
        assertFails { RssScheduleCommands.run(arrayOf("rss", "pack-observe", "publish", "aus", state.toString(), file.toString()), output::add) }
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
