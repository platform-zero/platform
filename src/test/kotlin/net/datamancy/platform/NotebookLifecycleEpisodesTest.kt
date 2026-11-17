package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

class NotebookLifecycleEpisodesTest {
    @Test fun `only terminal native episode permits next container start and RESTORE has no inherited authority`() {
        val base = Files.createTempDirectory("notebook-episodes-test-",PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------")))
        try {
            val generation = base.resolve("q-012345abcdef")
            Files.createDirectory(generation,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val ledger = NotebookLifecycleEpisodes(generation,"q-012345abcdef-jupyterhub","alice","a".repeat(64))
            val intent = ledger.begin("1".repeat(32))
            assertFails { ledger.begin("2".repeat(32)) } // Original START ACK missing.
            val started = ledger.acceptStart(intent,"b".repeat(64),"c".repeat(64),"d".repeat(64))
            assertFails { ledger.begin("2".repeat(32)) } // A live workload is not a terminal episode.
            assertFails { ledger.terminal(intent,started,"e".repeat(64),"f".repeat(64),"not-a-hash") }
            ledger.terminal(intent,started,"e".repeat(64),"f".repeat(64),"0".repeat(64))
            val next = ledger.begin("2".repeat(32))
            assertEquals(2,next.ordinal)
            assertFails { ledger.begin("3".repeat(32)) } // Second intent is uncertain, never renamed/replayed.
            val restored = base.resolve("q-abcdef012345")
            Files.createDirectory(restored,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val fresh = NotebookLifecycleEpisodes(restored,"q-abcdef012345-jupyterhub","alice","a".repeat(64))
            assertTrue(fresh.completed().isEmpty()) // No OLD episode or CID imported.
            assertEquals(1,fresh.begin("9".repeat(32)).ordinal)
        } finally { Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
