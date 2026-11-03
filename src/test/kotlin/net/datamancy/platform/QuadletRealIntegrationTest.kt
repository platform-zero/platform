package net.datamancy.platform

import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Assumptions.assumeTrue
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals

/** Explicit native task only. Never part of the unit gate, even if the opt-in environment leaks. */
@Tag("native")
class QuadletRealIntegrationTest {
    @Test fun `installed generator preserves explicit private store arguments`() {
        assumeTrue(System.getenv("P0V3_QUADLET_INTEGRATION") == "1")
        val root = Files.createTempDirectory("quadlet-native-")
        try {
            val graph = root.resolve("graph").toString()
            val run = root.resolve("run").toString()
            val bundle = QuadletBundle(mapOf("p0v3-unit.container" to
                "[Container]\nImage=example.test/unit@sha256:${"a".repeat(64)}\nPull=never\nReadOnly=true\nUser=1000\nGlobalArgs=--root=$graph --runroot=$run\n"), graph, run)
            assertEquals(1, QuadletDryRun.verify(bundle))
        } finally { Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
