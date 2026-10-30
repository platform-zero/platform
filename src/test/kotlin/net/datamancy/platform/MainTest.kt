package net.datamancy.platform

import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MainTest {
    @Test fun `postgres CLI rejects malformed actions before any real sandbox side effects`() {
        val output = mutableListOf<String>()
        val errors = mutableListOf<String>()
        for (action in listOf("prepare", "install", "stop", "remove", "write", "query")) {
            assertEquals(1, runCommand(arrayOf("module", "postgres", action, "unexpected"), output::add, errors::add))
        }
        for (action in listOf("backup", "restore", "restored-write", "restored-query", "restore-remove")) {
            assertEquals(1, runCommand(arrayOf("module", "postgres", action), output::add, errors::add))
        }
        assertEquals(1, runCommand(arrayOf("module", "postgres", "unrecognized"), output::add, errors::add))
        assertTrue(output.isEmpty())
        assertTrue(errors.all { it.startsWith("Rejected:") })
    }
    @Test fun `catalog CLI exposes inventory without deployment claims`() {
        val output = mutableListOf<String>()
        val errors = mutableListOf<String>()
        assertEquals(0, runCommand(arrayOf("catalog", "validate"), output::add, errors::add))
        assertTrue(output.single().contains("89 IDs"))
        output.clear()
        assertEquals(0, runCommand(arrayOf("catalog", "list"), output::add, errors::add))
        assertEquals(89, output.size)
        assertTrue(output.all { it.endsWith("inventory-only") })
        assertTrue(errors.isEmpty())
        main(arrayOf("catalog", "validate")) // real entrypoint, successful path only
    }

    @Test fun `CLI renders and stages only explicit site then restores offline`() {
        val root = Files.createTempDirectory("p0v3-cli-")
        val config = Files.createTempFile("p0v3-site-", ".json")
        val output = mutableListOf<String>()
        val errors = mutableListOf<String>()
        val call: (Array<String>) -> Int = { runCommand(it, output::add, errors::add) }
        try {
            Files.writeString(config, """{"schemaVersion":1,"sites":[{"id":"scratch","workloads":[{"id":"probe","image":"docker.io/library/busybox@sha256:${"a".repeat(64)}"}]}]}""")
            assertEquals(0, call(arrayOf("site", "validate", config.toString(), "scratch")))
            assertEquals(0, call(arrayOf("plan", "render", config.toString(), "scratch")))
            assertTrue(output.last().contains("Network=none"))
            assertFalse(output.last().contains("PublishPort"))
            assertEquals(0, call(arrayOf("stage", "offline", config.toString(), "scratch", root.toString())))
            assertTrue(Files.isRegularFile(root.resolve("current/p0v3-scratch-probe.container")))
            assertEquals(0, call(arrayOf("stage", "restore", root.toString(), "scratch")))
            assertFalse(Files.exists(root.resolve("current")))
            assertEquals(2, call(arrayOf("unrecognized")))
            assertTrue(errors.last().startsWith("Usage:"))
            assertEquals(1, call(arrayOf("site", "validate", config.toString(), "unknown")))
            assertTrue(errors.last().startsWith("Rejected:"))
        } finally {
            Files.delete(config)
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}
