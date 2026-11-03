package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MainTest {
    @Test fun `integrated entrypoints reject absent input before any runtime effect`() {
        val root = Files.createTempDirectory("integrated-cli-unit-")
        try {
            val missing = root.resolve("missing.json").toString()
            val calls = listOf("install", "update", "backup", "restore-test", "rollback", "reconcile", "qualify", "activate")
                .map { arrayOf("release", it, missing) } + listOf(
                    arrayOf("runtime", "ingress-lifecycle", missing),
                    arrayOf("runtime", "private-pki-lifecycle", missing),
                    arrayOf("runtime", "prepare-matrix-rtc", missing),
                    arrayOf("runtime", "prepare-erpnext-restore", missing, missing, "erprestore-unit"),
                    arrayOf("release", "generation-canonical-plan", missing, missing))
            calls.forEach { call ->
                val errors = mutableListOf<String>()
                assertEquals(1, runCommand(call, { error("No success output expected") }, errors::add))
                assertTrue(errors.isNotEmpty())
                assertTrue(Files.list(root).use { it.findAny().isEmpty })
            }
            val request = root.resolve("request.json")
            ReleasePrivateFiles.save(request, """{"operation":"backup","generation":{"id":"q-aaaaaaaaaaaa","bundleSha256":"${"a".repeat(64)}"},"inventory":{"path":"$missing","sha256":"${"b".repeat(64)}"},"capture":"cap-aaaaaaaaaaaa"}""".toByteArray())
            val errors = mutableListOf<String>()
            assertEquals(1, runCommand(arrayOf("release", "install", request.toString()), { error("must reject") }, errors::add))
            assertEquals(listOf("Rejected: Typed release request operation differs from CLI"), errors)
            assertEquals(1, Files.list(root).use { it.count() }.toInt())
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    @Test fun `private typed request parse failures do not echo rejected secret fields`() {
        val root = Files.createTempDirectory("private-cli-diagnostics-unit-")
        try {
            val path = root.resolve("private.json")
            ReleasePrivateFiles.save(path, """{"unexpected":"unit-private-secret-not-for-diagnostics"}""".toByteArray())
            for ((kind, operation) in listOf("release" to "install", "runtime" to "ingress-lifecycle", "runtime" to "private-pki-lifecycle")) {
                val errors = mutableListOf<String>()
                assertEquals(1, runCommand(arrayOf(kind, operation, path.toString()), { error("must reject") }, errors::add))
                assertTrue(errors.single().contains("withheld"))
                assertFalse(errors.single().contains("unit-private-secret"))
            }
            assertEquals(1, Files.list(root).use { it.count() }.toInt())
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    @Test fun `canonical planning CLI reports partial source topology without preparation`() {
        val root = Files.createTempDirectory("canonical-plan-cli-unit-")
        try {
            val inventory = Path.of("release/downloaded-candidate-inventory.json").toAbsolutePath()
            val request = AssemblyRequest(id = "q-012345abcdef", candidateSha256 = "a".repeat(64),
                inventorySha256 = ReleaseLocks.sha256(Files.readAllBytes(inventory)),
                selections = listOf(AssemblySelection("canonical-providers")), diskReservationMiB = 131072,
                store = RuntimeStore.CANONICAL_V2)
            val path = root.resolve("request.json")
            ReleasePrivateFiles.save(path, Json.encodeToString(request).toByteArray())
            val output = mutableListOf<String>()
            assertEquals(0, runCommand(arrayOf("release", "generation-canonical-plan", inventory.toString(), path.toString()),
                output::add, { error(it) }))
            val report = Json.decodeFromString<CanonicalTopologyReport>(output.single())
            assertFalse(report.complete || report.runtimeValidated || report.publicActivation)
            assertTrue(report.missingCapabilities.containsAll(setOf("worklane", "tuios", "pi")))
            assertEquals(1, Files.list(root).use { it.count() }.toInt())
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    @Test fun `weekly retention and RSS enrollment reject absent inputs without creating runtime state`() {
        val root = Files.createTempDirectory("p0v3-cli-no-effects-")
        try {
            val missing = root.resolve("absent.json").toString()
            val schedule = root.resolve("schedule").toString()
            val calls = listOf(
                arrayOf("release", "weekly-restore-enroll", missing, missing, missing),
                arrayOf("release", "generation-kopia-retain", missing, "invalid-generation", "invalid-hash", "invalid-operation"),
                arrayOf("rss", "schedule-enroll", schedule, missing)
            ) + listOf("weekly-restore-units", "weekly-restore-tick", "weekly-restore-suspend", "weekly-restore-alert").map {
                arrayOf("release", it, "invalid-generation", "invalid-hash")
            }
            calls.forEach { args ->
                val output = mutableListOf<String>(); val errors = mutableListOf<String>()
                assertEquals(1, runCommand(args, output::add, errors::add), args.joinToString(" "))
                assertTrue(output.isEmpty() && errors.isNotEmpty())
                assertTrue(Files.list(root).use { it.findAny().isEmpty })
            }
        } finally { Files.delete(root) }
    }

    @Test fun `legacy active RSS is refused before opening state credentials or transport`() {
        val output = mutableListOf<String>(); val errors = mutableListOf<String>()
        assertEquals(1, runCommand(arrayOf("rss", "poll", "active", "invalid-state", "not-a-uri", "invalid-token-path"),
            output::add, errors::add))
        assertTrue(output.isEmpty())
        assertEquals(listOf("Rejected: Active RSS requires an enrolled release-bound schedule; use rss schedule-tick"), errors)
    }

    @Test fun `identity CLI rejects malformed arguments before sandbox side effects`() {
        val output = mutableListOf<String>()
        val errors = mutableListOf<String>()
        for (action in listOf("prepare", "install", "stop", "remove")) {
            assertEquals(1, runCommand(arrayOf("module", "identity", action, "extra"), output::add, errors::add))
        }
        for (action in listOf("backup", "restore", "restore-remove")) {
            assertEquals(1, runCommand(arrayOf("module", "identity", action), output::add, errors::add))
        }
        assertEquals(1, runCommand(arrayOf("module", "identity", "unknown"), output::add, errors::add))
        assertTrue(output.isEmpty() && errors.all { it.startsWith("Rejected:") })
    }
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
        output.clear()
        assertEquals(0, runCommand(arrayOf("catalog", "products"), output::add, errors::add))
        assertEquals(39, output.size)
        assertTrue(output.none { it.startsWith("portal\t") })
        assertTrue(output.all { it.endsWith("provisional-logical-product") })
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
