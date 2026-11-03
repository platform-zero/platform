package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PrivateQuadletsTest {
    private val digest = "example.org/app@sha256:${"b".repeat(64)}"
    private fun lock(): ReleaseLock {
        val products = ProductSelection.bundled().products.map { id ->
            val process = if (id == "mastodon-rss-publisher") LockedProcess(id, ProcessRole.TIMER, digest,
                listOf("mastodon"), "last poll outcome", listOf("BOT_TOKEN"), 65532,
                listOf(NetworkRole.APP), listOf("rss-state"), "*-*-* *:30:00")
            else LockedProcess(id, ProcessRole.DAEMON, digest, emptyList(), "GET /health", emptyList(),
                65532, if (id == "caddy") listOf(NetworkRole.APP, NetworkRole.INGRESS) else listOf(NetworkRole.APP),
                if (id == "ntfy") listOf("cache") else emptyList(),
                capabilities = if (id == "caddy") listOf("NET_BIND_SERVICE") else emptyList())
            ProductContract(id, "1.0.0", listOf(process),
                when (id) {
                    "mastodon-rss-publisher" -> listOf(StateSet("rss-state", id, "/data", "dump", "restore"))
                    "ntfy" -> listOf(StateSet("cache", id, "/var/cache/ntfy", "backup", "restore"))
                    else -> emptyList()
                }, if (id == "caddy") listOf(Route("datamancy.net", "caddy", 443)) else emptyList(),
                listOf(Journey("read", "real outcome")))
        }
        return ReleaseLock(1, products)
    }
    @Test fun `offline private unit types have store arguments and non-root users`() {
        val temp = Files.createTempDirectory("p0v3-quadlet-")
        try {
            val bundle = PrivateQuadlets.render(lock(), setOf("datamancy.net"), temp.resolve("release"))
            assertEquals(39, bundle.files.keys.count { it.endsWith(".container") })
            assertEquals(3, bundle.files.keys.count { it.endsWith(".network") })
            assertEquals(2, bundle.files.keys.count { it.endsWith(".volume") })
            assertEquals(1, bundle.files.keys.count { it.endsWith(".timer") })
            assertTrue(bundle.files.getValue("p0v3-caddy.container").contains("AddCapability=NET_BIND_SERVICE"))
            assertTrue(!bundle.files.getValue("p0v3-ntfy.container").contains("AddCapability="))
            assertTrue(bundle.files.getValue("p0v3-ntfy.container").contains("Volume=p0v3-ntfy-cache.volume:/var/cache/ntfy"))
            assertTrue(bundle.files.getValue("p0v3-mastodon-rss-publisher.container").contains("Secret=p0v3-mastodon-rss-publisher-bot_token,type=mount"))
            assertTrue(bundle.files.getValue("p0v3-mastodon-rss-publisher.timer").contains("Persistent=false"))
            assertTrue(bundle.files.filterKeys { !it.endsWith(".timer") }.values.all {
                it.contains("GlobalArgs=--root=${bundle.graphRoot} --runroot=${bundle.runRoot}")
            })
            assertTrue(bundle.files.filterKeys { it.endsWith(".container") }.values.all {
                it.contains("Pull=never") && it.contains("DropCapability=all") && it.contains("User=65532")
            })
            val output = bundle.files.keys.filterNot { it.endsWith(".timer") }.joinToString("\n") {
                "ExecStart=/usr/bin/podman --root=${bundle.graphRoot} --runroot=${bundle.runRoot} create $it"
            }
            var calls = 0
            var generated: Path? = null
            assertEquals(bundle.files.size, QuadletDryRun.verify(bundle) { args, units, timeout ->
                calls++
                if (args == listOf("--version")) {
                    assertEquals(null, units); assertEquals(5, timeout)
                    RuntimeCommandResult(0, "5.4.2\n")
                } else {
                    assertEquals(listOf("--dryrun"), args); assertEquals(20, timeout)
                    generated = units
                    bundle.files.forEach { (name, contents) -> assertEquals(contents, Files.readString(units!!.resolve(name))) }
                    RuntimeCommandResult(0, output)
                }
            })
            assertEquals(2, calls)
            assertTrue(!Files.exists(generated!!))
            for (bad in listOf(output.replace(" --root=${bundle.graphRoot} ", " --root=/var/lib/containers/storage "),
                output.replace(" create ", " --pull always create "), output + "\nwarning: bad unit", "")) {
                assertFailsWith<IllegalArgumentException> { PrivateQuadlets.verifyGeneratorOutput(bundle, bad) }
            }
            assertFailsWith<IllegalArgumentException> { QuadletDryRun.verify(bundle) { _, _, _ -> RuntimeCommandResult(0, "5.5.0") } }
            for (reply in listOf(RuntimeCommandResult(1, "rejected"), RuntimeCommandResult(0, "x".repeat(2_000_001)))) {
                assertFailsWith<IllegalArgumentException> { QuadletDryRun.verify(bundle) { args, _, _ ->
                    if (args == listOf("--version")) RuntimeCommandResult(0, "5.4.2") else reply
                } }
            }
            assertFailsWith<IllegalArgumentException> { QuadletDryRun.verify(bundle.copy(files = mapOf("../escape" to "bad"))) {
                _, _, _ -> RuntimeCommandResult(0, "5.4.2")
            } }
        } finally {
            Files.walk(temp).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
    @Test fun `unsafe roots and unapproved routes cannot render`() {
        assertFailsWith<IllegalArgumentException> { PrivateQuadlets.render(lock(), emptySet(), Path.of("/tmp/v3/release")) }
        assertFailsWith<IllegalArgumentException> { PrivateQuadlets.render(lock(), setOf("datamancy.net"), Path.of("/var/lib/containers/graph")) }
    }
}
