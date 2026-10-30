package net.datamancy.platform

import java.net.HttpURLConnection
import java.net.Proxy
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Opt-in real Podman test, never part of ordinary unit-test side effects. Only the dedicated ntfy sandbox. */
class NtfyRealIntegrationTest {
    private fun request(port: Int, path: String, message: String? = null): String {
        val connection = URI("http://127.0.0.1:$port/$path").toURL().openConnection(Proxy.NO_PROXY) as HttpURLConnection
        connection.connectTimeout = 1000
        connection.readTimeout = 3000
        if (message != null) {
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.outputStream.use { it.write(message.toByteArray()) }
        }
        try {
            assertEquals(200, connection.responseCode)
            return connection.inputStream.bufferedReader().use { it.readText() }
        } finally { connection.disconnect() }
    }

    private fun ready(port: Int) {
        repeat(20) {
            if (runCatching { request(port, "v1/health").contains("\"healthy\":true") }.getOrDefault(false)) return
            Thread.sleep(500)
        }
        error("ntfy never became healthy on loopback $port")
    }

    private fun digest(path: Path): String = MessageDigest.getInstance("SHA-256")
        .digest(Files.readAllBytes(path)).joinToString("") { "%02x".format(it) }

    @Test fun `official digest publish and isolated functional restore plus two sandbox reinstalls`() {
        assumeTrue(System.getenv("P0V3_NTFY_SANDBOX_INTEGRATION") == "1", "Requires deliberate opt-in and preloaded official digest")
        val id = "it" + System.nanoTime().toString(36).replace('-', 'x').takeLast(14)
        val topic = "p0v3-$id"
        val service = NtfySandbox.real()
        service.prepare()
        try {
            service.install()
            ready(18486)
            assertTrue(request(18486, topic, "original-$id").contains("original-$id"))
            assertTrue(request(18486, "$topic/json?poll=1").contains("original-$id"))
            service.stop()
            service.snapshot(id)
            val snapshot = Path.of("/mnt/media/p0-v3/backup/ntfy-fixture/$id/cache.db")
            assertTrue(Files.size(snapshot) > 0)
            service.restore(id)
            ready(18487)
            assertTrue(request(18487, "$topic/json?poll=1").contains("original-$id"))
            assertTrue(request(18487, topic, "restored-new-$id").contains("restored-new-$id"))
            assertTrue(request(18487, "$topic/json?poll=1").contains("restored-new-$id"))
            assertTrue(Files.readString(snapshot.parent.resolve(".manifest")).contains(digest(snapshot)))
            service.removeRestore(id)
            service.remove()
            repeat(2) { cycle ->
                service.install()
                ready(18486)
                assertTrue(request(18486, "$topic/json?poll=1").contains("original-$id"))
                assertTrue(request(18486, topic, "cycle-$cycle-$id").contains("cycle-$cycle-$id"))
                service.stop()
                service.remove()
            }
        } finally {
            // Refuses foreign containers; preserve backup/data for inspection. Never delete directories or other workloads.
            runCatching { service.removeRestore(id) }
            runCatching { service.remove() }
        }
    }
}
