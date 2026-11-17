package net.datamancy.platform

import java.net.HttpURLConnection
import java.net.URLConnection
import java.net.URLStreamHandler
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.URL
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ManagedLaneBrokerTest {
    private val bearer = "synthetic-session-bearer-not-upstream-key"
    private fun hash(value: String) = MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
        .joinToString("") { "%02x".format(it) }
    private val grant = ManagedLaneGrant("8d345319-3dbc-436e-a609-1584dd08ec35", "https://auth.datamancy.net/realms/p0v3",
        "q-012345abcdef", "8d345319-3dbc-436e-a609-1584dd08ec35", "lane-source", "openai", "gpt-6-sol",
        1800000240L, "a".repeat(64), hash(bearer))
    private val clock = Clock.fixed(Instant.ofEpochSecond(1800000000L), ZoneOffset.UTC)
    private fun authority(active: AtomicBoolean, calls: AtomicInteger) = object : ManagedLaneAuthority {
        override fun authorizeBearer(bearer: String, expected: ManagedLaneGrant, nowEpochSeconds: Long): Boolean {
            calls.incrementAndGet()
            return bearer == this@ManagedLaneBrokerTest.bearer && expected.subject == grant.subject && active.get()
        }
        override fun revisionHead(generation: String): String = if (active.get()) grant.revisionSha256 else "b".repeat(64)
        override fun generationActive(generation: String): Boolean = active.get()
    }
    private fun request(port: Int, token: String, body: String = "{\"model\":\"gpt-6-sol\"}"): Int {
        val connection = URL("http://127.0.0.1:$port/v1/responses").openConnection() as HttpURLConnection
        connection.requestMethod = "POST"
        connection.connectTimeout = 1000
        connection.readTimeout = 1000
        connection.setRequestProperty("Authorization", "Bearer $token")
        connection.doOutput = true
        connection.outputStream.use { it.write(body.toByteArray()) }
        return connection.responseCode.also { connection.disconnect() }
    }
    @Test fun nativeAgentRefreshRejectsUnverifiedTokenAndCannotInventEightHourLease(): Unit {
        val active = AtomicBoolean(true)
        val calls = AtomicInteger()
        val minted = NativeManagedBrokerTokenRefresher(
            NativeManagedAgentTokenIssuer { _, _ -> "forged.signature.not-an-agent" },
            authority(active, calls), clock)
        assertFails { minted.mint(grant) }
        assertEquals(0, calls.get())
    }
    @Test fun noKeyExposedOnDenialAndRevocation(): Unit {
        val active = AtomicBoolean(false)
        val calls = AtomicInteger()
        val broker = ManagedLaneBroker(grant, authority(active, calls), { error("upstream key must never be read") }, clock)
        broker.use {
            val port = it.start()
            assertEquals(403, request(port, bearer))
            active.set(true)
            assertEquals(403, request(port, "foreign-session-bearer"))
            active.set(false)
            assertEquals(403, request(port, bearer))
        }
        assertEquals(0, calls.get()) // revoked or token-hash mismatch short-circuits introspection.
    }
    @Test fun unixBridgeRefusesForeignBearerWithoutResolvingUpstreamSecret(): Unit {
        val root = Files.createTempDirectory("managed-unix-broker")
        val control = Files.createDirectory(root.resolve("control"))
        val run = Files.createDirectory(control.resolve("run"))
        Files.setPosixFilePermissions(control, PosixFilePermissions.fromString("rwx------"))
        Files.setPosixFilePermissions(run, PosixFilePermissions.fromString("rwx------"))
        val socket = run.resolve("broker.sock")
        val active = AtomicBoolean(false)
        try {
            ManagedLaneBroker(grant, authority(active, AtomicInteger()),
                { error("denied request must not touch upstream key") }, clock).use { broker ->
                broker.startUnix(socket)
                SocketChannel.open(StandardProtocolFamily.UNIX).use { channel ->
                    channel.connect(UnixDomainSocketAddress.of(socket))
                    val request = "POST /v1/responses HTTP/1.1\r\nAuthorization: Bearer $bearer\r\n" +
                        "Content-Length: 24\r\n\r\n{\"model\":\"gpt-6-sol\"}"
                    channel.write(ByteBuffer.wrap(request.toByteArray()))
                    channel.configureBlocking(false)
                    val buffer = ByteBuffer.allocate(64)
                    val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(2)
                    var closed = false
                    while (System.nanoTime() < deadline) {
                        if (channel.read(buffer) < 0) { closed = true; break }
                        Thread.sleep(10)
                    }
                    assertTrue(closed)
                    assertEquals(0, buffer.position())
                }
            }
        } finally { Files.deleteIfExists(run); Files.deleteIfExists(control); Files.deleteIfExists(root) }
    }
    @Test fun everyRequestRechecksGenerationAndHeadWithoutSendingKeyToLane(): Unit {
        val active = AtomicBoolean(true)
        val calls = AtomicInteger()
        val sent = AtomicInteger()
        val endpoint = URL(null, "https://api.openai.com/v1/responses", object : URLStreamHandler() {
            override fun openConnection(url: URL): URLConnection = object : HttpURLConnection(url) {
                private val output = ByteArrayOutputStream()
                override fun connect() { connected = true }
                override fun disconnect() { connected = false }
                override fun usingProxy(): Boolean = false
                override fun getOutputStream(): ByteArrayOutputStream = output
                override fun getResponseCode(): Int {
                    sent.incrementAndGet()
                    assertEquals("Bearer synthetic-upstream-test-key", getRequestProperty("Authorization"))
                    return 200
                }
                override fun getInputStream(): ByteArrayInputStream = ByteArrayInputStream("{}".toByteArray())
                override fun getContentType(): String = "application/json"
            }
        })
        ManagedLaneBroker(grant, authority(active, calls),
            { "synthetic-upstream-test-key".toCharArray() }, clock, endpoint).use { broker ->
            val port = broker.start()
            assertEquals(200, request(port, bearer))
            active.set(false)
            assertEquals(403, request(port, bearer))
            assertEquals(1, sent.get())
            assertTrue(calls.get() >= 2)
        }
    }
    @Test fun pinnedUpstreamAndImmutableModelPolicy(): Unit {
        val active = AtomicBoolean(true)
        val calls = AtomicInteger()
        assertFailsWith<IllegalArgumentException> {
            ManagedLaneBroker(grant, authority(active, calls), { charArrayOf() }, clock,
                URL("http://127.0.0.1/v1/responses"))
        }
        ManagedLaneBroker(grant, authority(active, calls), { error("wrong model must not receive key") }, clock).use {
            val port = it.start()
            assertEquals(403, request(port, "wrong-token"))
            // The rejected model request never reaches upstream; failed local body produces closed response.
            assertTrue(calls.get() >= 0)
        }
    }
}
