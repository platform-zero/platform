package net.datamancy.platform

import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

class NotebookParentControlSocketTest {
    private fun dir(parent: Path, name: String) = Files.createDirectory(parent.resolve(name),
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    @Test fun `only sealed user's key and generation reach serialized typed parent effects`() {
        val base = Files.createTempDirectory("notebook-parent-",PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------")))
        val gen = "q-012345abcdef"
        val member = "$gen-jupyterhub"
        val root = dir(base,gen)
        val runtime = dir(base,"runtime")
        val memberRoot = dir(runtime,member)
        val settings = """{"notebookGeneration":"$gen","servers":{"alice":{"parentControlKey":"${"a".repeat(64)}"},"bob":{"parentControlKey":"${"b".repeat(64)}"}}}"""
        val input = memberRoot.resolve("jupyterhub-hub-settings.json")
        ReleasePrivateFiles.save(input,settings.toByteArray())
        val effects = AtomicInteger()
        val socket = NotebookParentControlSocket(root,member,ReleaseLocks.sha256(settings.toByteArray()),
            NotebookParentEffects { user, action, intent ->
                assertEquals("alice",user); assertEquals(NotebookParentAction.START,action)
                assertEquals("1".repeat(32),intent); effects.incrementAndGet()
                NotebookParentReply(201)
            },runtime,base,ownerAuthorized = { true })
        fun exchange(key: String, generation: String = gen): String {
            SocketChannel.open(StandardProtocolFamily.UNIX).use { channel ->
                channel.connect(UnixDomainSocketAddress.of(root.resolve("notebooks/control.sock")))
                val message = "POST /v1/notebooks/alice/start HTTP/1.1\r\nHost: p0-notebook-parent\r\nAuthorization: Bearer $key\r\nX-P0-Generation: $generation\r\nX-P0-Notebook-User: alice\r\nX-P0-Intent: ${"1".repeat(32)}\r\nContent-Length: 0\r\n\r\n"
                channel.write(ByteBuffer.wrap(message.toByteArray()))
                val reply = ByteBuffer.allocate(2048)
                while (channel.read(reply) > 0) {}
                return reply.array().copyOf(reply.position()).decodeToString()
            }
        }
        try {
            socket.start()
            assertTrue(exchange("b".repeat(64)).startsWith("HTTP/1.1 503"))
            assertTrue(exchange("a".repeat(64),"q-abcdef012345").startsWith("HTTP/1.1 503"))
            assertEquals(0,effects.get())
            assertTrue(exchange("a".repeat(64)).startsWith("HTTP/1.1 201"))
            assertEquals(1,effects.get())
        } finally {
            socket.close()
            Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}
