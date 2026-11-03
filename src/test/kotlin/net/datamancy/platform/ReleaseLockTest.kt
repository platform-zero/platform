package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermission
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ReleaseLockTest {
    private val digest = "registry.example.test/app@sha256:${"a".repeat(64)}"
    private fun lock() = ReleaseLock(1, ProductSelection.bundled().products.map { id ->
        ProductContract(id, "1.0.0", listOf(LockedProcess("$id-web", ProcessRole.DAEMON, digest,
            emptyList(), "GET /health", emptyList(), 65532, listOf(NetworkRole.APP), emptyList())),
            emptyList(), emptyList(), listOf(Journey("login", "user can log in")))
    })
    @Test fun `39 logical products are not old container inventory or portal`() {
        val selected = ProductSelection.bundled()
        assertEquals(39, selected.products.size)
        assertTrue("portal" !in selected.products)
        ReleaseLocks.check(lock(), emptySet())
    }
    @Test fun `reject omissions mutable images dependencies cycles and self-approved routes`() {
        val full = lock()
        assertFailsWith<IllegalArgumentException> { ReleaseLocks.check(full.copy(products = full.products.drop(1)), emptySet()) }
        val first = full.products.first()
        fun replaced(p: ProductContract) = full.copy(products = listOf(p) + full.products.drop(1))
        assertFailsWith<IllegalArgumentException> { ReleaseLocks.check(replaced(first.copy(processes = first.processes.map { it.copy(image = "app:latest") })), emptySet()) }
        assertFailsWith<IllegalArgumentException> { ReleaseLocks.check(replaced(first.copy(processes = first.processes.map { it.copy(dependencies = listOf("missing")) })), emptySet()) }
        assertFailsWith<IllegalArgumentException> { ReleaseLocks.check(replaced(first.copy(processes = first.processes.map { it.copy(dependencies = listOf(it.id)) })), emptySet()) }
        assertFailsWith<IllegalArgumentException> { ReleaseLocks.check(replaced(first.copy(routes = listOf(Route("private.datamancy.net", first.processes[0].id, 443)))), emptySet()) }
        ReleaseLocks.check(replaced(first.copy(routes = listOf(Route("private.datamancy.net", first.processes[0].id, 443)))), setOf("private.datamancy.net"))
        assertFailsWith<IllegalArgumentException> { ReleaseLocks.check(replaced(first.copy(processes = first.processes.map {
            it.copy(userId = 0)
        })), emptySet()) }
        assertFailsWith<IllegalArgumentException> { ReleaseLocks.check(replaced(first.copy(processes = first.processes.map {
            it.copy(capabilities = listOf("SYS_ADMIN"))
        })), emptySet()) }
        assertFailsWith<IllegalArgumentException> { ReleaseLocks.check(replaced(first.copy(processes = first.processes.map {
            it.copy(capabilities = listOf("NET_BIND_SERVICE"))
        })), emptySet()) }
        assertFailsWith<IllegalArgumentException> { ReleaseLocks.check(replaced(first.copy(processes = first.processes.map {
            it.copy(networks = listOf(NetworkRole.INGRESS))
        })), emptySet()) }
        assertFailsWith<IllegalArgumentException> { ReleaseLocks.check(replaced(first.copy(processes = first.processes.map {
            it.copy(role = ProcessRole.TIMER)
        })), emptySet()) }
        assertFailsWith<IllegalArgumentException> { ReleaseLocks.check(replaced(first.copy(state = listOf(
            StateSet("orphan", first.id, "/data", "backup", "restore")
        ))), emptySet()) }
    }
    @Test fun `private signed checksum inputs must match bytes and forbid symlink or public files`() {
        val dir = Files.createTempDirectory("lock-test")
        try {
            val lockFile = dir.resolve("lock.json")
            val sum = dir.resolve("sum")
            val approval = dir.resolve("approved.json")
            val signatureFile = dir.resolve("signature")
            val keyFile = dir.resolve("trusted-key")
            val keys = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
            val bytes = Json.encodeToString(lock()).toByteArray()
            val signer = Signature.getInstance("Ed25519")
            signer.initSign(keys.private)
            signer.update(bytes)
            Files.write(lockFile, bytes)
            Files.writeString(sum, ReleaseLocks.sha256(bytes))
            Files.writeString(signatureFile, Base64.getEncoder().encodeToString(signer.sign()))
            Files.writeString(keyFile, Base64.getEncoder().encodeToString(keys.public.encoded))
            Files.writeString(approval, "[]")
            val privateMode = setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)
            listOf(lockFile, sum, signatureFile, keyFile, approval).forEach { Files.setPosixFilePermissions(it, privateMode) }
            assertEquals(ReleaseLocks.sha256(bytes), ReleaseLocks.validate(lockFile, sum, signatureFile, keyFile, approval).second)
            val output = mutableListOf<String>()
            val args = arrayOf(lockFile.toString(), sum.toString(), signatureFile.toString(), keyFile.toString(), approval.toString())
            assertEquals(0, runCommand(arrayOf("release", "plan") + args, output::add, { }))
            assertTrue(output.single().contains("\"executable\":false"))
            assertEquals(1, runCommand(arrayOf("release", "install") + args, output::add, { }))
            Files.writeString(sum, "0".repeat(64))
            assertFailsWith<IllegalArgumentException> { ReleaseLocks.validate(lockFile, sum, signatureFile, keyFile, approval) }
            Files.writeString(sum, ReleaseLocks.sha256(bytes))
            Files.writeString(signatureFile, Base64.getEncoder().encodeToString(ByteArray(64)))
            assertFailsWith<IllegalArgumentException> { ReleaseLocks.validate(lockFile, sum, signatureFile, keyFile, approval) }
            signer.initSign(keys.private)
            signer.update(bytes)
            Files.writeString(signatureFile, Base64.getEncoder().encodeToString(signer.sign()))
            Files.setPosixFilePermissions(lockFile, privateMode + PosixFilePermission.OTHERS_READ)
            assertFailsWith<IllegalArgumentException> { ReleaseLocks.validate(lockFile, sum, signatureFile, keyFile, approval) }
            Files.setPosixFilePermissions(lockFile, privateMode)
            val link = dir.resolve("symlink")
            Files.createSymbolicLink(link, lockFile)
            assertFailsWith<IllegalArgumentException> { ReleaseLocks.validate(link, sum, signatureFile, keyFile, approval) }
        } finally {
            Files.list(dir).use { it.forEach(Files::delete) }
            Files.delete(dir)
        }
    }
}
