package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import kotlin.test.*

class FreshManagedDeviceGrantSourceTest {
    @TempDir lateinit var temp: Path
    private val generation = "q-012345abcdef"
    private val subject = "a5e2cab1-851b-49fe-8f14-6b40f8712447"
    private fun root(): Path {
        val root = temp.resolve(generation)
        Files.createDirectories(root.resolve("managed/control"))
        for (p in listOf(root,root.resolve("managed"),root.resolve("managed/control")))
            Files.setPosixFilePermissions(p,PosixFilePermissions.fromString("rwx------"))
        return root
    }
    @Test fun `device grants are owner-generation bound and once disclosed, revocable and expire`() {
        val root = root()
        var now = Instant.ofEpochSecond(1750000000)
        var active = true
        val clock = object : Clock() {
            override fun getZone() = ZoneOffset.UTC
            override fun withZone(zone: java.time.ZoneId) = this
            override fun instant() = now
        }
        val grants = FreshManagedDeviceGrantStore(generation,subject,{active},clock,root)
        grants.prepare()
        val token = grants.issue("a".repeat(32))
        assertTrue(token.startsWith("p0d_") && grants.valid(token))
        assertFalse(grants.valid(token + "x"))
        assertFailsWith<IllegalArgumentException> { grants.issue("a".repeat(32)) }
        assertFalse(Files.readString(root.resolve("managed/control/device-grants/" + "a".repeat(32) + ".result.json"))
            .contains(token))
        active = false
        assertFalse(grants.valid(token))
        active = true
        grants.revoke("a".repeat(32))
        assertFalse(grants.valid(token))
        assertFailsWith<java.nio.file.FileAlreadyExistsException> { grants.revoke("a".repeat(32)) }
        val second = grants.issue("b".repeat(32))
        now = now.plusSeconds(3600)
        assertFalse(grants.valid(second))
    }
    @Test fun `uncertain issuance intent cannot be replayed`() {
        val root=root();val grants=FreshManagedDeviceGrantStore(generation,subject,{true},
            Clock.fixed(Instant.ofEpochSecond(1750000000),ZoneOffset.UTC),root)
        grants.prepare()
        ReleasePrivateFiles.save(root.resolve("managed/control/device-grants/"+"c".repeat(32)+".intent.json"),
            "uncertain\n".toByteArray())
        assertFailsWith<IllegalArgumentException> { grants.issue("c".repeat(32)) }
    }
}
