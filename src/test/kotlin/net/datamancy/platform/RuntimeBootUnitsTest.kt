package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class RuntimeBootUnitsTest {
    private val hash = "a".repeat(64)
    private fun spec() = PrivateDeploymentSpec(name = "boot-test", volumes = emptyList(), processes = listOf(
        RuntimeProcess("app", "example.org/app@sha256:$hash", "b".repeat(64), 1000, readiness = listOf("check"))))

    @Test fun `unit pins controller manifest identity and dedicated paths without timer or updater`() {
        val unit = RuntimeBootUnits.render(spec(), hash, "c".repeat(64), 1000)
        assertContains(unit, "/runtime-supervision/releases/${"c".repeat(64)}/bin/p0-v3-platform runtime boot-apply boot-test $hash")
        assertContains(unit, "runtime boot-stop boot-test $hash")
        assertContains(unit, "User=1000\n")
        assertContains(unit, "RemainAfterExit=yes")
        assertContains(unit, "KillMode=process")
        assertContains(unit, "Restart=no")
        assertContains(unit, "TimeoutStopSec=180")
        assertFalse(unit.contains("OnCalendar"))
        assertFalse(unit.contains("pull "))
        for (uid in listOf(0, -1, 65535)) assertFailsWith<IllegalArgumentException> { RuntimeBootUnits.render(spec(), hash, hash, uid) }
        assertFailsWith<IllegalArgumentException> { RuntimeBootUnits.render(spec(), "../bad", hash, 1000) }
        assertFailsWith<IllegalArgumentException> { RuntimeBootUnits.render(spec(), hash, "$hash\nExecStart=/bad", 1000) }
        assertFailsWith<IllegalArgumentException> { RuntimeBootUnits.render(spec().copy(name = "bad%name"), hash, hash, 1000) }
    }
    @Test fun `historical boot wrapper cannot accidentally enroll a Quadlet generation`() {
        val fragment = FragmentAssemblyFixture.plan().specs.single()
        assertFailsWith<IllegalArgumentException> {
            RuntimeBootUnits.render(fragment, hash, "c".repeat(64), 1000)
        }.also { assertContains(it.message.orEmpty(), "direct-Podman fallback refused") }
    }

    @Test fun `bound inputs refuse content drift identity drift symlinks and path injection`() {
        val base = Files.createTempDirectory("boot-unit-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            val path = RuntimeBootUnits.manifest("boot-test", base)
            Files.createFile(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            val bytes = Json.encodeToString(spec()).toByteArray()
            Files.write(path, bytes)
            val digest = RuntimeBootUnits.hash(bytes)
            assertEquals(spec(), RuntimeBootUnits.boundSpec("boot-test", digest, base))
            assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", RuntimeBootUnits.hash(byteArrayOf()))
            assertFailsWith<IllegalArgumentException> { RuntimeBootUnits.boundSpec("boot-test", "bad", base) }
            Files.writeString(path, Json.encodeToString(spec().copy(name = "other")))
            assertFailsWith<IllegalArgumentException> { RuntimeBootUnits.boundSpec("boot-test", digest, base) }
            assertFailsWith<IllegalArgumentException> { RuntimeBootUnits.boundSpec("boot-test", RuntimeBootUnits.hash(Files.readAllBytes(path)), base) }
            Files.delete(path)
            Files.createSymbolicLink(path, base.resolve("absent"))
            assertFails { RuntimeBootUnits.boundSpec("boot-test", digest, base) }
            for (name in listOf("../other", "bad\nunit", "bad%unit", "/absolute"))
                assertFailsWith<IllegalArgumentException> { RuntimeBootUnits.manifest(name, base) }
        } finally { Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `CLI rejects malformed boot operations before live effects`() {
        val errors = mutableListOf<String>()
        assertEquals(1, runCommand(arrayOf("runtime", "boot-apply", "../other", hash), {}, errors::add))
        assertEquals(1, runCommand(arrayOf("runtime", "boot-stop", "boot-test", "bad"), {}, errors::add))
        assertEquals(1, runCommand(arrayOf("runtime", "boot-unit", "../other", hash, "1000"), {}, errors::add))
        assertTrue(errors.all { it.startsWith("Rejected:") })
    }
}
