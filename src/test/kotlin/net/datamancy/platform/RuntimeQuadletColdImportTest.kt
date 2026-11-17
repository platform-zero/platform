package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

class RuntimeQuadletColdImportTest {
    @Test fun `tampered original tar rejects all volume effects before an import intent`() {
        val home = Files.createTempDirectory("quadlet-cold-import-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            val root = Files.createDirectory(home.resolve("generation"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val verification = Files.createDirectory(home.resolve("verify"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val original = FragmentAssemblyFixture.plan().specs.single()
            val spec = original.copy(processes = original.processes.filterNot { it.oneShot })
            val archives = spec.volumes.associate { volume -> volume.id to
                home.resolve("${volume.id}.tar").also { Files.writeString(it, "not the original archive") } }
            var nativeEffects = 0
            val commands = RuntimeCommands { _ -> nativeEffects++; RuntimeCommandResult(0, "unexpected") }
            assertFailsWith<IllegalArgumentException> {
                RuntimeQuadletColdImport(root, commands).importVolumes(spec, "a".repeat(64), archives,
                    archives.mapValues { "b".repeat(64) }, verification)
            }
            assertEquals(0, nativeEffects)
            assertTrue(Files.list(root).use { it.findAny().isEmpty })
        } finally { FragmentAssemblyFixture.remove(home) }
    }
}
