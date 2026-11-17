package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

class RuntimeQuadletResourcesTest {
    @Test fun `partial native resource effect leaves original intent and never creates a process or retries`() {
        val root = Files.createTempDirectory("quadlet-resource-ledger-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            val generation = Files.createDirectory(root.resolve("generation"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val runtime = Files.createDirectory(root.resolve("runtime"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val spec = FragmentAssemblyFixture.plan().specs.single()
            val member = Files.createDirectory(runtime.resolve(spec.name),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            val hashes = PrivateDeployment.inputNames(spec).associateWith { name ->
                val data = "original:$name".toByteArray()
                ReleasePrivateFiles.save(member.resolve(name), data)
                ReleaseLocks.sha256(data)
            }
            val fingerprint = PrivateDeployment.expectedFingerprint(spec, hashes)
            var effects = 0
            val fake = RuntimeCommands { args -> when {
                args.size == 3 && args[1] == "exists" -> RuntimeCommandResult(1, "")
                args.size > 3 && args[1] == "create" -> {
                    assertEquals("network", args.first())
                    effects++; RuntimeCommandResult(1, "lost native ACK")
                }
                else -> error("No container start or unexpected resource query: $args")
            } }
            val resources = RuntimeQuadletResources(generation, runtime, fake)
            assertFails { resources.provision(spec, fingerprint, hashes) }
            assertEquals(1, effects)
            assertTrue(Files.exists(generation.resolve("quadlet-resource-network-${spec.networks.first()}.intent.json")))
            assertFails { resources.provision(spec, fingerprint, hashes) }
            assertEquals(1, effects)
            val changed = member.resolve(PrivateDeployment.inputNames(spec).first())
            Files.writeString(changed, "foreign")
            assertFails { resources.provision(spec, fingerprint, hashes) }
            assertEquals(1, effects)
        } finally { FragmentAssemblyFixture.remove(root) }
    }
}
