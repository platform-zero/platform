package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*
import kotlinx.serialization.json.Json

class CanonicalPrivateImageStagingTest {
    private val bytes = GenerationAssembly.readInventory(java.nio.file.Path.of("release/downloaded-candidate-inventory.json"))
    private val image = Json.decodeFromString<AcquiredInventory>(bytes.decodeToString()).images.single { it.product == "kopia" }
    private val info = """{"store":{"graphRoot":"${RuntimeStore.CANONICAL_V2.graph}","runRoot":"${RuntimeStore.CANONICAL_V2.run}"},"host":{"security":{"rootless":false,"apparmorEnabled":true,"seccompEnabled":true}}}"""
    private val native = """[{"Id":"sha256:${image.imageId}","Digest":"${image.selectedManifestDigest}","Architecture":"amd64","Os":"linux"}]"""
    private fun root() = Files.createTempDirectory("canonical-private-images-",
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))

    @Test fun `original digest pull is once only and keeps its own ACK distinct from image readback`() {
        val root = root()
        try {
            var present = false; var pulls = 0
            val commands = RuntimeCommands { args -> when (args.first()) {
                "info" -> RuntimeCommandResult(0, info)
                "image" -> if (present) RuntimeCommandResult(0, native) else RuntimeCommandResult(1, "")
                "pull" -> {
                    assertEquals(listOf("pull", "--quiet", "--platform=linux/amd64", image.pinnedImage), args)
                    present = true; pulls++; RuntimeCommandResult(0, image.imageId)
                }
                else -> error("Unexpected native command $args")
            } }
            val staging = CanonicalPrivateImageStaging(root, commands) {}
            assertNull(staging.audit(bytes, "kopia"))
            val result = staging.stage(bytes, "kopia")
            assertTrue(result.originalPullAcknowledged)
            assertFalse(result.alreadyPresent)
            assertEquals(image.imageId, result.imageId)
            assertTrue(Files.exists(root.resolve("kopia.pull.intent.json")))
            assertTrue(Files.exists(root.resolve("kopia.pull.result.json")))
            assertEquals(1, pulls)
            assertFails { staging.stage(bytes, "kopia") }
            assertEquals(1, pulls)
            assertTrue(staging.audit(bytes, "kopia")?.alreadyPresent == true)
        } finally { FragmentAssemblyFixture.remove(root) }
    }
    @Test fun `unknown pull result retains one-use original intent and cannot be replayed`() {
        val root = root()
        try {
            var pulls = 0
            val commands = RuntimeCommands { args -> when (args.first()) {
                "info" -> RuntimeCommandResult(0, info)
                "image" -> RuntimeCommandResult(1, "")
                "pull" -> { pulls++; RuntimeCommandResult(125, "") }
                else -> error("Unexpected native command $args")
            } }
            val staging = CanonicalPrivateImageStaging(root, commands) {}
            assertFails { staging.stage(bytes, "kopia") }
            assertTrue(Files.exists(root.resolve("kopia.pull.intent.json")))
            assertFalse(Files.exists(root.resolve("kopia.pull.result.json")))
            assertFails { staging.stage(bytes, "kopia") }
            assertEquals(1, pulls)
        } finally { FragmentAssemblyFixture.remove(root) }
    }
    @Test fun `assembled closure skips prior originals by native readback without another pull`() {
        val root = root()
        try {
            val images = Json.decodeFromString<AcquiredInventory>(bytes.decodeToString()).images.associateBy { it.pinnedImage }
            var nativeInspections = 0
            val commands = RuntimeCommands { args -> when (args.first()) {
                "info" -> RuntimeCommandResult(0, info)
                "image" -> {
                    nativeInspections++
                    val pin = images.getValue(args.last())
                    RuntimeCommandResult(0, """[{"Id":"sha256:${pin.imageId}","Digest":"${pin.selectedManifestDigest}","Architecture":"amd64","Os":"linux"}]""")
                }
                else -> error("Closure must not acquire a second image")
            } }
            val staging = CanonicalPrivateImageStaging(root, commands) {}
            val order = images.values.map { it.product }
            val first = staging.stageAll(bytes, order)
            assertEquals(order.size, first.size)
            assertTrue(first.all { it.alreadyPresent && !it.originalPullAcknowledged })
            assertEquals(first, staging.stageAll(bytes, order))
            assertEquals(first, staging.auditAll(bytes, order))
            assertEquals(order.size, Files.list(root).use { list ->
                list.filter { it.fileName.toString().endsWith(".already-present.observation.json") }.count().toInt()
            })
            val beforeIncompleteAudit = nativeInspections
            Files.delete(root.resolve("${order.last()}.already-present.observation.json"))
            assertFails { staging.auditAll(bytes, order) }
            assertEquals(beforeIncompleteAudit, nativeInspections, "Incomplete closure must fail before native inspection")
        } finally { FragmentAssemblyFixture.remove(root) }
    }
    @Test fun `read-only closure audit binds original pull intent and cannot invent a missing ACK`() {
        val root = root()
        try {
            val single = Json.encodeToString(AcquiredInventory(1,
                "downloaded-candidates-not-a-reviewed-compatible-release", listOf(image))).toByteArray()
            var present = false; var pulls = 0; var inspections = 0
            val commands = RuntimeCommands { args -> when (args.first()) {
                "info" -> RuntimeCommandResult(0, info)
                "image" -> { inspections++; if (present) RuntimeCommandResult(0, native) else RuntimeCommandResult(1, "") }
                "pull" -> { pulls++; present = true; RuntimeCommandResult(0, image.imageId) }
                else -> error("No other native effect allowed")
            } }
            val staging = CanonicalPrivateImageStaging(root, commands) {}
            assertTrue(staging.stageAll(single, listOf("kopia")).single().originalPullAcknowledged)
            assertEquals(1, pulls)
            assertEquals(1, staging.auditAll(single, listOf("kopia")).size)
            val beforeTamper = inspections
            Files.writeString(root.resolve("kopia.pull.intent.json"), "{}")
            assertFails { staging.auditAll(single, listOf("kopia")) }
            assertEquals(beforeTamper, inspections, "Original intent is checked before any native image inspection")
            assertEquals(1, pulls)
        } finally { FragmentAssemblyFixture.remove(root) }
    }
    @Test fun `already pinned image is observation not a fabricated pull ACK`() {
        val root = root()
        try {
            val commands = RuntimeCommands { args -> when (args.first()) {
                "info" -> RuntimeCommandResult(0, info)
                "image" -> RuntimeCommandResult(0, native)
                else -> error("No image pull permitted")
            } }
            val result = CanonicalPrivateImageStaging(root, commands) {}.stage(bytes, "kopia")
            assertTrue(result.alreadyPresent)
            assertFalse(result.originalPullAcknowledged)
            assertTrue(Files.exists(root.resolve("kopia.already-present.observation.json")))
            assertFalse(Files.exists(root.resolve("kopia.pull.intent.json")))
        } finally { FragmentAssemblyFixture.remove(root) }
    }
}
