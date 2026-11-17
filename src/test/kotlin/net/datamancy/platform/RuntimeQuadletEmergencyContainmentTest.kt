package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RuntimeQuadletEmergencyContainmentTest {
    @Test fun `negative exit observation binds only original uncertain emergency intent never a stop result`() {
        val parent = Files.createTempDirectory("quadlet-uncertain-stop-")
        val generation = "q-123456abcdef"
        val root = Files.createDirectory(parent.resolve(generation),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val member = "$generation-canonical-shared-core-v3"
        val process = RuntimeProcess("identity-realm-init", "keycloak@test", "a".repeat(64),
            userId = 1000, oneShot = true)
        val spec = PrivateDeploymentSpec(name = member, volumes = emptyList(), processes = listOf(process),
            store = RuntimeStore.CANONICAL_V2, executionBackend = RuntimeExecutionBackend.QUADLET_V2)
        val fingerprint = "f".repeat(64)
        val cid = "b".repeat(64)
        val fence = "fixed-fence"
        val stop = root.resolve("quadlet-delegate-$member-${process.id}-stop.intent.json")
        val emergency = root.resolve("quadlet-emergency-$member-${process.id}.intent.json")
        val originalStop = root.resolve("quadlet-stop-$member-${process.id}.intent.json")
        val result = root.resolve("quadlet-emergency-$member-${process.id}.result.json")
        val observed = QuadletUnacknowledgedCid(cid, process.imageId, -1, "native-read-only")
        try {
            ReleasePrivateFiles.save(stop, "original stop delegation".toByteArray())
            val binding = QuadletEmergencyContainment(generation, "e".repeat(64), member,
                process.id, cid, process.imageId, fingerprint,
                ReleaseLocks.sha256(ReleasePrivateFiles.read(stop, 8192)), fence,
                "independent-owner-death-emergency-stop-not-original-stop-ack")
            ReleasePrivateFiles.save(emergency, Json { encodeDefaults = true }.encodeToString(binding).toByteArray())
            fun observe() = RuntimeQuadletEmergencyContainment.uncertainStoppedIntentSha256(
                root, "e".repeat(64), spec, process, fingerprint, fence, observed)
            assertEquals(ReleaseLocks.sha256(ReleasePrivateFiles.read(emergency, 8192)), observe())
            ReleasePrivateFiles.save(originalStop, "uncertain original effect".toByteArray())
            assertFails { observe() }
            Files.delete(originalStop)
            ReleasePrivateFiles.save(result, "unacknowledged result".toByteArray())
            assertFails { observe() }
            Files.delete(result)
            assertFails { RuntimeQuadletEmergencyContainment.uncertainStoppedIntentSha256(
                root, "e".repeat(64), spec, process, fingerprint, fence, observed.copy(cid = "c".repeat(64))) }
        } finally {
            Files.deleteIfExists(emergency); Files.deleteIfExists(stop); Files.deleteIfExists(root); Files.delete(parent)
        }
    }
    @Test fun `any original stop or owner-loss intent forbids a different emergency operation id`() {
        val root = Files.createTempDirectory("original-quadlet-stop-proof-")
        val member = "q-123456abcdef-canonical-shared-core-v3"
        val process = "identity-realm-init"
        try {
            assertTrue(RuntimeQuadletEmergencyContainment.originalNativeStopUnissued(root, member, process))
            for (stem in listOf("quadlet-stop-$member-$process.intent.json",
                "quadlet-stop-$member-$process.result.json",
                "quadlet-stop-$member-$process.reconciliation.json",
                "quadlet-owner-loss-$member-$process.intent.json",
                "quadlet-owner-loss-$member-$process.result.json")) {
                val path = root.resolve(stem)
                Files.writeString(path, "original effect or uncertainty")
                assertFalse(RuntimeQuadletEmergencyContainment.originalNativeStopUnissued(root, member, process))
                Files.delete(path)
            }
        } finally { Files.delete(root) }
    }
}
