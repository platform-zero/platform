package net.datamancy.platform

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class QuadletColdEvidenceTest {
    @Test fun `recovered Quadlet initializer proof is original receipt data not direct runtime jobs`() {
        val plan = FragmentAssemblyFixture.plan()
        val spec = plan.specs.single()
        val inputs = PrivateDeployment.inputNames(spec).associateWith { "a".repeat(64) }
        val fingerprint = PrivateDeployment.expectedFingerprint(spec, inputs)
        val pin = GenerationPin(GenerationMember(spec.name), "b".repeat(64), inputs, fingerprint, spec)
        val initializers = spec.processes.filter { it.oneShot }.associate { process ->
            "quadlet-member-${spec.name}-${process.id}.result.json" to
                "original-fixture-initializer-${process.id}\n".toByteArray()
        }
        val filename = initializers.keys.first()
        val receipt = QuadletCapacityTerminalObservation(generation = plan.generation.id,
            bundleSha256 = "c".repeat(64), member = spec.name, fingerprint = fingerprint,
            fenceId = "00000000-0000-0000-0000-000000000001",
            originalEvidenceSha256 = initializers.mapValues { (_, bytes) -> ReleaseLocks.sha256(bytes) },
            installedPolicy = emptyMap(), stoppedCids = spec.processes.associate { it.id to "d".repeat(64) },
            originalServeAcknowledged = true)
        // A real terminal observation also contains every delegation/launch/stop
        // digest; this fixture exercises the authenticated payload partition.
        val terminal = Json.encodeToString(receipt).toByteArray()
        val entry = QuadletColdSourceEvidence(spec.name, ReleaseLocks.sha256(terminal), initializers.keys.toList())
        val paths = mapOf(QuadletColdEvidence.terminal(spec.name) to terminal) +
            initializers.mapKeys { (name, _) -> QuadletColdEvidence.original(spec.name, name) }
        val frozen = FrozenRuntimeObservation(spec.name, fingerprint, receipt.fenceId,
            QuadletColdEvidence.ledgerHash(spec, receipt), spec.processes.filter { it.oneShot }.map { it.id }.toSet(),
            spec.processes.map { RuntimeStatus(it.id, if (it.oneShot) "completed" else "exited", 0) })
        val manifest = CapsuleManifest(id = "cap-123456789abc", generation = plan.generation.id,
            bundleSha256 = receipt.bundleSha256, members = listOf(frozen),
            files = paths.map { (name, bytes) -> CapsuleFile(name, bytes.size.toLong(), ReleaseLocks.sha256(bytes)) },
            quadletSources = listOf(entry))
        QuadletColdEvidence.validate(manifest)
        assertEquals(paths.keys, QuadletColdEvidence.verifyRecovered(entry, pin, frozen, manifest) { paths.getValue(it) })
        assertFails { QuadletColdEvidence.verifyRecovered(entry, pin, frozen, manifest) {
            if (it == QuadletColdEvidence.original(spec.name, filename)) "changed".toByteArray() else paths.getValue(it)
        } }
        assertFails { QuadletColdEvidence.verifyRecovered(entry, pin, frozen.copy(jobsSha256 = "e".repeat(64)), manifest) { paths.getValue(it) } }
        assertFails { QuadletColdEvidence.validate(manifest.copy(files = manifest.files.dropLast(1))) }
        assertFails { QuadletColdEvidence.validate(manifest.copy(quadletSources = listOf(entry.copy(originalFiles = listOf("runtime.jobs"))))) }
        assertFails { QuadletColdEvidence.validate(manifest.copy(quadletSources = emptyList())) }
    }
}
