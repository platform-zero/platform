package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class OwnedReleaseUpdateTest {
    private val json = Json { encodeDefaults = true }
    private data class Fixture(val source: GenerationBundle, val old: ByteArray, val next: ByteArray,
        val intent: ReleaseUpdateIntent, val receipt: KopiaSnapshotReceipt)
    private fun fixture(): Fixture {
        val observed = Json.decodeFromString<AcquiredInventory>(GenerationAssembly.readInventory(Path.of("release/downloaded-candidate-inventory.json")).decodeToString())
        val old = observed.copy(images = observed.images.map { if (it.product != "planka") it else it.copy(
            reference = "ghcr.io/plankanban/planka:2.2.0", pinnedImage = "example.test/planka@sha256:" + "1".repeat(64), imageId = "2".repeat(64)) })
        val next = old.copy(images = old.images.map { if (it.product != "planka") it else it.copy(reference = "ghcr.io/plankanban/planka:2.2.1",
            pinnedImage = "example.test/planka@sha256:" + "3".repeat(64), imageId = "4".repeat(64)) })
        val bytes = json.encodeToString(old).toByteArray(); val nextBytes = json.encodeToString(next).toByteArray()
        val plan = GenerationAssembly().plan(AssemblyRequest(id = "q-111111111111", candidateSha256 = "a".repeat(64),
            inventorySha256 = ReleaseLocks.sha256(bytes), selections = listOf(AssemblySelection("canonical-core")),
            diskReservationMiB = 8192, store = RuntimeStore.CANONICAL_V2), bytes)
        val graph = SiteOwnerships.inspect(plan)
        val owners = graph.processes.associate { it.process to requireNotNull(it.compiledProduct) }
        val contract = SiteOwnership(site = "unit", assemblySha256 = graph.assemblySha256,
            processes = owners.map { SiteProcessOwner(it.key, it.value) },
            state = graph.state.map { SiteStateOwner(it.volume, owners.getValue(it.writers.first()), "core") },
            inputs = graph.inputs.map { SiteInputOwner(it.input, requireNotNull(it.compiledProduct), true, it.consumers) }, routes = emptyList())
        val pins = plan.specs.map { spec ->
            val inputs = PrivateDeployment.inputNames(spec).associateWith { "b".repeat(64) }
            GenerationPin(plan.generation.members.single { it.name == spec.name }, ReleaseLocks.sha256(Json.encodeToString(spec).toByteArray()),
                inputs, PrivateDeployment.expectedFingerprint(spec, inputs), spec)
        }
        val reservation = plan.specs.sumOf { spec -> spec.processes.filterNot { it.oneShot }.sumOf { it.memoryMiB.toLong() } +
            (spec.processes.filter { it.oneShot }.maxOfOrNull { it.memoryMiB } ?: 0) }
        val source = GenerationBundle(plan.generation, pins, reservation, contract.assemblySha256,
            ownership = SiteOwnerships.bind(plan, contract, emptySet()))
        val hash = ReleaseLocks.sha256(json.encodeToString(source).toByteArray())
        val intent = ReleaseUpdateIntent(ReleaseGeneration(source.request.id, hash), "q-222222222222", "c".repeat(64), "d".repeat(64),
            ReleaseLocks.sha256(bytes), ReleaseLocks.sha256(nextBytes), PlankaVersionTransition("2.2.0", "2.2.1"))
        val receipt = KopiaSnapshotReceipt(id = "cap-111111111111", generation = source.request.id, bundleSha256 = hash,
            snapshotId = "e".repeat(32), rootObjectId = "k" + "f".repeat(40), manifestSha256 = "0".repeat(64), files = 12, plaintextBytes = 1024,
            image = "example.test/kopia@sha256:" + "9".repeat(64), imageId = "8".repeat(64))
        return Fixture(source, bytes, nextBytes, intent, receipt)
    }
    @Test fun `owned patch update preserves state credentials site scope and retires every initializer`() {
        val f = fixture()
        val target = OwnedReleaseUpdates.compile(f.source, f.old, f.next, f.intent, f.receipt)
        assertEquals(f.intent.targetGeneration, target.request.id); assertEquals(f.intent.candidateSha256, target.request.candidateSha256)
        assertEquals(OwnedUpdateLineage(intent = f.intent, snapshot = f.receipt, original = f.source), target.ownedUpdate)
        assertNull(target.recoverySourceKopia); assertNull(target.recoverySourceArchiveSha256)
        assertTrue(target.members.all { member -> member.spec.processes.none { it.oneShot } })
        assertEquals(target.request.diskReservationMiB, target.ownership!!.assembly.request.diskReservationMiB)
        assertTrue(target.request.diskReservationMiB > f.source.request.diskReservationMiB,
            "Update ownership must retain the cold-import reservation increase")
        assertEquals(f.source.ownership!!.approvedHosts, target.ownership.approvedHosts)
        assertEquals(f.source.ownership.contract.site, target.ownership.contract.site)
        val ca = target.ownership.contract.inputs.single { it.input.endsWith("/postgres-ca.pem") }
        assertEquals("postgres", ca.product)
        assertEquals(listOf("${target.request.id}-canonical-core/planka"), ca.consumers)
        assertFails { OwnedReleaseUpdates.validate(target.copy(ownership = target.ownership.copy(
            contract = target.ownership.contract.copy(inputs = target.ownership.contract.inputs.map {
                if (it == ca) it.copy(product = "planka") else it
            })))) }
        assertEquals(f.source.members.single().spec.volumes, target.members.single().spec.volumes)
        assertTrue(target.members.single().inputHashes.all { (file, hash) -> f.source.members.single().inputHashes[file] == hash })
        assertEquals("4".repeat(64), target.members.single().spec.processes.single { it.id == "planka" }.imageId)
        OwnedReleaseUpdates.validate(target)
        OwnedReleaseUpdates.validate(json.decodeFromString<GenerationBundle>(json.encodeToString(target)))
        assertFails { OwnedReleaseUpdates.validate(target.copy(recoverySourceKopia = f.receipt)) }
        assertFails { OwnedReleaseUpdates.compile(target, f.old, f.next, f.intent, f.receipt) }
    }
    @Test fun `initializer retirement requires exact original evidence and never weakens fresh ownership`() {
        val f = fixture()
        val target = OwnedReleaseUpdates.compile(f.source, f.old, f.next, f.intent, f.receipt)
        val lineage = requireNotNull(target.ownedUpdate)
        assertFails { OwnedReleaseUpdates.validate(target.copy(ownedUpdate = lineage.copy(original = null))) }
        assertFails { OwnedReleaseUpdates.validate(target.copy(ownedUpdate = lineage.copy(
            original = f.source.copy(memoryReservationMiB = f.source.memoryReservationMiB + 1)))) }
        assertFails { OwnedReleaseUpdates.validate(target.copy(ownedUpdate = lineage.copy(
            original = f.source.copy(ownedUpdate = lineage.copy(original = null))))) }
        assertFails { SiteOwnerships.checkSealed(target.copy(ownedUpdate = null)) }
        val owner = requireNotNull(target.ownership)
        assertFails { OwnedReleaseUpdates.validate(target.copy(ownership = owner.copy(approvedHosts = setOf("foreign.datamancy.net")))) }
        assertFails { OwnedReleaseUpdates.validate(target.copy(ownership = owner.copy(contract = owner.contract.copy(site = "foreign")))) }
        val input = owner.contract.inputs.first()
        assertFails { OwnedReleaseUpdates.validate(target.copy(ownership = owner.copy(contract = owner.contract.copy(
            inputs = listOf(input.copy(credential = !input.credential)) + owner.contract.inputs.drop(1))))) }

        // Resealing hashes does not turn a surviving daemon into authorized initialization.
        val pin = target.members.single()
        val spec = pin.spec.copy(processes = pin.spec.processes.map { if (it.id == "planka") it.copy(oneShot = true, readiness = emptyList(), readinessHttpPort = null) else it })
        val specHash = ReleaseLocks.sha256(Json.encodeToString(spec).toByteArray())
        val summary = owner.assembly.copy(members = owner.assembly.members.map { it.copy(specSha256 = specHash) })
        val plan = AssemblyPlan(summary, target.request, AcquiredInventory(1, "unit-only", emptyList()), listOf(spec), emptyList())
        val assemblyHash = SiteOwnerships.assemblyDigest(plan)
        val changed = target.copy(members = listOf(pin.copy(spec = spec, manifestSha256 = specHash,
            runtimeFingerprint = PrivateDeployment.expectedFingerprint(spec, pin.inputHashes))), assemblySha256 = assemblyHash,
            ownership = owner.copy(assembly = summary, contract = owner.contract.copy(assemblySha256 = assemblyHash)))
        assertFails { SiteOwnerships.checkSealed(changed) }
    }

    @Test fun `wrong snapshot tampered inventories unsupported versions and recovery promotion are rejected`() {
        val f = fixture()
        for (bad in listOf(f.intent.copy(targetGeneration = f.intent.source.id), f.intent.copy(previousInventorySha256 = "0".repeat(64)),
            f.intent.copy(transition = PlankaVersionTransition("2.2.1", "2.2.0")))) {
            assertFails { OwnedReleaseUpdates.compile(f.source, f.old, f.next, bad, f.receipt) }
        }
        assertFails { OwnedReleaseUpdates.compile(f.source, f.old, f.next, f.intent, f.receipt.copy(generation = "q-333333333333")) }
        assertFails { OwnedReleaseUpdates.compile(f.source.copy(recoverySourceKopia = f.receipt), f.old, f.next, f.intent, f.receipt) }
        val next = json.decodeFromString<AcquiredInventory>(f.next.decodeToString())
        val changedProvider = json.encodeToString(next.copy(images = next.images.map {
            if (it.product == "postgres") it.copy(imageId = "5".repeat(64)) else it
        })).toByteArray()
        assertFails { OwnedReleaseUpdates.compile(f.source, f.old, changedProvider,
            f.intent.copy(candidateInventorySha256 = ReleaseLocks.sha256(changedProvider)), f.receipt) }
    }
}
