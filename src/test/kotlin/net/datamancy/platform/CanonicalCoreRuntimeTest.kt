package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class CanonicalCoreRuntimeTest {
    private val bytes = GenerationAssembly.readInventory(Path.of("release/downloaded-candidate-inventory.json"))
    private val inventory = Json.decodeFromString<AcquiredInventory>(bytes.decodeToString())
    private val request = AssemblyRequest(id = "q-abcdef123456", candidateSha256 = "a".repeat(64),
        inventorySha256 = ReleaseLocks.sha256(bytes), selections = listOf(AssemblySelection("canonical-core")), diskReservationMiB = 8192)
    private fun contract(plan: AssemblyPlan): SiteOwnership {
        val graph = SiteOwnerships.inspect(plan)
        val owners = graph.processes.associate { it.process to it.compiledProduct!! }
        return SiteOwnership(site = "unit", assemblySha256 = graph.assemblySha256,
            processes = owners.map { SiteProcessOwner(it.key, it.value) },
            state = graph.state.map { SiteStateOwner(it.volume, owners.getValue(it.writers.first()), "core") },
            inputs = graph.inputs.map { SiteInputOwner(it.input, it.compiledProduct!!, true, it.consumers) }, routes = emptyList())
    }
    @Test fun `one provider with explicit TLS principal and recovery contracts`() {
        val plan = GenerationAssembly().plan(request, bytes)
        val spec = plan.specs.single()
        assertEquals(4, spec.processes.count { !it.oneShot })
        assertEquals(1, spec.processes.count { it.id == "postgres" })
        assertEquals(setOf("planka", "planka_migrate"), spec.databaseAccess.map { it.principal }.toSet())
        assertEquals(listOf("planka-web", "planka-data"), spec.processes.single { it.id == "planka" }.networks)
        assertEquals(listOf("postgres-finalize"), spec.processes.single { it.id == "planka" }.dependencies)
        assertTrue(spec.processes.single { it.id == "postgres-finalize" }.command.last().contains("planka_migrate NOLOGIN"))
        val graph = SiteOwnerships.inspect(plan)
        val pg = graph.state.single { it.volume.endsWith("/postgres") }
        assertEquals(2, pg.writers.size)
        assertEquals(2, pg.networkWriters.size)
        assertEquals(2, graph.databaseAccess.size)
        val owner = contract(plan)
        assertFalse(SiteOwnerships.check(plan, owner, emptySet()).centralWiringVerified)
        assertFails { SiteOwnerships.check(plan, owner.copy(state = owner.state.map {
            if (it.volume.endsWith("/uploads")) it.copy(recoveryGroup = "separate") else it
        }), emptySet()) }
        for (duplicate in listOf("foundation", "planka")) assertFails {
            GenerationAssembly().plan(request.copy(selections = request.selections + AssemblySelection(duplicate)), bytes)
        }
    }
    @Test fun `fresh secrets separate bootstrap migration and daemon privileges`() {
        var i = 0
        val values = CanonicalCoreRuntime.inputs({ mapOf("ca.pem" to "unit-ca", "web.pem" to "unit-cert", "web-key.pem" to "unit-key") },
            { (++i).toString(16).padStart(64, '0') })
        assertEquals(PrivateDeployment.inputNames(CanonicalCoreRuntime.spec(inventory)).toSet(), values.keys)
        assertTrue(values.getValue("planka.env").contains("sslmode=verify-full"))
        assertFalse(values.getValue("planka.env").contains("DEFAULT_ADMIN"))
        assertFalse(values.getValue("planka.env").contains("planka_migrate"))
        assertTrue(values.getValue("planka-bootstrap.env").contains("DEFAULT_ADMIN_PASSWORD="))
        assertTrue(values.getValue("postgres-admin.env").contains("PGSSLMODE=verify-full"))
        assertTrue(values.getValue("postgres-hba.conf").contains("hostnossl all all 0.0.0.0/0 reject"))
        assertFails { CanonicalCoreRuntime.inputs({ emptyMap() }, { "a".repeat(64) }) }
        assertFails { CanonicalCoreRuntime.inputs({ emptyMap() }, { (++i).toString(16).padStart(64, '0') }) }
    }
    @Test fun `invalid network and database declarations fail before runtime effects`() {
        val s = CanonicalCoreRuntime.spec(inventory)
        val access = s.databaseAccess.first()
        val invalid = listOf(s.copy(networks = listOf("net")), s.copy(networks = s.networks + "orphan"),
            s.copy(networks = s.networks + "net"), s.copy(networks = listOf("../foreign")),
            s.copy(processes = s.processes.map { if (it.id == "planka") it.copy(networks = emptyList()) else it }),
            s.copy(databaseAccess = s.databaseAccess + access)) + listOf(
                access.copy(consumer = "absent"), access.copy(provider = "planka-init"), access.copy(provider = access.consumer),
                access.copy(volume = "uploads"), access.copy(network = "net"), access.copy(database = "bad;sql"),
                access.copy(principal = "bad-role"), access.copy(credentialFile = "postgres-admin.env")
            ).map { s.copy(databaseAccess = listOf(it)) }
        invalid.forEach { assertFails { PrivateDeployment.validate(it) } }
        val legacy = FoundationRuntime.spec(inventory)
        for (encoded in listOf(Json.encodeToString(legacy), Json { encodeDefaults = true }.encodeToString(legacy))) {
            assertFalse(encoded.contains("\"networks\""))
            assertFalse(encoded.contains("\"databaseAccess\""))
        }
    }
    @Test fun `canonical restore retires bootstraps without losing network writers or inheriting authority`() {
        val plan = GenerationAssembly().plan(request.copy(selections = listOf(AssemblySelection("canonical-core"),
            AssemblySelection("sql-cache", listOf("canonical-core")), AssemblySelection("forgejo", listOf("canonical-core")))), bytes)
        val pins = plan.specs.map { spec ->
            val member = plan.generation.members.single { it.name == spec.name }
            val hashes = PrivateDeployment.inputNames(spec).associateWith { "b".repeat(64) }
            GenerationPin(member, ReleaseLocks.sha256(Json.encodeToString(spec).toByteArray()), hashes,
                PrivateDeployment.expectedFingerprint(spec, hashes), spec)
        }
        val source = GenerationBundle(plan.generation, pins, 8192, assemblySha256 = SiteOwnerships.assemblyDigest(plan),
            ownership = SiteOwnerships.bind(plan, contract(plan), emptySet()))
        val restored = FoundationRestore.bundle(source, inventory, "q-123456abcdef", "c".repeat(64), ColdRestoreCohort.CANONICAL_CORE)
        assertNull(restored.ownership)
        val core = restored.members.single { it.spec.name.endsWith("-canonical-core") }
        assertEquals(4, core.spec.processes.size)
        assertTrue(core.spec.processes.none { it.oneShot })
        assertEquals(listOf("postgres"), core.spec.processes.single { it.id == "planka" }.dependencies)
        assertEquals(listOf("planka"), core.spec.databaseAccess.map { it.consumer })
        assertFalse(core.inputHashes.keys.any { it in setOf("planka-bootstrap.env", "postgres-admin.env", "postgres.env") })
        assertFails { FoundationRestore.bundle(source, inventory, "q-123456abcdef", "c".repeat(64)) }
        assertFails { FoundationRestore.bundle(source.copy(members = pins.map { pin ->
            if (pin.spec.name.endsWith("-canonical-core")) pin.copy(spec = pin.spec.copy(databaseAccess = emptyList())) else pin
        }, ownership = null), inventory, "q-123456abcdef", "c".repeat(64), ColdRestoreCohort.CANONICAL_CORE) }
    }
}
