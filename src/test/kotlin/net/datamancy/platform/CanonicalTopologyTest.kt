package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.Json
import kotlin.test.*

class CanonicalTopologyTest {
    private val bytes = GenerationAssembly.readInventory(Path.of("release/downloaded-candidate-inventory.json"))
    private val inventory = Json.decodeFromString<AcquiredInventory>(bytes.decodeToString())
    private val request = AssemblyRequest(id = "q-abcdef123456", candidateSha256 = "a".repeat(64),
        inventorySha256 = ReleaseLocks.sha256(bytes), selections = listOf(AssemblySelection("canonical-providers")),
        diskReservationMiB = 32768, store = RuntimeStore.CANONICAL_V2)
    private fun partial() = GenerationAssembly().canonicalPlan(request, bytes, false)

    @Test fun `canonical provider cohort genuinely shares postgres and wires distinct application networks`() {
        val compiled = partial()
        val spec = compiled.assembly.specs.single()
        assertEquals(spec, partial().assembly.specs.single())
        assertEquals(setOf("postgres", "mariadb", "valkey", "memcached", "keycloak", "ntfy"), compiled.topology.providers.map { it.product }.toSet())
        assertEquals(1, spec.processes.count { it.id == "postgres" })
        assertEquals(setOf("planka", "keycloak", "firefly"), spec.databaseAccess.map { it.database }.toSet())
        assertEquals(setOf("db-admin", "planka-data", "keycloak-data", "firefly-data"), spec.processes.single { it.id == "postgres" }.networks.toSet())
        val caddy = spec.processes.single { it.id == "caddy" }
        assertEquals(setOf("ingress-control", "planka-web", "ntfy-web", "identity-web", "firefly-web"), caddy.networks.toSet())
        assertFalse(caddy.networks.any { it.endsWith("-data") || it == "db-admin" })
        assertEquals(listOf("maria-data"), spec.processes.single { it.id == "mariadb" }.networks)
        assertEquals(listOf("memcache-data"), spec.processes.single { it.id == "memcached" }.networks)
        assertFalse(compiled.topology.complete)
        assertFalse(compiled.topology.runtimeValidated)
        assertFalse(compiled.topology.publicActivation)
        assertTrue(compiled.topology.missingCapabilities.containsAll(setOf("worklane", "tuios", "pi", "mastodon-rss-publisher")))
        assertFailsWith<IllegalArgumentException> { GenerationAssembly().canonicalPlan(request, bytes) }
        val legacy = CanonicalCoreRuntime.spec(inventory)
        assertEquals(4, legacy.processes.count { !it.oneShot })
        assertFalse(legacy.processes.any { it.id == "keycloak" })
    }

    @Test fun `complete exact fresh inputs separate migration credentials from runtime and authenticate providers`() {
        var counter = 0
        val inputs = CanonicalCoreRuntime.providersInputs(inventory,
            { host -> mapOf("ca.pem" to "-----BEGIN CERTIFICATE-----\nunit-$host\n-----END CERTIFICATE-----\n",
                "web.pem" to "unit-certificate-$host", "web-key.pem" to "unit-key-$host") },
            { (++counter).toString(16).padStart(64, '0') })
        val spec = CanonicalCoreRuntime.providersSpec(inventory)
        assertEquals(PrivateDeployment.inputNames(spec).toSet(), inputs.keys)
        assertContains(inputs.getValue("valkey.acl"), "user default off")
        assertContains(inputs.getValue("valkey.acl"), "~app:*")
        assertFalse(inputs.getValue("valkey.conf").contains("requirepass"))
        assertContains(inputs.getValue("ntfy.yml"), "auth-default-access: deny-all")
        assertContains(inputs.getValue("mariadb-bootstrap.env"), "MARIADB_ROOT_PASSWORD=")
        assertFalse(inputs.getValue("mariadb-health.env").contains("ROOT"))
        assertTrue(spec.processes.single { it.id == "mariadb" }.command.contains("--require-secure-transport=ON"))
        val runtime = inputs.getValue("firefly-runtime.env")
        assertContains(runtime, "DB_USERNAME=firefly_runtime")
        assertContains(runtime, "PGSQL_SSL_MODE=verify-full")
        assertContains(runtime, "APP_URL=https://finance.datamancy.net")
        assertFalse(runtime.contains("P0V3_FIXTURE"))
        assertFalse(runtime.contains("firefly_migration"))
        assertTrue(spec.processes.single { it.id == "firefly-db-finalize" }.command.last().contains("firefly_migration NOLOGIN"))
        assertEquals(listOf("postgres", "firefly-db-finalize"), spec.processes.single { it.id == "firefly-php" }.dependencies)
        assertFails { CanonicalCoreRuntime.providersInputs(inventory, { emptyMap() }, { "a".repeat(64) }) }
        assertFails { CanonicalCoreRuntime.providersInputs(inventory, { emptyMap() }, { (++counter).toString(16).padStart(64, '0') }) }
    }

    @Test fun `automatic ownership joins physical and logical writers without inventing public authority`() {
        val compiled = partial()
        val member = compiled.assembly.specs.single().name
        val route = SiteRouteOwner("finance.datamancy.net", "firefly-iii", "$member/firefly", 8080)
        val contract = CanonicalTopology.ownership(compiled, "unit", listOf(route), setOf(route.host))
        val state = contract.state.associateBy { it.volume.substringAfter('/') }
        val postgresGroup = state.getValue("postgres").recoveryGroup
        assertEquals(postgresGroup, state.getValue("firefly-storage").recoveryGroup)
        assertEquals(postgresGroup, state.getValue("firefly-cache").recoveryGroup)
        assertNotEquals(postgresGroup, state.getValue("mariadb").recoveryGroup)
        assertTrue(contract.inputs.single { it.input.endsWith("/identity-realm.json") }.consumers.all { it.endsWith("/identity-realm-init") })
        SiteOwnerships.bind(compiled.assembly, contract, setOf(route.host))
        assertFails { CanonicalTopology.ownership(compiled, "unit", listOf(route), setOf("datamancy.net")) }
        assertFails { CanonicalTopology.ownership(compiled, "unit", listOf(route), setOf("*.datamancy.net")) }
        assertFails { CanonicalTopology.ownership(compiled, "unit", listOf(route), setOf("finance.example.test")) }
        assertFails { CanonicalTopology.ownership(compiled.copy(topology = compiled.topology.copy(complete = true)), "unit", emptyList(), emptySet()) }
    }

    @Test fun `support provider copies and undeclared primary owners are never canonicalized by image reuse`() {
        val duplicates = GenerationAssembly().plan(request.copy(selections = listOf(AssemblySelection("foundation"), AssemblySelection("identity"))), bytes)
        assertFailsWith<IllegalArgumentException> { CanonicalTopology.compile(duplicates, false) }
        val unselected = GenerationAssembly().plan(request.copy(selections = listOf(AssemblySelection("identity"))), bytes)
        assertFailsWith<IllegalArgumentException> { CanonicalTopology.compile(unselected, false) }
        for (alternative in listOf("canonical-core", "foundation", "sql-cache", "identity", "firefly", "caddy")) {
            assertFails { GenerationAssembly().plan(request.copy(selections = request.selections + AssemblySelection(alternative)), bytes) }
        }
    }

    @Test fun `restore retires exact initializer authorities and cannot resume source ingress autosave`() {
        val spec = CanonicalCoreRuntime.providersSpec(inventory)
        val restored = CanonicalCoreRuntime.coldRestoreProvidersSpec(spec)
        assertTrue(restored.processes.none { it.oneShot })
        assertEquals(spec.volumes, restored.volumes)
        assertEquals(spec.networks, restored.networks)
        assertEquals(listOf("postgres"), restored.processes.single { it.id == "keycloak" }.dependencies)
        assertEquals(listOf("postgres"), restored.processes.single { it.id == "firefly-php" }.dependencies)
        assertFalse(restored.processes.single { it.id == "caddy" }.command.contains("--resume"))
        assertTrue(restored.databaseAccess.all { it.consumer in setOf("keycloak", "planka", "firefly-php") })
        val retired = PrivateDeployment.inputNames(spec) - PrivateDeployment.inputNames(restored).toSet()
        assertTrue(retired.containsAll(setOf("identity-realm.json", "identity-migration.env", "firefly-migration.env",
            "postgres-admin.env", "mariadb-bootstrap.env", "ntfy-bootstrap.env")))
        assertTrue("identity-ca.pem" in PrivateDeployment.inputNames(restored))
        assertTrue("valkey.acl" in PrivateDeployment.inputNames(restored))
        assertFails { CanonicalCoreRuntime.coldRestoreProvidersSpec(restored) }
        assertFails { CanonicalCoreRuntime.coldRestoreProvidersSpec(spec.copy(processes = spec.processes +
            spec.processes.first { it.oneShot }.copy(id = "unreviewed-init"))) }
    }
}
