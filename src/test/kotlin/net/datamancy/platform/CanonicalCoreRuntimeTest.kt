package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

class CanonicalCoreRuntimeTest {
    @Test fun `native pinned ERP cache and RQ patterns are disjoint from other app ACLs`(): Unit {
        val native = CanonicalCachePrincipal("erpnext", "a".repeat(64)).aclRule()
        val other = CanonicalCachePrincipal("huly", "b".repeat(64)).aclRule()
        assertContains(native, "~p0_erp|*")
        assertContains(native, "~rq:[^q]* ~rq:queues ~rq:queue:p0v3-erp:*")
        assertContains(native, "&events &open_in_editor &rq:pubsub:*")
        assertContains(native, "-@admin -@dangerous +keys")
        assertFalse(native.contains("~*"))
        assertFalse(native.contains("&*"))
        assertFalse(native.contains("~app:erpnext:"))
        assertContains(other, "~app:huly:*")
        assertFalse(other.contains("rq:"))
    }

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
    @Test fun `v2 native ERP same-login cutover and BookStack Maria migration lock are fixed`() : Unit {
        val selected = setOf(CanonicalMariaGrant.ERPNEXT, CanonicalMariaGrant.BOOKSTACK)
        val spec = CanonicalCoreRuntime.releaseProvidersSpec(inventory, mariaGrants = selected)
            .copy(store = RuntimeStore.CANONICAL_V2)
        val init = spec.processes.single { it.id == "mariadb-init" }
        assertEquals(setOf("mariadb-qualification.env", "mariadb-erp-grants.env", "mariadb-bookstack-grants.env"),
            init.files.map { it.file }.toSet())
        assertEquals(setOf("mariadb-health.env", "mariadb-ca.pem", "mariadb.pem", "mariadb-key.pem"),
            (spec.processes.single { it.id == "mariadb" }.files.map { it.file } +
                spec.processes.single { it.id == "mariadb" }.environmentFile).toSet())
        val sql = init.command.last()
        assertContains(sql, "CREATE DATABASE p0_erp CHARACTER SET utf8mb4")
        assertContains(sql, "CREATE USER 'p0_erp'@'%' IDENTIFIED BY '")
        assertContains(sql, "GRANT ALL PRIVILEGES ON p0_erp.* TO 'p0_erp'@'%'")
        assertFalse(sql.contains("CREATE USER 'frappe_migrate'"))
        assertFalse(sql.contains("CREATE USER 'frappe_runtime'"))
        assertFalse(sql.contains("GRANT OPTION"))
        assertFalse(sql.contains("ON *.* TO 'p0_erp'"))
        assertContains(sql, "CREATE DATABASE bookstack CHARACTER SET utf8mb4")
        assertContains(sql, "ON bookstack.* TO 'bookstack_migrate'@'%'")
        assertContains(sql, "GRANT SELECT, INSERT, UPDATE, DELETE ON bookstack.* TO 'bookstack_runtime'@'%'")
        val v1 = CanonicalCoreRuntime.legacyProvidersSpec(inventory)
        assertEquals(Json.encodeToString(v1), Json.encodeToString(CanonicalCoreRuntime.providersSpec(inventory)))
        assertFalse(v1.processes.single { it.id == "mariadb-init" }.command.last().contains("CREATE USER 'p0_erp'"))
        assertFails { CanonicalCoreRuntime.legacyColdProjection(v1.copy(processes = v1.processes.map {
            if (it.id == "mariadb-init") it.copy(files = it.files +
                RuntimeFile("mariadb-erp-grants.env", "/run/secrets/mariadb-erp-grants.env")) else it
        })) }
        assertFails { CanonicalCoreRuntime.composeProviders(spec, emptyList()) }
        for (grant in setOf(CanonicalMariaGrant.BOOKSTACK, CanonicalMariaGrant.SEAFILE)) {
            val retirement = CanonicalCoreRuntime.mariaMigrationRetirement(grant)
            assertEquals(grant, retirement.grant)
            assertEquals("ALTER USER '${retirement.migrationAccount}'@'%' ACCOUNT LOCK;", retirement.lockStatement)
            assertEquals("SHOW CREATE USER '${retirement.migrationAccount}'@'%';", retirement.readbackStatement)
            assertTrue(retirement.databases.isNotEmpty())
        }
        assertFails { CanonicalCoreRuntime.mariaMigrationRetirement(CanonicalMariaGrant.ERPNEXT) }
        val erp = CanonicalCoreRuntime.erpMariaCutover()
        assertEquals("p0_erp", erp.account)
        assertEquals("p0_erp", erp.database)
        assertContains(erp.beforeSessionCensus, "information_schema.PROCESSLIST WHERE USER = 'p0_erp'")
        assertEquals(erp.beforeSessionCensus, erp.afterSessionCensus)
        assertEquals("KILL USER p0_erp;", erp.killSessionsStatement)
        assertContains(erp.revokeStatement, "REVOKE ALL PRIVILEGES ON p0_erp.*")
        assertContains(erp.runtimeGrantStatement, "GRANT SELECT, INSERT, UPDATE, DELETE ON p0_erp.*")
        assertContains(erp.rotateStatement, "ERP_RUNTIME_PASSWORD")
        assertEquals("SHOW GRANTS FOR 'p0_erp'@'%';", erp.readbackStatement)
        val ca: (String) -> Map<String, String> = { host -> mapOf(
            "ca.pem" to "-----BEGIN CERTIFICATE-----\n$host\n-----END CERTIFICATE-----\n",
            "web.pem" to "unit-web-$host", "web-key.pem" to "unit-key-$host") }
        var calls = 0
        val produce = { (++calls).toString(16).padStart(64, '0') }
        val pairs = mapOf(CanonicalMariaGrant.ERPNEXT to CanonicalMariaCredentialPair("a".repeat(64), "b".repeat(64)),
            CanonicalMariaGrant.BOOKSTACK to CanonicalMariaCredentialPair("c".repeat(64), "d".repeat(64)))
        assertFails { CanonicalCoreRuntime.releaseProvidersInputs(inventory, ca, produce,
            mariaGrants = selected, mariaFeatureCredentials = mapOf(CanonicalMariaGrant.ERPNEXT to pairs.getValue(CanonicalMariaGrant.ERPNEXT))) }
        assertEquals(0, calls) // Reject missing selected grant before entropy/PKI.
        assertFails { CanonicalCoreRuntime.releaseProvidersInputs(inventory, ca, produce,
            mariaGrants = selected, mariaFeatureCredentials = pairs +
                (CanonicalMariaGrant.SEAFILE to CanonicalMariaCredentialPair("e".repeat(64), "f".repeat(64)))) }
        assertEquals(0, calls) // No unselected or duplicate grant enters credential generation.
        assertFails { CanonicalCoreRuntime.releaseProvidersInputs(inventory, ca, produce,
            mariaGrants = selected, mariaFeatureCredentials = mapOf(
                CanonicalMariaGrant.ERPNEXT to pairs.getValue(CanonicalMariaGrant.ERPNEXT),
                CanonicalMariaGrant.BOOKSTACK to pairs.getValue(CanonicalMariaGrant.ERPNEXT))) }
        val originalUsers = FireflyOriginalSubjects("11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222", "9".repeat(64), "8".repeat(64), "q-111111111111")
        assertFails { CanonicalCoreRuntime.releaseProvidersInputs(inventory, ca, produce,
            mariaGrants = selected, mariaFeatureCredentials = pairs) }
        val inputs = CanonicalCoreRuntime.releaseProvidersInputs(inventory, ca, produce,
            mariaGrants = selected, mariaFeatureCredentials = pairs, fireflyOriginalSubjects = originalUsers)
        assertEquals(PrivateDeployment.inputNames(spec).toSet(), inputs.keys)
        assertContains(inputs.getValue("firefly-onboarding.env"), "P0V3_OWNER_SUB=${originalUsers.ownerUuid}")
        assertContains(inputs.getValue("firefly-onboarding.env"), "P0V3_OUTSIDER_SUB=${originalUsers.outsiderUuid}")
        assertFalse(inputs.getValue("firefly-runtime.env").contains("P0V3_OWNER_PASSWORD"))
        val realmUsers = Json.parseToJsonElement(inputs.getValue("identity-realm.json")).jsonObject
            .getValue("users").jsonArray.map { it.jsonObject }
        assertEquals(setOf(originalUsers.ownerUuid, originalUsers.outsiderUuid),
            realmUsers.mapNotNull { it["id"]?.jsonPrimitive?.content }.toSet())
        assertEquals("ERP_MIGRATION_PASSWORD=${"a".repeat(64)}\nERP_RUNTIME_PASSWORD=${"b".repeat(64)}\n",
            inputs.getValue("mariadb-erp-grants.env"))
        assertEquals("BOOKSTACK_MIGRATION_PASSWORD=${"c".repeat(64)}\nBOOKSTACK_RUNTIME_PASSWORD=${"d".repeat(64)}\n",
            inputs.getValue("mariadb-bookstack-grants.env"))
        val bookstack = BookStackRuntime.releaseInputs(pairs.getValue(CanonicalMariaGrant.BOOKSTACK),
            "base64:" + "A".repeat(43) + "=", "123e4567-e89b-12d3-a456-426614174000",
            "e".repeat(64), "f".repeat(64))
        assertContains(bookstack.getValue("bookstack-runtime.env"),
            "DB_PASSWORD=${pairs.getValue(CanonicalMariaGrant.BOOKSTACK).runtimePassword}")
        assertContains(bookstack.getValue("bookstack-migration.env"),
            "DB_PASSWORD=${pairs.getValue(CanonicalMariaGrant.BOOKSTACK).migrationPassword}")
        assertFalse(PrivateDeployment.inputNames(CanonicalCoreRuntime.releaseColdRestoreProvidersSpec(spec))
            .any { it in setOf("mariadb-erp-grants.env", "mariadb-bookstack-grants.env") })
    }

    @Test fun `typed identity web permits only MAS or BookStack PHP, not bootstrap or arbitrary processes`() : Unit {
        val base = CanonicalCoreRuntime.releaseProvidersSpec(inventory, mariaGrants = setOf(CanonicalMariaGrant.BOOKSTACK))
            .copy(store = RuntimeStore.CANONICAL_V2)
        val wiki = BookStackRuntime.releaseFragment(inventory, base.name)
        val composed = CanonicalCoreRuntime.composeProviders(base, listOf(wiki))
        assertEquals(setOf(CanonicalIdentityWebConsumer.BOOKSTACK_PHP), wiki.identityWebConsumers)
        assertEquals(setOf("bookstack-php"), wiki.spec.processes.filter { "identity-web" in it.networks }.map { it.id }.toSet())
        assertTrue(composed.processes.single { it.id == "bookstack-php" }.networks.contains("identity-web"))
        val cold = BookStackRuntime.releaseColdFragment(wiki)
        CanonicalCoreRuntime.coldRestoreComposedSpec(composed, base, listOf(wiki), listOf(cold))
        val foreign = base.copy(processes = base.processes.map { if (it.id == "mariadb-init") it.copy(files =
            it.files + RuntimeFile("mariadb-foreign-grants.env", "/run/secrets/mariadb-foreign-grants.env")) else it })
        assertFails { CanonicalCoreRuntime.composeProviders(foreign, listOf(wiki)) }
        assertFails { CanonicalCoreRuntime.composeProviders(base, listOf(wiki.copy(identityWebConsumers = setOf(CanonicalIdentityWebConsumer.MAS)))) }
        assertFails { CanonicalCoreRuntime.composeProviders(base, listOf(wiki.copy(identityWebConsumers = emptySet()))) }
        assertFails { CanonicalCoreRuntime.composeProviders(base, listOf(wiki.copy(spec = wiki.spec.copy(processes =
            wiki.spec.processes.map { if (it.id == "bookstack-migrate") it.copy(networks = it.networks + "identity-web") else it })))) }
        assertFails { CanonicalCoreRuntime.composeProviders(base, listOf(wiki.copy(providerNetworks =
            wiki.providerNetworks + ("keycloak" to setOf("identity-web"))))) }
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
