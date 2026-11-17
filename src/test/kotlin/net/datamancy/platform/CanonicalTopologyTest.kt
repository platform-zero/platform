package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.test.*

class CanonicalTopologyTest {
    private val bytes = GenerationAssembly.readInventory(Path.of("release/downloaded-candidate-inventory.json"))
    private val inventory = Json.decodeFromString<AcquiredInventory>(bytes.decodeToString())
    private val request = AssemblyRequest(id = "q-abcdef123456", candidateSha256 = "a".repeat(64),
        inventorySha256 = ReleaseLocks.sha256(bytes), selections = listOf(AssemblySelection("canonical-providers")),
        diskReservationMiB = 32768, store = RuntimeStore.CANONICAL_V2)
    private fun partial() = GenerationAssembly().canonicalPlan(request, bytes, false)
    private val subjects = FireflyOriginalSubjects("11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222", "9".repeat(64), "8".repeat(64), "q-abcdef123456")

    @Test fun `canonical provider cohort genuinely shares postgres and wires distinct application networks`() : Unit {
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

    @Test fun `historical V1 provider compiler inputs and cold projection reject new release authority`() : Unit {
        val original = CanonicalCoreRuntime.legacyProvidersSpec(inventory)
        val release = CanonicalCoreRuntime.releaseProvidersSpec(inventory, original.name)
        assertEquals(original, CanonicalCoreRuntime.providersSpec(inventory))
        assertNotEquals(original, release)
        assertFalse(original.processes.single { it.id == "planka-db-init" }.command.last().contains("qualification"))
        assertTrue(original.processes.single { it.id == "mariadb-init" }.files.isEmpty())
        assertFalse(original.processes.single { it.id == "mariadb-init" }.command.last().contains("qualification"))
        assertFalse(original.processes.single { it.id == "ntfy-auth-init" }.command.last().contains("ntfy tier"))
        assertContains(original.processes.single { it.id == "ntfy-auth-init" }.command.last(), "publisher 'events-*' rw")
        val ca: (String) -> Map<String, String> = { host -> mapOf("ca.pem" to "-----BEGIN CERTIFICATE-----\nunit-ca-$host\n-----END CERTIFICATE-----\n",
            "web.pem" to "unit-web-$host", "web-key.pem" to "unit-key-$host") }
        fun uniquePasswords(): () -> String {
            var value = 0
            return { (++value).toString(16).padStart(64, '0') }
        }
        val v1 = CanonicalCoreRuntime.legacyInputs(inventory, ca, uniquePasswords())
        assertEquals(PrivateDeployment.inputNames(original).toSet(), v1.keys)
        assertContains(v1.getValue("valkey.acl"), "~app:* &app:*")
        assertContains(v1.getValue("ntfy.yml"), "base-url: http://ntfy:8080\n")
        assertTrue(v1.getValue("ntfy-bootstrap.env").matches(Regex("NTFY_PASSWORD=[a-f0-9]{64}\\n")))
        assertFalse(v1.keys.any { it.endsWith("qualification.env") })
        assertContains(v1.getValue("identity-runtime.env"), "KC_HOSTNAME=https://keycloak:8443\n")
        val realm = Json.parseToJsonElement(v1.getValue("identity-realm.json")).jsonObject
        assertFalse("loginWithEmailAllowed" in realm)
        assertFalse("otpPolicyAlgorithm" in realm)
        assertFalse(v1.getValue("identity-realm.json").contains("manage-realm"))
        assertEquals(v1.keys, CanonicalCoreRuntime.providersInputs(inventory, ca, uniquePasswords()).keys)
        val restored = CanonicalCoreRuntime.legacyColdProjection(original)
        assertEquals(restored, CanonicalCoreRuntime.coldRestoreProvidersSpec(original))
        assertEquals(original.volumes, restored.volumes)
        assertTrue(restored.processes.none { it.oneShot })
        assertFails { CanonicalCoreRuntime.legacyColdProjection(release) }
        assertFails { CanonicalCoreRuntime.releaseColdRestoreProvidersSpec(original) }
    }

    @Test fun `fixed Seafile MariaDB bootstrap grants only three empty databases then retires bootstrap authority`() : Unit {
        val selected = setOf(CanonicalMariaGrant.SEAFILE)
        val fresh = CanonicalCoreRuntime.releaseProvidersSpec(inventory, mariaGrants = selected)
        val legacy = CanonicalCoreRuntime.legacyProvidersSpec(inventory)
        val init = fresh.processes.single { it.id == "mariadb-init" }
        assertEquals(setOf("mariadb-qualification.env", "mariadb-seafile-grants.env"), init.files.map { it.file }.toSet())
        val sql = init.command.last()
        for (db in listOf("ccnet_db", "seafile_db", "seahub_db")) {
            assertContains(sql, "CREATE DATABASE $db CHARACTER SET utf8mb4")
            assertContains(sql, "ON $db.* TO 'seafile_migrate'@'%'")
            assertContains(sql, "GRANT SELECT, INSERT, UPDATE, DELETE ON $db.* TO 'seafile_runtime'@'%'")
        }
        assertContains(sql, "CREATE USER 'seafile_migrate'@'%' IDENTIFIED BY '${'$'}SEAFILE_MIGRATION_PASSWORD'")
        assertContains(sql, "CREATE USER 'seafile_runtime'@'%' IDENTIFIED BY '${'$'}SEAFILE_RUNTIME_PASSWORD'")
        assertFalse(sql.contains("GRANT OPTION"))
        assertFalse(sql.contains("ON *.* TO 'seafile"))
        assertFalse(legacy.processes.single { it.id == "mariadb-init" }.command.last().contains("seafile_migrate"))
        assertFalse(legacy.processes.single { it.id == "mariadb-init" }.files.any { it.file == "mariadb-seafile-grants.env" })
        assertFalse(fresh.processes.single { it.id == "mariadb" }.files.any { it.file == "mariadb-seafile-grants.env" })
        assertFails { CanonicalCoreRuntime.composeProviders(fresh, emptyList()) }
        val ca: (String) -> Map<String, String> = { host -> mapOf("ca.pem" to "-----BEGIN CERTIFICATE-----\nunit-ca-$host\n-----END CERTIFICATE-----\n",
            "web.pem" to "unit-web-$host", "web-key.pem" to "unit-key-$host") }
        var attempts = 0
        assertFails { CanonicalCoreRuntime.releaseProvidersInputs(inventory, ca,
            { attempts++; attempts.toString(16).padStart(64, '0') }, mariaGrants = selected) }
        assertEquals(0, attempts) // Reject unbound principals before any credential preparation.
        assertFails { CanonicalMariaCredentialPair("bad", "e".repeat(64)) }
        val pair = CanonicalMariaCredentialPair("d".repeat(64), "e".repeat(64))
        assertFails { CanonicalCoreRuntime.releaseProvidersInputs(inventory, ca,
            { attempts++; attempts.toString(16).padStart(64, '0') }, mariaCredentials = pair) }
        assertEquals(0, attempts) // Credentials must never be prepared for an unselected grant.
        val inputs = CanonicalCoreRuntime.releaseProvidersInputs(inventory, ca,
            { (++attempts).toString(16).padStart(64, '0') }, mariaGrants = selected, mariaCredentials = pair,
            fireflyOriginalSubjects = subjects)
        assertEquals(PrivateDeployment.inputNames(fresh).toSet(), inputs.keys)
        assertEquals("SEAFILE_MIGRATION_PASSWORD=${pair.migrationPassword}\nSEAFILE_RUNTIME_PASSWORD=${pair.runtimePassword}\n",
            inputs.getValue("mariadb-seafile-grants.env"))
        val restored = CanonicalCoreRuntime.releaseColdRestoreProvidersSpec(fresh)
        assertEquals(fresh.volumes, restored.volumes)
        assertFalse("mariadb-seafile-grants.env" in PrivateDeployment.inputNames(restored))
        assertTrue(restored.processes.none { it.oneShot || it.files.any { f -> f.file == "mariadb-seafile-grants.env" } })
    }

    @Test fun `complete exact fresh inputs separate migration credentials from runtime and authenticate providers`() : Unit {
        var counter = 0
        val inputs = CanonicalCoreRuntime.releaseProvidersInputs(inventory,
            { host -> mapOf("ca.pem" to "-----BEGIN CERTIFICATE-----\nunit-$host\n-----END CERTIFICATE-----\n",
                "web.pem" to "unit-certificate-$host", "web-key.pem" to "unit-key-$host") },
            { (++counter).toString(16).padStart(64, '0') }, fireflyOriginalSubjects = subjects)
        val spec = CanonicalCoreRuntime.releaseProvidersSpec(inventory)
        assertEquals(PrivateDeployment.inputNames(spec).toSet(), inputs.keys)
        assertContains(inputs.getValue("valkey.acl"), "user default off")
        assertContains(inputs.getValue("valkey.acl"), "~app:q_*")
        assertFalse(inputs.getValue("valkey.acl").contains("~app:*"))
        assertFalse(inputs.getValue("valkey.conf").contains("requirepass"))
        assertContains(inputs.getValue("ntfy.yml"), "auth-default-access: deny-all")
        assertContains(inputs.getValue("ntfy.yml"), "base-url: https://notify.datamancy.net")
        val authBootstrap = spec.processes.single { it.id == "ntfy-auth-init" }.command.last()
        assertContains(authBootstrap, "--message-expiry-duration=60s")
        assertContains(authBootstrap, "--message-expiry-duration=840h")
        assertContains(authBootstrap, "change-tier expiry p0expiry")
        assertContains(authBootstrap, "change-tier publisher p0history")
        assertContains(authBootstrap, "subscriber 'events-*' ro")
        val bootPasswords = Regex("NTFY_[A-Z_]*PASSWORD=([a-f0-9]{64})").findAll(inputs.getValue("ntfy-bootstrap.env"))
            .map { it.groupValues[1] }.toList()
        assertEquals(3, bootPasswords.size)
        assertEquals(3, bootPasswords.toSet().size)
        assertFalse(PrivateDeployment.inputNames(spec.copy(processes = spec.processes.filterNot { it.id == "ntfy-auth-init" }))
            .contains("ntfy-bootstrap.env"))
        assertContains(inputs.getValue("mariadb-bootstrap.env"), "MARIADB_ROOT_PASSWORD=")
        assertContains(inputs.getValue("mariadb-qualification.env"), "MARIADB_QUALIFICATION_PASSWORD=")
        assertContains(inputs.getValue("postgres-qualification.env"), "POSTGRES_QUALIFICATION_PASSWORD=")
        assertContains(spec.processes.single { it.id == "mariadb-init" }.command.last(),
            "GRANT ALL PRIVILEGES ON qualification.* TO 'qualification'@'%'")
        assertContains(spec.processes.single { it.id == "planka-db-init" }.command.last(),
            "CREATE DATABASE qualification OWNER qualification")
        assertFalse(spec.processes.single { it.id == "postgres" }.files.any { it.file == "postgres-qualification.env" })
        assertFalse(spec.processes.single { it.id == "mariadb" }.files.any { it.file == "mariadb-qualification.env" })
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
        val principal = CanonicalCachePrincipal("mastodon", "f".repeat(64))
        assertFails { CanonicalCoreRuntime.releaseProvidersInputs(inventory,
            { host -> mapOf("ca.pem" to "-----BEGIN CERTIFICATE-----\nunit-$host\n-----END CERTIFICATE-----\n",
                "web.pem" to "unit-cert-$host", "web-key.pem" to "unit-key-$host") },
            object { var index = 0; fun fresh() = (++index).toString(16).padStart(64, '0') }::fresh,
            listOf(principal), fireflyOriginalSubjects = subjects) }
        // Historical Redis keys have no proven disjoint namespace; fresh
        // Mastodon may bootstrap an empty isolated cache, not borrow this ACL.
        assertFails { CanonicalCoreRuntime.releaseProvidersInputs(inventory,
            { host -> mapOf("ca.pem" to "-----BEGIN CERTIFICATE-----\nunit-$host\n-----END CERTIFICATE-----\n",
                "web.pem" to "unit-cert-$host", "web-key.pem" to "unit-key-$host") },
            object { var index = 0; fun fresh() = (++index).toString(16).padStart(64, '0') }::fresh,
            listOf(principal, principal), fireflyOriginalSubjects = subjects) }
        assertFails { CanonicalCoreRuntime.releaseProvidersInputs(inventory, { emptyMap() }, { "a".repeat(64) },
            fireflyOriginalSubjects = subjects) }
        assertFails { CanonicalCoreRuntime.releaseProvidersInputs(inventory, { emptyMap() },
            { (++counter).toString(16).padStart(64, '0') }, fireflyOriginalSubjects = subjects) }
    }

    @Test fun `automatic ownership joins physical and logical writers without inventing public authority`() : Unit {
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

    @Test fun `support provider copies and undeclared primary owners are never canonicalized by image reuse`() : Unit {
        val duplicates = GenerationAssembly().plan(request.copy(selections = listOf(AssemblySelection("foundation"), AssemblySelection("identity"))), bytes)
        assertFailsWith<IllegalArgumentException> { CanonicalTopology.compile(duplicates, false) }
        val unselected = GenerationAssembly().plan(request.copy(selections = listOf(AssemblySelection("identity"))), bytes)
        assertFailsWith<IllegalArgumentException> { CanonicalTopology.compile(unselected, false) }
        for (alternative in listOf("canonical-core", "foundation", "sql-cache", "identity", "firefly", "caddy")) {
            assertFails { GenerationAssembly().plan(request.copy(selections = request.selections + AssemblySelection(alternative)), bytes) }
        }
    }

    @Test fun `only fixed prometheus contribution may own internal monitoring network`(): Unit {
        val base = CanonicalCoreRuntime.releaseProvidersSpec(inventory).copy(store = RuntimeStore.CANONICAL_V2)
        val original = ObservabilityRuntime.canonicalFragment(inventory, base.name)
        val joined = CanonicalCoreRuntime.composeProviders(base, listOf(original))
        val local = "observability-net"
        val web = "observability-web"
        val observed = setOf("metrics-init", "node", "prometheus", "alertmanager", "alloy", "loki", "grafana")
        assertEquals(observed, joined.processes.filter { local in it.networks }.map { it.id }.toSet())
        assertEquals(setOf("caddy", "prometheus", "alertmanager", "grafana"),
            joined.processes.filter { web in it.networks }.map { it.id }.toSet())
        assertFalse(local in joined.processes.single { it.id == "caddy" }.networks)
        assertFails { CanonicalCoreRuntime.composeProviders(base, listOf(original.copy(product = "huly"))) }
        assertFails { CanonicalCoreRuntime.composeProviders(base, listOf(original.copy(
            spec = original.spec.copy(processes = original.spec.processes.map { process ->
                if (process.id == "loki") process.copy(networks = process.networks + web) else process
            })))) }
        assertFails { CanonicalCoreRuntime.composeProviders(base, listOf(original.copy(
            providerNetworks = mapOf("ntfy" to setOf(local))))) }
        val image = inventory.images.single { it.product == "huly-front" }
        val alien = CanonicalProviderFragment("huly", PrivateDeploymentSpec(name = base.name,
            store = base.store, volumes = emptyList(), networks = listOf(local),
            processes = listOf(RuntimeProcess("huly-probe", image.pinnedImage, image.imageId, 1000,
                networks = listOf(local), readiness = listOf("/bin/true")))))
        assertFails { CanonicalCoreRuntime.composeProviders(base, listOf(original, alien)) }
        assertFails { CanonicalCoreRuntime.composeProviders(base, listOf(alien)) }
    }

    @Test fun `provider-less fragments resolve shared database edges before secret preparation`() : Unit {
        val base = CanonicalCoreRuntime.releaseProvidersSpec(inventory)
        val name = base.name
        val image = inventory.images.single { it.product == "forgejo" }
        val app = RuntimeProcess("newapp", image.pinnedImage, image.imageId, 999,
            environmentFile = "newapp.env", dependencies = listOf("postgres"),
            networks = listOf("newapp-data", "newapp-web"), readiness = listOf("/bin/true"),
            files = listOf(RuntimeFile("postgres-ca.pem", "/run/secrets/postgres-ca.pem")))
        val projection = PrivateDeploymentSpec(name = name, volumes = emptyList(),
            processes = listOf(app), networks = listOf("newapp-data", "newapp-web"), store = base.store,
            databaseAccess = listOf(RuntimeDatabaseAccess("newapp", "postgres", "postgres", "newapp", "newapp",
                "newapp.env", "newapp-data")))
        val fragment = CanonicalProviderFragment("forgejo", projection,
            mapOf("postgres" to setOf("newapp-data")), setOf("newapp-web"))
        val joined = CanonicalCoreRuntime.composeProviders(base, listOf(fragment))
        assertEquals(1, joined.processes.count { it.id == "postgres" })
        assertEquals(1, joined.processes.count { it.id == "newapp" })
        assertTrue("newapp-data" in joined.processes.single { it.id == "postgres" }.networks)
        assertTrue("newapp-web" in joined.processes.single { it.id == "caddy" }.networks)
        assertFalse("newapp-data" in joined.processes.single { it.id == "caddy" }.networks)
        assertEquals("postgres", joined.databaseAccess.last().provider)
        val cold = CanonicalCoreRuntime.coldRestoreComposedSpec(joined, base, listOf(fragment), listOf(fragment))
        assertTrue(cold.processes.none { it.oneShot })
        assertEquals(joined.volumes, cold.volumes)
        assertFails { CanonicalCoreRuntime.coldRestoreComposedSpec(joined.copy(volumes = emptyList()), base,
            listOf(fragment), listOf(fragment)) }
        assertFails { CanonicalCoreRuntime.coldRestoreComposedSpec(joined, base, listOf(fragment),
            listOf(fragment.copy(spec = projection.copy(processes = listOf(app.copy(imageId = "f".repeat(64))))))) }
        assertFails { CanonicalCoreRuntime.composeProviders(base, listOf(fragment, fragment)) }
        assertFails { CanonicalCoreRuntime.composeProviders(base, listOf(fragment.copy(
            spec = projection.copy(processes = listOf(app.copy(id = "postgres")))))) }
        assertFails { CanonicalCoreRuntime.composeProviders(base, listOf(fragment.copy(providerNetworks = emptyMap()))) }
        assertFails { CanonicalCoreRuntime.composeProviders(base, listOf(fragment.copy(webNetworks = setOf("newapp-data")))) }
        assertFails { CanonicalCoreRuntime.composeProviders(base, listOf(fragment.copy(spec = projection.copy(
            processes = listOf(app.copy(networks = app.networks + "firefly-web")))))) }
        assertFails { CanonicalCoreRuntime.composeProviders(base, listOf(fragment.copy(
            providerNetworks = mapOf("ntfy" to setOf("planka-web"))))) }
        assertFails { CanonicalCoreRuntime.composeProviders(base, listOf(fragment.copy(
            spec = projection.copy(processes = listOf(app.copy(environmentFile = "postgres-admin.env")))))) }
        val inputs = CanonicalCoreRuntime.releaseProvidersInputs(inventory,
            { host -> mapOf("ca.pem" to "-----BEGIN CERTIFICATE-----\nunit-$host\n-----END CERTIFICATE-----\n",
                "web.pem" to "unit-cert-$host", "web-key.pem" to "unit-key-$host") },
            object { var index = 0; fun fresh() = (++index).toString(16).padStart(64, '0') }::fresh,
            fireflyOriginalSubjects = subjects)
        assertEquals("DB_PASSWORD=unit\n", CanonicalCoreRuntime.mergeProviderInputs(joined, inputs,
            listOf(mapOf("newapp.env" to "DB_PASSWORD=unit\n"))).getValue("newapp.env"))
        assertFails { CanonicalCoreRuntime.mergeProviderInputs(joined, inputs, listOf(emptyMap())) }
        assertFails { CanonicalCoreRuntime.mergeProviderInputs(joined, inputs,
            listOf(mapOf("postgres-ca.pem" to "forged-ca", "newapp.env" to "x"))) }
    }

    @Test fun `restore retires exact initializer authorities and cannot resume source ingress autosave`() : Unit {
        val spec = CanonicalCoreRuntime.releaseProvidersSpec(inventory)
        val restored = CanonicalCoreRuntime.releaseColdRestoreProvidersSpec(spec)
        assertTrue(restored.processes.none { it.oneShot })
        assertEquals(spec.volumes, restored.volumes)
        assertEquals(spec.networks, restored.networks)
        assertEquals(listOf("postgres"), restored.processes.single { it.id == "keycloak" }.dependencies)
        assertEquals(listOf("postgres"), restored.processes.single { it.id == "firefly-php" }.dependencies)
        assertFalse(restored.processes.single { it.id == "caddy" }.command.contains("--resume"))
        assertTrue(restored.databaseAccess.all { it.consumer in setOf("keycloak", "planka", "firefly-php") })
        val retired = PrivateDeployment.inputNames(spec) - PrivateDeployment.inputNames(restored).toSet()
        assertTrue(retired.containsAll(setOf("identity-realm.json", "identity-migration.env", "firefly-migration.env",
            "firefly-onboarding.env", "firefly-users.php",
            "postgres-admin.env", "postgres-qualification.env", "mariadb-bootstrap.env",
            "mariadb-qualification.env", "ntfy-bootstrap.env")))
        assertTrue("identity-ca.pem" in PrivateDeployment.inputNames(restored))
        assertTrue("valkey.acl" in PrivateDeployment.inputNames(restored))
        assertFails { CanonicalCoreRuntime.releaseColdRestoreProvidersSpec(restored) }
        assertFails { CanonicalCoreRuntime.releaseColdRestoreProvidersSpec(spec.copy(processes = spec.processes +
            spec.processes.first { it.oneShot }.copy(id = "unreviewed-init"))) }
    }
}
