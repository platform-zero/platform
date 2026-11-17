package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.*
import kotlin.test.*

class CanonicalSharedYamlGraphTest {
    @Test fun `fresh Forgejo runtime and migration INI use only the selected graph APP origin`() {
        val historic = mapOf("forgejo-runtime.ini" to "[server]\nROOT_URL = https://git.datamancy.net/\n",
            "forgejo-migration.ini" to "[server]\nROOT_URL = https://git.datamancy.net/\n")
        val fresh = CanonicalSharedYamlGraph.freshForgejoSelectedOrigin(historic)
        assertEquals("ROOT_URL = https://git.datamancy.net/\n",
            historic.getValue("forgejo-runtime.ini").substringAfter("[server]\n"))
        for (key in historic.keys) {
            assertContains(fresh.getValue(key), "ROOT_URL = https://forgejo.datamancy.net/")
            assertFalse(fresh.getValue(key).contains("git.datamancy.net"))
        }
        assertFails { CanonicalSharedYamlGraph.freshForgejoSelectedOrigin(fresh) }
    }
    @Test fun `pending fresh r9 source retains complete indexed graph without activating it`() {
        val index = FragmentYaml.parse(java.nio.file.Files.readAllBytes(
            Path.of("src/main/resources/fragments/v3/canonical/r9/index.yaml")))
        index.getValue("entries").jsonArray.forEach { raw ->
            val entry = raw.jsonObject
            val id = entry.getValue("id").jsonPrimitive.content
            val revision = entry.getValue("revision").jsonPrimitive.int
            try { PackagedGraphFragment.loadPendingV3(id, revision, 9) }
            catch (failure: Exception) { throw AssertionError("Invalid indexed fragment: $id/$revision", failure) }
        }
        val counts = CanonicalSharedYamlGraph.pendingR9FreshSource()
        assertEquals(41, counts.getValue("selectedFragments"))
        assertTrue(counts.getValue("sourceProcesses") >= 57)
        assertTrue(counts.getValue("sourceInputs") > 0)
        assertEquals("development-core", CanonicalSharedYamlGraph.manifest().scope)
    }

    private fun inventory(): AcquiredInventory {
        val broad = Json.decodeFromString<AcquiredInventory>(
            GenerationAssembly.readInventory(Path.of("release/downloaded-candidate-inventory.json")).decodeToString())
        val development = Json.decodeFromString<AcquiredInventory>(
            GenerationAssembly.readInventory(Path.of("release/forgejo-pg-v2-development-inventory.json")).decodeToString())
        require(broad.images.single { it.product == "forgejo" }.imageId ==
            development.images.single { it.product == "forgejo" }.imageId)
        return broad.copy(images = broad.images + development.images.single { it.product == "postgres-timescale" })
    }

    @Test fun `hash-bound independent YAML index composes real sole providers and cold projection without historical index rewrite`() {
        val manifest = CanonicalSharedYamlGraph.manifest()
        assertEquals(14, manifest.fragments.size)
        assertEquals(7, manifest.revision)
        assertEquals("development-core", manifest.scope)
        val reference = requireNotNull(manifest.integratedReference)
        assertEquals(39, reference.modules.count { it.role == "selected" })
        assertEquals(8, reference.modules.count { it.role == "historical-support" })
        assertEquals(setOf("postgres", "forgejo", "valkey", "ntfy", "planka", "mariadb", "memcached", "keycloak",
            "alertmanager", "prometheus", "loki", "alloy", "node-exporter", "grafana"),
            reference.modules.flatMap { it.nativeDaemons }.toSet())
        val pinnedSix = Json.parseToJsonElement(java.nio.file.Files.readString(
            Path.of("release/fragment-provenance.json"))).jsonObject.getValue("sources").jsonArray
        for (source in pinnedSix) {
            val entry = source.jsonObject
            val path = entry.getValue("path").jsonPrimitive.content
            val module = reference.modules.single { it.id == path.substringAfter("modules/").substringBefore('/') }
            val hash = entry.getValue("sha256").jsonPrimitive.content
            assertEquals(hash, if (path.endsWith("stack.module.json")) module.descriptorSha256 else module.runtimeSha256)
        }
        assertTrue(reference.modules.single { it.id == "huly" }.nativeDaemons.isEmpty())
        assertTrue(reference.modules.single { it.id == "forgejo" }.services.single().dependsOn.contains("postgres-ssd-bootstrap"))
        assertTrue(reference.modules.single { it.id == "seafile" }.services.single().dependsOn.contains("mariadb"))
        assertTrue(reference.modules.single { it.id == "matrix-authentication-service" }.services.any {
            "synapse" in it.dependsOn })
        assertEquals(setOf("huly-account", "huly-front"), reference.routes.single { it.label == "huly" }.upstreams.toSet())
        assertTrue(reference.wiring.any { it.source == "seafile" && it.target == "onlyoffice" && it.kind == "config" })
        assertTrue(reference.wiring.any { it.source == "matrix-authentication-service" && it.target == "synapse" &&
            it.kind == "identity" })
        assertTrue(reference.wiring.any { it.source == "forgejo" && it.target == "kopia" &&
            it.kind == "state-backup" })
        val inventory = inventory()
        val name = "q-123456abcdef-v3"
        val fresh = CanonicalSharedYamlGraph.spec(inventory, name, controllerSha256 = "a".repeat(64),
            controllerUid = 1000, controllerGid = 1000)
        val cold = CanonicalSharedYamlGraph.spec(inventory, name, FragmentPhase.RESTORE,
            controllerSha256 = "a".repeat(64), controllerUid = 1000, controllerGid = 1000)
        assertEquals(RuntimeExecutionBackend.QUADLET_V2, fresh.executionBackend)
        assertEquals(RuntimeStore.CANONICAL_V2, fresh.store)
        val expected = setOf("postgres", "forgejo", "valkey", "ntfy", "planka", "mariadb", "memcached", "keycloak",
            "alertmanager", "prometheus", "loki", "alloy", "node-exporter", "grafana")
        assertEquals(expected, fresh.processes.filterNot { it.oneShot }.map { it.id }.toSet())
        assertEquals(14, fresh.processes.count { !it.oneShot })
        assertEquals(listOf("alertmanager", "node-exporter", "loki", "alloy"),
            fresh.processes.single { it.id == "prometheus" }.dependencies)
        assertEquals(listOf("alertmanager", "node-exporter", "loki", "alloy"),
            cold.processes.single { it.id == "prometheus" }.dependencies)
        assertEquals(listOf("prometheus", "loki"), fresh.processes.single { it.id == "grafana" }.dependencies)
        assertEquals(listOf("loki"), fresh.processes.single { it.id == "alloy" }.dependencies)
        assertEquals(setOf("metrics-private"), fresh.processes.single { it.id == "prometheus" }.networks.toSet())
        assertEquals(setOf("postgres", "forgejo", "valkey", "ntfy", "forgejo-bootstrap", "uploads", "mariadb",
            "alertmanager", "prometheus", "loki", "alloy", "grafana"),
            fresh.volumes.map { it.id }.toSet())
        assertEquals(expected, cold.processes.map { it.id }.toSet())
        assertEquals(setOf("forgejo-bootstrap"), cold.unmountedRecoveryVolumes)
        assertTrue(fresh.processes.single { it.id == "forgejo" }.dependencies.contains("forgejo-db-finalize"))
        assertTrue(cold.processes.single { it.id == "forgejo" }.dependencies.contains("postgres"))
        assertEquals(setOf("forgejo", "forgejo_migrate", "planka", "planka_migrate", "keycloak", "keycloak_migrate"),
            fresh.databaseAccess.map { it.principal }.toSet())
        assertEquals("planka-data", fresh.databaseAccess.single { it.consumer == "planka" }.network)
        assertEquals("keycloak-data", fresh.databaseAccess.single { it.consumer == "keycloak" }.network)
        assertTrue(fresh.processes.single { it.id == "keycloak" }.command.contains("--spi-connections-jpa--quarkus--migration-strategy=validate"))
        assertTrue(fresh.processes.single { it.id == "keycloak" }.command.contains("--optimized"))
        assertTrue(fresh.processes.single { it.id == "identity-realm-init" }.command.contains("--optimized"))
        assertEquals(listOf("postgres"), cold.processes.single { it.id == "keycloak" }.dependencies)
        assertTrue(CanonicalSharedYamlGraph.exportedProviderInput(fresh, "postgres-ca.pem", "postgres"))
        assertFalse(CanonicalSharedYamlGraph.exportedProviderInput(fresh, "planka-db-admin.env", "postgres"))
        assertFalse(CanonicalSharedYamlGraph.exportedProviderInput(fresh.copy(fragmentBinding =
            fresh.fragmentBinding!!.copy(resources = fresh.fragmentBinding.resources - "fragments/v3/index.yaml")),
            "postgres-ca.pem", "postgres"))
        assertContains(fresh.processes.single { it.id == "postgres" }.networks, "planka-data")
        assertEquals(listOf("postgres"), cold.processes.single { it.id == "planka" }.dependencies)
        assertFalse(cold.processes.any { it.id == "planka-init" || it.id == "planka-db-init" })
        assertTrue(fresh.fragmentBinding!!.resources.keys.any { it == "fragments/v2/index.yaml" })
        assertTrue(fresh.fragmentBinding.resources.keys.any { it == "fragments/v3/manifest.yaml" })
        assertTrue(fresh.fragmentBinding.resources.keys.any { it == "fragments/v3/valkey/r1/fragment.yaml" })
        assertTrue(fresh.fragmentBinding.resources.keys.any { it == "fragments/v3/planka/r1/fragment.yaml" })
        assertTrue(fresh.fragmentBinding.resources.keys.any { it == "fragments/v3/canonical/r2/manifest.yaml" })
        assertTrue(fresh.fragmentBinding.resources.keys.any { it == "fragments/v3/canonical/r3/manifest.yaml" })
        assertTrue(fresh.fragmentBinding.resources.keys.any { it == "fragments/v3/canonical/r4/manifest.yaml" })
        assertTrue(fresh.fragmentBinding.resources.keys.any { it == "fragments/v3/canonical/r5/manifest.yaml" })
        assertTrue(fresh.fragmentBinding.resources.keys.any { it == "fragments/v3/canonical/r6/manifest.yaml" })
        assertTrue(fresh.fragmentBinding.resources.keys.any { it == "fragments/v3/canonical/r7/manifest.yaml" })
        assertTrue(fresh.fragmentBinding.resources.keys.any { it == "fragments/v3/keycloak/r3/fragment.yaml" })
        assertEquals("9eb13f0a60c5732371687e8ebc26a68ed521cdf25e0f728467264a1b9cfe89f6",
            ReleaseLocks.sha256(java.nio.file.Files.readAllBytes(
                Path.of("src/main/resources/fragments/v3/keycloak/r1/fragment.yaml"))))
        assertEquals("33e62501b015c58f96edf785214b14631f7569508c658bd31acabbc0e96717af",
            ReleaseLocks.sha256(java.nio.file.Files.readAllBytes(
                Path.of("src/main/resources/fragments/v3/keycloak/r2/fragment.yaml"))))
        assertTrue(fresh.fragmentBinding.resources.keys.any { it == "fragments/v3/mariadb/r1/fragment.yaml" })
        assertTrue(fresh.fragmentBinding.resources.keys.any { it == "fragments/v3/memcached/r1/fragment.yaml" })
        assertTrue(fresh.processes.single { it.id == "mariadb" }.environmentFile == null)
        assertTrue(cold.processes.none { it.id == "mariadb-init" })
        val rendered = RuntimeQuadlets.render(fresh)
        assertEquals(fresh.processes.size * 2, rendered.files.size)
        assertTrue(rendered.files.values.any { "--memory=256m" in it })
        assertFalse(rendered.runtimeAdmitted)
    }

    @Test fun `original r4 packaged index authenticates historical provider CA without current r5 index substitution`() {
        val (historical, pins) = PackagedGraphFragment.v3HistoricalR4Manifest()
        assertEquals(4, historical.revision)
        val sources = historical.fragments.drop(2).map { PackagedGraphFragment.loadV3(it.id, it.revision) }
        val expected = (FragmentRecipes.fragments().flatMap { f ->
            f.resourceHashes.entries.map { "fragments/v2/${it.key}" to it.value }
        } + sources.flatMap { f ->
            f.resourceHashes.entries.map { "fragments/v3/${it.key}" to it.value }
        } + pins.map { "fragments/v3/${it.key}" to it.value }).toMap()
        assertEquals("f3be0c686903151aceb8abb2ab26ccaceec5b11a6a9274352c5122942ca546b0",
            expected.getValue("fragments/v3/index.yaml"))
        val current = CanonicalSharedYamlGraph.spec(inventory(), "q-123456abcdef-v3",
            controllerSha256 = "a".repeat(64), controllerUid = 1000, controllerGid = 1000)
        val old = current.copy(fragmentBinding = current.fragmentBinding!!.copy(resources = expected))
        assertTrue(CanonicalSharedYamlGraph.exportedProviderInput(old, "postgres-ca.pem", "postgres"))
        val (historicalR5, pinsR5) = PackagedGraphFragment.v3HistoricalManifest(5)
        assertEquals(5, historicalR5.revision)
        assertEquals("c32526e8e31d900fe7972f81ff8d944983107fe9ba44ec146b44248e37b70526",
            pinsR5.getValue("index.yaml"))
        val r5Sources = historicalR5.fragments.drop(2).map { PackagedGraphFragment.loadV3(it.id, it.revision) }
        val r5Resources = (FragmentRecipes.fragments().flatMap { f ->
            f.resourceHashes.entries.map { "fragments/v2/${it.key}" to it.value }
        } + r5Sources.flatMap { f ->
            f.resourceHashes.entries.map { "fragments/v3/${it.key}" to it.value }
        } + pinsR5.map { "fragments/v3/${it.key}" to it.value }).toMap()
        assertTrue(CanonicalSharedYamlGraph.exportedProviderInput(current.copy(fragmentBinding =
            current.fragmentBinding!!.copy(resources = r5Resources)), "postgres-ca.pem", "postgres"))
        val (historicalR6, pinsR6) = PackagedGraphFragment.v3HistoricalManifest(6)
        assertEquals(6, historicalR6.revision)
        assertEquals("03760b5473a8bdf3fdac52de5a720015b2429811e4356b0dccf01265cde196b1",
            pinsR6.getValue("index.yaml"))
        val r6Resources = (FragmentRecipes.fragments().flatMap { f ->
            f.resourceHashes.entries.map { "fragments/v2/${it.key}" to it.value }
        } + historicalR6.fragments.drop(2).flatMap { ref ->
            PackagedGraphFragment.loadV3(ref.id, ref.revision).resourceHashes.entries.map {
                "fragments/v3/${it.key}" to it.value }
        } + pinsR6.map { "fragments/v3/${it.key}" to it.value }).toMap()
        assertTrue(CanonicalSharedYamlGraph.exportedProviderInput(current.copy(fragmentBinding =
            current.fragmentBinding!!.copy(resources = r6Resources)), "postgres-ca.pem", "postgres"))
        val originalIds = (FragmentRecipes.processOwners(FragmentRecipes.FORGEJO_POSTGRES).keys +
            historicalR6.fragments.drop(2).flatMap { PackagedGraphFragment.loadV3(it.id, it.revision)
                .definition.processes.map { p -> p.id } }).toSet()
        val original = current.copy(processes = current.processes.filter { it.id in originalIds },
            fragmentBinding = current.fragmentBinding!!.copy(resources = r6Resources))
        assertEquals(originalIds, CanonicalSharedYamlGraph.processOwnersFor(original).keys)
        assertFails { CanonicalSharedYamlGraph.processOwnersFor(current.copy(fragmentBinding =
            current.fragmentBinding!!.copy(resources = r6Resources))) }
        assertFalse(CanonicalSharedYamlGraph.exportedProviderInput(old.copy(fragmentBinding =
            old.fragmentBinding!!.copy(resources = expected + ("fragments/v3/index.yaml" to "c".repeat(64)))), 
            "postgres-ca.pem", "postgres"))
    }

    @Test fun `integrated old topology rejects removed providers unbound dependencies and forged routes`() {
        val old = requireNotNull(CanonicalSharedYamlGraph.manifest().integratedReference)
        val selected = ProductSelection.bundled().products.toSet()
        assertFails { old.copy(modules = old.modules.filterNot { it.id == "postgres" }).validate(selected) }
        assertFails { old.copy(modules = old.modules.map { module ->
            if (module.id == "seafile") module.copy(services = module.services.map { it.copy(
                dependsOn = it.dependsOn + "unbound-backend") }) else module
        }).validate(selected) }
        assertFails { old.copy(routes = old.routes + IntegratedOldRoute("private-postgres", listOf("missing")))
            .validate(selected) }
        assertFails { old.copy(generatorSha256 = "0".repeat(64)).validate(selected) }
        assertFails { old.copy(modules = old.modules.map { if (it.id == "forgejo")
            it.copy(nativeDaemons = listOf("postgres")) else it }).validate(selected) }
        assertFails { old.copy(wiring = old.wiring.filterNot {
            it.source == "matrix-authentication-service" && it.target == "synapse" && it.kind == "identity"
        }).validate(selected) }
        assertFails { old.copy(wiring = old.wiring + IntegratedWiring("seafile", "unreviewed-provider",
            "provider", "not a pinned original service")).validate(selected) }
    }

    @Test fun `monitoring configuration comes from exact packaged templates not Kotlin topology strings`() {
        for ((id, output) in listOf("private-alertmanager" to "alertmanager.yml",
            "private-prometheus" to "prometheus.yml", "private-loki" to "loki.yml",
            "private-alloy" to "config.alloy", "private-grafana" to "grafana-datasources.yml")) {
            val pinned = PackagedGraphFragment.loadV3(id, 1)
            val bytes = java.nio.file.Files.readAllBytes(Path.of("src/main/resources/fragments/v3/${pinned.definition.product}/r1/$output"))
            assertEquals(bytes.decodeToString(), FragmentTemplates.render(pinned, output, emptyMap()))
            assertEquals(ReleaseLocks.sha256(bytes), pinned.resourceHashes.getValue("${pinned.definition.product}/r1/$output"))
            assertFails { FragmentTemplates.validate(pinned.definition.templates.single(),
                bytes.decodeToString() + "\n{{UNDECLARED}}\n") }
        }
    }

    @Test fun `pinned native Quadlet generator translates expanded shared providers without unit installation`() {
        val spec = CanonicalSharedYamlGraph.spec(inventory(), "q-123456abcdef-v3",
            controllerSha256 = "a".repeat(64), controllerUid = 1000, controllerGid = 1000)
        val generated = RuntimeQuadletDiagnostics.verify(spec, RuntimeQuadlets.render(spec)) { args, units ->
            RuntimeQuadletDiagnostics.invoke(args, units)
        }
        assertEquals("5.4.2", generated.generatorVersion)
        assertEquals(spec.processes.size, generated.services.size)
        assertFalse(generated.runtimeAdmitted || generated.effectiveInstalledUnitsVerified)
    }

    @Test fun `r7 archived source index retains its original exact hashes`() {
        val (historical, pins) = PackagedGraphFragment.v3HistoricalManifest(7)
        assertEquals(7, historical.revision)
        assertEquals(14, historical.fragments.size)
        assertEquals("8b490d8b6b525e0bd59363ea197f11dc17ca5654308bb9ce4d8050351dd15345",
            pins.getValue("index.yaml"))
        val oldResources = (FragmentRecipes.fragments().flatMap { f ->
            f.resourceHashes.map { "fragments/v2/${it.key}" to it.value }
        } + historical.fragments.drop(2).flatMap { ref ->
            PackagedGraphFragment.loadV3(ref.id, ref.revision).resourceHashes.map {
                "fragments/v3/${it.key}" to it.value }
        } + pins.map { "fragments/v3/${it.key}" to it.value }).toMap()
        val newSpec = CanonicalSharedYamlGraph.spec(inventory(), "q-123456abcdef-v3",
            controllerSha256 = "a".repeat(64), controllerUid = 1000, controllerGid = 1000)
        val oldIds = (FragmentRecipes.processOwners(FragmentRecipes.FORGEJO_POSTGRES).keys +
            historical.fragments.drop(2).flatMap { ref ->
                PackagedGraphFragment.loadV3(ref.id, ref.revision).definition.processes.map { it.id }
            }).toSet()
        val oldSpec = newSpec.copy(processes = newSpec.processes.filter { it.id in oldIds },
            fragmentBinding = newSpec.fragmentBinding!!.copy(resources = oldResources))
        assertEquals(oldIds, CanonicalSharedYamlGraph.processOwnersFor(oldSpec).keys)
        assertFalse(oldResources.containsKey("fragments/v3/canonical/r7/index.yaml"))
        assertFalse(newSpec.fragmentBinding!!.resources.containsKey("fragments/v3/canonical/r7/index.yaml"))
    }

    @Test fun `registered YAML shared recipe binds exact ownership topology and honest single-member capacity`() {
        val inventory = inventory()
        val bytes = Json.encodeToString(inventory).toByteArray()
        val request = AssemblyRequest(id = "q-123456abcdef", candidateSha256 = "a".repeat(64),
            inventorySha256 = ReleaseLocks.sha256(bytes),
            selections = listOf(AssemblySelection(CanonicalSharedYamlGraph.RECIPE)),
            diskReservationMiB = 32768, store = RuntimeStore.CANONICAL_V2,
            quadletControllerSha256 = "b".repeat(64))
        val plan = GenerationAssembly().plan(request, bytes)
        val compiled = CanonicalTopology.compile(plan, false)
        assertEquals(6, compiled.topology.providers.count { it.product in plan.summary.members.single().primaryCapabilities })
        assertEquals(0, compiled.topology.providers.groupBy { it.product }.filterValues { it.size > 1 }.size)
        assertEquals(9856L, compiled.topology.capacity.steady.memoryMiB)
        assertEquals(26240L, compiled.topology.capacity.install.memoryMiB + request.memoryHeadroomMiB)
        assertTrue(compiled.topology.capacity.install.memoryMiB >= compiled.topology.capacity.steady.memoryMiB)
        assertEquals(1, plan.specs.size)
        assertEquals(RuntimeExecutionBackend.QUADLET_V2, plan.specs.single().executionBackend)
        assertFalse(compiled.topology.complete || compiled.topology.runtimeValidated || compiled.topology.publicActivation)
        val ownership = CanonicalTopology.ownership(compiled, "private-shared-core", emptyList(), emptySet())
        assertEquals("postgres", ownership.inputs.single { it.input.endsWith("/postgres-ca.pem") }.product)
        assertEquals(ownership.state.single { it.volume.endsWith("/postgres") }.recoveryGroup,
            ownership.state.single { it.volume.endsWith("/uploads") }.recoveryGroup)
        val parent = java.nio.file.Files.createTempDirectory("canonical-shared-export-")
        try {
            val output = parent.resolve("new-private-export")
            val exported = GenerationRender.export(plan, output)
            assertFalse(exported.runtimeAdmitted || exported.privateInputsIncluded || exported.qualificationEvidence)
            assertEquals(ReleaseLocks.sha256(java.nio.file.Files.readAllBytes(
                Path.of("src/main/resources/fragments/v3/canonical/r7/manifest.yaml"))),
                exported.files.getValue("sources/fragments/v3/canonical/r7/manifest.yaml"))
            assertEquals("08bbd8fb06880329deb6fc60de1876d621b049abe177eb65262cf640bd7f5355",
                exported.files.getValue("sources/fragments/v3/canonical/r6/manifest.yaml"))
            assertEquals("01a16971a26a2b30e2e8c395029ef46bee1081c4380c32ad323b4ce9171199a8",
                exported.files.getValue("sources/fragments/v3/canonical/r5/manifest.yaml"))
            assertEquals("fad72915041487cd34c1dcf650d8f924f873a196d3f02305222c15423ae3b0cb",
                exported.files.getValue("sources/fragments/v3/canonical/r4/manifest.yaml"))
            assertTrue(exported.files.keys.any { it.endsWith("/quadlets/p0v3-${plan.specs.single().name}-planka.container") })
        } finally { FragmentAssemblyFixture.remove(parent) }
    }

    @Test fun `unreviewed YAML input or dependency cannot substitute for packaged canonical authority`() {
        val planka = java.nio.file.Files.readString(Path.of("src/main/resources/fragments/v3/planka/r1/fragment.yaml"))
        assertFails { GraphFragment.lint(planka.replace("planka: [planka-db-finalize]",
            "planka: [planka]").toByteArray()) }
        assertFails { GraphFragment.lint(planka.replace("consumers: [planka-db-init, planka-db-finalize]",
            "consumers: [planka]").toByteArray()) }
        val baseline = PackagedGraphFragment.loadV3("planka-postgres", 1).definition
        assertEquals("planka_migrate", baseline.install.databaseAccess.single { it.consumer == "planka-init" }.principal)
        assertEquals("planka", baseline.restore.databaseAccess.single().principal)
        assertTrue(baseline.inputs.single { it.name == "planka-db-admin.env" }.consumers.all {
            id -> baseline.processes.single { it.id == id }.oneShot
        })
    }

    @Test fun `private shared cache principal has distinct credential and refuses fabricated duplicate`() {
        val inventory = inventory()
        var serial = 0
        val next = { (++serial).toString(16).padStart(64, '0') }
        val tls = { mapOf("ca.pem" to "ca", "web.pem" to "cert", "web-key.pem" to "key") }
        val inputs = CanonicalSharedYamlGraph.inputs(inventory, "q-123456abcdef-v3", next, tls, tls)
        assertEquals(30, inputs.size)
        assertContains(inputs.getValue("grafana-datasources.yml"), "url: http://loki:3100")
        assertContains(inputs.getValue("grafana-runtime.env"), "GF_AUTH_ANONYMOUS_ENABLED=false")
        assertContains(inputs.getValue("prometheus.yml"), "targets: ['alertmanager:9093']")
        assertContains(inputs.getValue("alertmanager.yml"), "receiver: private-inert")
        assertContains(inputs.getValue("valkey.conf"), "requirepass ${"7".padStart(64, '0')}")
        assertFalse(inputs.getValue("forgejo-runtime.env").contains("${"7".padStart(64, '0')}"))
        assertContains(inputs.getValue("postgres-hba.conf"), "hostssl planka planka,planka_migrate")
        assertContains(inputs.getValue("postgres-hba.conf"), "hostssl keycloak keycloak,keycloak_migrate")
        assertContains(inputs.getValue("identity-runtime.env"), "KC_HTTP_ENABLED=false")
        assertContains(inputs.getValue("identity-runtime.env"), "sslmode=verify-full")
        assertFalse(inputs.getValue("identity-runtime.env").contains("KEYCLOAK_MIGRATION_PASSWORD"))
        assertContains(inputs.getValue("identity-realm.json"), "identity-controller")
        assertContains(inputs.getValue("identity-realm.json"), "CONFIGURE_TOTP")
        assertContains(inputs.getValue("planka-db-admin.env"), "PGSSLMODE=verify-full")
        assertContains(inputs.getValue("planka-runtime.env"), "@postgres:5432/planka?sslmode=verify-full")
        assertFalse(inputs.getValue("planka-runtime.env").contains("DEFAULT_ADMIN_PASSWORD"))
        assertContains(inputs.getValue("planka-migration.env"), "DEFAULT_ADMIN_PASSWORD=")
        assertContains(inputs.getValue("mariadb-bootstrap.env"), "MARIADB_ROOT_PASSWORD=${"c".padStart(64, '0')}")
        assertFalse(inputs.getValue("planka-runtime.env").contains("MARIADB_ROOT_PASSWORD"))
    }
}
