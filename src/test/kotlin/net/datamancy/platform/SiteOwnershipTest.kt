package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class SiteOwnershipTest {
    private val inventory = Json.encodeToString(AcquiredInventory(1, "unit-only", listOf("postgres", "valkey", "ntfy", "mariadb", "memcached").map {
        AcquiredImage(it, "unit", "example.test/$it:1", "example.test/$it@sha256:" + "a".repeat(64), "b".repeat(64),
            emptyList(), "sha256:" + "a".repeat(64), "amd64", "linux")
    })).toByteArray()
    private val request = AssemblyRequest(id = "q-abcdef123456", candidateSha256 = "c".repeat(64),
        inventorySha256 = ReleaseLocks.sha256(inventory), selections = listOf(AssemblySelection("foundation"), AssemblySelection("sql-cache")),
        diskReservationMiB = 8192)
    private val plan = GenerationAssembly().plan(request, inventory)
    private val host = "ntfy.v3.example.org"
    private fun contract(p: AssemblyPlan = plan): SiteOwnership {
        val owners = p.specs.flatMap { member -> member.processes.map { SiteProcessOwner("${member.name}/${it.id}", it.id.removeSuffix("-init").removeSuffix("-copy")) } }
        val byActor = owners.associate { it.process to it.product }
        return SiteOwnership(site = "unit-site", assemblySha256 = SiteOwnerships.assemblyDigest(p), processes = owners,
            state = p.specs.flatMap { m -> m.volumes.map { SiteStateOwner("${m.name}/${it.id}", it.id, "cohort") } },
            inputs = p.specs.flatMap { m -> PrivateDeployment.inputNames(m).map { file ->
                val actors = m.processes.filter { it.environmentFile == file || it.files.any { f -> f.file == file } }.map { "${m.name}/${it.id}" }
                SiteInputOwner("${m.name}/$file", byActor.getValue(actors.first()), true, actors)
            } }, routes = listOf(SiteRouteOwner(host, "ntfy", "${request.id}-foundation/ntfy", 8080)))
    }
    @Test fun `isolated store fresh preparation binds ownership store and credentials before runtime execution`() {
        val root = Files.createTempDirectory("isolated-owned-unit-")
        val runtimes = Files.createDirectory(root.resolve("runtimes"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val isolated = GenerationAssembly().plan(request.copy(store = RuntimeStore.CANONICAL_V2), inventory)
        val engine = GenerationRuntime(root.resolve("generations"), runtimes,
            { error("No native runtime in preparation units") }, { error("No live capacity in preparation units") })
        try {
            assertFails { engine.prepareAssembly(isolated) }
            assertFalse(Files.exists(root.resolve("generations/${request.id}")))
            assertFails { engine.prepareOwnedAssembly(isolated.copy(generation = isolated.generation.copy(store = RuntimeStore.LEGACY)),
                contract(isolated), setOf(host)) }
            val sha = engine.prepareOwnedAssembly(isolated, contract(isolated), setOf(host))
            val control = root.resolve("generations/${request.id}")
            val bundle = Json.decodeFromString<GenerationBundle>(Files.readString(control.resolve("bundle.json")))
            assertEquals(sha, ReleaseLocks.sha256(Files.readAllBytes(control.resolve("bundle.json"))))
            assertEquals(RuntimeStore.CANONICAL_V2, bundle.request.store)
            assertEquals(RuntimeStore.CANONICAL_V2, bundle.ownership!!.assembly.request.store)
            assertTrue(bundle.members.all { it.spec.store == RuntimeStore.CANONICAL_V2 })
            SiteOwnerships.checkSealed(bundle)
            for (pin in bundle.members) {
                assertEquals(pin.spec, PrivateDeployment.read(runtimes.resolve("${pin.member.name}.json")))
                assertFalse(Files.exists(runtimes.resolve("${pin.member.name}/runtime.owner")))
                assertFalse(Files.exists(runtimes.resolve("${pin.member.name}/runtime.jobs")))
            }
            assertFails { engine.prepareOwnedAssembly(isolated, contract(isolated), setOf(host)) }
            assertFails { FoundationRuntime.prepare(isolated.inventory, runtimes, "${request.id}-foundation", RuntimeStore.LEGACY) }
            assertFails { engine.seal(isolated.generation) }
            assertEquals(bundle, Json.decodeFromString<GenerationBundle>(Files.readString(control.resolve("bundle.json"))))
            assertFalse(Json { encodeDefaults = true }.encodeToString(request).contains("\"store\""))
            assertEquals(request.copy(store = RuntimeStore.CANONICAL_V2),
                Json.decodeFromString<AssemblyRequest>(Json.encodeToString(isolated.summary.request)))
        } finally { Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `historical load used by capture rejects forged sealed ownership even without live input recheck`() {
        val root = Files.createTempDirectory("historical-owned-capture-unit-")
        val runtime = Files.createDirectory(root.resolve("runtimes"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val assembly = GenerationAssembly().plan(request.copy(store = RuntimeStore.CANONICAL_V2), inventory)
        val engine = GenerationRuntime(root.resolve("generations"), runtime,
            { error("No runtime effects permitted") }, { error("No capacity effects permitted") })
        try {
            val sealedHash = engine.prepareOwnedAssembly(assembly, contract(assembly), setOf(host))
            val path = root.resolve("generations/${request.id}/bundle.json")
            val original = Json.decodeFromString<GenerationBundle>(Files.readString(path))
            // The same historical load(false) boundary is used by cold capture,
            // retired capacity, and isolated source inspection. Reflection keeps
            // this unit fixture on that exact private gate, not a weaker surrogate.
            val historical = GenerationRuntime::class.java.declaredMethods.single {
                it.name == "load" && it.parameterCount == 3
            }.apply { isAccessible = true }
            assertNotNull(historical.invoke(engine, request.id, sealedHash, false))
            val contract = requireNotNull(original.ownership).contract
            val forged = original.copy(ownership = original.ownership.copy(contract = contract.copy(
                processes = contract.processes.mapIndexed { index, owner ->
                    if (index == 0) owner.copy(product = "ntfy") else owner
                })))
            val forgedBytes = Json { encodeDefaults = true }.encodeToString(forged).toByteArray()
            Files.write(path, forgedBytes) // Isolated unit fixture only: attacker knows its new hash.
            assertFails { historical.invoke(engine, request.id, ReleaseLocks.sha256(forgedBytes), false) }
        } finally {
            Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
    @Test fun `exact compiled ownership reports remaining release gaps without claiming execution`() {
        val value = contract()
        assertEquals(value, SiteOwnerships.decode(Json.encodeToString(value).toByteArray()))
        val report = SiteOwnerships.check(plan, value, setOf(host))
        assertEquals(5, report.serviceArtifactProcesses.size)
        assertTrue(report.repeatedServiceArtifacts.isEmpty())
        assertTrue(report.unclassifiedDaemonArtifacts.isEmpty())
        assertTrue(report.unverifiedProcessRoles.isEmpty())
        assertEquals(4, report.recoveryGroups.getValue("cohort").size)
        assertTrue("worklane" in report.missingCapabilities)
        assertFalse(report.executable); assertFalse(report.centralWiringVerified); assertFalse(report.publicActivation)
        assertEquals(64, report.ownershipSha256.length)
    }
    @Test fun `ownership assembly digest is identical to durable preparation intent`() {
        val root = Files.createTempDirectory("site-ownership-binding-unit-")
        val runtimes = Files.createDirectory(root.resolve("runtimes"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            val engine = GenerationRuntime(root.resolve("generations"), runtimes, { error("No runtime effects permitted") }, { error("No allocation permitted") })
            engine.prepareAssembly(plan)
            val intent = root.resolve("generations/${request.id}/assembly.intent.json")
            assertEquals(ReleaseLocks.sha256(Files.readAllBytes(intent)), SiteOwnerships.assemblyDigest(plan))
            val bundle = Json.decodeFromString<GenerationBundle>(Files.readString(intent.parent.resolve("bundle.json")))
            assertEquals(bundle.memoryReservationMiB, SiteOwnerships.inspect(plan).memoryReservationMiB)
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `foreign bindings omitted duplicated and invented owners fail closed`() {
        val c = contract()
        val bad = listOf(c.copy(schemaVersion = 2), c.copy(site = "../other"), c.copy(assemblySha256 = "f".repeat(64)),
            c.copy(processes = c.processes.dropLast(1)), c.copy(processes = c.processes + c.processes.first()),
            c.copy(state = c.state.dropLast(1)), c.copy(inputs = c.inputs.dropLast(1)),
            c.copy(processes = c.processes.map { it.copy(product = "missing") }),
            c.copy(processes = c.processes.map { if (it.product == "memcached") it.copy(product = "mariadb") else it }),
            c.copy(state = c.state.map { it.copy(recoveryGroup = "../escape") }),
            c.copy(state = c.state.map { it.copy(product = "ntfy") }),
            c.copy(inputs = c.inputs.map { it.copy(consumers = emptyList()) }),
            c.copy(inputs = c.inputs.map { it.copy(product = "memcached") }))
        bad.forEach { assertFailsWith<IllegalArgumentException> { SiteOwnerships.check(plan, it, setOf(host)) } }
        assertFails { SiteOwnerships.decode(byteArrayOf()) }
        assertFails { SiteOwnerships.decode("{\"foreign\":true}".toByteArray()) }
        assertFails { SiteOwnerships.check(plan.copy(specs = emptyList()), c, setOf(host)) }
        assertFails { SiteOwnerships.check(plan, c, setOf("https://wrong")) }
    }
    @Test fun `routes must stay in exact host process and product boundaries`() {
        val c = contract(); val r = c.routes.single()
        val bad = listOf(r.copy(host = "elsewhere.example.org"), r.copy(host = "https://$host"),
            r.copy(process = "foreign/ntfy"), r.copy(process = "${request.id}-foundation/postgres-init", product = "postgres"),
            r.copy(port = 0), r.copy(port = 65536), r.copy(product = "postgres"))
        bad.forEach { assertFails { SiteOwnerships.check(plan, c.copy(routes = listOf(it)), setOf(host)) } }
        assertFails { SiteOwnerships.check(plan, c.copy(routes = listOf(r, r)), setOf(host)) }
    }
    @Test fun `compiled roles cannot be relabelled and unknown artifacts stay explicit`() {
        val c = contract()
        val altered = c.copy(processes = c.processes.map { if (it.product == "memcached") it.copy(product = "ntfy") else if (it.process.endsWith("/ntfy")) it.copy(product = "memcached") else it },
            state = c.state.map { if (it.product == "ntfy") it.copy(product = "memcached") else it }, routes = emptyList())
        assertFailsWith<IllegalArgumentException> { SiteOwnerships.check(plan, altered, emptySet()) }
        val ambiguous = plan.inventory.copy(images = plan.inventory.images + plan.inventory.images.first().copy(product = "alias"))
        assertTrue(SiteOwnerships.check(plan.copy(inventory = ambiguous), c, setOf(host)).unclassifiedDaemonArtifacts.any { it.endsWith("/postgres") })
        assertEquals(5, SiteOwnerships.check(plan.copy(inventory = plan.inventory.copy(images = emptyList())), c, setOf(host)).unclassifiedDaemonArtifacts.size)
    }
    @Test fun `image provenance is not confused with the logical service role`() {
        val original = plan.specs.first()
        val reusable = plan.specs.last().processes.first { it.id == "memcached" }
        val changed = original.copy(processes = original.processes.map {
            if (it.id == "ntfy") it.copy(image = reusable.image, imageId = reusable.imageId) else it
        })
        val p = rebind(listOf(changed) + plan.specs.drop(1))
        val report = SiteOwnerships.check(p, contract(p), setOf(host))
        assertEquals(2, report.repeatedServiceArtifacts.getValue("memcached").size)
        assertFalse(report.centralWiringVerified)
    }
    private fun rebind(specs: List<PrivateDeploymentSpec>): AssemblyPlan = plan.copy(specs = specs,
        summary = plan.summary.copy(members = plan.summary.members.zip(specs).map { (member, spec) ->
            member.copy(specSha256 = ReleaseLocks.sha256(Json.encodeToString(spec).toByteArray()))
        }))
    @Test fun `repeated daemon artifacts stay visible without inferring service topology`() {
        val original = plan.specs.first()
        val duplicate = original.processes.first { it.id == "postgres" }.copy(id = "postgres-copy", volumes = emptyList(), dependencies = emptyList())
        val p = rebind(listOf(original.copy(processes = original.processes + duplicate)) + plan.specs.drop(1))
        val report = SiteOwnerships.check(p, contract(p), setOf(host))
        assertEquals(2, report.repeatedServiceArtifacts.getValue("postgres").size)
        assertFalse(report.centralWiringVerified)
        assertEquals(2, SiteOwnerships.inspect(p).repeatedServiceArtifacts.getValue("postgres").size)
    }
    @Test fun `all nonconflicting recipes expose real duplicated services without preparing credentials`() {
        val bytes = GenerationAssembly.readInventory(Path.of("release/downloaded-candidate-inventory.json"))
        val excluded = setOf("canonical-core", "canonical-providers", "caddy", "openbao", "seafile", "sogo", "mail", "synapse", "matrix", "matrix-rtc", "knowledge-identity", CanonicalSharedYamlGraph.RECIPE,
            CanonicalSharedYamlGraph.R9_ASSEMBLY_RECIPE,
            CanonicalSharedYamlGraph.R10_ASSEMBLY_RECIPE) + FragmentRecipes.recipeIds
        val all = GenerationAssembly().plan(request.copy(inventorySha256 = ReleaseLocks.sha256(bytes), diskReservationMiB = 131072,
            selections = GenerationAssembly.catalog.filterNot { it.id in excluded }.map { AssemblySelection(it.id) }), bytes)
        val report = SiteOwnerships.inspect(all)
        assertEquals(27, all.specs.size)
        assertTrue(report.repeatedServiceArtifacts.isNotEmpty())
        assertTrue(report.unclassifiedDaemons.isNotEmpty())
        assertEquals(144, report.processes.size)
        assertTrue(report.processes.all { it.compiledProduct != null })
        val owners = report.processes.associate { it.process to requireNotNull(it.compiledProduct) }
        val fullContract = SiteOwnership(site = "complete-private-role-graph", assemblySha256 = report.assemblySha256,
            processes = owners.map { SiteProcessOwner(it.key, it.value) },
            state = report.state.map { state ->
                val products = state.writers.map { owners.getValue(it) }.toSet()
                assertEquals(1, products.size, "Shared state needs an explicit delegation contract: ${state.volume}")
                SiteStateOwner(state.volume, products.single(), "cohort")
            },
            inputs = report.inputs.map { input -> SiteInputOwner(input.input, requireNotNull(input.compiledProduct), true, input.consumers) },
            routes = emptyList())
        val checked = SiteOwnerships.check(all, fullContract, emptySet())
        assertTrue(checked.unverifiedProcessRoles.isEmpty())
        assertFalse(checked.centralWiringVerified)
        assertEquals(fullContract, SiteOwnerships.bind(all, fullContract, emptySet()).contract)
        val wrongSharedOwner = fullContract.copy(inputs = fullContract.inputs.map {
            if (it.input.endsWith("-office/ca.pem")) it.copy(product = "onlyoffice") else it
        })
        assertFails { SiteOwnerships.bind(all, wrongSharedOwner, emptySet()) }
        assertTrue(report.missingCapabilities.containsAll(setOf("worklane", "tuios", "pi", "mastodon-rss-publisher", "caddy")))
        assertTrue(report.state.all { it.writers.isNotEmpty() })
        assertTrue(report.inputs.all { it.consumers.isNotEmpty() })
        assertFalse(report.executable)
    }
    @Test fun `role catalog is exact for every compiled recipe including alternative composites`() {
        val bytes = GenerationAssembly.readInventory(Path.of("release/downloaded-candidate-inventory.json"))
        // Pending full r9 roles are derived from the exact checked generation
        // fragment binding, not the active r7 static role table.
        assertEquals(GenerationAssembly.catalog.map { it.id }.toSet() -
            setOf(CanonicalSharedYamlGraph.R9_ASSEMBLY_RECIPE,
                CanonicalSharedYamlGraph.R10_ASSEMBLY_RECIPE), CompiledProcessOwners.recipes.keys)
        // The repository inventory predates Timescale; new packaged ownership is tested with an
        // explicit unit-only artifact fixture in FragmentAssemblyTest, never a relabelled live image.
        for (recipe in GenerationAssembly.catalog.filter { it.id !in FragmentRecipes.recipeIds &&
            it.id != CanonicalSharedYamlGraph.RECIPE &&
            it.id !in setOf(CanonicalSharedYamlGraph.R9_ASSEMBLY_RECIPE,
                CanonicalSharedYamlGraph.R10_ASSEMBLY_RECIPE) }) {
            val p = GenerationAssembly().plan(request.copy(inventorySha256 = ReleaseLocks.sha256(bytes), diskReservationMiB = 131072,
                selections = listOf(AssemblySelection(recipe.id))), bytes)
            val roles = CompiledProcessOwners.recipes.getValue(recipe.id)
            assertEquals(p.specs.single().processes.map { it.id }.toSet(), roles.keys, recipe.id)
            assertTrue(roles.values.all { it in GenerationAssembly.requiredCapabilities }, recipe.id)
            val graph = SiteOwnerships.inspect(p)
            assertTrue(graph.processes.all { it.compiledProduct != null }, recipe.id)
            assertTrue(graph.inputs.all { it.compiledProduct != null }, recipe.id)
        }
        // Generic web images and Hub notebook images do not silently acquire their inventory product's ownership.
        assertEquals("livekit", CompiledProcessOwners.recipes.getValue("livekit").getValue("rtc"))
        assertEquals("jupyterhub", CompiledProcessOwners.recipes.getValue("jupyterhub").getValue("alice"))
        assertEquals("keycloak", CompiledProcessOwners.recipes.getValue("matrix-identity").getValue("identity"))
        assertEquals("bookstack", CompiledProcessOwners.recipes.getValue("knowledge-identity").getValue("knowledge"))
    }
    @Test fun `shared input ownership is explicit and unknown consumers are never guessed`() {
        assertNull(CompiledProcessOwners.inputOwner("unknown", "shared.env", emptySet()))
        assertNull(CompiledProcessOwners.inputOwner("unknown", "shared.env", setOf(null, "postgres")))
        assertNull(CompiledProcessOwners.inputOwner("unknown", "shared.env", setOf("postgres", "keycloak")))
        assertEquals("openbao", CompiledProcessOwners.inputOwner("keykeeper", "ca.pem", setOf("keykeeper", "openbao")))
        assertFails { CompiledProcessOwners.inputOwner("keykeeper", "ca.pem", setOf("keykeeper", "valkey")) }
    }
    @Test fun `shared writer cannot split its volumes into separate recovery points`() {
        val original = plan.specs.first()
        val changed = original.copy(volumes = original.volumes + RuntimeVolume("extra", 999), processes = original.processes.map {
            if (it.id == "postgres") it.copy(volumes = it.volumes + RuntimeMount("extra", "/extra")) else it
        })
        val p = rebind(listOf(changed) + plan.specs.drop(1)); val c = contract(p)
        val correctedOwner = c.copy(state = c.state.map { if (it.volume.endsWith("/extra")) it.copy(product = "postgres", recoveryGroup = "other") else it })
        val error = assertFailsWith<IllegalArgumentException> { SiteOwnerships.check(p, correctedOwner, setOf(host)) }
        assertTrue(error.message!!.contains("crosses recovery groups"))
    }
    private fun ownedFixture(block: (Path, GenerationRuntime, () -> Int) -> Unit) {
        val root = Files.createTempDirectory("owned-assembly-unit-")
        val runtimes = Files.createDirectory(root.resolve("runtimes"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        var audits = 0
        val engine = GenerationRuntime(root.resolve("generations"), runtimes, { bindings -> object : GenerationBackend {
            override fun audit(spec: PrivateDeploymentSpec, pristine: Boolean): RuntimeAudit {
                audits++
                return RuntimeAudit(spec.name, bindings.getValue(spec.name), 0, null, spec.processes.map { RuntimeStatus(it.id, "absent", null) })
            }
            override fun apply(spec: PrivateDeploymentSpec): List<RuntimeStatus> = error("Unit must not start services")
            override fun isolate(spec: PrivateDeploymentSpec): String = error("Unit must not manipulate fences")
        } }, { error("Preparation must not allocate runtime resources") })
        try { block(root, engine) { audits } }
        finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `invalid ownership never reaches registry or credential preparation`() = ownedFixture { root, engine, audits ->
        var prepared = 0
        val p = plan.copy(recipes = plan.recipes.map { r -> r.copy(prepare = { _, _, _, _ -> prepared++; error("Forbidden preparation") }) })
        assertFails { engine.prepareOwnedAssembly(p, contract().copy(processes = emptyList()), setOf(host)) }
        assertFails { engine.prepareOwnedAssembly(p.copy(generation = p.generation.copy(candidateSha256 = "f".repeat(64))), contract(), setOf(host)) }
        assertEquals(0, prepared); assertEquals(0, audits())
        assertFalse(Files.exists(root.resolve("generations")))
        assertEquals(0L, Files.list(root.resolve("runtimes")).use { it.count() })
        val original = plan.specs.first()
        val extra = original.processes.first { it.id == "postgres" }.copy(id = "postgres-copy", volumes = emptyList(), dependencies = emptyList())
        val unknown = rebind(listOf(original.copy(processes = original.processes + extra)) + plan.specs.drop(1))
        assertFails { engine.prepareOwnedAssembly(unknown, contract(unknown), setOf(host)) }
        assertFalse(Files.exists(root.resolve("generations")))
    }
    @Test fun `ownership intent precedes credentials and is sealed with immutable caller policy snapshot`() = ownedFixture { root, engine, audits ->
        val hosts = mutableSetOf(host)
        var prepared = 0
        val p = plan.copy(recipes = plan.recipes.map { recipe -> recipe.copy(prepare = { inventory, base, name, store ->
            val intent = root.resolve("generations/${request.id}/ownership.intent.json")
            assertTrue(Files.isRegularFile(intent))
            hosts.clear() // Caller collections must not change the validated/prepared policy.
            prepared++; recipe.prepare(inventory, base, name, store)
        }) })
        val digest = engine.prepareOwnedAssembly(p, contract(), hosts)
        assertEquals(2, prepared); assertEquals(0, audits())
        val bundle = Json.decodeFromString<GenerationBundle>(Files.readString(root.resolve("generations/${request.id}/bundle.json")))
        assertEquals(setOf(host), bundle.ownership!!.approvedHosts)
        SiteOwnerships.checkSealed(bundle)
        assertEquals(2, engine.inspect(request.id, digest).members.size)
        assertEquals(2, audits())
        assertFails { engine.prepareOwnedAssembly(p, contract(), setOf(host)) }
        assertEquals(2, prepared)
        assertFails { SiteOwnerships.checkSealed(bundle.copy(recoverySourceArchiveSha256 = "a".repeat(64))) }
        assertFails { SiteOwnerships.checkSealed(bundle.copy(request = bundle.request.copy(candidateSha256 = "f".repeat(64)))) }
        assertFails { SiteOwnerships.checkSealed(bundle.copy(ownership = bundle.ownership.copy(contract = contract().copy(routes = listOf(contract().routes.single().copy(port = 0)))))) }
        val restored = FoundationRestore.bundle(bundle, plan.inventory, "q-112233445566", "f".repeat(64))
        assertNull(restored.ownership) // Archived source authority never becomes authority over a new restore namespace.
        assertEquals("f".repeat(64), restored.recoverySourceArchiveSha256)
    }
    @Test fun `changed ownership preparation intent blocks auditing before any backend access`() = ownedFixture { root, engine, audits ->
        val digest = engine.prepareOwnedAssembly(plan, contract(), setOf(host))
        val intent = root.resolve("generations/${request.id}/ownership.intent.json")
        Files.writeString(intent, Files.readString(intent) + "\n") // Temporary unit fixture only.
        assertFails { engine.inspect(request.id, digest) }
        assertEquals(0, audits())
    }
    @Test fun `missing ownership intent blocks live loading while inline source binding remains inspectable`() = ownedFixture { root, engine, audits ->
        val digest = engine.prepareOwnedAssembly(plan, contract(), setOf(host))
        Files.delete(root.resolve("generations/${request.id}/ownership.intent.json")) // Temporary unit fixture only.
        assertFails { engine.inspect(request.id, digest) }
        assertEquals(0, audits())
    }
    @Test fun `failed owned preparation retains its policy and never regenerates partial credentials`() = ownedFixture { root, engine, _ ->
        var calls = 0
        val p = plan.copy(recipes = plan.recipes.mapIndexed { index, recipe -> recipe.copy(prepare = { inventory, base, name, store ->
            calls++; if (index == 1) error("Unit preparation failure") else recipe.prepare(inventory, base, name, store)
        }) })
        assertFails { engine.prepareOwnedAssembly(p, contract(), setOf(host)) }
        val group = root.resolve("generations/${request.id}")
        assertTrue(Files.exists(group.resolve("ownership.intent.json")))
        assertFalse(Json.decodeFromString<AssemblyPreparationOutcome>(Files.readString(group.resolve("assembly.result.json"))).passed)
        assertFalse(Files.exists(group.resolve("bundle.json")))
        assertFails { engine.prepareOwnedAssembly(p, contract(), setOf(host)) }
        assertEquals(2, calls)
    }
    @Test fun `CLI validates private contracts without preparing a runtime`() {
        val root = Files.createTempDirectory("site-ownership-unit-")
        fun file(name: String, text: String): String = root.resolve(name).also {
            Files.writeString(it, text); Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rw-------"))
        }.toString()
        try {
            val args = arrayOf("release", "site-ownership-check", file("inventory.json", inventory.decodeToString()),
                file("assembly.json", Json.encodeToString(request)), file("ownership.json", Json.encodeToString(contract())),
                file("hosts.json", Json.encodeToString(listOf(host))))
            val lines = mutableListOf<String>()
            assertEquals(0, runCommand(args, lines::add, lines::add))
            assertTrue(lines.last().contains("Structural ownership only"))
            assertEquals(0, runCommand(arrayOf("release", "site-ownership-inventory", args[2], args[3]), lines::add, lines::add))
            val inventoryReport = Json.decodeFromString<SiteOwnershipInventory>(lines.last())
            assertEquals(7, inventoryReport.processes.size)
            assertFalse(inventoryReport.executable)
            Files.writeString(Path.of(args[4]), "{}")
            assertEquals(1, runCommand(args, lines::add, lines::add))
            assertEquals(4L, Files.list(root).use { it.count() })
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
