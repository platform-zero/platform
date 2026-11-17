package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

internal object FragmentAssemblyFixture {
    val inventory = AcquiredInventory(1, "unit-fixture-not-runtime-evidence", listOf("postgres-timescale", "forgejo").mapIndexed { n, id ->
        val sha = (n + 1).toString().repeat(64)
        AcquiredImage(id, "unit-fixture", "example.test/$id:unit", "example.test/$id@sha256:$sha",
            sha, emptyList(), "sha256:$sha", "amd64", "linux")
    })
    val bytes = Json.encodeToString(inventory).toByteArray()
    val request = AssemblyRequest(id = "q-aabbccddeeff", candidateSha256 = "c".repeat(64),
        inventorySha256 = ReleaseLocks.sha256(bytes), selections = listOf(AssemblySelection(FragmentRecipes.FORGEJO_POSTGRES)),
        diskReservationMiB = 8192, store = RuntimeStore.CANONICAL_V2, quadletControllerSha256 = "d".repeat(64))
    fun plan() = GenerationAssembly().plan(request, bytes)
    fun secrets(): () -> String { var n = 0; return { (++n).toString().repeat(64) } }
    fun pki() = mapOf("ca.pem" to "unit-ca", "web.pem" to "unit-leaf", "web-key.pem" to "unit-key")
    fun remove(root: Path) = Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
}

class FragmentAssemblyTest {
    @Test fun `canonical graph derives ownership and exact input closure from YAML`() {
        val plan = FragmentAssemblyFixture.plan()
        val spec = plan.specs.single()
        val report = CanonicalTopology.compile(plan, false).topology
        assertEquals(RuntimeExecutionBackend.QUADLET_V2, spec.executionBackend)
        assertEquals("d".repeat(64), spec.fragmentBinding!!.controllerSha256)
        assertEquals(com.sun.security.auth.module.UnixSystem().uid.toInt(), spec.fragmentBinding.controllerUid)
        assertEquals(setOf("postgres", "forgejo"), plan.summary.members.single().primaryCapabilities)
        assertEquals(spec.processes.map { it.id }.toSet(), CompiledProcessOwners.recipes.getValue(FragmentRecipes.FORGEJO_POSTGRES).keys)
        assertTrue(report.inputs.all { it.owner in setOf("postgres", "forgejo") })
        assertEquals("postgres", report.inputs.single { it.input.endsWith("/postgres-ca.pem") }.owner)
        assertEquals(1, report.providers.count { it.product == "postgres" })
        assertTrue(FragmentRecipes.exportedProviderInput(spec, "postgres-ca.pem", "postgres"))
        assertFalse(FragmentRecipes.exportedProviderInput(spec, "postgres-key.pem", "postgres"))
        assertFalse(FragmentRecipes.exportedProviderInput(spec, "postgres-ca.pem", "forgejo"))
        assertFalse(FragmentRecipes.exportedProviderInput(spec.copy(fragmentBinding = spec.fragmentBinding.copy(resources = emptyMap())),
            "postgres-ca.pem", "postgres"))
        assertFalse(report.complete || report.runtimeValidated || report.publicActivation)
        assertEquals(spec, FragmentRecipes.spec(plan.inventory, spec.name, controllerSha256 = spec.fragmentBinding.controllerSha256,
            controllerUid = spec.fragmentBinding.controllerUid, controllerGid = spec.fragmentBinding.controllerGid))
    }

    @Test fun `pinned native-built development artifact is accepted by the packaged graph without runtime admission`() {
        val bytes = GenerationAssembly.readInventory(Path.of("release/forgejo-pg-v2-development-inventory.json"))
        val inventory = Json.decodeFromString<AcquiredInventory>(bytes.decodeToString())
        assertTrue(inventory.status.contains("not-a-reviewed-compatible-release"))
        val pg = inventory.images.single { it.product == "postgres-timescale" }
        assertEquals("7cd945ac49388b3a008caee3fa77599bfc7901dbdda9ff6746562af82c49793c", pg.imageId)
        assertEquals("sha256:a124e99c35c9a6ae7f6cfccb5db1bd51dfc024bacd957fee8848c82d7ff31919",
            pg.selectedManifestDigest)
        val plan = GenerationAssembly().plan(FragmentAssemblyFixture.request.copy(
            inventorySha256 = ReleaseLocks.sha256(bytes)), bytes)
        assertEquals(pg.imageId, plan.specs.single().processes.single { it.id == "postgres" }.imageId)
        assertFalse(CanonicalTopology.compile(plan, false).topology.runtimeValidated)
    }

    @Test fun `controller store and source binding fail before preparation`() {
        val request = FragmentAssemblyFixture.request
        for (bad in listOf(request.copy(quadletControllerSha256 = null), request.copy(quadletControllerSha256 = "bad"),
            request.copy(store = RuntimeStore.LEGACY))) {
            assertFails { GenerationAssembly().plan(bad, FragmentAssemblyFixture.bytes) }
        }
        val plan = FragmentAssemblyFixture.plan(); var entropy = 0
        val spec = plan.specs.single()
        assertFails { FragmentRecipes.inputs(spec.copy(processes = spec.processes.dropLast(1)), plan.inventory,
            { entropy++; "a".repeat(64) }, { error("PKI must not run") }) }
        assertEquals(0, entropy)
    }

    @Test fun `Forgejo r4 raw URL Base64 JWT key has exactly 32 decoded bytes while r2 and r3 remain intact`() {
        val r2 = PackagedGraphFragment.load("forgejo-postgres", 2)
        val r3 = PackagedGraphFragment.load("forgejo-postgres", 3)
        val r4 = PackagedGraphFragment.load("forgejo-postgres", 4)
        assertEquals(2, r2.definition.revision)
        assertEquals(3, r3.definition.revision)
        assertEquals(4, r4.definition.revision)
        assertEquals("9c726e1b01e5d1a503edccfaca93991e739f5c994959c49393d6d12eb6a85e4f",
            r2.resourceHashes.getValue("forgejo/r2/fragment.yaml"))
        assertEquals(FragmentValueKind.BASE64_32,
            r3.definition.templates.single { it.output == "forgejo-runtime.ini" }.parameters.getValue("JWT_SECRET"))
        assertEquals(FragmentValueKind.BASE64URL_32,
            r4.definition.templates.single { it.output == "forgejo-runtime.ini" }.parameters.getValue("JWT_SECRET"))
        val plan = FragmentAssemblyFixture.plan()
        val ini = FragmentRecipes.inputs(plan.specs.single(), plan.inventory,
            FragmentAssemblyFixture.secrets(), FragmentAssemblyFixture::pki).getValue("forgejo-runtime.ini")
        val jwt = ini.lineSequence().single { it.startsWith("JWT_SECRET = ") }.substringAfter("JWT_SECRET = ")
        assertEquals(32, java.util.Base64.getUrlDecoder().decode(jwt).size)
        assertEquals(43, jwt.length)
        assertFalse('=' in jwt)
        val good = mapOf("DATABASE_PASSWORD" to "a".repeat(64), "SECRET_KEY" to "b".repeat(64),
            "INTERNAL_TOKEN" to "c".repeat(64), "JWT_SECRET" to jwt)
        assertFails { FragmentTemplates.render(r4, "forgejo-runtime.ini", good + ("JWT_SECRET" to "6".repeat(64))) }
        assertFails { FragmentTemplates.render(r4, "forgejo-runtime.ini", good + ("JWT_SECRET" to "bad")) }
        assertFails { FragmentTemplates.render(r4, "forgejo-runtime.ini", good + ("JWT_SECRET" to
            java.util.Base64.getEncoder().encodeToString(ByteArray(32) { 0xff.toByte() }))) }
        assertTrue("JWT_SECRET = $jwt" in FragmentTemplates.render(r4, "forgejo-runtime.ini", good))
    }

    @Test fun `fresh producer separates runtime credentials from administration and migrations`() {
        val plan = FragmentAssemblyFixture.plan(); val spec = plan.specs.single()
        val inputs = FragmentRecipes.inputs(spec, plan.inventory, FragmentAssemblyFixture.secrets(), FragmentAssemblyFixture::pki)
        assertEquals(PrivateDeployment.inputNames(spec).toSet(), inputs.keys)
        val runtime = inputs.getValue("forgejo-runtime.env") + inputs.getValue("forgejo-runtime.ini")
        assertTrue("PGSSLMODE=verify-full" in runtime && "PGSSLROOTCERT=/run/secrets/postgres-ca.pem" in runtime)
        assertTrue("3".repeat(64) in runtime)
        assertFalse("1".repeat(64) in runtime || "2".repeat(64) in runtime || "BOOTSTRAP_PASSWORD" in runtime)
        assertTrue("USER = forgejo_migrate\n" in inputs.getValue("forgejo-migration.ini"))
        val cold = FragmentRecipes.coldInputs(plan.inventory, spec.name, inputs)
        assertTrue(cold.keys.none { it.contains("migration") || it.contains("bootstrap") || it.contains("admin") })
        cold.forEach { (name, bytes) -> assertEquals(inputs[name], bytes) }
        assertEquals(cold, FragmentRecipes.coldInputs(plan.inventory, spec.name, cold))
        assertFails { FragmentRecipes.coldInputs(plan.inventory, spec.name, inputs - "postgres-key.pem") }
    }

    @Test fun `prepared fragment cannot be executed by direct backend`() {
        val root = Files.createTempDirectory("fragment-prepare-")
        try {
            val plan = FragmentAssemblyFixture.plan(); val spec = plan.specs.single()
            val path = RuntimePreparation.prepare(spec, root) {
                FragmentRecipes.inputs(spec, plan.inventory, FragmentAssemblyFixture.secrets(), FragmentAssemblyFixture::pki)
            }
            assertEquals(spec, Json.decodeFromString<PrivateDeploymentSpec>(Files.readString(path)))
            var generated = false
            assertEquals(path, RuntimePreparation.prepare(spec, root) { generated = true; error("No credential regeneration") })
            assertFalse(generated)
            val driver = PrivateDeployment(root, RuntimeCommands { error("Direct Podman must never be invoked") })
            val error = assertFailsWith<IllegalArgumentException> { driver.apply(spec) }
            assertTrue(error.message!!.contains("fallback refused"))
            assertFails { PrivateDeployment.validate(spec.copy(executionBackend = RuntimeExecutionBackend.DIRECT_PODMAN_V1)) }
        } finally { FragmentAssemblyFixture.remove(root) }
    }

    @Test fun `owned generation preparation uses bound recipe and no runtime backend`() {
        val root = Files.createTempDirectory("fragment-owned-prepare-")
        try {
            val runtime = Files.createDirectory(root.resolve("runtime"), java.nio.file.attribute.PosixFilePermissions
                .asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
            val basePlan = FragmentAssemblyFixture.plan()
            val recipes = GenerationAssembly.catalog.map { recipe -> if (recipe.id != FragmentRecipes.FORGEJO_POSTGRES) recipe else
                recipe.copy(prepareBound = { inventory, base, spec -> RuntimePreparation.prepare(spec, base) {
                    FragmentRecipes.inputs(spec, inventory, FragmentAssemblyFixture.secrets(), FragmentAssemblyFixture::pki)
                } }) }
            val plan = GenerationAssembly(recipes).plan(FragmentAssemblyFixture.request, FragmentAssemblyFixture.bytes)
            val owner = CanonicalTopology.ownership(CanonicalTopology.compile(plan, false), "fragment-unit", emptyList(), emptySet())
            val engine = GenerationRuntime(root.resolve("generations"), runtime, { error("No runtime backend") }, { error("No capacity effect") })
            val hash = engine.prepareOwnedAssembly(plan, owner, emptySet())
            assertTrue(hash.matches(Regex("[a-f0-9]{64}")))
            assertTrue(Files.exists(root.resolve("generations/${plan.generation.id}/assembly.result.json")))
            assertEquals(basePlan.specs, plan.specs)
            val source = Json.decodeFromString<GenerationBundle>(Files.readString(root.resolve("generations/${plan.generation.id}/bundle.json")))
            val restored = FoundationRestore.bundle(source, plan.inventory, "q-112233445566", "e".repeat(64),
                ColdRestoreCohort.FORGEJO_POSTGRES, RuntimeStore.CANONICAL_V2)
            assertTrue(restored.members.single().spec.processes.none { it.oneShot })
            assertEquals("RESTORE", restored.members.single().spec.fragmentBinding!!.phase)
            assertEquals(setOf("forgejo-bootstrap"), restored.members.single().spec.unmountedRecoveryVolumes)
            assertFails { engine.prepareOwnedAssembly(plan, owner, emptySet()) }
        } finally { FragmentAssemblyFixture.remove(root) }
    }

    @Test fun `offline export is deterministic private and never admits runtime`() {
        val root = Files.createTempDirectory("fragment-export-")
        try {
            val plan = FragmentAssemblyFixture.plan()
            val first = GenerationRender.export(plan, root.resolve("one"))
            val second = GenerationRender.export(plan, root.resolve("two"))
            assertEquals(first, second)
            assertFalse(first.runtimeAdmitted || first.privateInputsIncluded || first.qualificationEvidence)
            first.files.forEach { (name, hash) ->
                val one = Files.readAllBytes(root.resolve("one/$name"))
                assertEquals(hash, ReleaseLocks.sha256(one))
                assertContentEquals(one, Files.readAllBytes(root.resolve("two/$name")))
            }
            assertTrue("sources/fragments/v2/provenance.json" in first.files)
            FragmentRecipes.fragments().forEach { fragment -> fragment.resourceHashes.forEach { (name, hash) ->
                assertEquals(hash, first.files.getValue("sources/fragments/v2/$name"))
            } }
            assertTrue(first.files.keys.any { it.endsWith(".container") })
            assertTrue(first.files.keys.any { it.endsWith("50-p0-lifecycle.conf") })
            assertFails { GenerationRender.export(plan, root.resolve("one")) }
            val link = root.resolve("linked"); Files.createSymbolicLink(link, root.resolve("one"))
            assertFails { GenerationRender.export(plan, link) }
        } finally { FragmentAssemblyFixture.remove(root) }
    }

    @Test fun `CLI exports a unit fixture with no admission claim`() {
        val root = Files.createTempDirectory("fragment-render-cli-")
        try {
            Files.write(root.resolve("inventory.json"), FragmentAssemblyFixture.bytes)
            Files.writeString(root.resolve("request.json"), Json.encodeToString(FragmentAssemblyFixture.request))
            Files.setPosixFilePermissions(root.resolve("request.json"), java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"))
            val output = mutableListOf<String>(); val errors = mutableListOf<String>()
            assertEquals(0, runCommand(arrayOf("release", "generation-render", root.resolve("inventory.json").toString(),
                root.resolve("request.json").toString(), root.resolve("export").toString()), output::add, errors::add), errors.joinToString("\n"))
            assertTrue(errors.isEmpty())
            val result = Json.decodeFromString<GenerationRenderManifest>(output.single())
            assertFalse(result.runtimeAdmitted || result.privateInputsIncluded || result.qualificationEvidence)
            assertTrue(Files.exists(root.resolve("export/export.result.json")))
        } finally { FragmentAssemblyFixture.remove(root) }
    }

    @Test fun `historical serialization omits every new default field`() {
        val legacy = ForgejoRuntime.spec(FragmentAssemblyFixture.inventory)
        val json = Json { encodeDefaults = true }.encodeToString(legacy)
        assertFalse("executionBackend" in json || "fragmentBinding" in json)
        assertFalse("quadletControllerSha256" in Json { encodeDefaults = true }.encodeToString(
            FragmentAssemblyFixture.request.copy(quadletControllerSha256 = null)))
    }
}
