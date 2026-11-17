package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class GenerationAssemblyTest {
    private val inventory = Json.encodeToString(AcquiredInventory(1, "unit-only", listOf("postgres", "valkey", "ntfy", "mariadb", "memcached").map {
        AcquiredImage(it, "unit", "example.test/$it:1", "example.test/$it@sha256:" + "a".repeat(64), "b".repeat(64),
            emptyList(), "sha256:" + "a".repeat(64), "amd64", "linux")
    })).toByteArray()
    private val request = AssemblyRequest(id = "q-abcdef123456", candidateSha256 = "c".repeat(64),
        inventorySha256 = ReleaseLocks.sha256(inventory), selections = listOf(AssemblySelection("sql-cache", listOf("foundation")),
            AssemblySelection("foundation")), diskReservationMiB = 8192)
    private fun fixture(block: (Path, Path, GenerationRuntime) -> Unit) {
        val root = Files.createTempDirectory("assembly-unit-")
        val runtimes = Files.createDirectory(root.resolve("runtimes"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        val engine = GenerationRuntime(root.resolve("generations"), runtimes, { error("Preparation must not invoke Podman") }, { error("Preparation must not admit/start workloads") })
        try { block(root, runtimes, engine) }
        finally { Thread.interrupted(); Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    @Test fun `typed plan declares input consumers state writers pins and honest missing capabilities`() {
        val plan = GenerationAssembly().plan(request, inventory)
        assertEquals(listOf("foundation", "sql-cache"), plan.summary.members.map { it.recipe })
        val foundation = plan.summary.members.first()
        assertEquals(setOf("postgres", "valkey", "ntfy"), foundation.primaryCapabilities)
        assertEquals(listOf("postgres-init"), foundation.inputs.single { it.name == "postgres.env" }.consumers)
        assertEquals(listOf("postgres", "postgres-init"), foundation.state.single { it.id == "postgres" }.potentialWriters)
        assertEquals(999, foundation.state.single { it.id == "postgres" }.userId)
        assertEquals(3, foundation.daemons.size)
        assertEquals(listOf("postgres-init"), foundation.initializers)
        assertTrue(foundation.images.keys.all { "@sha256:" in it })
        assertTrue(plan.summary.missingCapabilities.containsAll(setOf("caddy", "mastodon-rss-publisher", "worklane", "tuios", "pi")))
        assertFalse(plan.summary.globalIntegrationValidated)
        assertFalse(plan.summary.fullStackQualification)
        assertFalse(plan.summary.publicActivation)
    }

    @Test fun `all registered existing recipes resolve against repository artifact metadata without execution`() {
        val bytes = GenerationAssembly.readInventory(Path.of("release/downloaded-candidate-inventory.json"))
        val historical = GenerationAssembly.catalog.filter {
            it.id !in FragmentRecipes.recipeIds && it.id != CanonicalSharedYamlGraph.RECIPE &&
                it.id !in setOf(CanonicalSharedYamlGraph.R9_ASSEMBLY_RECIPE,
                    CanonicalSharedYamlGraph.R10_ASSEMBLY_RECIPE) }
        assertEquals(38, historical.size)
        assertEquals(42, GenerationAssembly.catalog.size)
        for (recipe in historical) {
            val plan = GenerationAssembly().plan(request.copy(inventorySha256 = ReleaseLocks.sha256(bytes),
                selections = listOf(AssemblySelection(recipe.id)), diskReservationMiB = 131072), bytes)
            assertEquals(1, plan.specs.size)
            assertEquals(recipe.capabilities, plan.summary.members.single().primaryCapabilities)
            assertTrue(plan.summary.members.single().state.all { it.potentialWriters.isNotEmpty() })
            val isolated = GenerationAssembly().plan(plan.summary.request.copy(store = RuntimeStore.CANONICAL_V2), bytes)
            assertEquals(plan.specs.map { it.copy(store = RuntimeStore.CANONICAL_V2) }, isolated.specs)
            assertEquals(RuntimeStore.CANONICAL_V2, isolated.generation.store)
            assertNotEquals(plan.summary.members.single().specSha256, isolated.summary.members.single().specSha256)
        }
    }

    @Test fun `new Timescale recipe refuses the old artifact inventory rather than relabeling plain PostgreSQL`() {
        val bytes = GenerationAssembly.readInventory(Path.of("release/downloaded-candidate-inventory.json"))
        assertFails { GenerationAssembly().plan(request.copy(inventorySha256 = ReleaseLocks.sha256(bytes),
            selections = listOf(AssemblySelection(FragmentRecipes.FORGEJO_POSTGRES)),
            store = RuntimeStore.CANONICAL_V2, quadletControllerSha256 = "d".repeat(64)), bytes) }
    }

    @Test fun `duplicate proofs unsupported recipes cross-scope dependencies and weak policies are rejected`() {
        val bad = listOf(request.copy(inventorySha256 = "d".repeat(64)), request.copy(schemaVersion = 2),
            request.copy(purpose = "full-release"), request.copy(memoryHeadroomMiB = 1), request.copy(diskReservationMiB = 1024),
            request.copy(id = "foundation-r3"), request.copy(selections = emptyList()),
            request.copy(selections = listOf(AssemblySelection("worklane"))),
            request.copy(selections = listOf(AssemblySelection("foundation"), AssemblySelection("foundation"))),
            request.copy(selections = listOf(AssemblySelection("foundation", listOf("foreign")))),
            request.copy(selections = listOf(AssemblySelection("foundation", listOf("sql-cache")), AssemblySelection("sql-cache", listOf("foundation")))),
            request.copy(selections = listOf(AssemblySelection("office"), AssemblySelection("seafile"))),
            request.copy(selections = listOf(AssemblySelection("sogo-mail"), AssemblySelection("mail"))),
            request.copy(selections = listOf(AssemblySelection("matrix"), AssemblySelection("matrix-identity"))),
            request.copy(selections = listOf(AssemblySelection("openbao"), AssemblySelection("keykeeper"))))
        for (value in bad) assertFailsWith<IllegalArgumentException> { GenerationAssembly().plan(value, inventory) }
        assertFailsWith<IllegalArgumentException> { GenerationAssembly().plan(request, ByteArray(0)) }
    }

    @Test fun `late recipe failure precedes all credential generation`() = fixture { root, runtimes, engine ->
        var generated = 0
        val recipes = GenerationAssembly.catalog.filter { it.id in setOf("foundation", "sql-cache") }.map { recipe ->
            recipe.copy(spec = { i, n -> if (recipe.id == "sql-cache") error("incompatible image") else recipe.spec(i, n) },
                prepare = { i, b, n, s -> generated++; recipe.prepare(i, b, n, s) })
        }
        assertFailsWith<IllegalStateException> { engine.prepareAssembly(GenerationAssembly(recipes).plan(request, inventory)) }
        assertEquals(0, generated)
        assertFalse(Files.exists(root.resolve("generations")))
        assertEquals(0L, Files.list(runtimes).use { it.count() })
    }

    @Test fun `preparation seals exact real inputs without invoking a backend and cannot regenerate them`() = fixture { root, runtimes, engine ->
        val plan = GenerationAssembly().plan(request, inventory)
        val digest = engine.prepareAssembly(plan)
        val control = root.resolve("generations/${request.id}")
        val bundle = Json.decodeFromString<GenerationBundle>(Files.readString(control.resolve("bundle.json")))
        assertEquals(digest, ReleaseLocks.sha256(Files.readAllBytes(control.resolve("bundle.json"))))
        assertEquals(ReleaseLocks.sha256(Files.readAllBytes(control.resolve("assembly.intent.json"))), bundle.assemblySha256)
        assertTrue(Json.decodeFromString<AssemblyPreparationOutcome>(Files.readString(control.resolve("assembly.result.json"))).passed)
        for (member in bundle.members) {
            assertEquals(member.spec, PrivateDeployment.read(runtimes.resolve("${member.member.name}.json")))
            assertFalse(Files.exists(runtimes.resolve("${member.member.name}/runtime.jobs")))
        }
        val hashes = bundle.members.associate { pin -> pin.member.name to pin.inputHashes }
        assertFailsWith<IllegalArgumentException> { engine.prepareAssembly(plan) }
        assertEquals(hashes, bundle.members.associate { pin -> pin.member.name to pin.inputHashes.mapValues {
            ReleaseLocks.sha256(Files.readAllBytes(runtimes.resolve(pin.member.name).resolve(it.key))) } })
        Files.delete(control.resolve("assembly.result.json")) // Unit-only simulated lost completion, not live evidence deletion.
        assertFailsWith<Exception> { engine.stage(request.id, digest) }
    }

    @Test fun `partial credential preparation retains failure and forbids implicit retry`() = fixture { root, runtimes, engine ->
        val recipes = GenerationAssembly.catalog.filter { it.id in setOf("foundation", "sql-cache") }.map { recipe ->
            if (recipe.id != "sql-cache") recipe else recipe.copy(prepare = { _, _, _, _ -> error("synthetic generation failure") })
        }
        val plan = GenerationAssembly(recipes).plan(request, inventory)
        assertFailsWith<IllegalStateException> { engine.prepareAssembly(plan) }
        val control = root.resolve("generations/${request.id}")
        val result = Json.decodeFromString<AssemblyPreparationOutcome>(Files.readString(control.resolve("assembly.result.json")))
        assertFalse(result.passed)
        assertTrue(Files.exists(runtimes.resolve("${request.id}-foundation/postgres.env")))
        assertFalse(Files.exists(control.resolve("bundle.json")))
        assertFailsWith<IllegalArgumentException> { engine.prepareAssembly(plan) }
    }

    @Test fun `interrupted preparation preserves intent and interrupt status without regenerating secrets`() = fixture { root, _, engine ->
        val recipes = GenerationAssembly.catalog.filter { it.id in setOf("foundation", "sql-cache") }.map { recipe ->
            recipe.copy(prepare = { _, _, _, _ -> Thread.currentThread().interrupt(); throw InterruptedException("unit interruption") })
        }
        try {
            assertFailsWith<InterruptedException> { engine.prepareAssembly(GenerationAssembly(recipes).plan(request, inventory)) }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
        assertFalse(Json.decodeFromString<AssemblyPreparationOutcome>(Files.readString(root.resolve("generations/${request.id}/assembly.result.json"))).passed)
    }

    @Test fun `private request binding rejects linked or public files`() = fixture { root, _, _ ->
        val path = root.resolve("request.json")
        Files.writeString(path, Json.encodeToString(request))
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
        assertEquals(request, GenerationAssembly.readRequest(path))
        val link = root.resolve("alias.json")
        Files.createLink(link, path)
        assertFailsWith<IllegalArgumentException> { GenerationAssembly.readRequest(path) }
        Files.delete(link)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r--r--"))
        assertFailsWith<IllegalArgumentException> { GenerationAssembly.readRequest(path) }
    }
}
