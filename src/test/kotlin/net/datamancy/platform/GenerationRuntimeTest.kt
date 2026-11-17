package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.UUID
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertFails
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GenerationRuntimeTest {
    private val h = "a".repeat(64)
    private val generation = "q-123456789abc"
    private class Fake : GenerationBackend, ColdGenerationBackend {
        val calls = mutableListOf<String>()
        val running = mutableSetOf<String>()
        val fences = mutableMapOf<String, String>()
        var bindings = emptyMap<String, String>()
        var failAudit: String? = null
        var failApply: String? = null
        var failIsolation: String? = null
        var badReady = false
        var interruptApply = false
        var interruptIsolation: String? = null
        var fatalApply = false
        var frozenDepth = 0
        var failExport = false
        override fun <T> withFrozen(spec: PrivateDeploymentSpec, fence: String, action: (FrozenRuntimeObservation) -> T): T {
            require(fences[spec.name] == fence && spec.name !in running)
            frozenDepth++
            try {
                return action(FrozenRuntimeObservation(spec.name, bindings.getValue(spec.name), fence, "d".repeat(64),
                    spec.processes.filter { it.oneShot }.map { it.id }.toSet(), spec.processes.map { RuntimeStatus(it.id, "exited", 0) }))
            } finally { frozenDepth-- }
        }
        override fun exportVolume(spec: PrivateDeploymentSpec, volume: RuntimeVolume, output: Path) {
            check(frozenDepth == 2) { "All member locks must remain held" }
            check(!failExport)
            Files.createFile(output, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            Files.writeString(output, "unit-only opaque volume payload: ${spec.name}/${volume.id}")
        }
        override fun audit(spec: PrivateDeploymentSpec, pristine: Boolean): RuntimeAudit {
            calls += "audit:${spec.name}:$pristine"
            check(spec.name != failAudit)
            if (pristine) require(spec.name !in running && spec.name !in fences)
            return RuntimeAudit(spec.name, bindings.getValue(spec.name), if (spec.name in running || spec.name in fences) 1 else 0,
                fences[spec.name], spec.processes.map { RuntimeStatus(it.id, if (spec.name in running) "running" else "exited", 0) })
        }
        override fun apply(spec: PrivateDeploymentSpec): List<RuntimeStatus> {
            calls += "apply:${spec.name}"
            running += spec.name // Simulate a possible partial effect before failure.
            if (fatalApply) throw AssertionError("Synthetic fatal interruption")
            if (interruptApply) { Thread.currentThread().interrupt(); throw InterruptedException("Synthetic interruption") }
            check(spec.name != failApply)
            return spec.processes.map { RuntimeStatus(it.id, if (it.oneShot) "completed" else if (badReady) "exited" else "running", 0) }
        }
        override fun isolate(spec: PrivateDeploymentSpec): String {
            calls += "isolate:${spec.name}"
            if (spec.name == interruptIsolation) { Thread.currentThread().interrupt(); throw InterruptedException("Synthetic interruption") }
            check(spec.name != failIsolation)
            running -= spec.name
            return fences.getOrPut(spec.name) { UUID.randomUUID().toString() }
        }
    }
    private data class Fixture(val root: Path, val runtime: Path, val control: Path, val fake: Fake,
        val engine: GenerationRuntime, val request: GenerationRequest)
    private fun fixture(block: (Fixture) -> Unit) {
        val root = Files.createTempDirectory("generation-unit-").toAbsolutePath()
        val runtime = root.resolve("deployments")
        val control = root.resolve("generations")
        val fake = Fake()
        val engine = GenerationRuntime(control, runtime, { fake.bindings = it; fake }, { GenerationCapacity(65536, 1048576) })
        try {
            val one = "$generation-first"; val two = "$generation-second"
            for (name in listOf(one, two)) prepare(runtime, name)
            val request = GenerationRequest(id = generation, candidateSha256 = h,
                members = listOf(GenerationMember(two, listOf(one)), GenerationMember(one)), diskReservationMiB = 2048)
            block(Fixture(root, runtime, control, fake, engine, request))
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private fun prepare(base: Path, name: String) {
        val spec = PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("data", 1000)), processes = listOf(
            RuntimeProcess("seed", "example.test/app@sha256:$h", "b".repeat(64), 1000, environmentFile = "fixture.env",
                volumes = listOf(RuntimeMount("data", "/data")), oneShot = true, memoryMiB = 64),
            RuntimeProcess("app", "example.test/app@sha256:$h", "b".repeat(64), 1000, dependencies = listOf("seed"),
                volumes = listOf(RuntimeMount("data", "/data")), readiness = listOf("true"), memoryMiB = 64)))
        RuntimePreparation.prepare(spec, base) { mapOf("fixture.env" to "VALUE=synthetic-unit-only\n") }
    }

    @Test fun `installed Quadlet audit refuses a direct-backend sealed member before inspecting host units`(): Unit = fixture { f ->
        val hash = f.engine.seal(f.request)
        assertFails { f.engine.auditInstalledQuadlet(generation, hash, "$generation-first", "app") }
        assertTrue(f.fake.calls.isEmpty())
        assertFails { f.engine.auditInstalledQuadlet(generation, hash, "$generation-foreign", "app") }
        assertFalse(Files.exists(f.runtime.resolve("$generation-foreign")))
    }
    @Test fun `install qualification scope refuses synthetic runtime before a child can launch`(): Unit = fixture { f ->
        assertFails { f.engine.withInstallQualificationScope(generation, h) {
            error("Unexpected qualification child")
        } }
        assertTrue(f.fake.calls.isEmpty())
    }
    @Test fun `restore orchestration refuses unowned test harness before nested native effects`(): Unit = fixture { f ->
        assertFails { f.engine.withRestoredIsolationLocks(ReleaseGeneration(generation, h),
            ReleaseGeneration("q-222222222222", h)) { error("Unexpected target invocation") } }
        assertTrue(f.fake.calls.isEmpty())
    }
    @Test fun `public TURN adopter refuses synthetic native actor before any Podman effect`(): Unit = fixture { f ->
        assertFails { f.engine.adoptEffectiveTurn("turn-111111111111", generation, h,
            ActivationInput(f.root.resolve("revision.json").toString(), h),
            setOf("rtc.datamancy.net"), ActivationInput(f.root.resolve("trust.pem").toString(), h)) }
        assertTrue(f.fake.calls.isEmpty())
    }
    @Test fun `public credential publisher refuses injected nonproduction source before native read`(): Unit = fixture { f ->
        assertFails { f.engine.publishEffectivePublicCertificate("r-111111111111", generation, h,
            "boards.datamancy.net", setOf("boards.datamancy.net"),
            ActivationInput(f.root.resolve("trust.pem").toString(), h)) }
        assertTrue(f.fake.calls.isEmpty())
    }
    @Test fun `owned reference retirement cannot infer missing terminal claims from successful callbacks`(): Unit = fixture { f ->
        assertFails { f.engine.retireOwnedReferences(emptyList()) }
        assertTrue(f.fake.calls.isEmpty())
    }
    @Test fun `owned import rejects raw inventory substitution before repository or target effects`(): Unit = fixture { f ->
        val sourceSha = f.engine.seal(f.request)
        val original = f.control.resolve("$generation/bundle.json")
        val oldInventory = f.root.resolve("old-inventory.json")
        val candidateInventory = f.root.resolve("candidate-inventory.json")
        val site = f.root.resolve("approved-site.json")
        ReleasePrivateFiles.save(oldInventory, "{\"images\":[]}".toByteArray())
        ReleasePrivateFiles.save(candidateInventory, "{\"images\":[]}".toByteArray())
        ReleasePrivateFiles.save(site, "{\"site\":\"unit\"}".toByteArray())
        val rawSha = ReleaseLocks.sha256(ReleasePrivateFiles.read(oldInventory))
        val intent = ReleaseUpdateIntent(ReleaseGeneration(generation, sourceSha), "q-222222222222",
            h, ReleaseLocks.sha256(ReleasePrivateFiles.read(site)), rawSha, "b".repeat(64),
            PlankaVersionTransition("2.2.0", "2.2.1"))
        val preparation = ReleaseUpdatePreparation(intent = intent,
            previousInventory = ActivationInput(oldInventory.toString(), rawSha),
            candidateInventory = ActivationInput(candidateInventory.toString(), "b".repeat(64)),
            sourceBundle = ActivationInput(original.toString(), sourceSha),
            sitePolicy = ActivationInput(site.toString(), intent.sitePolicySha256),
            migrationOperation = "r-111111111111")
        assertFails { f.engine.importOwnedUpdate(preparation, "cap-111111111111", "unit") }
        assertFalse(Files.exists(f.control.resolve(intent.targetGeneration)))
        assertTrue(f.fake.calls.isEmpty(), "Raw SHA mismatch cannot be normalized by JSON reserialization")
    }
    @Test fun `legacy private fixture cannot gain activation authority from a matching candidate digest`() = fixture { f ->
        val candidate = kotlinx.serialization.json.JsonObject(listOf("implementationSha256", "artifactsSha256", "configurationSha256",
            "acceptanceSha256", "sitePolicySha256").associateWith { kotlinx.serialization.json.JsonPrimitive(h) })
        val sealed = f.engine.seal(f.request.copy(candidateSha256 = ReleaseLocks.sha256(candidate.toString().toByteArray())))
        val deployment = ReleaseDeploymentBinding(generation, sealed, h, h)
        val images = setOf("example.test/app@sha256:$h" to "b".repeat(64))
        assertFails { f.engine.checkActivationSource(deployment, kotlinx.serialization.json.JsonObject(emptyMap()), images) }
        assertFails { f.engine.checkActivationSource(deployment, candidate, images) }
        assertTrue(f.fake.calls.isEmpty())
    }

    @Test fun `all members are pinned and audited before ordered single-use staging`() = fixture { f ->
        val hash = f.engine.seal(f.request)
        assertTrue(f.fake.calls.isEmpty())
        val inspection = f.engine.inspect(generation, hash)
        assertFalse(inspection.publicActivation)
        assertFalse(inspection.fullStackQualification)
        assertEquals(256L, inspection.memoryReservationMiB)
        f.fake.calls.clear()
        assertTrue(f.engine.stage(generation, hash).passed)
        assertEquals(listOf("audit:$generation-first:true", "audit:$generation-second:true",
            "apply:$generation-first", "apply:$generation-second"), f.fake.calls)
        val original = Files.readAllBytes(f.control.resolve("$generation/stage.result.json"))
        assertFailsWith<IllegalArgumentException> { f.engine.stage(generation, hash) }
        assertTrue(original.contentEquals(Files.readAllBytes(f.control.resolve("$generation/stage.result.json"))))
        val isolated = f.engine.isolate(generation, hash)
        assertTrue(isolated.passed)
        assertEquals(setOf("$generation-first", "$generation-second"), isolated.fences.keys)
        assertEquals(listOf("isolate:$generation-second", "isolate:$generation-first"), f.fake.calls.takeLast(2))
        assertTrue(f.fake.running.isEmpty())
        assertFailsWith<Exception> { f.engine.isolate(generation, hash) }
        assertFailsWith<Exception> { f.engine.seal(f.request) }
    }

    @Test fun `late audit failure prevents all mutations and reserves no capacity`() = fixture { f ->
        val hash = f.engine.seal(f.request)
        f.fake.failAudit = "$generation-second"
        assertFailsWith<IllegalStateException> { f.engine.stage(generation, hash) }
        assertFalse(f.fake.calls.any { it.startsWith("apply:") || it.startsWith("isolate:") })
        assertFalse(Files.exists(f.control.resolve("$generation/stage.intent.json")))
        f.fake.failAudit = null // Read-only failure can be corrected without replaying effects.
        assertTrue(f.engine.stage(generation, hash).passed)
    }

    @Test fun `partial apply failures retain results and fence every generation member`() = fixture { f ->
        val hash = f.engine.seal(f.request)
        f.fake.failApply = "$generation-second"
        val result = f.engine.stage(generation, hash)
        assertFalse(result.passed)
        assertEquals("java.lang.IllegalStateException", result.failureType)
        assertTrue(f.fake.running.isEmpty())
        assertEquals(2, f.fake.fences.size)
        assertTrue(Files.exists(f.control.resolve("$generation/isolate.result.json")))
        f.fake.failApply = null
        assertFailsWith<IllegalArgumentException> { f.engine.stage(generation, hash) }
    }

    @Test fun `unready member and isolation failure do not become success`() = fixture { f ->
        val hash = f.engine.seal(f.request)
        f.fake.badReady = true
        f.fake.failIsolation = "$generation-first"
        assertFalse(f.engine.stage(generation, hash).passed)
        val result = Json.decodeFromString<GenerationOutcome>(Files.readString(f.control.resolve("$generation/isolate.result.json")))
        assertFalse(result.passed)
        assertEquals(setOf("$generation-second"), result.fences.keys)
        assertTrue("$generation-first" in f.fake.running)
    }

    @Test fun `protected names missing dependencies cycles and weakened headroom cannot be sealed`() = fixture { f ->
        val bad = listOf(f.request.copy(id = "foundation-r3"), f.request.copy(candidateSha256 = "bad"),
            f.request.copy(releaseCandidateSha256 = "bad"),
            f.request.copy(purpose = "full-stack-qualified"), f.request.copy(memoryHeadroomMiB = 0),
            f.request.copy(diskHeadroomMiB = 0), f.request.copy(diskReservationMiB = 1024),
            f.request.copy(members = emptyList()), f.request.copy(members = listOf(GenerationMember("foundation-r3"))),
            f.request.copy(members = listOf(GenerationMember("$generation-first"), GenerationMember("$generation-first"))),
            f.request.copy(members = listOf(GenerationMember("$generation-first", listOf("absent")))),
            f.request.copy(members = listOf(GenerationMember("$generation-first", listOf("$generation-second")),
                GenerationMember("$generation-second", listOf("$generation-first")))))
        for (request in bad) assertFailsWith<IllegalArgumentException> { f.engine.seal(request) }
        assertTrue(f.fake.calls.isEmpty())
        assertFalse(Files.exists(f.control.resolve(generation)))
    }

    @Test fun `changed private input manifest bundle or digest is rejected before runtime effects`() = fixture { f ->
        val hash = f.engine.seal(f.request)
        assertFailsWith<IllegalArgumentException> { f.engine.inspect("../escape", hash) }
        assertFailsWith<IllegalArgumentException> { f.engine.inspect(generation, "b".repeat(64)) }
        val input = f.runtime.resolve("$generation-first/fixture.env")
        val original = Files.readString(input)
        Files.writeString(input, "VALUE=changed\n")
        assertFailsWith<IllegalArgumentException> { f.engine.stage(generation, hash) }
        Files.writeString(input, original)
        val manifest = f.runtime.resolve("$generation-first.json")
        Files.writeString(manifest, Files.readString(manifest) + "\n")
        assertFailsWith<IllegalArgumentException> { f.engine.stage(generation, hash) }
        assertTrue(f.fake.calls.isEmpty())
    }

    @Test fun `capacity reservations include earlier active or uncertain generations and revalidate isolation`() = fixture { f ->
        var memory = 16500L // Below 16384 headroom plus the actual serial 128 MiB startup peak.
        val engine = GenerationRuntime(f.control, f.runtime, { f.fake.bindings = it; f.fake }, { GenerationCapacity(memory, 1048576) })
        val hash = engine.seal(f.request)
        assertFailsWith<IllegalArgumentException> { engine.stage(generation, hash) }
        assertFalse(Files.exists(f.control.resolve("$generation/stage.intent.json")))
        memory = 16512 // Exact serial peak + headroom; historical bundle still declares conservative 256 MiB.
        assertTrue(engine.stage(generation, hash).passed)
        val next = "q-aaaaaaaaaaaa"
        prepare(f.runtime, "$next-first")
        prepare(f.runtime, "$next-second")
        val request = f.request.copy(id = next, members = listOf(GenerationMember("$next-first"), GenerationMember("$next-second")))
        val secondHash = engine.seal(request)
        memory = 16700 // Fits this generation alone, not both.
        assertFailsWith<IllegalArgumentException> { engine.stage(next, secondHash) }
        assertTrue(engine.isolate(generation, hash).passed)
        f.fake.running += "$generation-first" // Saved green isolation is insufficient if actual state changed.
        assertFailsWith<IllegalArgumentException> { engine.stage(next, secondHash) }
        f.fake.running -= "$generation-first"
        assertTrue(engine.stage(next, secondHash).passed)
    }

    @Test fun `isolation reconciliation retains failed evidence and only stops fenced members`() = fixture { f ->
        val hash = f.engine.seal(f.request)
        f.fake.failApply = "$generation-second"
        f.fake.failIsolation = "$generation-first"
        assertFalse(f.engine.stage(generation, hash).passed)
        val root = f.control.resolve(generation)
        val original = Files.readAllBytes(root.resolve("isolate.result.json"))
        val prior = ReleaseLocks.sha256(Files.readAllBytes(root.resolve("isolate.intent.json")))
        assertFailsWith<IllegalArgumentException> { f.engine.reconcileIsolation(generation, hash, "../bad", prior) }
        assertFailsWith<IllegalArgumentException> { f.engine.reconcileIsolation(generation, hash, "r-123456789abc", "f".repeat(64)) }
        f.fake.failIsolation = null
        val calls = f.fake.calls.size
        assertTrue(f.engine.reconcileIsolation(generation, hash, "r-123456789abc", prior).passed)
        assertTrue(f.fake.calls.drop(calls).all { it.startsWith("isolate:") })
        assertTrue(original.contentEquals(Files.readAllBytes(root.resolve("isolate.result.json"))))
        assertTrue(f.fake.running.isEmpty())
        assertFailsWith<Exception> { f.engine.reconcileIsolation(generation, hash, "r-123456789abc", prior) }
        assertFailsWith<IllegalArgumentException> { f.engine.stage(generation, hash) }
        val next = "q-bbbbbbbbbbbb"
        prepare(f.runtime, "$next-app")
        val request = f.request.copy(id = next, members = listOf(GenerationMember("$next-app")))
        val nextHash = f.engine.seal(request)
        assertTrue(f.engine.stage(next, nextHash).passed) // Validates linked outcomes and authoritative fences.
    }

    @Test fun `interruption is persisted before restoring interrupt status and remaining cleanup proceeds`() = fixture { f ->
        val hash = f.engine.seal(f.request)
        f.fake.interruptApply = true
        try {
            assertFailsWith<InterruptedException> { f.engine.stage(generation, hash) }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
        assertTrue(f.fake.running.isEmpty())
        val outcome = Json.decodeFromString<GenerationOutcome>(Files.readString(f.control.resolve("$generation/stage.result.json")))
        assertFalse(outcome.passed)
        assertEquals("java.lang.InterruptedException", outcome.failureType)
    }

    @Test fun `interrupted isolation retains failure and can be reconciled without startup`() = fixture { f ->
        val hash = f.engine.seal(f.request)
        assertTrue(f.engine.stage(generation, hash).passed)
        f.fake.interruptIsolation = "$generation-second"
        try {
            assertFailsWith<InterruptedException> { f.engine.isolate(generation, hash) }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
        assertTrue("$generation-first" in f.fake.fences)
        f.fake.interruptIsolation = null
        val prior = ReleaseLocks.sha256(Files.readAllBytes(f.control.resolve("$generation/isolate.intent.json")))
        assertTrue(f.engine.reconcileIsolation(generation, hash, "r-aaaaaaaaaaaa", prior).passed)
        assertTrue(f.fake.running.isEmpty())
    }

    @Test fun `fatal errors leave unresolved intents rather than success and isolation uses sealed definitions`() = fixture { f ->
        val hash = f.engine.seal(f.request)
        f.fake.fatalApply = true
        assertFailsWith<AssertionError> { f.engine.stage(generation, hash) }
        assertTrue(Files.exists(f.control.resolve("$generation/stage.intent.json")))
        assertFalse(Files.exists(f.control.resolve("$generation/stage.result.json")))
        Files.writeString(f.runtime.resolve("$generation-first.json"), "corrupt manifest")
        assertTrue(f.engine.isolate(generation, hash).passed)
        assertTrue(f.fake.running.isEmpty())
    }

    @Test fun `new production capsule capture is refused in every generation lifecycle state`() = fixture { f ->
        val hash = f.engine.seal(f.request)
        val custody = f.root.resolve("custody")
        fun refused() {
            val before = f.fake.calls.toList()
            val failure = assertFailsWith<IllegalStateException> {
                f.engine.capture(generation, hash, "cap-123456789abc", custody)
            }
            assertTrue(failure.message!!.contains("New production backups require Kopia"))
            assertEquals(before, f.fake.calls)
            assertFalse(Files.exists(f.control.resolve("$generation/captures")))
            assertFalse(Files.exists(custody))
        }
        refused()
        assertTrue(f.engine.stage(generation, hash).passed)
        refused()
        f.engine.isolate(generation, hash)
        refused()
        assertEquals(0, f.fake.frozenDepth)
    }

    @Test fun `low disk cannot route new backups through the retired capsule engine`() = fixture { f ->
        val hash = f.engine.seal(f.request)
        f.engine.stage(generation, hash); f.engine.isolate(generation, hash)
        val constrained = GenerationRuntime(f.control, f.runtime, { f.fake.bindings = it; f.fake }, { GenerationCapacity(65536, 20000) })
        assertFailsWith<IllegalStateException> { constrained.capture(generation, hash, "cap-bbbbbbbbbbbb", f.root.resolve("custody")) }
        assertFalse(Files.exists(f.control.resolve("$generation/captures")))
    }

    @Test fun `retired capture never starts an export or manufactures historical verification`() = fixture { f ->
        val hash = f.engine.seal(f.request)
        f.engine.stage(generation, hash); f.engine.isolate(generation, hash)
        f.fake.failExport = true
        val before = f.fake.calls.toList()
        val id = "cap-aaaaaaaaaaaa"
        assertFailsWith<IllegalStateException> { f.engine.capture(generation, hash, id, f.root.resolve("custody")) }
        assertFalse(Files.exists(f.control.resolve("$generation/captures/$id")))
        assertEquals(before, f.fake.calls)
        assertEquals(0, f.fake.frozenDepth)
        assertFails { f.engine.verifyCapture(generation, hash, id, f.root.resolve("custody")) }
    }

    @Test fun `foreign files and public control parents fail closed`() = fixture { f ->
        val requestPath = f.root.resolve("request.json")
        Files.writeString(requestPath, Json.encodeToString(f.request))
        Files.setPosixFilePermissions(requestPath, PosixFilePermissions.fromString("rw-------"))
        assertEquals(f.request, GenerationRuntime.request(requestPath))
        val hash = f.engine.seal(f.request)
        Files.writeString(f.control.resolve("foreign"), "unknown")
        assertFailsWith<IllegalArgumentException> { f.engine.stage(generation, hash) }
        Files.delete(f.control.resolve("foreign")) // Unit fixture only; not a live operation intent.
        Files.setPosixFilePermissions(f.control, PosixFilePermissions.fromString("rwxr-xr-x"))
        assertFailsWith<IllegalArgumentException> { f.engine.inspect(generation, hash) }
    }
}
