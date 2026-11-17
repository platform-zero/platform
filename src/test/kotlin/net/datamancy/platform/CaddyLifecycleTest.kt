package net.datamancy.platform

import java.nio.file.Files
import java.time.Instant
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

class CaddyLifecycleTest {
    @Test fun `held-source quiescence refuses caller-authored capture before native stop or journal effects`(): Unit {
        val root = Files.createTempDirectory("held-bridge-invalid-")
        val site = Files.createDirectory(root.resolve("unit"))
        Files.setPosixFilePermissions(site, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
        val binding = ListenerSuccessionBinding("r-000000000071", "unit", "q-000000000001", "a".repeat(64),
            "q-000000000002", "b".repeat(64), setOf("auth.datamancy.net"))
        var nativeCalls = 0
        val control = object : ListenerGenerationControl {
            override fun owned(generation: String, fingerprint: String, port: Int): PortOwner {
                nativeCalls++; return PortOwner.FREE
            }
            override fun hostPort(port: Int): PortOwner { nativeCalls++; return PortOwner.FREE }
            override fun stop(generation: String, fingerprint: String) { nativeCalls++; error("must never stop held source") }
            override fun start(generation: String, fingerprint: String) { nativeCalls++; error("must never start restore target") }
            override fun stateSha256(generation: String, fingerprint: String, running: Boolean): String {
                nativeCalls++; return "c".repeat(64)
            }
        }
        try {
            val source = PrivateDeploymentSpec(name = "q-000000000001-caddy", store = RuntimeStore.CANONICAL_V2,
                volumes = emptyList(), processes = emptyList())
            val actor = IngressListenerSuccession(site, control)
            assertFailsWith<IllegalArgumentException> {
                actor.heldQuiesceForBridge(binding, ActivationInput(root.resolve("fake-held.json").toString(),
                    "a".repeat(64)), source)
            }
            assertEquals(0, nativeCalls)
            assertFalse(Files.exists(site.resolve("listener.pending")))
            assertFalse(Files.exists(site.resolve("${binding.operation}.bridge-result.json")))
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    @Test fun `restore bridge quiescence stops original listener without publishing restored target`(): Unit {
        val root = Files.createTempDirectory("listener-bridge-unit-")
        val site = Files.createDirectory(root.resolve("unit"))
        Files.setPosixFilePermissions(site, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
        val binding = ListenerSuccessionBinding("r-000000000031", "unit", "q-000000000001", "a".repeat(64),
            "q-000000000002", "b".repeat(64), setOf("auth.datamancy.net"))
        var old = true; var starts = 0
        val control = object : ListenerGenerationControl {
            override fun owned(generation: String, fingerprint: String, port: Int) =
                if (generation == binding.source && old) PortOwner.OWNED_V3 else PortOwner.FREE
            override fun hostPort(port: Int) = if (old) PortOwner.PROTECTED else PortOwner.FREE
            override fun stop(generation: String, fingerprint: String) { old = false }
            override fun start(generation: String, fingerprint: String) { starts++ }
            override fun stateSha256(generation: String, fingerprint: String, running: Boolean): String {
                require(generation == binding.source && old == running)
                return "c".repeat(64)
            }
        }
        try {
            val actor = IngressListenerSuccession(site, control)
            val quiesced = actor.quiesceForBridge(binding)
            assertEquals(0, starts)
            assertEquals("c".repeat(64), quiesced.sourceStoppedProofSha256)
            assertEquals(quiesced, actor.readQuiesce(binding, quiesced.intentSha256))
            assertFailsWith<IllegalArgumentException> { actor.quiesceForBridge(binding.copy(operation = "r-000000000032")) }
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    @Test fun `lost quiescence acknowledgement reconciles stopped source without calling stop again`(): Unit {
        val root = Files.createTempDirectory("bridge-stop-lost-ack-")
        val site = Files.createDirectory(root.resolve("unit"))
        Files.setPosixFilePermissions(site, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
        val binding = ListenerSuccessionBinding("r-000000000041", "unit", "q-000000000001", "a".repeat(64),
            "q-000000000002", "b".repeat(64), setOf("auth.datamancy.net"))
        var old = true; var stops = 0
        val control = object : ListenerGenerationControl {
            override fun owned(generation: String, fingerprint: String, port: Int) =
                if (generation == binding.source && old) PortOwner.OWNED_V3 else PortOwner.FREE
            override fun hostPort(port: Int) = if (old) PortOwner.PROTECTED else PortOwner.FREE
            override fun stop(generation: String, fingerprint: String) { old = false; stops++; error("lost acknowledgement") }
            override fun start(generation: String, fingerprint: String) = error("restore target must remain unpublished")
            override fun stateSha256(generation: String, fingerprint: String, running: Boolean): String {
                require(generation == binding.source && old == running)
                return "f".repeat(64)
            }
        }
        try {
            val actor = IngressListenerSuccession(site, control)
            assertFailsWith<IllegalStateException> { actor.quiesceForBridge(binding) }
            assertTrue(Files.exists(site.resolve("listener.pending")))
            val expected = ReleaseLocks.sha256(Json.encodeToString(binding).toByteArray())
            assertEquals("f".repeat(64), actor.readQuiesce(binding, expected).sourceStoppedProofSha256)
            assertFalse(Files.exists(site.resolve("listener.pending")))
            assertEquals(1, stops)
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    @Test fun `listener stop interruption retains intent and cannot retry or start a second target`(): Unit {
        val root = Files.createTempDirectory("listener-failure-unit-")
        val site = Files.createDirectory(root.resolve("unit"))
        Files.setPosixFilePermissions(site, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
        val binding = ListenerSuccessionBinding("r-000000000021", "unit", "q-000000000001", "a".repeat(64),
            "q-000000000002", "b".repeat(64), setOf("auth.datamancy.net"))
        var stops = 0; var starts = 0
        val control = object : ListenerGenerationControl {
            override fun owned(generation: String, fingerprint: String, port: Int) = PortOwner.OWNED_V3
            override fun hostPort(port: Int) = PortOwner.PROTECTED
            override fun stop(generation: String, fingerprint: String) { stops++; error("synthetic lost stop acknowledgement") }
            override fun start(generation: String, fingerprint: String) { starts++ }
            override fun stateSha256(generation: String, fingerprint: String, running: Boolean) = "a".repeat(64)
        }
        try {
            val actor = IngressListenerSuccession(site, control)
            assertFailsWith<IllegalStateException> { actor.succeed(binding) }
            assertTrue(Files.exists(site.resolve("listener.pending")))
            assertEquals(1, stops); assertEquals(0, starts)
            assertFailsWith<IllegalArgumentException> { actor.succeed(binding.copy(operation = "r-000000000022")) }
            assertEquals(1, stops); assertEquals(0, starts)
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    @Test fun `exclusive 80 and 443 listener succession retains one intent and reconciles lost acknowledgement without replay`(): Unit {
        val root = Files.createTempDirectory("listener-succession-unit-")
        val binding = ListenerSuccessionBinding("r-000000000011", "unit",
            "q-000000000001", "a".repeat(64), "q-000000000002", "b".repeat(64), setOf("auth.datamancy.net"))
        val siteRoot = Files.createDirectory(root.resolve("unit"))
        Files.setPosixFilePermissions(siteRoot, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"))
        var old = true; var target = false; var stops = 0; var starts = 0
        val control = object : ListenerGenerationControl {
            override fun owned(generation: String, fingerprint: String, port: Int): PortOwner = when (generation) {
                binding.source -> if (old) PortOwner.OWNED_V3 else PortOwner.FREE
                binding.target -> if (target) PortOwner.OWNED_V3 else PortOwner.FREE
                else -> PortOwner.UNKNOWN
            }
            override fun hostPort(port: Int): PortOwner = if (old || target) PortOwner.PROTECTED else PortOwner.FREE
            override fun stop(generation: String, fingerprint: String) { stops++; old = false }
            override fun start(generation: String, fingerprint: String) { starts++; target = true }
            override fun stateSha256(generation: String, fingerprint: String, running: Boolean): String {
                require((if (generation == binding.source) old else target) == running)
                return (if (running) "b" else "a").repeat(64)
            }
        }
        try {
            val actor = IngressListenerSuccession(siteRoot, control)
            val result = actor.succeed(binding)
            assertTrue(result.sourceStopped && result.targetStarted)
            assertEquals(1, stops); assertEquals(1, starts)
            assertFailsWith<Exception> { actor.succeed(binding.copy(operation = "r-000000000012")) }
            assertEquals(1, stops); assertEquals(1, starts)
            val lost = Files.readAllBytes(siteRoot.resolve("${binding.operation}.intent.json"))
            ReleasePrivateFiles.save(siteRoot.resolve("listener.pending"), lost)
            assertEquals(result, actor.reconcile(binding, ReleaseLocks.sha256(lost)))
            assertEquals(1, starts)
            assertFalse(Files.exists(siteRoot.resolve("listener.pending")))
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    private val binding = CaddySiteBinding("unit", "owned", "http://127.0.0.1:2019", setOf("web.datamancy.net"))
    private val operation = "r-000000000001"
    private fun request(action: String = "stage-http01") = HttpsLifecycleRequest(action = action, operation = operation,
        runtimeManifest = "/unused/unit.json", runtimeFingerprint = "a".repeat(64), binding = binding,
        expectedConfiguration = "b".repeat(64), nonces = mapOf("web.datamancy.net" to "n".repeat(40)))
    @Test fun `typed lifecycle rejects implicit issuer unknown action and replay-shaped request before construction`() {
        val control = CaddyLifecycle({ error("must not construct") }, { error("must not observe") })
        for (request in listOf(request("unknown"), request("provision"), request("provision").copy(environment = "UNTRUSTED"),
            request("reconcile"), request().copy(schemaVersion = 2), request().copy(operation = "bad"),
            request().copy(expectedIntent = "a".repeat(64)), request().copy(nonces = emptyMap()))) {
            assertFailsWith<IllegalArgumentException> { control.execute(request) }
        }
    }
    @Test fun `typed lifecycle dispatches staging provisioning and read only reconciliation`() {
        val base = Files.createTempDirectory("caddy-lifecycle-unit-")
        val root = privateControlDirectory(base.resolve("control"))
        var config = Json.parseToJsonElement("""{"storage":{"module":"file_system","root":"/data/caddy"},"apps":{"http":{"servers":{}}}}""").jsonObject
        var writes = 0
        var lose = false
        val transport = CaddyTransport { method, _, _, bytes ->
            if (method == "GET") CaddyReply(200, config.toString().toByteArray(), "\"/config/ 0123456789abcdef\"")
            else {
                writes++; config = Json.parseToJsonElement(requireNotNull(bytes).decodeToString()).jsonObject
                if (lose) error("lost acknowledgement")
                CaddyReply(200, byteArrayOf(), null)
            }
        }
        val controller = CaddyHttpsProvisioner(root, binding, transport)
        val lifecycle = CaddyLifecycle({ controller }, { object : AcmeObservation {
            override fun portOwner(port: Int) = PortOwner.OWNED_V3
            override fun challenge(host: String, nonce: String) = ChallengeResponse(200, "p0v3-http01-$nonce", false)
        } })
        try {
            lifecycle.execute(request().copy(expectedConfiguration = TransactionalCaddy.digest(config)))
            lose = true
            val next = request("provision").copy(operation = "r-000000000002", environment = "STAGING", expectedConfiguration = TransactionalCaddy.digest(config))
            assertFails { lifecycle.execute(next) }
            val hash = ReleaseLocks.sha256(Files.readAllBytes(root.resolve("${next.operation}.intent.json")))
            assertEquals("applied", lifecycle.execute(next.copy(action = "reconcile", expectedConfiguration = null,
                expectedIntent = hash, nonces = emptyMap(), environment = null)).status)
            assertEquals(2, writes)
            val file = base.resolve("request.json")
            ReleasePrivateFiles.save(file, Json.encodeToString(next).toByteArray())
            assertEquals(next, CaddyLifecycle.readHttps(file))
            assertEquals(root, privateControlDirectory(root))
        } finally { Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `private PKI lifecycle emits metadata only and retains signing material privately`() {
        val root = Files.createTempDirectory("pki-lifecycle-unit-")
        var now = Instant.parse("2026-01-01T00:00:00Z")
        val pki = ManagedPrivatePki(root, { temp, args ->
            for (flag in listOf("-out", "-keyout")) if (flag in args) Files.writeString(temp.resolve(args[args.indexOf(flag) + 1]), "synthetic-material:$now")
        }, { now })
        val request = PrivatePkiLifecycleRequest(action = "initialize", site = "unit", authority = "web", operation = "pki-0000000000000001")
        try {
            val authority = { _: String, _: String -> pki }
            val initialized = CaddyLifecycle.privatePki(request, authority)
            val issued = CaddyLifecycle.privatePki(request.copy(action = "issue", profile = PrivatePkiProfile(PrivatePkiKind.WEB, "hub")), authority)
            assertEquals(initialized.caSha256, issued.caSha256)
            assertEquals(ReleaseLocks.sha256(Files.readAllBytes(root.resolve("${request.operation}.json"))), issued.issueSha256)
            assertFalse("synthetic-material" in Json.encodeToString(issued))
            now = now.plusSeconds(60L * 86400)
            val renew = request.copy(action = "renew", operation = "pki-0000000000000002", previousOperation = request.operation, previousSha256 = issued.issueSha256)
            val renewed = CaddyLifecycle.privatePki(renew, authority)
            assertEquals(issued.caSha256, renewed.caSha256)
            val input = root.resolve("request.json")
            ReleasePrivateFiles.save(input, Json.encodeToString(renew).toByteArray())
            assertEquals(renew, CaddyLifecycle.readPrivatePki(input))
            for (bad in listOf(request.copy(site = "../foreign"), request.copy(action = "unknown"), request.copy(action = "issue"), renew.copy(profile = PrivatePkiProfile(PrivatePkiKind.WEB, "hub")))) {
                assertFailsWith<IllegalArgumentException> { CaddyLifecycle.privatePki(bad) { _, _ -> error("must not create custody") } }
            }
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
