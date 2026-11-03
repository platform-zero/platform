package net.datamancy.platform

import java.nio.file.Files
import java.time.Instant
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

class CaddyLifecycleTest {
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
            for (flag in listOf("-out", "-keyout")) if (flag in args) Files.writeString(temp.resolve(args[args.indexOf(flag) + 1]), "synthetic-material")
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
