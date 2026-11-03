package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.*
import kotlin.test.*

class CaddyHttpsProvisionerTest {
    private val binding = CaddySiteBinding("unit", "owned", "http://127.0.0.1:2019", setOf("web.datamancy.net", "client.matrix.datamancy.net"))
    private val nonces = binding.approvedHosts.sorted().mapIndexed { i, host -> host to ('a' + i).toString().repeat(40) }.toMap()
    private val first = "r-000000000001"
    private val second = "r-000000000002"
    private class Fake : CaddyTransport {
        var configuration = Json.parseToJsonElement("""{
          "admin":{"listen":"127.0.0.1:2019"},"storage":{"module":"file_system","root":"/data/caddy"},
          "apps":{"http":{"servers":{"unrelated":{"listen":[":8443"],"routes":[]}}},
          "tls":{"automation":{"policies":[{"subjects":["outside.example.org"],"issuers":[{"module":"internal"}]}]},
          "certificates":{"automate":["outside.example.org"]}}}}
        """).jsonObject
        var failure = ""
        var writes = 0
        fun hash() = TransactionalCaddy.digest(configuration)
        private fun etag() = "\"/config/ ${hash().take(16)}\""
        override fun exchange(method: String, path: String, etag: String?, body: ByteArray?): CaddyReply {
            assertEquals("/config/", path)
            if (method == "GET") return CaddyReply(200, configuration.toString().toByteArray(), etag())
            assertEquals("POST", method); assertEquals(etag(), etag); writes++
            if (failure == "before") error("lost request")
            if (failure == "conflict") return CaddyReply(412, byteArrayOf(), null)
            if (failure != "ignored") configuration = Json.parseToJsonElement(requireNotNull(body).decodeToString()).jsonObject
            if (failure == "after") error("lost acknowledgement")
            return CaddyReply(200, byteArrayOf(), null)
        }
    }
    private fun test(action: (Path, Fake, CaddyHttpsProvisioner) -> Unit) {
        val root = Files.createTempDirectory("https-unit-")
        try { val fake = Fake(); action(root, fake, CaddyHttpsProvisioner(root, binding, fake)) }
        finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    private fun servers(fake: Fake) = fake.configuration.getValue("apps").jsonObject.getValue("http").jsonObject.getValue("servers").jsonObject
    private fun tls(fake: Fake) = fake.configuration.getValue("apps").jsonObject.getValue("tls").jsonObject
    private fun observation(bad: Boolean = false) = object : AcmeObservation {
        override fun portOwner(port: Int) = if (port == 80) PortOwner.OWNED_V3 else PortOwner.FREE
        override fun challenge(host: String, nonce: String) = ChallengeResponse(if (bad) 521 else 200, "p0v3-http01-$nonce", false)
    }
    @Test fun `HTTP nonce admission then exact subject automation preserves unrelated resources`() = test { root, fake, provisioner ->
        val original = fake.configuration
        provisioner.stageHttp01(first, fake.hash(), nonces) { PortOwner.FREE }
        val staged = servers(fake).getValue("owned-http01")
        assertTrue("p0v3-http01-" in staged.toString())
        assertFalse("reverse_proxy" in staged.toString())
        val result = provisioner.provision(second, fake.hash(), nonces, AcmeEnvironment.STAGING, observation())
        assertEquals("applied", result.status)
        assertEquals(fake.hash(), provisioner.observeConfigurationSha256())
        assertEquals(original["storage"], fake.configuration["storage"])
        assertEquals(original["admin"], fake.configuration["admin"])
        assertEquals(staged, servers(fake)["owned-http01"])
        assertEquals(original.getValue("apps").jsonObject.getValue("http").jsonObject.getValue("servers").jsonObject["unrelated"], servers(fake)["unrelated"])
        assertEquals(JsonArray(emptyList()), servers(fake).getValue("owned").jsonObject["routes"])
        val policies = tls(fake).getValue("automation").jsonObject.getValue("policies").jsonArray
        assertEquals("outside.example.org", policies.first().jsonObject.getValue("subjects").jsonArray.single().jsonPrimitive.content)
        assertEquals(binding.approvedHosts, policies.last().jsonObject.getValue("subjects").jsonArray.map { it.jsonPrimitive.content }.toSet())
        assertTrue(AcmeEnvironment.STAGING.directory in policies.last().toString())
        assertTrue("tls-alpn" in policies.last().toString())
        assertEquals(3, tls(fake).getValue("certificates").jsonObject.getValue("automate").jsonArray.size)
        assertFalse(Files.exists(root.resolve("pending.json")))
        assertFails { provisioner.provision(second, fake.hash(), nonces, AcmeEnvironment.PRODUCTION, observation()) }
        assertEquals(2, fake.writes)
    }
    @Test fun `free ports do not authorize adoption of an existing listener or overlapping policies`() {
        test { _, fake, control ->
            for (owner in listOf(PortOwner.UNKNOWN, PortOwner.PROTECTED)) {
                assertFails { control.stageHttp01(first, fake.hash(), nonces) { owner } }
            }
            assertFails { control.stageHttp01(first, "0".repeat(64), nonces) { PortOwner.FREE } }
            assertFails { control.stageHttp01(first, fake.hash(), nonces.mapValues { "a".repeat(40) }) { PortOwner.FREE } }
            fake.configuration = Json.parseToJsonElement(fake.configuration.toString().replace(":8443", ":443")).jsonObject
            assertFails { control.stageHttp01(first, fake.hash(), nonces) { PortOwner.FREE } }
            assertEquals(0, fake.writes)
        }
        for (replacement in listOf("web.datamancy.net", "*.example.org")) test { _, fake, control ->
            fake.configuration = Json.parseToJsonElement(fake.configuration.toString().replace("outside.example.org", replacement)).jsonObject
            assertFails { control.stageHttp01(first, fake.hash(), nonces) { PortOwner.FREE } }
            assertEquals(0, fake.writes)
        }
    }
    @Test fun `issuance refuses failed public challenge unsafe storage and changed nonce route`() = test { _, fake, control ->
        control.stageHttp01(first, fake.hash(), nonces) { PortOwner.FREE }
        assertFails { control.provision(second, fake.hash(), nonces, AcmeEnvironment.PRODUCTION, observation(true)) }
        assertFails { control.provision(second, fake.hash(), nonces.mapValues { it.value + "x" }, AcmeEnvironment.PRODUCTION, observation()) }
        fake.configuration = Json.parseToJsonElement(fake.configuration.toString().replace("/data/caddy", "/tmp/ephemeral")).jsonObject
        assertFails { control.provision(second, fake.hash(), nonces, AcmeEnvironment.PRODUCTION, observation()) }
        assertEquals(1, fake.writes)
    }
    @Test fun `uncertain provisioning reconciles by observation without another write`() {
        for (failure in listOf("before", "after", "ignored", "conflict")) test { root, fake, control ->
            fake.failure = failure
            assertFails { control.stageHttp01(first, fake.hash(), nonces) { PortOwner.FREE } }
            assertTrue(Files.exists(root.resolve("pending.json")))
            assertFails { control.stageHttp01(second, fake.hash(), nonces) { PortOwner.FREE } }
            assertFails { control.reconcile(first, "0".repeat(64)) }
            val hash = ReleaseLocks.sha256(Files.readAllBytes(root.resolve("$first.intent.json")))
            val result = control.reconcile(first, hash)
            assertEquals(if (failure == "after") "applied" else "not-applied", result.status)
            assertEquals(1, fake.writes)
            assertFalse(Files.exists(root.resolve("pending.json")))
            // Lost acknowledgement of claim removal remains idempotent and read-only.
            ReleasePrivateFiles.save(root.resolve("pending.json"), Files.readAllBytes(root.resolve("$first.intent.json")))
            assertEquals(result.status, control.reconcile(first, hash).status)
        }
    }
    @Test fun `divergence stays pending and foreign journal is not adoptable`() = test { root, fake, control ->
        fake.failure = "after"
        assertFails { control.stageHttp01(first, fake.hash(), nonces) { PortOwner.FREE } }
        fake.configuration = Json.parseToJsonElement(fake.configuration.toString().replace("p0v3-http01-", "foreign-")).jsonObject
        val hash = ReleaseLocks.sha256(Files.readAllBytes(root.resolve("$first.intent.json")))
        assertFails { control.reconcile(first, hash) }
        assertTrue(Files.exists(root.resolve("pending.json")))
        assertFails { CaddyHttpsProvisioner(root, binding.copy(site = "foreign"), fake).reconcile(first, hash) }
        assertFails { CaddyHttpsProvisioner.real(root, binding) }
    }
}
