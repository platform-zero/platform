package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AcmePreflightTest {
    private val approved = setOf("web.datamancy.net", "chat.datamancy.net")
    private val nonces = mapOf("web.datamancy.net" to "a".repeat(40), "chat.datamancy.net" to "b".repeat(40))
    private class Probe(val owner: PortOwner = PortOwner.FREE, val broken: String? = null) : AcmeObservation {
        val called = mutableListOf<String>()
        override fun portOwner(port: Int) = owner
        override fun challenge(host: String, nonce: String): ChallengeResponse {
            called += host
            return if (host == broken) ChallengeResponse(521, "", false)
            else ChallengeResponse(200, "p0v3-http01-$nonce", false)
        }
    }
    @Test fun `each host must independently pass its existing HTTP challenge route`() {
        val probe = Probe()
        AcmePreflight.check(approved, approved, probe, nonces::getValue)
        assertEquals(approved, probe.called.toSet())
        val broken = Probe(broken = "chat.datamancy.net")
        assertFailsWith<IllegalArgumentException> {
            AcmePreflight.check(approved, approved, broken, nonces::getValue)
        }
        assertEquals(listOf("chat.datamancy.net"), broken.called)
    }
    @Test fun `apex wildcard and foreign hosts cannot be authorized even by an approval list`() {
        for (host in listOf("datamancy.net", "*.datamancy.net", "foreign.example.org", "a".repeat(64) + ".datamancy.net")) {
            val probe = Probe()
            assertFailsWith<IllegalArgumentException> { AcmePreflight.check(setOf(host), setOf(host), probe) { "a".repeat(40) } }
            assertEquals(emptyList(), probe.called)
        }
        val adapter = PublicHttp01Observation(approved) { PortOwner.PROTECTED }
        assertEquals(PortOwner.PROTECTED, adapter.portOwner(80))
        assertFailsWith<IllegalArgumentException> { adapter.portOwner(8080) }
        assertFailsWith<IllegalArgumentException> { adapter.challenge("datamancy.net", "a".repeat(40)) }
    }
    @Test fun `port conflicts unapproved hosts and reused nonces block issuance`() {
        for (owner in listOf(PortOwner.PROTECTED, PortOwner.UNKNOWN)) {
            val probe = Probe(owner)
            assertFailsWith<IllegalArgumentException> { AcmePreflight.check(approved, approved, probe, nonces::getValue) }
            assertEquals(emptyList(), probe.called)
        }
        assertFailsWith<IllegalArgumentException> {
            AcmePreflight.check(approved, setOf("web.datamancy.net"), Probe(), nonces::getValue)
        }
        assertFailsWith<IllegalArgumentException> {
            AcmePreflight.check(approved, approved, Probe()) { "a".repeat(40) }
        }
    }
}
