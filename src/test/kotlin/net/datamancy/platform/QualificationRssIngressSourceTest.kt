package net.datamancy.platform

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class QualificationRssIngressSourceTest {
    private val issuerCa = "a".repeat(64)
    private val leaf = "b".repeat(64)
    private fun selected(endpoint: String = "https://10.44.0.3:443",
        ingress: String = "10.44.0.3", network: String = "ingress-control",
        ca: String = issuerCa, observedLeaf: String = leaf) = QualificationRssIngressSource.address(
        endpoint, ingress, network, ca, issuerCa, observedLeaf, leaf)

    @Test fun `host-native RSS chooses current served ingress control not qualification web`() {
        assertEquals("10.44.0.3", selected())
        for (bad in listOf("https://10.45.0.4:443", "https://198.51.100.7:443",
            "http://10.44.0.3:443", "https://10.44.0.3:444", "https://10.44.0.3:443/foreign")) {
            assertThrows(IllegalArgumentException::class.java) { selected(endpoint = bad) }
        }
        assertThrows(IllegalArgumentException::class.java) { selected(network = "qualification-web") }
        assertThrows(IllegalArgumentException::class.java) { selected(ca = "c".repeat(64)) }
        assertThrows(IllegalArgumentException::class.java) { selected(observedLeaf = "d".repeat(64)) }
    }
}
