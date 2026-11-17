package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

class RuntimeNativeIngressTest {
    @Test fun `exact reviewed TURN host and transport ports form one scoped table not a host-wide rewrite`(): Unit {
        val source = RuntimeNativeIngress.fixedRules("p0v3_rtc_0123456789ab", "192.0.2.41",
            "10.89.2.11", "10.89.2.1").decodeToString()
        assertContains(source, "table ip p0v3_rtc_0123456789ab")
        assertContains(source, "ip daddr 192.0.2.41 udp dport 3478 counter dnat to 10.89.2.11:3478")
        assertContains(source, "ip daddr 192.0.2.41 tcp dport 5349 counter dnat to 10.89.2.11:5349")
        assertContains(source, "ip daddr 10.89.2.11 udp dport 3478 counter snat to 10.89.2.1")
        assertContains(source, "ip daddr 10.89.2.11 tcp dport 5349 counter snat to 10.89.2.1")
        assertFalse("flush ruleset" in source || "0.0.0.0" in source || "50000" in source || "7880" in source)
        assertEquals(2, "policy accept;".toRegex().findAll(source).count())
        assertFailsWith<IllegalArgumentException> {
            RuntimeNativeIngress.fixedRules("foreign", "192.0.2.41", "10.89.2.11", "10.89.2.1")
        }
        assertFailsWith<IllegalArgumentException> {
            RuntimeNativeIngress.fixedRules("p0v3_rtc_0123456789ab", "192.0.2.41", "8.8.8.8", "10.89.2.1")
        }
        assertFailsWith<IllegalArgumentException> {
            RuntimeNativeIngress.fixedRules("p0v3_rtc_0123456789ab", "192.0.2.41", "10.89.2.1", "10.89.2.1")
        }
    }

    @Test fun `legacy private spec remains byte compatible without an RTC public ingress field`(): Unit {
        val original = PrivateDeploymentSpec(name = "unit", volumes = emptyList(), processes = emptyList())
        val serialized = Json { encodeDefaults = true }.encodeToString(original)
        assertFalse("nativeIngress" in serialized)
        val fixed = RuntimeNativeIngressPublication("canonical", listenAddress = "192.0.2.41")
        assertEquals("rtc.datamancy.net", fixed.approvedHost)
        assertEquals("livekit", fixed.processId)
        assertEquals(3478, fixed.udpPort)
        assertEquals(5349, fixed.tlsPort)
        assertTrue("192.0.2.41" in Json.encodeToString(fixed))
    }

    @Test fun `native installation receipt is NOT TURN return or accepted media evidence`(): Unit {
        val receipt = RuntimeNativeIngressResult("r-0123456789ab", "install",
            "a".repeat(64), "b".repeat(64), 123L, "c".repeat(64))
        assertEquals("installed-needs-native-return-proof", receipt.status)
        assertFalse("functional" in Json.encodeToString(receipt))
    }
}
