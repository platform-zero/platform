package net.datamancy.platform

import java.net.URI
import org.junit.jupiter.api.Test
import kotlin.test.*

class GenerationOriginalActorGroupCookieTest {
    @Test fun `private Donetick SSO cookie is host and TLS scoped per original actor`() {
        val owner = GenerationOriginalActorHttp.scopedGroupCookie("donetick.datamancy.net",
            "_p0v3_edge=" + "a".repeat(32))
        val outsider = GenerationOriginalActorHttp.scopedGroupCookie("donetick.datamancy.net",
            "_p0v3_edge=" + "b".repeat(32))
        fun header(uri: String, manager: java.net.CookieManager) =
            manager.get(URI(uri), emptyMap()).getOrDefault("Cookie", emptyList()).joinToString(";")
        assertContains(header("https://donetick.datamancy.net/api/v1/chores/1", owner), "a".repeat(32))
        assertContains(header("https://donetick.datamancy.net/api/v1/chores/1", outsider), "b".repeat(32))
        assertFalse(header("https://donetick.datamancy.net/", owner).contains("b".repeat(32)))
        for (host in listOf("auth.datamancy.net", "keycloak-auth.datamancy.net", "donetick-native.datamancy.net")) {
            assertEquals("", header("https://$host/", owner))
        }
        assertEquals("", header("http://donetick.datamancy.net/", owner))
        assertFails { GenerationOriginalActorHttp.scopedGroupCookie("donetick-native.datamancy.net",
            "_p0v3_edge=" + "a".repeat(32)) }
        assertFails { GenerationOriginalActorHttp.scopedGroupCookie("donetick.datamancy.net", "Bearer " + "a".repeat(32)) }
    }
}
