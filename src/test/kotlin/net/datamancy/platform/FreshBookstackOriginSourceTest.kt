package net.datamancy.platform

import kotlin.test.*
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive

class FreshBookstackOriginSourceTest {
    @Test fun `fresh browser OIDC client and application origin match module owned ingress`() {
        val origin = "https://bookstack.datamancy.net"
        val client = BookStackRuntime.releaseOidcClient("a".repeat(64))
        assertEquals(origin + "/oidc/callback", client.getValue("redirectUris").jsonArray.single().jsonPrimitive.content)
        assertEquals(origin, client.getValue("webOrigins").jsonArray.single().jsonPrimitive.content)
        val inputs = BookStackRuntime.releaseInputs(CanonicalMariaCredentialPair("b".repeat(64), "c".repeat(64)),
            "base64:" + "A".repeat(43) + "=", "00000000-0000-4000-8000-000000000001",
            "a".repeat(64), "d".repeat(64))
        assertContains(inputs.getValue("bookstack-runtime.env"), "APP_URL=$origin\n")
        val manifest = PackagedGraphFragment.pendingV3R9().first
        assertTrue(manifest.integratedReference!!.modules.single { it.id == "bookstack" }
            .privateRoutes.any { it.host == "bookstack.datamancy.net" && it.policy == "APP" })
    }
}
