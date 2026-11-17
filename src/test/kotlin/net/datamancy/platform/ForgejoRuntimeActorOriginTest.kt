package net.datamancy.platform

import java.net.URI
import kotlin.test.*

class ForgejoRuntimeActorOriginTest {
    @Test fun `actor issuance and readback accept only selected Forgejo APP origin`() {
        val route = PackagedGraphFragment.pendingV3R9().first.integratedReference!!.modules
            .single { it.id == "forgejo" }.privateRoutes.single { it.policy == "APP" }
        val selected = URI.create("https://${route.host}")
        assertEquals("forgejo.datamancy.net", route.host)
        assertEquals("https://forgejo.datamancy.net", ForgejoRuntime.requireActorOrigin(selected))
        listOf("https://git.datamancy.net", "http://forgejo.datamancy.net",
            "https://forgejo.datamancy.net:443", "https://forgejo.datamancy.net/",
            "https://forgejo.datamancy.net@evil.invalid", "https://forgejo.datamancy.net?q=1",
            "https://forgejo.datamancy.net#fragment").forEach { foreign ->
            assertFailsWith<IllegalArgumentException>(foreign) {
                ForgejoRuntime.requireActorOrigin(URI.create(foreign))
            }
        }
    }
}
