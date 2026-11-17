package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class FreshFinanceNativeSourceTest {
    @Test fun `r9 finance uses pinned narrow native Passport transport not browser SSO bypass`() {
        val module = PackagedGraphFragment.loadPendingV3("private-firefly-iii", 5, 9).definition
        val transport = module.processes.single { it.id == "firefly-native-api" }
        assertEquals("caddy", transport.artifact)
        assertEquals(8081, transport.readinessHttpPort)
        assertTrue(transport.networks.contains("firefly-web"))
        assertTrue("firefly-native-api" in module.install.processes &&
            "firefly-native-api" in module.restore.processes)
        val original = Path.of("/tmp/p0-old-full-36b6b7/modules/firefly-iii/legacy/stack.config/firefly-iii/native-api.Caddyfile")
        if (Files.isRegularFile(original)) {
            assertEquals("f3e416acb73c120a6216dc8253a06ad5ca83e6cdd3cfbce5f68fb28be3beb88e",
                ReleaseLocks.sha256(Files.readAllBytes(original)))
            val expected = Files.readString(original).replace("firefly.{\$DOMAIN}", "firefly.datamancy.net")
            val rendered = FragmentTemplates.render(PackagedGraphFragment.loadPendingV3("private-firefly-iii", 5, 9),
                "finance-native-api.caddyfile", emptyMap())
            assertEquals(expected, rendered)
            assertContains(rendered, "request_header -Cookie")
            assertContains(rendered, "method POST")
            assertContains(rendered, "header_regexp Authorization")
            assertContains(rendered, "Native importer API route refused.")
        }
    }
}
