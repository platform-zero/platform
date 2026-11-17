package net.datamancy.platform

import kotlin.test.*

class BusinessApplicationRecoveryTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "valkey", "ntfy", "mariadb", "memcached", "firefly-iii",
        "bookstack", "sogo", "erpnext", "forgejo", "donetick", "qbittorrent", "searxng", "element", "opensearch", "prometheus", "node-exporter").map {
        val pin = if (it == "node-exporter") NodeMetricsRuntime.BASE_IMAGE else image
        AcquiredImage(it, "upstream", "example.org/app:1", pin, "b".repeat(64), emptyList(), pin.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `v2 Forgejo and Donetick own original state without cloning providers or bootstrap secrets`() : Unit {
        val forge = ForgejoRuntime.canonicalFragment(inventory, "canonical-release-v2")
        val forgeCold = ForgejoRuntime.canonicalColdFragment(forge)
        assertEquals(RuntimeStore.CANONICAL_V2, forge.spec.store)
        assertEquals(setOf("forgejo-web"), forge.webNetworks)
        assertEquals(forge.spec.volumes, forgeCold.spec.volumes)
        assertEquals(listOf("forgejo"), forgeCold.spec.processes.map { it.id })
        assertEquals("forgejo-runtime.env", forgeCold.spec.processes.single().environmentFile)
        val keys = listOf("1", "2", "3", "4").iterator()
        val sealed = ForgejoRuntime.canonicalInputs { keys.next().repeat(64) }
        assertContains(sealed.getValue("app.ini"), "ROOT_URL = https://git.datamancy.net/")
        assertFalse(sealed.getValue("forgejo-runtime.env").contains("BOOTSTRAP_PASSWORD"))
        assertFails { ForgejoRuntime.canonicalColdFragment(forge.copy(product = "foreign")) }
        val chores = DonetickRuntime.canonicalFragment(inventory, "canonical-release-v2")
        assertEquals(chores, DonetickRuntime.canonicalColdFragment(chores))
        assertEquals(setOf("donetick-web"), chores.webNetworks)
        assertTrue(chores.spec.processes.none { it.id in setOf("postgres", "mariadb", "valkey", "caddy") })
        val config = DonetickRuntime.canonicalInputs { "a".repeat(64) }
        assertContains(config.getValue("selfhosted.yaml"), "is_user_creation_disabled: true")
        assertContains(config.getValue("selfhosted.yaml"), "public_host: https://donetick.datamancy.net")
        assertContains(config.getValue("selfhosted.yaml"), "cors_allow_origins: ['https://donetick.datamancy.net']")
        assertContains(config.getValue("selfhosted.yaml"), "allowed_origins: ['https://donetick.datamancy.net']")
        assertFalse("chores.datamancy.net" in config.getValue("selfhosted.yaml"))
        assertFailsWith<IllegalArgumentException> {
            DonetickRuntime.requireActorOrigin(java.net.URI.create("https://chores.datamancy.net"))
        }
        assertFailsWith<IllegalArgumentException> {
            DonetickRuntime.requireActorOrigin(java.net.URI.create("https://donetick-native.datamancy.net"))
        }
        assertFalse(config.getValue("donetick-runtime.env").contains("P0V3_FIXTURE_PASSWORD"))
        assertFails { DonetickRuntime.canonicalColdFragment(chores.copy(product = "foreign")) }
    }

    @Test fun `reviewed recipes retire every initializer and preserve restored storage and provider ordering`() {
        val specs = mapOf("erpnext" to ErpNextRuntime.spec(inventory), "firefly" to FireflyRuntime.spec(inventory),
            "bookstack" to BookStackRuntime.spec(inventory), "sogo" to SogoRuntime.spec(inventory),
            "mail" to MailRuntime.spec(), "sogo-mail" to SogoMailRuntime.spec(inventory),
            "node-metrics" to NodeMetricsRuntime.spec(inventory), "qbittorrent" to QbittorrentRuntime.spec(inventory),
            "searxng" to SearxngRuntime.spec(inventory), "opensearch" to OpenSearchRuntime.spec(inventory))
        assertEquals(specs.keys, BusinessApplicationRecovery.recipes)
        specs.forEach { (recipe, source) ->
            val target = BusinessApplicationRecovery.coldRestoreSpec(recipe, source)
            PrivateDeployment.validate(target)
            assertEquals(source.volumes, target.volumes)
            assertEquals(source.networks, target.networks)
            assertEquals(source.processes.filterNot { it.oneShot }.map { it.id }, target.processes.map { it.id })
            assertTrue(target.processes.none { it.oneShot })
            assertTrue(target.processes.none { it.environmentFile in setOf("bootstrap.env", "installer.env", "mariadb.env", "database-init.env", "mail-bootstrap.env") })
            assertFails { BusinessApplicationRecovery.coldRestoreSpec(recipe, target) }
            assertFails { BusinessApplicationRecovery.coldRestoreSpec(recipe, source.copy(processes = source.processes +
                source.processes.first().copy(id = "foreign-init", oneShot = true, dependencies = emptyList()))) }
        }
        val erp = BusinessApplicationRecovery.coldRestoreSpec("erpnext", specs.getValue("erpnext"))
        assertEquals(setOf("mariadb", "cache", "queue"), erp.processes.single { it.id == "backend" }.dependencies.toSet())
        val firefly = BusinessApplicationRecovery.coldRestoreSpec("firefly", specs.getValue("firefly"))
        assertEquals(listOf("postgres"), firefly.processes.single { it.id == "php" }.dependencies)
        assertFails { BusinessApplicationRecovery.coldRestoreSpec("unreviewed", specs.getValue("erpnext")) }
    }
}
