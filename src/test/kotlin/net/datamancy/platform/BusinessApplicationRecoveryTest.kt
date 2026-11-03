package net.datamancy.platform

import kotlin.test.*

class BusinessApplicationRecoveryTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "valkey", "ntfy", "mariadb", "memcached", "firefly-iii",
        "bookstack", "sogo", "erpnext", "qbittorrent", "searxng", "element", "opensearch", "prometheus", "node-exporter").map {
        val pin = if (it == "node-exporter") NodeMetricsRuntime.BASE_IMAGE else image
        AcquiredImage(it, "upstream", "example.org/app:1", pin, "b".repeat(64), emptyList(), pin.substringAfter('@'), "amd64", "linux")
    })
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
