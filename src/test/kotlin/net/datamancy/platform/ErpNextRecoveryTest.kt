package net.datamancy.platform

import kotlin.test.*

class ErpNextRecoveryTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("erpnext", "mariadb", "valkey").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `ERP restore checks all state and never installs schema site or credentials`() {
        val source = ErpNextRuntime.spec(inventory)
        val restored = ErpNextRecovery.spec(source, inventory, "erprestore-unit", "c".repeat(64))
        PrivateDeployment.validate(restored)
        assertEquals(source.volumes, restored.volumes)
        assertEquals(source.processes.map { it.id }, restored.processes.map { it.id })
        assertEquals(8, restored.processes.count { !it.oneShot })
        assertTrue(restored.processes.filterNot { it.oneShot }.none { it.environmentFile in setOf("bootstrap.env", "installer.env", "mariadb.env") })
        val commands = restored.processes.flatMap { it.command }.joinToString("\n")
        for (forbidden in listOf("mariadb-install-db", "new_site", "DROP USER", "CREATE USER", "migrate --", "initdb")) assertFalse(forbidden in commands)
        for (id in listOf("mariadb-init", "cache", "queue")) {
            assertContains(restored.processes.single { it.id == id }.command.last(), ".p0v3-restore-complete")
            assertContains(restored.processes.single { it.id == id }.command.last(), "test ! -L")
        }
        assertEquals(setOf("sites", "config", "logs"), restored.processes.single { it.id == "site-config-init" }.volumes.map { it.volume }.toSet())
        assertContains(commands, "error.args[0] != 1045")
        assertContains(commands, "SHOW GRANTS FOR CURRENT_USER")
        assertFalse("bootstrap.env" in PrivateDeployment.inputNames(restored))
        assertFalse("mariadb.env" in PrivateDeployment.inputNames(restored))
        assertContains(PrivateDeployment.inputNames(restored), "erp-restore-check.py")
        assertFails { ErpNextRecovery.spec(source.copy(processes = source.processes.drop(1)), inventory, "erprestore-unit", "c".repeat(64)) }
        assertFails { ErpNextRecovery.spec(source, inventory, source.name, "c".repeat(64)) }
        assertFails { ErpNextRecovery.spec(source, inventory, "erprestore-unit", "not-a-digest") }
        assertFails { ErpNextRecovery.spec(source, inventory, "unrestricted", "c".repeat(64)) }
    }
}
