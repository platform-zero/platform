package net.datamancy.platform

import kotlin.test.*

class FireflyCanonicalTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "valkey", "ntfy", "firefly-iii").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    private fun fragment(runtime: String = "1".repeat(64), migration: String = "2".repeat(64), origin: String = "https://finance.datamancy.net") =
        FireflyCanonical.fragment(inventory, "postgres", "postgres", runtime, migration,
            "-----BEGIN CERTIFICATE-----\nunit-only\n-----END CERTIFICATE-----\n", "base64:" + "A".repeat(43) + "=", origin)

    @Test fun `canonical fragment has no providers and strictly separates migration credentials`() {
        val f = fragment()
        assertEquals(setOf("firefly-storage", "firefly-cache"), f.volumes.map { it.id }.toSet())
        assertEquals(setOf("firefly-iii"), f.processOwners.values.toSet())
        assertEquals(5, f.processes.size)
        assertTrue(f.processes.none { it.id in setOf("postgres", "valkey", "ntfy") })
        assertTrue(f.inputs.values.none { it.contains("POSTGRES_PASSWORD=") || it.contains("P0V3_FIXTURE_PASSWORD=") })
        assertContains(f.inputs.getValue("firefly-runtime.env"), "DB_USERNAME=firefly_runtime\n")
        assertContains(f.inputs.getValue("firefly-runtime.env"), "PGSQL_SSL_MODE=verify-full\n")
        assertContains(f.inputs.getValue("firefly-runtime.env"), "PGSSLROOTCERT=/run/secrets/firefly-db-ca.pem\n")
        assertFalse(f.inputs.getValue("firefly-runtime.env").contains("2".repeat(64)))
        assertEquals("firefly-migration.env", f.processes.single { it.id == "firefly-migrate" }.environmentFile)
        assertTrue(f.processes.filterNot { it.oneShot }.none { it.environmentFile == "firefly-migration.env" })
        val config = f.processes.single { it.id == "firefly-runtime-config" }
        assertEquals(listOf("firefly-migrate"), config.dependencies)
        assertEquals("firefly-runtime.env", config.environmentFile)
        val pg = FoundationRuntime.spec(inventory).processes.single { it.id == "postgres" }.copy(dependencies = emptyList(), environmentFile = null)
        val full = PrivateDeploymentSpec(name = "canonical-test", volumes = f.volumes + RuntimeVolume("postgres", 999), processes = listOf(pg) + f.processes)
        PrivateDeployment.validate(full)
        assertEquals(f.inputs.keys, PrivateDeployment.inputNames(full).toSet())
        val restored = FireflyCanonical.coldRestoreSpec(full)
        PrivateDeployment.validate(restored)
        assertTrue(restored.processes.none { it.oneShot })
        assertFalse(PrivateDeployment.inputNames(restored).contains("firefly-migration.env"))
        assertEquals(listOf("postgres"), restored.processes.single { it.id == "firefly-php" }.dependencies)
        assertFails { FireflyCanonical.coldRestoreSpec(full.copy(processes = full.processes.dropLast(1))) }
    }

    @Test fun `planning is deterministic and input changes cannot change process topology`() {
        val a = FireflyCanonical.projection(inventory, "postgres")
        assertEquals(a, FireflyCanonical.projection(inventory, "postgres"))
        val b = fragment("3".repeat(64), "4".repeat(64))
        assertEquals(a.processes, b.processes)
        assertEquals(a.volumes, b.volumes)
        assertFails { fragment(migration = "1".repeat(64)) }
        assertFails { fragment(runtime = "password\nINJECT=true") }
        assertFails { fragment(origin = "http://finance.datamancy.net") }
        assertFails { fragment(origin = "https://finance.datamancy.net/other") }
        assertFails { fragment(origin = "https://finance.example.org") }
    }
}
