package net.datamancy.platform

import kotlin.test.*

class FireflyCanonicalTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "valkey", "ntfy", "firefly-iii").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    private fun fragment(runtime: String = "1".repeat(64), migration: String = "2".repeat(64), origin: String = "https://finance.datamancy.net") =
        FireflyCanonical.fragment(inventory, "postgres", "postgres", runtime, migration,
            "-----BEGIN CERTIFICATE-----\nunit-only\n-----END CERTIFICATE-----\n", "base64:" + "A".repeat(43) + "=", origin,
            FireflyOriginalSubjects("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
                "5".repeat(64), "6".repeat(64), "q-111111111111"))

    @Test fun `fresh remote guard binds the same UUIDs as native financial users`() {
        val subjects = FireflyOriginalSubjects("11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222", "5".repeat(64), "6".repeat(64), "q-111111111111")
        val selected = FireflyCanonical.fragment(inventory, "postgres", "postgres", "1".repeat(64),
            "2".repeat(64), "-----BEGIN CERTIFICATE-----\nunit-only\n-----END CERTIFICATE-----\n",
            "base64:" + "A".repeat(43) + "=", "https://firefly.datamancy.net", subjects,
            freshRemoteSubjects = true)
        assertContains(selected.inputs.getValue("firefly-runtime.env"), "AUTHENTICATION_GUARD=remote_user_guard\n")
        assertEquals(listOf("firefly-migrate", "keycloak"),
            selected.processes.single { it.id == "firefly-users-init" }.dependencies)
        assertContains(selected.inputs.getValue("firefly-users.php"), "\$ownerEmail = \$ownerSub; \$outsiderEmail = \$outsiderSub;")
        val importer = FireflyCanonical.fragment(inventory, "postgres", "postgres", "1".repeat(64),
            "2".repeat(64), "-----BEGIN CERTIFICATE-----\nunit-only\n-----END CERTIFICATE-----\n",
            "base64:" + "A".repeat(43) + "=", "https://firefly.datamancy.net", subjects,
            freshRemoteSubjects = true, freshImporterClientId = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
        val native = importer.inputs.getValue("firefly-users.php")
        assertContains(native, "app(Laravel\\Passport\\Client::class)->newQuery()->find(")
        assertContains(native, "\$client->redirect_uris = ['https://firefly-importer.datamancy.net/callback'];")
        assertFalse(native.contains("Passport::client()"))
        assertFailsWith<IllegalArgumentException> {
            FireflyCanonical.fragment(inventory, "postgres", "postgres", "1".repeat(64), "2".repeat(64),
                "-----BEGIN CERTIFICATE-----\nunit-only\n-----END CERTIFICATE-----\n",
                "base64:" + "A".repeat(43) + "=", "https://firefly.datamancy.net",
                freshRemoteSubjects = true)
        }
    }

    @Test fun `release projection refuses a duplicate Firefly and cold preserves original files`() : Unit {
        val bytes = GenerationAssembly.readInventory(java.nio.file.Path.of("release/downloaded-candidate-inventory.json"))
        val full = kotlinx.serialization.json.Json.decodeFromString<AcquiredInventory>(bytes.decodeToString())
        val base = CanonicalCoreRuntime.releaseProvidersSpec(full).copy(store = RuntimeStore.CANONICAL_V2)
        val finance = FireflyCanonical.releaseProjection(base)
        assertEquals(setOf("firefly-iii"), finance.processOwners.values.toSet())
        assertEquals(setOf("firefly-storage", "firefly-cache"), finance.volumes.map { it.id }.toSet())
        assertEquals(setOf("firefly-db-init", "firefly-db-finalize"),
            finance.processes.filter { it.id.startsWith("firefly-db-") }.map { it.id }.toSet())
        val restored = CanonicalCoreRuntime.releaseColdRestoreProvidersSpec(base)
        FireflyCanonical.verifyReleaseCold(base, restored)
        assertFails { FireflyCanonical.releaseProjection(restored) }
        assertFails { FireflyCanonical.verifyReleaseCold(base, restored.copy(volumes = restored.volumes.dropLast(1))) }
    }

    @Test fun `canonical fragment has no providers and strictly separates migration credentials`() {
        val f = fragment()
        assertEquals(setOf("firefly-storage", "firefly-cache"), f.volumes.map { it.id }.toSet())
        assertEquals(setOf("firefly-iii"), f.processOwners.values.toSet())
        assertEquals(6, f.processes.size)
        assertTrue(f.processes.none { it.id in setOf("postgres", "valkey", "ntfy") })
        assertTrue(f.inputs.values.none { it.contains("POSTGRES_PASSWORD=") || it.contains("P0V3_FIXTURE_PASSWORD=") })
        assertContains(f.inputs.getValue("firefly-runtime.env"), "DB_USERNAME=firefly_runtime\n")
        assertContains(f.inputs.getValue("firefly-runtime.env"), "PGSQL_SSL_MODE=verify-full\n")
        assertContains(f.inputs.getValue("firefly-runtime.env"), "PGSSLROOTCERT=/run/secrets/firefly-db-ca.pem\n")
        assertFalse(f.inputs.getValue("firefly-runtime.env").contains("2".repeat(64)))
        assertEquals("firefly-migration.env", f.processes.single { it.id == "firefly-migrate" }.environmentFile)
        assertTrue(f.processes.filterNot { it.oneShot }.none { it.environmentFile == "firefly-migration.env" })
        val config = f.processes.single { it.id == "firefly-runtime-config" }
        assertEquals(listOf("firefly-users-init"), config.dependencies)
        val users = f.processes.single { it.id == "firefly-users-init" }
        assertTrue(users.oneShot)
        assertEquals(listOf("firefly-migrate"), users.dependencies)
        assertEquals("firefly-onboarding.env", users.environmentFile)
        assertContains(f.inputs.getValue("firefly-users.php"), "UserRepositoryInterface::class")
        assertContains(f.inputs.getValue("firefly-users.php"), "UserGroupFactory::class")
        assertContains(f.inputs.getValue("firefly-users.php"), "ownerGroupId")
        assertContains(f.inputs.getValue("firefly-users.php"), "outsiderGroupId")
        assertContains(f.inputs.getValue("firefly-users.php"), "getAdministrationId()")
        assertContains(f.inputs.getValue("firefly-users.php"), "p0v3-original-users-intent.json")
        assertContains(f.inputs.getValue("firefly-users.php"), "p0v3-original-users-receipt.json")
        assertContains(f.inputs.getValue("firefly-users.php"), "findByEmail")
        assertContains(f.inputs.getValue("firefly-users.php"), "fsync(")
        assertFalse(f.inputs.getValue("firefly-runtime.env").contains("P0V3_OWNER_PASSWORD"))
        assertContains(f.inputs.getValue("firefly-runtime.env"), "SITE_OWNER=owner@localhost.invalid")
        assertEquals("firefly-runtime.env", config.environmentFile)
        val pg = FoundationRuntime.spec(inventory).processes.single { it.id == "postgres" }.copy(dependencies = emptyList(), environmentFile = null)
        val full = PrivateDeploymentSpec(name = "canonical-test", volumes = f.volumes + RuntimeVolume("postgres", 999), processes = listOf(pg) + f.processes)
        PrivateDeployment.validate(full)
        assertEquals(f.inputs.keys, PrivateDeployment.inputNames(full).toSet())
        val restored = FireflyCanonical.coldRestoreSpec(full)
        PrivateDeployment.validate(restored)
        assertTrue(restored.processes.none { it.oneShot })
        assertFalse(PrivateDeployment.inputNames(restored).contains("firefly-migration.env"))
        assertFalse(PrivateDeployment.inputNames(restored).contains("firefly-onboarding.env"))
        assertEquals(listOf("postgres"), restored.processes.single { it.id == "firefly-php" }.dependencies)
        assertFails { FireflyCanonical.coldRestoreSpec(full.copy(processes = full.processes.dropLast(1))) }
    }

    @Test fun `planning is deterministic and input changes cannot change process topology`() {
        val a = FireflyCanonical.projection(inventory, "postgres", includeNativeOnboarding = true)
        assertEquals(a, FireflyCanonical.projection(inventory, "postgres", includeNativeOnboarding = true))
        assertEquals(5, FireflyCanonical.projection(inventory, "postgres").processes.size)
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
