package net.datamancy.platform

import kotlin.test.*

class SeafileRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("seafile", "mariadb", "valkey").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `recovery binds inputs and never replays schema or identity creation`(): Unit {
        val base = java.nio.file.Files.createTempDirectory("p0v3-files-restore-")
        try {
            val source = SeafileRuntime.spec(inventory)
            val inputs = SeafileRuntime.inputs { mapOf("ca.pem" to "ca", "web.pem" to "cert", "web-key.pem" to "key") }
            val manifest = RuntimePreparation.prepare(source, base) { inputs }
            val recovered = java.nio.file.Files.createDirectory(base.resolve("recovered"), java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
            java.nio.file.Files.copy(manifest, recovered.resolve("source-spec.json"))
            inputs.keys.forEach { java.nio.file.Files.copy(base.resolve(source.name).resolve(it), recovered.resolve(it)) }
            val path = SeafileRecovery.prepare(inventory, recovered, "restored", base)
            val target = PrivateDeployment.read(path)
            assertEquals(inputs.keys, SingleUserRestore.inputNames(target))
            val check = target.processes.single { it.id == "schema-init" }.command.joinToString(" ")
            assertContains(check, ".p0v3-database-import-complete")
            assertContains(check, "test ! -L /state/.restore-in-progress")
            assertContains(check, "SHOW TABLES")
            assertFalse("schema.py" in check)
            val users = target.processes.single { it.id == "users-init" }.command.joinToString(" ")
            assertContains(users, "get_emailuser")
            assertFalse("add_emailuser" in users)
            assertEquals(source.processes.single { it.id == "mariadb-init" }, target.processes.single { it.id == "mariadb-init" })
            assertEquals(path, SeafileRecovery.prepare(inventory, recovered, "restored", base))
            assertFails { SeafileRecovery.prepare(inventory, recovered, source.name, base) }
            assertFails { SeafileRecovery.prepare(inventory, base.resolve("missing"), "other", base) }
            assertFails { SeafileRecovery.spec(source, inventory, "restored", "bad") }
            assertFails { SeafileRecovery.spec(source.copy(processes = source.processes.drop(1)), inventory, "restored", "a".repeat(64)) }
            java.nio.file.Files.writeString(recovered.resolve("app.env"), "changed")
            assertFails { SeafileRecovery.prepare(inventory, recovered, "restored", base) }
        } finally { java.nio.file.Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(java.nio.file.Files::delete) } }
    }
    @Test fun `canonical shared SQL cache fragment uses only bounded native Seafile authorities`(): Unit {
        val fresh = SeafileRuntime.canonicalFragment(inventory, "canonical-files")
        assertEquals("seafile", fresh.product)
        assertEquals(setOf("seafile-data", "seafile-web"), fresh.spec.networks.toSet())
        assertEquals(setOf("seafile-web"), fresh.webNetworks)
        assertEquals(setOf("mariadb", "valkey"), fresh.providerNetworks.keys)
        assertEquals(setOf("seafile-state", "seafile-rpc"), fresh.spec.volumes.map { it.id }.toSet())
        assertFalse(fresh.spec.processes.any { it.id in setOf("mariadb", "cache", "valkey", "caddy") })
        assertEquals(setOf("ccnet_db", "seafile_db", "seahub_db"), fresh.spec.databaseAccess.map { it.database }.toSet())
        assertTrue(fresh.spec.databaseAccess.filter { it.consumer == "seafile-schema-init" }
            .all { it.principal == "seafile_migrate" && it.credentialFile == "seafile-migration.env" })
        val cold = SeafileRuntime.coldRestoreFragment(fresh)
        assertEquals(fresh.spec.volumes, cold.spec.volumes)
        assertTrue(cold.spec.processes.none { it.oneShot })
        assertEquals(fresh.spec.processes.filterNot { it.oneShot }.map { it.id }.toSet(),
            cold.spec.processes.map { it.id }.toSet())
        val ca = "-----BEGIN CERTIFICATE-----\nunit\n-----END CERTIFICATE-----\n"
        val inputs = SeafileRuntime.canonicalInputs("1".repeat(64), "2".repeat(64), "3".repeat(64),
            ca, pki = { mapOf("ca.pem" to ca, "web.pem" to "leaf", "web-key.pem" to "key") })
        assertEquals(PrivateDeployment.inputNames(fresh.spec).toSet(), inputs.keys)
        assertContains(inputs.getValue("seafile-schema.py"), "ssl_verify_identity=True")
        assertFalse(inputs.getValue("seafile-app.env").contains("1".repeat(64)))
        assertFalse(inputs.getValue("seafile-migration.env").contains("3".repeat(64)))
        assertFails { SeafileRuntime.canonicalInputs("1".repeat(64), "1".repeat(64), "3".repeat(64), ca) }
    }
    @Test fun `native schema and identities are journalled without exposing bootstrap passwords to serving processes`(): Unit {
        val spec = SeafileRuntime.spec(inventory)
        assertEquals(8, PrivateDeployment.validate(spec).size)
        assertEquals(5, spec.processes.count { !it.oneShot })
        assertTrue(spec.processes.all { it.userId != 0 && it.capabilities.isEmpty() && it.apparmorProfile == "p0v3-private-v1" })
        val files = SeafileRuntime.inputs { mapOf("ca.pem" to "ca", "web.pem" to "cert", "web-key.pem" to "key") }
        assertEquals(SingleUserRestore.inputNames(spec), files.keys)
        assertTrue(spec.processes.filterNot { it.oneShot }.none { p -> p.files.any { it.file == "users.json" } })
        assertContains(files.getValue("schema.py"), "Existing or interrupted state retained")
        assertContains(files.getValue("schema.py"), "Existing database retained; refusing schema replay")
        assertContains(files.getValue("users.py"), "Existing user retained")
        assertContains(files.getValue("users.py"), "if not __debug__")
        assertContains(files.getValue("seahub-settings.py"), "ENABLE_SIGNUP=False")
        assertContains(files.getValue("seahub-settings.py"), "dummy.EmailBackend")
        assertContains(files.getValue("app.env"), "ENABLE_SEADOC=false")
        assertContains(files.getValue("seafile-web.py"), "losing", ignoreCase = true)
        assertContains(files.getValue("nginx.conf"), "proxy_pass http://backend:8082/;")
        assertFails { SeafileRuntime.spec(inventory.copy(images = emptyList())) }
        assertFails { SeafileRuntime.spec(inventory.copy(images = inventory.images.map { it.copy(os = "other") })) }
        assertFails { SeafileRuntime.spec(inventory, "../bad") }
    }
}
