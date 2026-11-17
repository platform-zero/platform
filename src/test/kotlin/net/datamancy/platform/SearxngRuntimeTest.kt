package net.datamancy.platform

import kotlin.test.*

class SearxngRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("searxng", "element").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `recovery checks existing corpus without reseeding and binds immutable inputs`(): Unit {
        val base = java.nio.file.Files.createTempDirectory("p0v3-search-restore-")
        try {
            val source = SearxngRuntime.spec(inventory)
            val inputs = SearxngRuntime.inputs { mapOf("ca.pem" to "ca", "web.pem" to "cert", "web-key.pem" to "key") }
            val manifest = RuntimePreparation.prepare(source, base) { inputs }
            val recovered = java.nio.file.Files.createDirectory(base.resolve("recovered"),
                java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
            java.nio.file.Files.copy(manifest, recovered.resolve("source-spec.json"))
            inputs.keys.forEach { java.nio.file.Files.copy(base.resolve(source.name).resolve(it), recovered.resolve(it)) }
            val restored = SearxngRecovery.prepare(inventory, recovered, "restored", base)
            val target = PrivateDeployment.read(restored)
            assertEquals(listOf("restore-check", "searxng", "search"), PrivateDeployment.validate(target).map { it.id })
            val check = target.processes.first().command.last()
            assertContains(check, ".restore-in-progress")
            assertContains(check, ".p0v3-restore-complete")
            assertContains(check, "PRAGMA integrity_check")
            assertFalse("seed.py" in check)
            assertEquals(inputs.keys, SingleUserRestore.inputNames(target))
            assertEquals(restored, SearxngRecovery.prepare(inventory, recovered, "restored", base))
            assertFails { SearxngRecovery.prepare(inventory, recovered, source.name, base) }
            assertFails { SearxngRecovery.spec(source, inventory, "restored", "invalid") }
            assertFails { SearxngRecovery.spec(source.copy(processes = source.processes.drop(1)), inventory, "restored", "a".repeat(64)) }
            assertFails { SearxngRecovery.prepare(inventory, base.resolve("missing"), "other", base) }
            java.nio.file.Files.writeString(recovered.resolve("settings.yml"), "changed")
            assertFails { SearxngRecovery.prepare(inventory, recovered, "restored", base) }
        } finally { java.nio.file.Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(java.nio.file.Files::delete) } }
    }
    @Test fun `native offline search is pinned isolated and durably initialized`(): Unit {
        val spec = SearxngRuntime.spec(inventory)
        assertEquals(listOf("corpus-init", "searxng", "search"), PrivateDeployment.validate(spec).map { it.id })
        assertEquals(2, spec.processes.count { !it.oneShot })
        assertTrue(spec.processes.all { it.capabilities.isEmpty() && it.apparmorProfile == "p0v3-private-v1" })
        val files = SearxngRuntime.inputs { mapOf("ca.pem" to "ca", "web.pem" to "cert", "web-key.pem" to "key") }
        assertEquals(SingleUserRestore.inputNames(spec), files.keys)
        assertContains(files.getValue("settings.yml"), "keep_only: []")
        assertContains(files.getValue("settings.yml"), "WHERE documents MATCH :query")
        assertContains(files.getValue("settings.yml"), "image_proxy: false")
        assertContains(files.getValue("seed.py"), "if not __debug__:")
        assertContains(files.getValue("seed.py"), "target.exists() or pending.exists()")
        assertContains(files.getValue("seed.py"), "os.fsync(descriptor)")
        assertContains(files.getValue("nginx.conf"), "access_log off;")
        assertFails { SearxngRuntime.spec(inventory.copy(images = inventory.images.take(1))) }
        assertFails { SearxngRuntime.spec(inventory.copy(images = inventory.images.map { it.copy(os = "other") })) }
        assertFails { SearxngRuntime.spec(inventory, "../unsafe") }
    }
    @Test fun `canonical search retains original query secret and FTS corpus without one-shot reseed`(): Unit {
        val graph = SearxngRuntime.canonicalFragment(inventory, "q-111111111111-searxng")
        val inputs = SearxngRuntime.canonicalInputs { mapOf(
            "ca.pem" to "CA", "web.pem" to "cert", "web-key.pem" to "key") }
        assertEquals(PrivateDeployment.inputNames(graph.spec).toSet(), inputs.keys)
        assertEquals(setOf("search-data", "search-web"), graph.spec.networks.toSet())
        assertEquals(setOf("search-web"), graph.webNetworks)
        val cold = SearxngRuntime.coldRestoreFragment(graph)
        assertEquals(graph.spec.volumes, cold.spec.volumes)
        assertEquals(setOf("searxng", "searxng-web"), cold.spec.processes.map { it.id }.toSet())
        assertFalse(cold.spec.processes.any { it.oneShot })
        assertEquals(graph.spec.processes.single { it.id == "searxng" }.environmentFile,
            cold.spec.processes.single { it.id == "searxng" }.environmentFile)
    }
}
