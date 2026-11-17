package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.*

class OpenSearchRuntimeTest {
    private val image = "example.org/search@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf(AcquiredImage("opensearch", "upstream", "example.org/search:1",
        image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")))
    @Test fun `search is private non-root TLS secured without demo users or host sysctl changes`(): Unit {
        val spec = OpenSearchRuntime.spec(inventory)
        assertEquals(listOf("search-config-init", "opensearch", "search-security-init"), PrivateDeployment.validate(spec).map { it.id })
        assertTrue(spec.processes.all { it.userId == 1000 && it.capabilities.isEmpty() })
        val node = spec.processes.single { it.id == "opensearch" }
        assertFalse(node.files.any { it.file.startsWith("admin") })
        assertContains(node.readiness.last(), ".p0-security-ready")
        val certs = listOf("ca.pem", "node.pem", "node-key.pem", "admin.pem", "admin-key.pem").associateWith { "unit-only-$it" }
        val inputs = OpenSearchRuntime.inputs(certs)
        assertEquals((spec.processes.mapNotNull { it.environmentFile } + spec.processes.flatMap { it.files.map { f -> f.file } }).toSet(), inputs.keys)
        assertContains(inputs.getValue("opensearch.yml"), "clientauth_mode: REQUIRE")
        assertContains(inputs.getValue("opensearch.yml"), "node.store.allow_mmap: false")
        assertContains(inputs.getValue("security.yml"), "type: clientcert")
        assertFalse(inputs.getValue("security.yml").contains("basic"))
        assertFalse(inputs.getValue("internal-users.yml").contains("hash:"))
        assertFails { OpenSearchRuntime.inputs(emptyMap()) }
        assertFails { OpenSearchRuntime.spec(inventory.copy(images = emptyList())) }
        assertFails { OpenSearchRuntime.spec(inventory.copy(images = listOf(inventory.images.single().copy(architecture = "arm64")))) }
        val base = Files.createTempDirectory("search-unit-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            val path = RuntimePreparation.prepare(spec, base) { inputs }
            assertEquals(path, OpenSearchRuntime.prepare(inventory, base)) // Existing inputs, never regenerates PKI.
            assertEquals(spec, PrivateDeployment.read(path))
        } finally { Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `PKI generation keeps issuing key temporary and cleans up even on failure`(): Unit {
        val paths = mutableListOf<Path>()
        val commands = mutableListOf<List<String>>()
        val generated = PrivateSearchPki.generate { root, args ->
            paths.add(root)
            commands += args
            assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(root))
            for (option in listOf("-keyout", "-out")) if (option in args)
                Files.writeString(root.resolve(args[args.indexOf(option) + 1]), "unit-only-pem")
        }
        assertEquals(5, generated.size)
        assertFalse("ca-key.pem" in generated)
        assertEquals(5, commands.size)
        assertTrue(paths.none { Files.exists(it) })
        var failedRoot: Path? = null
        assertFails { PrivateSearchPki.generate { root, _ -> failedRoot = root; error("unit-only failure") } }
        assertFalse(Files.exists(failedRoot!!))
    }
    @Test fun `canonical OpenSearch preserves original security index and native mTLS identities cold`(): Unit {
        val graph = OpenSearchRuntime.canonicalFragment(inventory, "q-111111111111-opensearch")
        val certs = listOf("ca.pem", "node.pem", "node-key.pem", "admin.pem", "admin-key.pem")
            .associateWith { "fixture-$it" }
        val inputs = OpenSearchRuntime.canonicalInputs(certs)
        assertEquals(PrivateDeployment.inputNames(graph.spec).toSet(), inputs.keys)
        assertEquals(listOf("opensearch-data"), graph.spec.networks)
        assertTrue(graph.providerNetworks.isEmpty() && graph.webNetworks.isEmpty())
        val cold = OpenSearchRuntime.coldRestoreFragment(graph)
        assertEquals(graph.spec.volumes, cold.spec.volumes)
        assertEquals(listOf("opensearch"), cold.spec.processes.map { it.id })
        assertEquals(graph.spec.processes.single { it.id == "opensearch" }.files, cold.spec.processes.single().files)
        assertFalse(cold.spec.processes.any { it.oneShot || it.files.any { file -> file.file == "opensearch-admin-key.pem" } })
    }
}
