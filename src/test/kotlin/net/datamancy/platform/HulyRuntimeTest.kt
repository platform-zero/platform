package net.datamancy.platform

import kotlin.test.*

class HulyRuntimeTest {
    private val products = listOf("account", "cockroach", "collaborator", "elasticsearch", "front", "fulltext", "kvs", "objectstore", "redpanda", "rekoni", "stats", "transactor", "workspace").map { "huly-$it" } + "caddy"
    private val inventory = AcquiredInventory(1, "candidate", products.map {
        val pin = when (it) { "huly-elasticsearch" -> HulyRuntime.SEARCH_BASE; "huly-kvs" -> HulyRuntime.KVS_BASE; "caddy" -> HulyRuntime.CADDY_BASE; else -> "example.org/$it@sha256:" + "a".repeat(64) }
        AcquiredImage(it, "upstream", "example.org/$it:1", pin, "b".repeat(64), emptyList(), pin.substringAfter('@'), "amd64", "linux")
    })
    private val pki = listOf("ca.pem", "node.pem", "node-key.pem", "admin.pem", "admin-key.pem").associateWith { "unit-only-$it\n" }
    @Test fun `closed private cohort retains native compatibility and narrowly scoped bootstrap inputs`() {
        val spec = HulyRuntime.spec(inventory)
        assertEquals(18, spec.processes.size)
        assertEquals(4, spec.processes.count { it.oneShot })
        assertTrue(spec.processes.all { it.userId == 1000 && it.capabilities.isEmpty() && it.apparmorProfile == "p0v3-private-v1" })
        val order = PrivateDeployment.validate(spec).map { it.id }
        assertTrue(order.indexOf("database-init") < order.indexOf("account-bootstrap"))
        assertTrue(order.indexOf("account-bootstrap") < order.indexOf("account"))
        assertTrue(spec.processes.filterNot { it.oneShot }.none { p -> p.files.any { it.file in setOf("cr-root-key.pem", "bootstrap-users.json", "search-bootstrap.json", "database.sql") } })
        assertEquals(HulyRuntime.SEARCH_IMAGE, spec.processes.single { it.id == "elastic" }.image)
        assertContains(spec.processes.single { it.id == "redpanda" }.command, "--unsafe-bypass-fsync=false")
        assertContains(spec.processes.single { it.id == "workspace" }.volumes, RuntimeMount("workspace-logs", "/usr/src/app/upgrade-logs"))
        var n = 0
        val inputs = HulyRuntime.inputs({ mapOf("ca.pem" to "web-ca", "web.pem" to "web", "web-key.pem" to "web-key") }, { pki }, { pki }, { (++n).toString(16).repeat(64) })
        assertEquals(SingleUserRestore.inputNames(spec), inputs.keys)
        assertContains(inputs.getValue("account.env"), "DISABLE_SIGNUP=true")
        assertContains(inputs.getValue("account.env"), "sslmode=verify-full")
        assertContains(inputs.getValue("kvs.env"), "@127.0.0.1:26257/huly?sslmode=disable")
        assertContains(inputs.getValue("huly-kvs-proxy.cjs"), "rejectUnauthorized: true")
        assertContains(inputs.getValue("front.env"), "https://huly:8443/_unavailable/gmail")
        assertContains(inputs.getValue("caddyfile"), "route {")
        assertContains(inputs.getValue("caddyfile"), "@collaboration path /_collaborator /_collaborator/*")
        assertContains(inputs.getValue("caddyfile"), "strict_sni_host on")
        assertContains(inputs.getValue("elasticsearch.yml"), "node.store.allow_mmap: false")
        assertContains(inputs.getValue("elasticsearch.yml"), "xpack.security.enabled: true")
        assertFalse(inputs.getValue("stats.env").contains("STORAGE_CONFIG="))
        assertFalse(inputs.getValue("rekoni.env").contains("STORAGE_CONFIG="))
        assertFalse(inputs.getValue("elastic.env").contains("PASSWORD"))
        assertContains(inputs.getValue("redpanda.yaml"), "enable_metrics_reporter: false")
        inputs.filterKeys { it.endsWith(".env") }.forEach { (_, value) ->
            val keys = value.lineSequence().filter { it.isNotEmpty() }.map { it.substringBefore('=') }.toList()
            assertEquals(keys.distinct(), keys)
        }
        assertContains(inputs.getValue("huly-loopback.cjs"), "127.0.0.1")
        assertFails { HulyRuntime.inputs(secret = { "a".repeat(64) }) }
        assertFails { HulyRuntime.spec(inventory.copy(images = emptyList())) }
        assertFails { HulyRuntime.spec(inventory.copy(images = inventory.images.map { it.copy(architecture = "arm64") })) }
        assertFails { HulyRuntime.spec(inventory, "../escape") }
    }
    @Test fun `database certificate subjects are explicit without changing hostname validation`() {
        val subjects = mutableListOf<String>()
        PrivateSearchPki.generate("cockroach", "node", "root") { root, args ->
            if ("-subj" in args) subjects += args[args.indexOf("-subj") + 1]
            for (flag in listOf("-out", "-keyout")) if (flag in args) java.nio.file.Files.writeString(root.resolve(args[args.indexOf(flag) + 1]), "unit-only")
        }
        assertContains(subjects, "/CN=node"); assertContains(subjects, "/CN=root")
        assertFails { PrivateSearchPki.generate("cockroach", "node/unsafe", "root") { _, _ -> error("must not execute") } }
    }
}
