package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SitesTest {
    private val digest = "a".repeat(64)
    private fun workload(id: String = "probe", image: String = "docker.io/library/busybox@sha256:$digest") = Workload(id, image)
    private fun sites(vararg workloads: Workload) = Sites(1, listOf(Site("testsite", workloads.toList())))

    @Test fun `selection is explicit and rejects inventory IDs`() {
        val config = sites(workload())
        config.validate()
        assertEquals("testsite", config.select("testsite").id)
        assertFailsWith<IllegalArgumentException> { config.select("another") }
        assertFailsWith<IllegalArgumentException> { sites(workload("keycloak")).validate() }
        assertFailsWith<IllegalArgumentException> { sites(workload(), workload()).validate() }
        assertFailsWith<IllegalArgumentException> { Sites(1, listOf(config.sites[0], config.sites[0])).validate() }
    }

    @Test fun `strict site file rejects unknown fields and unpinned or unsafe images`() {
        val file = Files.createTempFile("v3-sites", ".json")
        try {
            Files.writeString(file, """{"schemaVersion":1,"sites":[{"id":"testsite","workloads":[{"id":"probe","image":"docker.io/library/busybox@sha256:$digest","environment":{"TOKEN":"secret"}}]}]}""")
            assertFailsWith<Exception> { Sites.from(file) }
            listOf("docker.io/library/busybox:latest", "docker.io/x@sha256:${"A".repeat(64)}", "docker.io/x@sha256:$digest\nExec=bad").forEach {
                assertFailsWith<IllegalArgumentException> { sites(workload(image = it)).validate() }
            }
            assertFailsWith<IllegalArgumentException> { sites(workload("../escape")).validate() }
        } finally { Files.delete(file) }
    }

    @Test fun `render is sorted deterministic isolated and contains no routes or secrets`() {
        val config = sites(workload("zeta"), workload("alpha"))
        config.validate()
        val plan = RenderPlan.forSite(config.select("testsite"))
        assertEquals(listOf("p0v3-testsite-alpha.container", "p0v3-testsite-zeta.container"), plan.files.map { it.name })
        assertEquals(plan, RenderPlan.forSite(config.select("testsite")))
        assertTrue(plan.files.all { "Network=none" in it.content && "ReadOnly=true" in it.content })
        assertFalse(plan.files.any { "PublishPort" in it.content || "Volume=" in it.content || "Environment=" in it.content })
        assertFalse(plan.files.any { "keycloak" in it.content || "datamancy.net" in it.content })
    }

    @Test fun `offline stage rolls back previous version and refuses unrelated files or locations`() {
        val root = Files.createTempDirectory("p0v3-offline-")
        try {
            val first = sites(workload())
            val second = sites(workload(image = "docker.io/library/alpine@sha256:${"b".repeat(64)}"))
            IsolatedStage.stage(first, "testsite", root)
            val current = root.resolve("current/p0v3-testsite-probe.container")
            val original = Files.readString(current)
            IsolatedStage.stage(second, "testsite", root)
            assertTrue("b".repeat(64) in Files.readString(current))
            assertFailsWith<IllegalArgumentException> { IsolatedStage.stage(first, "testsite", root) }
            IsolatedStage.restore(root, "testsite")
            assertEquals(original, Files.readString(current))
            IsolatedStage.restore(root, "testsite")
            assertFalse(Files.exists(root.resolve("current")))
            assertFailsWith<Exception> { IsolatedStage.restore(root, "wrongsite") }
            Files.writeString(root.resolve("unrelated"), "untouched")
            assertFailsWith<IllegalArgumentException> { IsolatedStage.stage(first, "testsite", root) }
            assertEquals("untouched", Files.readString(root.resolve("unrelated")))
            assertFailsWith<IllegalArgumentException> { IsolatedStage.stage(first, "testsite", Path.of("/etc")) }
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    @Test fun `tampering with staged content blocks rollback`() {
        val root = Files.createTempDirectory("p0v3-offline-")
        try {
            IsolatedStage.stage(sites(workload()), "testsite", root)
            val file = root.resolve("current/p0v3-testsite-probe.container")
            Files.writeString(file, "modified")
            assertFailsWith<IllegalArgumentException> { IsolatedStage.restore(root, "testsite") }
            assertEquals("modified", Files.readString(file))
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    @Test fun `symlink in staged tree is rejected without following it`() {
        val root = Files.createTempDirectory("p0v3-offline-")
        val target = Files.createTempFile("p0v3-untouched-", ".txt")
        try {
            Files.writeString(target, "untouched")
            IsolatedStage.stage(sites(workload()), "testsite", root)
            Files.createSymbolicLink(root.resolve("current/p0v3-testsite-link.container"), target)
            assertFailsWith<IllegalArgumentException> { IsolatedStage.restore(root, "testsite") }
            assertEquals("untouched", Files.readString(target))
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
            Files.delete(target)
        }
    }
}
