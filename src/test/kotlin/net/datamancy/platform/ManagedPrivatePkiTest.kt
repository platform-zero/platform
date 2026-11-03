package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.time.Instant
import kotlin.test.*

class ManagedPrivatePkiTest {
    private val first = "pki-0000000000000001"
    private val second = "pki-0000000000000002"
    private val third = "pki-0000000000000003"
    private class Fake {
        val calls = mutableListOf<List<String>>()
        val directories = mutableSetOf<Path>()
        var failure = false
        fun run(root: Path, args: List<String>) {
            directories.add(root)
            calls += args
            if (failure) error("synthetic signing failure")
            for (flag in listOf("-keyout", "-out")) {
                val index = args.indexOf(flag)
                if (index >= 0) Files.writeString(root.resolve(args[index + 1]), "synthetic:${args[index + 1]}:${calls.size}")
            }
        }
    }
    private fun test(action: (Path, Fake) -> Unit) {
        val root = Files.createTempDirectory("managed-pki-unit-")
        try { action(root, Fake()) }
        finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `managed web renewal keeps trust and replaces only immutable leaf bundle`() = test { root, fake ->
        var clock = Instant.parse("2026-01-01T00:00:00Z")
        val control = ManagedPrivatePki(root, fake::run) { clock }
        val caHash = control.initialize(first)
        val key = Files.readAllBytes(root.resolve("ca-key.pem"))
        val materials = PrivateWebPki.managed(control, first, "hub", listOf("hub", "alice.hub"))
        assertEquals(setOf("ca.pem", "web.pem", "web-key.pem"), materials.keys)
        val original = control.read(first)
        assertEquals(caHash, original.caSha256)
        assertEquals(materials, original.material)
        val bytes = Files.readAllBytes(root.resolve("$first.json"))
        val digest = ReleaseLocks.sha256(bytes)
        assertFails { control.renew(second, first, digest) }
        assertFalse(Files.exists(root.resolve("$first.renewal")))
        clock = clock.plusSeconds(60L * 86400)
        assertFails { control.renew(second, first, "0".repeat(64)) }
        val renewed = control.renew(second, first, digest)
        assertEquals(materials["ca.pem"], renewed.material["ca.pem"])
        assertNotEquals(materials["web.pem"], renewed.material["web.pem"])
        assertEquals(digest, renewed.previousSha256)
        assertEquals(original.profile, renewed.profile)
        assertContentEquals(key, Files.readAllBytes(root.resolve("ca-key.pem")))
        assertContentEquals(bytes, Files.readAllBytes(root.resolve("$first.json")))
        assertFails { control.renew(third, first, digest) }
        assertTrue(fake.calls.any { "-checkend" in it })
        assertTrue(fake.calls.any { it.first() == "verify" && "sslserver" in it })
        assertTrue(fake.calls.filter { "-set_serial" in it }.map { it[it.indexOf("-set_serial") + 1] }.distinct().size == 2)
        assertTrue(fake.directories.none { Files.exists(it) })
        assertFails { control.initialize(third) }
        assertFails { control.issue(first, original.profile) }
    }
    @Test fun `search issuance retains node and client profiles without exporting signing key`() = test { root, fake ->
        val control = ManagedPrivatePki(root, fake::run)
        control.initialize(first)
        val material = PrivateSearchPki.managed(control, first, "cockroach", "node", "root")
        assertEquals(setOf("ca.pem", "node.pem", "node-key.pem", "admin.pem", "admin-key.pem"), material.keys)
        assertTrue(fake.calls.any { "sslclient" in it })
        assertEquals(PrivatePkiKind.SEARCH, control.read(first).profile.kind)
        assertFalse(Files.exists(root.resolve("issue.pending")))
    }
    @Test fun `invalid profiles operations and absent custody fail before signing`() = test { root, fake ->
        val control = ManagedPrivatePki(root, fake::run)
        assertFails { ManagedPrivatePki.real("site", "authority", root) }
        assertFails { control.initialize("../escape") }
        assertFails { control.issue(first, PrivatePkiProfile(PrivatePkiKind.WEB, "hub")) }
        control.initialize(first)
        val calls = fake.calls.size
        for (profile in listOf(
            PrivatePkiProfile(PrivatePkiKind.WEB, "bad/host"),
            PrivatePkiProfile(PrivatePkiKind.WEB, "hub", listOf("hub", "hub")),
            PrivatePkiProfile(PrivatePkiKind.WEB, "hub", listOf("other")),
            PrivatePkiProfile(PrivatePkiKind.WEB, "hub", listOf("hub", "*.hub")),
            PrivatePkiProfile(PrivatePkiKind.SEARCH, "node", listOf("node", "other"))
        )) assertFails { control.issue(second, profile) }
        assertEquals(calls, fake.calls.size)
        assertFalse(Files.exists(root.resolve("issue.pending")))
        assertFails { control.read("../escape") }
    }
    @Test fun `failed issuance is fenced and cleans temporary copies without touching authority`() = test { root, fake ->
        val control = ManagedPrivatePki(root, fake::run)
        control.initialize(first)
        val ca = Files.readAllBytes(root.resolve("ca.pem"))
        fake.failure = true
        assertFails { control.issue(first, PrivatePkiProfile(PrivatePkiKind.WEB, "hub")) }
        assertTrue(Files.exists(root.resolve("issue.pending")))
        fake.failure = false
        val calls = fake.calls.size
        assertFails { control.issue(second, PrivatePkiProfile(PrivatePkiKind.WEB, "hub")) }
        assertEquals(calls, fake.calls.size)
        assertContentEquals(ca, Files.readAllBytes(root.resolve("ca.pem")))
        assertTrue(fake.directories.none { Files.exists(it) })
    }
    @Test fun `partial initialization cannot be retried or used to issue certificates`() = test { root, fake ->
        val control = ManagedPrivatePki(root, fake::run)
        fake.failure = true
        assertFails { control.initialize(first) }
        fake.failure = false
        assertFails { control.initialize(second) }
        assertFails { control.issue(first, PrivatePkiProfile(PrivatePkiKind.WEB, "hub")) }
        assertTrue(Files.exists(root.resolve("initialize.pending")))
        assertTrue(fake.directories.none { Files.exists(it) })
    }
}
