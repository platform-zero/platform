package net.datamancy.platform

import kotlin.test.*
import java.math.BigInteger
import java.security.*
import java.security.spec.*
import java.util.Base64

class MastodonRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    @Test fun `canonical social projection shares PostgreSQL and Valkey without legacy RSS writer`() : Unit {
        val available = kotlinx.serialization.json.Json.decodeFromString<AcquiredInventory>(
            GenerationAssembly.readInventory(java.nio.file.Path.of("release/downloaded-candidate-inventory.json")).decodeToString())
        val base = CanonicalCoreRuntime.releaseProvidersSpec(available).copy(store = RuntimeStore.CANONICAL_V2)
        val fresh = MastodonRuntime.canonicalFragment(available, base)
        assertEquals("mastodon", fresh.product)
        assertEquals(setOf("mastodon-web"), fresh.webNetworks)
        assertEquals(mapOf("postgres" to setOf("mastodon-data"), "valkey" to setOf("mastodon-cache")),
            fresh.providerNetworks)
        assertEquals(listOf("uploads", "mastodon-bootstrap"), fresh.spec.volumes.map { it.id })
        assertFalse(fresh.spec.processes.any { it.id in setOf("postgres", "valkey", "caddy", "mastodon-rss-accounts", "mastodon-migrate") })
        assertTrue(fresh.spec.processes.any { it.id == "mastodon-sql-adopt" && it.oneShot &&
            "--single-transaction" in it.command.last() && "original-mastodon.dump" in it.command.last() })
        assertTrue(fresh.spec.processes.any { it.id == "mastodon-original-check" && it.oneShot })
        assertTrue(fresh.spec.processes.any { it.id == "mastodon-rssq-provision" && it.oneShot })
        assertTrue(fresh.spec.processes.filter { !it.oneShot }.all { process ->
            process.files.none { it.file in setOf("rss-accounts.json", "rss-bootstrap.rb", "mastodon-users.json") }
        })
        val cold = MastodonRuntime.canonicalColdFragment(available, base, fresh)
        assertEquals(fresh.spec.volumes, cold.spec.volumes)
        assertEquals(setOf("mastodon-bootstrap"), cold.spec.unmountedRecoveryVolumes)
        assertTrue(cold.spec.processes.none { process -> process.volumes.any { it.volume == "mastodon-bootstrap" } })
        assertEquals(fresh.spec.databaseAccess.filter { it.consumer == "mastodon" }, cold.spec.databaseAccess)
        assertTrue(cold.spec.processes.none { it.oneShot })
        assertEquals(fresh.spec.processes.filterNot { it.oneShot }.map { it.id }, cold.spec.processes.map { it.id })
        assertFails { MastodonRuntime.canonicalColdFragment(available, base,
            fresh.copy(spec = fresh.spec.copy(volumes = emptyList()))) }
        val scripts = MastodonRecovery.syntheticRssqInputs(setOf("rssq-" + "1".repeat(12), "rssq-" + "2".repeat(12)),
            "q-" + "a".repeat(12), "b".repeat(64))
        assertEquals(setOf("mastodon-rssq-fixtures.json", "mastodon-rssq-provision.rb"), scripts.keys)
        val writer = scripts.getValue("mastodon-rssq-provision.rb")
        assertContains(writer, "'/bootstrap/rss-tokens.json'")
        assertContains(writer, "File::CREAT | File::EXCL")
        assertContains(writer, "'read:accounts write:statuses'")
        assertContains(writer, "'read:accounts read:statuses write:statuses'")
        assertFalse(writer.contains("Mastodon::CLI::Accounts.start"))
        assertFalse(writer.contains("rss_[a-z0-9_]"))
        val adopted = MastodonRecovery.canonicalOriginalCheckScript()
        assertContains(adopted, "Original SQL account/token ID/scope changed")
        assertFalse(adopted.contains("Account.create!"))
        assertFails { MastodonRecovery.syntheticRssqInputs(setOf("rssq-" + "1".repeat(12)),
            "q-" + "a".repeat(12), "b".repeat(64)) }
    }
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "valkey", "ntfy", "mastodon", "mastodon-streaming", "element").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `closed private social recipe has durable setup and confidential bootstrap storage`() : Unit {
        val spec = MastodonRuntime.spec(inventory)
        assertEquals(11, PrivateDeployment.validate(spec).size)
        assertEquals(6, spec.processes.count { !it.oneShot })
        val inputs = MastodonRuntime.inputs { mapOf("ca.pem" to "ca", "web.pem" to "cert", "web-key.pem" to "key") }
        assertEquals(SingleUserRestore.inputNames(spec), inputs.keys)
        assertContains(inputs.getValue("mastodon.env"), "LIMITED_FEDERATION_MODE=true")
        assertContains(inputs.getValue("mastodon.env"), "SMTP_SERVER=127.0.0.1")
        assertContains(inputs.getValue("nginx.conf"), "X-Forwarded-Proto https")
        val accounts = spec.processes.single { it.id == "mastodon-accounts" }
        assertContains(accounts.command.last(), "registrations close")
        assertContains(accounts.command.last(), "> /bootstrap/owner.txt")
        assertTrue(spec.processes.filter { !it.oneShot }.none { p -> p.volumes.any { it.volume == "bootstrap" } })
        assertFalse(inputs.getValue("streaming.env").contains("SECRET_KEY_BASE"))
        val feeds = kotlinx.serialization.json.Json.parseToJsonElement(inputs.getValue("rss-accounts.json")) as kotlinx.serialization.json.JsonArray
        assertEquals(47, feeds.size)
        assertContains(inputs.getValue("rss-bootstrap.rb"), "'publicationEnabled' => false")
        assertContains(inputs.getValue("rss-bootstrap.rb"), "scopes: 'read:accounts write:statuses'")
        assertContains(inputs.getValue("rss-bootstrap.rb"), "bot: true, locked: true, discoverable: false, indexable: false")
        assertFails { MastodonRuntime.spec(inventory.copy(images = inventory.images.filter { it.product != "mastodon" })) }
        assertFails { MastodonRuntime.spec(inventory.copy(images = inventory.images.map { it.copy(architecture = "arm64") })) }
    }
    @Test fun `social recovery preserves keys and replaces every application initializer with read only guards`() : Unit {
        val source = MastodonRuntime.spec(inventory, "source")
        val restored = MastodonRecovery.spec(source, inventory, "restored", "a".repeat(64))
        assertEquals(source.volumes, restored.volumes)
        for (id in listOf("mastodon-migrate", "mastodon-accounts", "mastodon-rss-accounts", "valkey")) {
            val command = restored.processes.single { it.id == id }.command.joinToString(" ")
            assertContains(command, ".restore-in-progress"); assertContains(command, "a".repeat(64))
            assertFalse("db:migrate" in command || "db:seed" in command || "Accounts.start" in command || "create!" in command)
        }
        assertContains(restored.processes.single { it.id == "mastodon-rss-accounts" }.command.last(), "token.resource_owner_id == account.user.id")
        assertFails { MastodonRecovery.spec(source, inventory, source.name, "a".repeat(64)) }
        assertFails { MastodonRecovery.spec(source, inventory, "restored", "bad") }
        assertFails { MastodonRecovery.spec(source.copy(processes = source.processes.dropLast(1)), inventory, "restored", "a".repeat(64)) }
        val base = java.nio.file.Files.createTempDirectory("social-recovery-unit-")
        try {
            val inputs = MastodonRuntime.inputs { mapOf("ca.pem" to "ca", "web.pem" to "cert", "web-key.pem" to "key") }
            val manifest = RuntimePreparation.prepare(source, base) { inputs }
            val recovered = java.nio.file.Files.createDirectory(base.resolve("recovered"), java.nio.file.attribute.PosixFilePermissions.asFileAttribute(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
            java.nio.file.Files.copy(manifest, recovered.resolve("source-spec.json"))
            inputs.keys.forEach { java.nio.file.Files.copy(base.resolve("source").resolve(it), recovered.resolve(it)) }
            val path = MastodonRecovery.prepare(inventory, recovered, "restored", base)
            assertEquals(path, MastodonRecovery.prepare(inventory, recovered, "restored", base))
            inputs.forEach { (file, content) -> assertEquals(content, java.nio.file.Files.readString(base.resolve("restored").resolve(file))) }
            java.nio.file.Files.writeString(recovered.resolve("mastodon.env"), "CHANGED=true\n")
            assertFails { MastodonRecovery.prepare(inventory, recovered, "restored", base) }
            assertFails { MastodonRecovery.prepare(inventory, java.nio.file.Path.of("relative"), "restored", base) }
        } finally { java.nio.file.Files.walk(base).use { it.sorted(Comparator.reverseOrder()).forEach(java.nio.file.Files::delete) } }
    }
    @Test fun `VAPID key material is an actual matching P256 key pair`() : Unit {
        val (privateValue, publicValue) = MastodonRuntime.vapid()
        val decoder = Base64.getUrlDecoder(); val secret = decoder.decode(privateValue); val public = decoder.decode(publicValue)
        assertEquals(32, secret.size); assertEquals(65, public.size); assertEquals(4, public[0].toInt())
        val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
        val factory = KeyFactory.getInstance("EC")
        val privateKey = factory.generatePrivate(ECPrivateKeySpec(BigInteger(1, secret), parameters))
        val publicKey = factory.generatePublic(ECPublicKeySpec(ECPoint(BigInteger(1, public.copyOfRange(1, 33)), BigInteger(1, public.copyOfRange(33, 65))), parameters))
        val signature = Signature.getInstance("SHA256withECDSA"); signature.initSign(privateKey); signature.update("fixture".toByteArray()); val signed = signature.sign()
        signature.initVerify(publicKey); signature.update("fixture".toByteArray()); assertTrue(signature.verify(signed))
        assertNotEquals(privateValue, MastodonRuntime.vapid().first)
    }
}
