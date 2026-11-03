package net.datamancy.platform

import kotlin.test.*
import java.math.BigInteger
import java.security.*
import java.security.spec.*
import java.util.Base64

class MastodonRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "valkey", "ntfy", "mastodon", "mastodon-streaming", "element").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `closed private social recipe has durable setup and confidential bootstrap storage`() {
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
    @Test fun `social recovery preserves keys and replaces every application initializer with read only guards`() {
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
    @Test fun `VAPID key material is an actual matching P256 key pair`() {
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
