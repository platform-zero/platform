package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.*
import kotlin.test.*

class KnowledgeIdentityRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "valkey", "ntfy", "mariadb", "memcached", "bookstack").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `composite keeps database secrets distinct and binds native confidential OIDC with PKCE`() {
        val spec = KnowledgeIdentityRuntime.spec(inventory)
        assertEquals(5, spec.processes.count { !it.oneShot })
        assertEquals(10, PrivateDeployment.validate(spec).size)
        val inputs = KnowledgeIdentityRuntime.inputs { mapOf("ca.pem" to "ca", "web.pem" to "cert", "web-key.pem" to "key") }
        assertEquals(SingleUserRestore.inputNames(spec), inputs.keys)
        assertContains(inputs.getValue("identity-database.env"), "KEYCLOAK_PASSWORD")
        assertFalse(inputs.getValue("database-init.env").contains("KEYCLOAK_PASSWORD"))
        assertContains(inputs.getValue("bookstack.env"), "AUTH_METHOD=oidc")
        assertContains(inputs.getValue("bookstack.env"), "SESSION_SECURE_COOKIE=true")
        assertContains(inputs.getValue("fpm.conf"), "curl.cainfo")
        assertContains(inputs.getValue("nginx.conf"), "listen 8443 ssl")
        assertContains(inputs.getValue("nginx.conf"), "location / { return 404; }")
        assertContains(inputs.getValue("closed-registration.php"), "return false")
        assertContains(inputs.getValue("admin.php"), "'--external-auth-id'")
        val realm = Json.parseToJsonElement(inputs.getValue("realm.json")).jsonObject
        val owner = realm.getValue("users").jsonArray.first().jsonObject
        assertEquals(setOf("UPDATE_PASSWORD", "CONFIGURE_TOTP"), owner.getValue("requiredActions").jsonArray.map { it.jsonPrimitive.content }.toSet())
        assertContains(inputs.getValue("admin.env"), "P0V3_OWNER_SUB=" + owner.getValue("id").jsonPrimitive.content)
        val client = realm.getValue("clients").jsonArray.single().jsonObject
        assertFalse(client.getValue("publicClient").jsonPrimitive.boolean)
        assertFalse(client.getValue("directAccessGrantsEnabled").jsonPrimitive.boolean)
        assertEquals("S256", client.getValue("attributes").jsonObject.getValue("pkce.code.challenge.method").jsonPrimitive.content)
        assertEquals(listOf("https://knowledge:8443/oidc/callback"), client.getValue("redirectUris").jsonArray.map { it.jsonPrimitive.content })
    }
    @Test fun `private TLS PKI is hostname-bound with discarded issuer key and failure cleanup`() {
        var temporary: Path? = null
        val calls = mutableListOf<List<String>>()
        val result = PrivateWebPki.generate("knowledge") { root, args ->
            temporary = root; calls += args
            for (option in listOf("-keyout", "-out")) if (option in args) Files.writeString(root.resolve(args[args.indexOf(option) + 1]), "fixture")
            if ("-extfile" in args) assertContains(Files.readString(root.resolve("web.ext")), "subjectAltName=DNS:knowledge")
        }
        assertEquals(setOf("ca.pem", "web.pem", "web-key.pem"), result.keys)
        assertEquals(3, calls.size)
        assertFalse(Files.exists(temporary))
        assertFails { PrivateWebPki.generate("bad/host") { _, _ -> error("must not run") } }
        assertFails { PrivateWebPki.generate("knowledge") { root, _ -> temporary = root; error("fixture failure") } }
        assertFalse(Files.exists(temporary))
    }
}
