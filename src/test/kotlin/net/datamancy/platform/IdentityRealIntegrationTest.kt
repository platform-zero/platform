package net.datamancy.platform

import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.RSAPublicKeySpec
import java.time.Instant
import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Opt-in only: fake direct password grant tests API tokens, NOT browser SSO or app authorization. */
class IdentityRealIntegrationTest {
    private val url = Base64.getUrlDecoder()
    private fun get(uri: String) = request(uri)
    private fun request(uri: String, body: String? = null, bearer: String? = null): String {
        require(uri.startsWith("http://127.0.0.1:18580/") || uri.startsWith("http://127.0.0.1:18581/"))
        val connection = URI.create(uri).toURL().openConnection() as HttpURLConnection
        connection.connectTimeout = 3000
        connection.readTimeout = 15000
        if (bearer != null) connection.setRequestProperty("Authorization", "Bearer $bearer")
        if (body != null) {
            connection.requestMethod = "POST"
            connection.doOutput = true
            connection.setRequestProperty("Content-Type", if (body.startsWith("{")) "application/json" else "application/x-www-form-urlencoded")
            connection.outputStream.use { it.write(body.toByteArray()) }
        }
        val code = connection.responseCode
        require(code in 200..204) { "Fake loopback OIDC API returned HTTP $code" } // never print response/tokens
        return if (code == 204) "" else connection.inputStream.use { it.readNBytes(65536).toString(Charsets.UTF_8) }
    }
    private fun form(vararg fields: Pair<String, String>) = fields.joinToString("&") {
        URLEncoder.encode(it.first, Charsets.UTF_8) + "=" + URLEncoder.encode(it.second, Charsets.UTF_8)
    }
    private fun token(endpoint: String, client: String, username: String, password: String): JsonObject =
        Json.parseToJsonElement(request(endpoint, form("grant_type" to "password", "scope" to "openid",
            "client_id" to client, "username" to username, "password" to password))).jsonObject

    private fun verifiedJwt(jwt: String, keys: JsonObject, issuer: String, subject: String) {
        val parts = jwt.split('.')
        assertEquals(3, parts.size)
        val header = Json.parseToJsonElement(url.decode(parts[0]).toString(Charsets.UTF_8)).jsonObject
        assertEquals("RS256", header["alg"]!!.jsonPrimitive.content)
        val key = keys["keys"]!!.jsonArray.map { it.jsonObject }.single { it["kid"]!!.jsonPrimitive.content == header["kid"]!!.jsonPrimitive.content }
        val public = KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(
            BigInteger(1, url.decode(key["n"]!!.jsonPrimitive.content)),
            BigInteger(1, url.decode(key["e"]!!.jsonPrimitive.content))))
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initVerify(public); signature.update("${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII))
        assertTrue(signature.verify(url.decode(parts[2])))
        val claims = Json.parseToJsonElement(url.decode(parts[1]).toString(Charsets.UTF_8)).jsonObject
        assertEquals(subject, claims["sub"]!!.jsonPrimitive.content)
        assertEquals(issuer, claims["iss"]!!.jsonPrimitive.content)
        assertTrue(claims["exp"]!!.jsonPrimitive.long > Instant.now().epochSecond)
    }
    private fun authenticate(port: Int, username: String, password: String, subject: String) {
        val base = "http://127.0.0.1:$port/realms/${IdentitySandbox.REALM}"
        val discovery = Json.parseToJsonElement(get("$base/.well-known/openid-configuration")).jsonObject
        assertEquals(base, discovery["issuer"]!!.jsonPrimitive.content)
        assertEquals("$base/protocol/openid-connect/token", discovery["token_endpoint"]!!.jsonPrimitive.content)
        val keys = Json.parseToJsonElement(get(discovery["jwks_uri"]!!.jsonPrimitive.content)).jsonObject
        val tokens = token(discovery["token_endpoint"]!!.jsonPrimitive.content, IdentitySandbox.CLIENT, username, password)
        verifiedJwt(tokens["access_token"]!!.jsonPrimitive.content, keys, base, subject)
        verifiedJwt(tokens["id_token"]!!.jsonPrimitive.content, keys, base, subject)
    }
    private fun await(port: Int) {
        val endpoint = "http://127.0.0.1:$port/realms/${IdentitySandbox.REALM}/.well-known/openid-configuration"
        repeat(70) {
            if (runCatching { get(endpoint); true }.getOrDefault(false)) return
            Thread.sleep(2000)
        }
        error("Fake Keycloak did not become ready on private loopback port $port")
    }
    private fun privateNetworks(expected: Set<String>) {
        val root = Path.of("/mnt/media/p0-v3/platform-lifecycle-sandbox/identity-fixture")
        val config = root.resolve("network-config")
        val privatePodman = RootlessPodman(root, config)
        assertTrue("--network-config-dir=$config" in privatePodman.argumentsPrefix())
        val actual = privatePodman.invoke(listOf("network", "ls", "--format", "{{.Name}}")).lines()
            .filter { it.startsWith("p0v3-identity-net") }.toSet()
        assertEquals(expected, actual)
        val definitions = Files.list(config).use { stream -> stream.map { it.fileName.toString() }
            .filter { it.startsWith("p0v3-identity-net") }.toList().toSet() }
        assertEquals(expected.map { "$it.json" }.toSet(), definitions)
        val homeNetworks = Path.of(System.getProperty("user.home"), ".config/containers/networks")
        if (Files.isDirectory(homeNetworks)) Files.list(homeNetworks).use { stream ->
            assertTrue(stream.noneMatch { it.fileName.toString().startsWith("p0v3-identity-net") })
        }
    }
    private fun addDatabaseOnlyUser(username: String, password: String): String {
        val env = Files.readAllLines(Path.of("/mnt/media/p0-v3/platform-lifecycle-sandbox/identity-fixture/secrets/keycloak.env"))
        val admin = env.single { it.startsWith("KC_BOOTSTRAP_ADMIN_PASSWORD=") }.substringAfter('=')
        val base = "http://127.0.0.1:18580"
        val adminToken = token("$base/realms/master/protocol/openid-connect/token", "admin-cli", "sandbox-admin", admin)["access_token"]!!.jsonPrimitive.content
        val user = buildJsonObject {
            put("username", username); put("enabled", true)
            put("firstName", "Database"); put("lastName", "Marker")
            put("email", "$username@example.invalid"); put("emailVerified", true)
            put("credentials", buildJsonArray { add(buildJsonObject {
                put("type", "password"); put("value", password); put("temporary", false)
            }) })
        }
        request("$base/admin/realms/${IdentitySandbox.REALM}/users", user.toString(), adminToken)
        val matches = Json.parseToJsonElement(request("$base/admin/realms/${IdentitySandbox.REALM}/users?username=$username&exact=true",
            bearer = adminToken)).jsonArray
        assertEquals(1, matches.size)
        return matches.single().jsonObject["id"]!!.jsonPrimitive.content
    }

    @Test fun `private network database only mutation survives hash verified isolated restore and fake OIDC tokens`() {
        assumeTrue(System.getenv("P0V3_IDENTITY_INTEGRATION") == "1", "Explicit opt-in only")
        val sandbox = IdentitySandbox.real()
        val id = "oidc-" + java.lang.Long.toString(System.currentTimeMillis(), 36)
        var prepared = false
        try {
            sandbox.prepare(); prepared = true
            sandbox.install()
            privateNetworks(setOf("p0v3-identity-net"))
            await(18580)
            authenticate(18580, "sandbox-human", sandbox.fakePassword("sandbox-human"), IdentitySandbox.HUMAN_SUB)
            authenticate(18580, "sandbox-agent", sandbox.fakePassword("sandbox-agent"), IdentitySandbox.AGENT_SUB)
            val markerPassword = java.util.UUID.randomUUID().toString() // fake, in memory only, never logged or committed
            val marker = "sandbox-database-marker-$id"
            val markerSubject = addDatabaseOnlyUser(marker, markerPassword)
            authenticate(18580, marker, markerPassword, markerSubject)
            sandbox.backup(id)
            await(18580)
            sandbox.restore(id)
            privateNetworks(setOf("p0v3-identity-net", "p0v3-identity-net-$id"))
            await(18581)
            authenticate(18581, "sandbox-human", sandbox.fakePassword("sandbox-human"), IdentitySandbox.HUMAN_SUB)
            authenticate(18581, "sandbox-agent", sandbox.fakePassword("sandbox-agent"), IdentitySandbox.AGENT_SUB)
            authenticate(18581, marker, markerPassword, markerSubject)
            authenticate(18580, marker, markerPassword, markerSubject)
        } finally {
            if (prepared) try { sandbox.removeRestore(id) } finally { sandbox.remove() }
        }
        privateNetworks(emptySet()) // scoped definitions and rootless namespaces removed, lock file remains private
    }
}
