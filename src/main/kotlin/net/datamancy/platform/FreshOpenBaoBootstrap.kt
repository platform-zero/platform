package net.datamancy.platform

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import kotlinx.serialization.json.*

/** Original fresh Raft only. The caller owns the generation lock, selected CID/network, PKIX +
 * served-leaf pinning, custody directory and operator offline handoff. Never used on RESTORE.
 * A CREATE_NEW record precedes every uncertain native write; no automatic resume/retry exists.
 */
internal object FreshOpenBaoBootstrap {
    private const val ORIGIN = "https://bao:8200"
    private const val POLICY_NAME = "p0v3-keykeeper"
    private const val POLICY = """path "keykeeper/data/*" { capabilities = ["create", "read", "update"] }
path "keykeeper/metadata/" { capabilities = ["list"] }
"""
    internal fun policySource(): String = POLICY

    /** Never contains a secret. Both paths are in caller-owned 0700 original custody;
     * the issuer does not represent offline root/unseal custody or release approval. */
    internal class Issued(val keykeeperTokenFile: Path, val keykeeperTokenSha256: String,
        val originalInitFile: Path, val originalInitSha256: String)

    private fun sha(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes).joinToString("") { "%02x".format(it) }
    private fun text(obj: JsonObject, field: String): String = obj[field]?.jsonPrimitive?.content
        ?.takeIf { it.matches(Regex("[A-Za-z0-9._~+/-]{16,8192}")) }
        ?: error("OpenBao native response missing bounded $field")
    private fun obj(bytes: ByteArray): JsonObject = try {
        Json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
    } catch (_: Exception) {
        error("Invalid bounded OpenBao response") // JSON parser exceptions may quote secret body
    }

    fun issueOriginal(client: HttpClient, endpoint: URI, generation: String, custodyRoot: Path): Issued {
        require(endpoint.toASCIIString() == ORIGIN && generation.matches(Regex("q-[a-f0-9]{12}")) &&
            custodyRoot.fileName.toString() == generation &&
            client.followRedirects() == HttpClient.Redirect.NEVER && client.proxy().isEmpty) {
            "Original private OpenBao issuer requires selected endpoint and no redirect/proxy"
        }
        ReleasePrivateFiles.directory(custodyRoot)
        val intent = custodyRoot.resolve("$generation-bao-init.intent")
        val original = custodyRoot.resolve("$generation-bao-init-original.json")
        val derived = custodyRoot.resolve("$generation-keykeeper-token")
        // A leftover record, including an incomplete intent, is a hard stop: never run a
        // second native init or mint a replacement token on an uncertain acknowledgment.
        require(listOf(intent, original, derived).none { java.nio.file.Files.exists(it, java.nio.file.LinkOption.NOFOLLOW_LINKS) })
        fun call(method: String, path: String, payload: String? = null, root: String? = null): Pair<Int, ByteArray> {
            require(path.matches(Regex("/v1/[a-z0-9/-]{1,80}")))
            val request = HttpRequest.newBuilder(URI.create(ORIGIN + path))
                .timeout(Duration.ofSeconds(20)).header("Accept", "application/json")
            if (root != null) request.header("X-Vault-Token", root)
            if (payload != null) request.header("Content-Type", "application/json")
            val response = try {
                client.send(request.method(method, if (payload == null) HttpRequest.BodyPublishers.noBody()
                    else HttpRequest.BodyPublishers.ofString(payload)).build(), HttpResponse.BodyHandlers.ofByteArray())
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                error("Original OpenBao request interrupted; native outcome unknown")
            } catch (_: Exception) {
                error("Original OpenBao request unavailable; native outcome unknown")
            }
            require(response.body().size <= 16384) { "Oversized OpenBao response" }
            return response.statusCode() to response.body()
        }
        val (initialCode, initialBytes) = call("GET", "/v1/sys/init")
        require(initialCode == 200 && obj(initialBytes)["initialized"]?.jsonPrimitive?.booleanOrNull == false) {
            "Original OpenBao Raft is already initialized or unavailable"
        }
        val (sealCode, sealBytes) = call("GET", "/v1/sys/seal-status")
        require(sealCode == 200 && obj(sealBytes)["sealed"]?.jsonPrimitive?.booleanOrNull == true) {
            "Original OpenBao Raft must be sealed before fresh init"
        }
        // Marker is durable before ANY native init request. The original init response
        // (root token and all unseal shares) is persisted before any subsequent action.
        ReleasePrivateFiles.save(intent, "$generation\ninit:3-of-2\n".toByteArray())
        val (initCode, initBytes) = call("PUT", "/v1/sys/init", """{"secret_shares":3,"secret_threshold":2}""")
        require(initCode == 200)
        ReleasePrivateFiles.save(original, initBytes) // preserve exact native result before parsing it
        val init = obj(initBytes)
        val root = text(init, "root_token")
        val shares = init["keys_base64"]?.jsonArray?.map { it.jsonPrimitive.content }
            ?.also { values -> require(values.size == 3 && values.toSet().size == 3 &&
                values.all { it.matches(Regex("[A-Za-z0-9+/=]{16,1024}")) }) }
            ?: error("Original OpenBao init lacks three distinct shares")
        // Operator must move the original result to independent offline custody before release.
        shares.take(2).forEachIndexed { index, share ->
            ReleasePrivateFiles.save(custodyRoot.resolve("$generation-bao-unseal-${index + 1}.intent"),
                "$generation\nunseal:${index + 1}\n".toByteArray())
            val (code, body) = call("PUT", "/v1/sys/unseal", buildJsonObject { put("key", share) }.toString())
            require(code == 200 && obj(body)["sealed"]?.jsonPrimitive?.booleanOrNull == (index == 0)) {
                "Original OpenBao unseal did not advance as expected"
            }
        }
        val (lookupCode, lookupBytes) = call("GET", "/v1/auth/token/lookup-self", root = root)
        require(lookupCode == 200 && obj(lookupBytes)["data"]?.jsonObject?.get("id")?.jsonPrimitive?.content == root) {
            "Original OpenBao root authority was not verified"
        }
        fun effect(name: String, path: String, body: String) {
            ReleasePrivateFiles.save(custodyRoot.resolve("$generation-bao-$name.intent"),
                "$generation\n$name\n${sha(body.toByteArray())}\n".toByteArray())
            val (code, _) = call("POST", path, body, root)
            require(code == 204 || code == 200) { "Original OpenBao $name did not acknowledge" }
        }
        effect("mount", "/v1/sys/mounts/keykeeper", """{"type":"kv","options":{"version":"2"}}""")
        effect("policy", "/v1/sys/policies/acl/$POLICY_NAME",
            buildJsonObject { put("policy", POLICY) }.toString())
        val (mountCode, mountBytes) = call("GET", "/v1/sys/mounts/keykeeper", root = root)
        val mount = if (mountCode == 200) obj(mountBytes).getValue("data").jsonObject else null
        require(mount?.get("type")?.jsonPrimitive?.content == "kv" &&
            mount?.get("options")?.jsonObject?.get("version")?.jsonPrimitive?.content == "2") {
            "Original OpenBao Keykeeper mount did not read back as KV-v2"
        }
        val (policyCode, policyBytes) = call("GET", "/v1/sys/policies/acl/$POLICY_NAME", root = root)
        require(policyCode == 200 && obj(policyBytes)["data"]?.jsonObject?.get("policy")
            ?.jsonPrimitive?.content == POLICY) { "Original OpenBao Keykeeper policy did not read back" }
        // Root token never flows into serving env. A period renewable, non-default orphan
        // token has only the Keykeeper KV-v2 read/write/list capabilities above.
        val request = buildJsonObject {
            put("policies", buildJsonArray { add(POLICY_NAME) })
            put("no_default_policy", true); put("orphan", true); put("renewable", true)
            put("period", "24h"); put("num_uses", 0)
            put("display_name", "p0v3-keykeeper-$generation")
        }.toString()
        ReleasePrivateFiles.save(custodyRoot.resolve("$generation-bao-keykeeper-issue.intent"),
            "$generation\nissue\n${sha(request.toByteArray())}\n".toByteArray())
        val (tokenCode, tokenBytes) = call("POST", "/v1/auth/token/create-orphan", request, root)
        require(tokenCode == 200)
        val token = text(obj(tokenBytes).getValue("auth").jsonObject, "client_token")
        require(token != root)
        // Persist first; if the response or this save is lost, never mint another token.
        val tokenFile = (token + "\n").toByteArray()
        ReleasePrivateFiles.save(derived, tokenFile)
        val (verifyCode, verifyBytes) = call("GET", "/v1/auth/token/lookup-self", root = token)
        val data = if (verifyCode == 200) obj(verifyBytes)["data"]?.jsonObject else null
        require(data?.get("policies")?.jsonArray?.map { it.jsonPrimitive.content } == listOf(POLICY_NAME) &&
            data?.get("orphan")?.jsonPrimitive?.booleanOrNull == true) {
            "Derived OpenBao Keykeeper token policy/authority not verified"
        }
        return Issued(derived, sha(tokenFile), original, sha(initBytes))
    }
}
