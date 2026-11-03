package net.datamancy.platform

import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.*

internal data class CaddyAdminTarget(val pid: Int, val containerId: String)

/** Connects to the audited Caddy's private loopback, never broadens its admin listen address.
 * Each request holds the runtime lock. Root helper source is included in the pinned controller,
 * not downloaded or selected by the request. Timeout leaves any dispatched write uncertain.
 */
internal class NamespaceCaddyTransport(
    private val audited: (Boolean, (CaddyAdminTarget) -> CaddyReply) -> CaddyReply,
    private val helper: (ByteArray) -> ByteArray = ::runCaddyNamespaceHelper
) : CaddyTransport {
    companion object {
        fun real(spec: PrivateDeploymentSpec, fingerprint: String): NamespaceCaddyTransport {
            require(spec.store == RuntimeStore.CANONICAL_V2 && fingerprint.matches(Regex("[a-f0-9]{64}")))
            val runtime = PrivateDeployment.real(mapOf(spec.name to fingerprint))
            return NamespaceCaddyTransport({ mutation, action -> runtime.withCaddyAdmin(spec, fingerprint, mutation, action) })
        }
        fun checkBinding(binding: CaddySiteBinding, spec: PrivateDeploymentSpec) {
            require(binding.endpoint == "http://127.0.0.1:2019") { "Namespaced admin uses only container-loopback port 2019" }
            spec.ingress?.let { require(it.site == binding.site && it.approvedHosts == binding.approvedHosts) { "Ingress approval differs from sealed publication" } }
        }
    }
    override fun exchange(method: String, path: String, etag: String?, body: ByteArray?): CaddyReply {
        val read = method == "GET" && path == "/config/" && etag == null && body == null
        val write = ((method == "POST" && path == "/config/") || (method == "PATCH" &&
            path.matches(Regex("/config/apps/http/servers/[a-z][a-z0-9-]{0,63}/routes")))) &&
            etag?.matches(Regex("\"/config/ [a-f0-9]{16}\"")) == true && body != null && body.size in 1..4 * 1024 * 1024
        require(read || write)
        return audited(!read) { target ->
            require(target.pid > 1 && target.containerId.matches(Regex("[a-f0-9]{64}")))
            val request = buildJsonObject {
                put("pid", target.pid); put("containerId", target.containerId); put("method", method); put("path", path)
                put("etag", etag?.let(::JsonPrimitive) ?: JsonNull)
                put("body", body?.let { JsonPrimitive(Base64.getEncoder().encodeToString(it)) } ?: JsonNull)
            }
            val bytes = helper(request.toString().toByteArray())
            require(bytes.size in 1..8 * 1024 * 1024)
            val response = Json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(response.keys == setOf("status", "etag", "body"))
            val status = response.getValue("status").jsonPrimitive.int
            val responseBody = Base64.getDecoder().decode(response.getValue("body").jsonPrimitive.content)
            require(status in 100..599 && responseBody.size <= 4 * 1024 * 1024)
            CaddyReply(status, responseBody, response["etag"]?.takeUnless { it == JsonNull }?.jsonPrimitive?.content)
        }
    }
}

internal fun runCaddyNamespaceHelper(request: ByteArray): ByteArray {
    val source = requireNotNull(NamespaceCaddyTransport::class.java.getResourceAsStream("/runtime/caddy-admin.py"))
        .use { it.readNBytes(65537) }.also { require(it.size in 1..65536) }.decodeToString(throwOnInvalidSequence = true)
    return runBoundedCaddyHelper(listOf("/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-c", source), request)
}

/** Exposed internally for synthetic subprocess unit fixtures, not a caller-controlled production CLI. */
internal fun runBoundedCaddyHelper(command: List<String>, request: ByteArray, seconds: Long = 35): ByteArray {
    require(request.size in 1..8 * 1024 * 1024 && seconds in 1..35)
    val builder = ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD)
    builder.environment().clear()
    val process = builder.start()
    val input = CompletableFuture.runAsync { process.outputStream.use { it.write(request) } }
    val output = CompletableFuture.supplyAsync { process.inputStream.use { it.readNBytes(8 * 1024 * 1024 + 1) } }
    try {
        check(process.waitFor(seconds, TimeUnit.SECONDS)) { "Caddy namespace exchange timed out; never replay a write" }
        input.get(1, TimeUnit.SECONDS)
        check(process.exitValue() == 0) { "Caddy namespace helper failed; retain uncertain intent" }
        return output.get(1, TimeUnit.SECONDS).also { require(it.size in 1..8 * 1024 * 1024) }
    } catch (error: InterruptedException) {
        Thread.currentThread().interrupt(); throw error
    } finally {
        process.descendants().forEach { it.destroyForcibly() }
        if (process.isAlive) process.destroyForcibly()
        input.cancel(true); output.cancel(true)
    }
}
