package net.datamancy.platform

import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.concurrent.TimeUnit
import java.util.concurrent.CompletableFuture
import kotlinx.serialization.json.*

/** Only an HTTP-01 readiness check. Caddy, not this code, owns issuance and renewal. */
enum class PortOwner { FREE, OWNED_V3, PROTECTED, UNKNOWN }

/** Conservative host-network TCP inventory. Busy is never inferred to be ours. No socket is opened. */
internal fun hostIngressPortOwner(port: Int): PortOwner {
    val sockets = inspectIngressPortOwner(port) { java.nio.file.Files.readString(java.nio.file.Path.of(it)) }
    if (sockets != PortOwner.FREE) return sockets
    // Rootful containers can publish through DNAT without any host listening socket. Inspect BOTH
    // netfilter families and nftables; unavailable/ambiguous inventory never means a free port.
    return try {
        inspectIngressFirewallPort(port, ingressInventory(listOf("/usr/sbin/nft", "-j", "list", "ruleset")),
            listOf("/usr/sbin/iptables-save", "/usr/sbin/ip6tables-save").map { ingressInventory(listOf(it, "-t", "nat")) })
    } catch (error: InterruptedException) { Thread.currentThread().interrupt(); throw error }
    catch (_: Exception) { PortOwner.UNKNOWN }
}
private fun ingressInventory(command: List<String>): String {
    val builder = ProcessBuilder(listOf("/usr/bin/sudo", "-n") + command).redirectError(ProcessBuilder.Redirect.DISCARD)
    builder.environment().clear()
    val process = builder.start()
    process.outputStream.close()
    val output = CompletableFuture.supplyAsync { process.inputStream.use { it.readNBytes(8 * 1024 * 1024 + 1) } }
    try {
        check(process.waitFor(10, TimeUnit.SECONDS) && process.exitValue() == 0)
        return output.get(1, TimeUnit.SECONDS).also { require(it.size in 1..8 * 1024 * 1024) }.decodeToString(throwOnInvalidSequence = true)
    } finally { if (process.isAlive) process.destroyForcibly(); output.cancel(true) }
}

internal fun inspectIngressFirewallPort(port: Int, nft: String, iptables: List<String>): PortOwner {
    require(port in setOf(80, 443))
    fun nat(value: JsonElement): Boolean = when (value) {
        is JsonObject -> value.keys.any { it in setOf("dnat", "redirect", "tproxy") } || value.values.any(::nat)
        is JsonArray -> value.any(::nat)
        else -> false
    }
    fun contains(value: JsonElement): Boolean = when (value) {
        is JsonPrimitive -> value.intOrNull?.let { it == port } ?: true
        is JsonObject -> when {
            "set" in value -> value.getValue("set").jsonArray.any(::contains)
            "range" in value -> value.getValue("range").jsonArray.let { it.size != 2 || port in it[0].jsonPrimitive.int..it[1].jsonPrimitive.int }
            else -> true
        }
        else -> true
    }
    return try {
        require(iptables.size == 2 && iptables.all { "*nat" in it && "COMMIT" in it })
        val legacy = iptables.any { rules -> rules.lineSequence().any { line ->
            if (!Regex("(?:^| )-j (?:DNAT|REDIRECT|TPROXY)(?: |$)").containsMatchIn(line) || Regex("(?:^| )-p udp(?: |$)").containsMatchIn(line)) false
            else {
                val ports = Regex("--dports? ([0-9,:]+)(?: |$)").find(line)?.groupValues?.get(1)
                ports == null || ports.split(',').any { entry ->
                    val range = entry.split(':').map(String::toInt)
                    if (range.size == 1) range.single() == port else port in range.first()..range.last()
                }
            }
        } }
        val rules = Json.parseToJsonElement(nft).jsonObject.getValue("nftables").jsonArray.mapNotNull { it.jsonObject["rule"]?.jsonObject }
        val native = rules.any { rule ->
            val expressions = rule.getValue("expr").jsonArray
            nat(expressions) && expressions.none { expression ->
                val match = expression.jsonObject["match"]?.jsonObject
                if (match == null || match["op"] != JsonPrimitive("==")) false
                else {
                    val left = match.getValue("left").jsonObject
                    val payload = left["payload"]?.jsonObject
                    val meta = left["meta"]?.jsonObject
                    (payload?.get("protocol") == JsonPrimitive("udp")) ||
                        (meta?.get("key") == JsonPrimitive("l4proto") && match["right"] == JsonPrimitive("udp")) ||
                        (payload?.get("protocol") == JsonPrimitive("tcp") && payload["field"] == JsonPrimitive("dport") && !contains(match.getValue("right")))
                }
            }
        }
        if (legacy || native) PortOwner.PROTECTED else PortOwner.FREE
    } catch (_: Exception) { PortOwner.UNKNOWN }
}
internal fun inspectIngressPortOwner(port: Int, read: (String) -> String): PortOwner {
    require(port in setOf(80, 443))
    return try {
        val listeners = listOf("/proc/net/tcp", "/proc/net/tcp6").flatMap { path ->
            val lines = read(path).lineSequence().filter { it.isNotBlank() }.toList()
            require(lines.isNotEmpty() && "local_address" in lines.first() && lines.size <= 65536)
            lines.drop(1).mapNotNull { line ->
                val fields = line.trim().split(Regex("\\s+"))
                require(fields.size >= 4)
                val localPort = fields[1].substringAfterLast(':').toInt(16)
                if (fields[3] == "0A") localPort else null
            }
        }
        if (port in listeners) PortOwner.PROTECTED else PortOwner.FREE
    } catch (_: Exception) { PortOwner.UNKNOWN }
}
interface AcmeObservation {
    /** Independently inspected port ownership; never infer "owned" from an open socket alone. */
    fun portOwner(port: Int): PortOwner
    /** Fetch public HTTP on port 80 through the already provisioned DNS/Cloudflare route, without redirects. */
    fun challenge(host: String, nonce: String): ChallengeResponse
}
data class ChallengeResponse(val status: Int, val body: String, val redirected: Boolean)

/** Runtime HTTP adapter. Port ownership must come from the release controller's independent inventory,
 * not from DNS, an open socket, or a successful HTTP response. No requests occur at construction. */
internal class PublicHttp01Observation(private val approvedHosts: Set<String>,
    private val ownership: (Int) -> PortOwner) : AcmeObservation {
    private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
        .followRedirects(HttpClient.Redirect.NEVER).build()
    override fun portOwner(port: Int): PortOwner {
        require(port in setOf(80, 443)); return ownership(port)
    }
    override fun challenge(host: String, nonce: String): ChallengeResponse {
        require(host in approvedHosts && AcmePreflight.hostPattern.matches(host) && nonce.matches(Regex("[a-zA-Z0-9_-]{32,128}")))
        val request = HttpRequest.newBuilder(URI.create("http://$host/.well-known/acme-challenge/$nonce"))
            .timeout(Duration.ofSeconds(15)).GET().build()
        val pending = client.sendAsync(request, HttpResponse.BodyHandler { BoundedCaddyBody(256) })
        try {
            val response = pending.get(15, TimeUnit.SECONDS)
            return ChallengeResponse(response.statusCode(), response.body().decodeToString(throwOnInvalidSequence = true),
                response.statusCode() in 300..399)
        } catch (error: InterruptedException) {
            pending.cancel(true); Thread.currentThread().interrupt(); throw error
        } catch (error: Exception) {
            pending.cancel(true); throw IllegalStateException("HTTP-01 preflight failed for approved host", error)
        }
    }
}

object AcmePreflight {
    internal val hostPattern = Regex("(?:[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?\\.)+datamancy\\.net")
    /** Each hostname gets its own nonce and test. Apex success is never inherited by subdomains. */
    fun check(hosts: Set<String>, approvals: Set<String>, observation: AcmeObservation,
              nonceFor: (String) -> String) {
        require(hosts.isNotEmpty() && hosts.size <= 64 && hosts.all { hostPattern.matches(it) && it.length <= 253 && it.split('.').all { label -> label.length <= 63 } && it in approvals }) {
            "Unapproved ACME hostname"
        }
        require((listOf(80, 443)).all {
            observation.portOwner(it) in setOf(PortOwner.FREE, PortOwner.OWNED_V3)
        }) { "HTTP/HTTPS port is protected or ownership unknown" }
        val nonces = hosts.associateWith(nonceFor)
        require(nonces.values.distinct().size == hosts.size && nonces.values.all {
            it.matches(Regex("[a-zA-Z0-9_-]{32,128}"))
        }) { "Fresh per-host challenge nonce required" }
        hosts.sorted().forEach { host ->
            val response = observation.challenge(host, nonces.getValue(host))
            require(response.status == 200 && !response.redirected &&
                response.body == "p0v3-http01-${nonces.getValue(host)}") { "HTTP-01 route not verified: $host" }
        }
    }
}
