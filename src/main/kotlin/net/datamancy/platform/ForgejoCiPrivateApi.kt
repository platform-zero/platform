package net.datamancy.platform

import java.io.ByteArrayOutputStream
import java.io.BufferedInputStream
import java.net.InetSocketAddress
import java.net.URI
import java.net.Socket
import java.nio.charset.StandardCharsets.US_ASCII
import java.util.Base64
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SNIHostName
import javax.net.ssl.TrustManagerFactory

/** Version-pinned Forgejo v17 repository runner API; no public DNS lookup,
 * redirects, URL credentials, proxy or host-engine socket. Token stays on the
 * host and is never passed on argv or included in any result/exception. */
internal object ForgejoCiPrivateApi {
    data class Reply(val status: Int, val body: ByteArray)
    fun request(plan: ForgejoCiSourcePlan, token: ByteArray, method: String, route: String): Reply {
        require(method in setOf("GET", "DELETE") && route.matches(
            Regex("/api/v1/repos/[a-zA-Z0-9_.-]{1,64}/[a-zA-Z0-9_.-]{1,64}/actions/runners/[1-9][0-9]{0,18}")))
        require(token.size in 20..4096 && token.all { it.toInt().toChar() in '!'..'~' })
        return transport(plan, "token ${token.toString(US_ASCII)}", method, route)
    }
    fun freshRepository(plan: ForgejoCiSourcePlan, password: ByteArray, route: String): Reply {
        val repo = plan.enrollment.repository
        require(plan.freshIssuerBootstrap && repo.matches(Regex("[a-zA-Z0-9_.-]{1,64}/[a-zA-Z0-9_.-]{1,64}")) &&
            route in setOf("/api/v1/repos/$repo/actions/runners/registration-token",
                "/api/v1/repos/$repo/git/commits/${plan.enrollment.trustedCommit}",
                "/api/v1/repos/$repo/branches/main") &&
            password.size in 20..256 && password.all { it.toInt().toChar() in '!'..'~' })
        val basic = Base64.getEncoder().encodeToString(
            "p0v3-bootstrap:".toByteArray(US_ASCII) + password)
        return transport(plan, "Basic $basic", "GET", route)
    }
    fun freshCreate(plan: ForgejoCiSourcePlan, password: ByteArray, route: String, body: ByteArray): Reply {
        val repo = plan.enrollment.repository.split('/')
        require(plan.freshIssuerBootstrap && repo.size == 2 && repo.all {
            it.matches(Regex("[a-zA-Z0-9_.-]{1,64}")) } &&
            route in setOf("/api/v1/orgs", "/api/v1/orgs/${repo[0]}/repos") &&
            body.size in 4..4096 && password.size in 20..256 &&
            password.all { it.toInt().toChar() in '!'..'~' })
        val basic = Base64.getEncoder().encodeToString("p0v3-bootstrap:".toByteArray(US_ASCII) + password)
        return transport(plan, "Basic $basic", "POST", route, body)
    }
    /** One reviewed workflow in the already-created trusted repository. The
     * caller must journal before dispatch; this transport never retries POST. */
    fun originalJob(plan: ForgejoCiSourcePlan, password: ByteArray, method: String,
        route: String, body: ByteArray = byteArrayOf()): Reply {
        val repo = plan.enrollment.repository
        val prefix = "/api/v1/repos/$repo/actions"
        require(plan.freshIssuerBootstrap && repo.matches(Regex("[a-zA-Z0-9_.-]{1,64}/[a-zA-Z0-9_.-]{1,64}")) &&
            password.size in 20..256 && password.all { it.toInt().toChar() in '!'..'~' })
        val dispatch = route.matches(Regex(Regex.escape(prefix) + "/workflows/[a-z0-9_-]+\\.ya?ml/dispatches"))
        val runs = route == "$prefix/runs"
        val jobs = route.matches(Regex(Regex.escape(prefix) + "/runs/[1-9][0-9]{0,18}/jobs"))
        require((method == "POST" && dispatch && body.size in 10..1024) ||
            (method == "GET" && (runs || jobs) && body.isEmpty()))
        val basic = Base64.getEncoder().encodeToString("p0v3-bootstrap:".toByteArray(US_ASCII) + password)
        return transport(plan, "Basic $basic", method, route, body)
    }
    private fun transport(plan: ForgejoCiSourcePlan, authorization: String, method: String, route: String,
        body: ByteArray = byteArrayOf()): Reply {
        val (endpoint, caPin) = if (plan.graphOwnedLateUpstream)
            ForgejoCiGraphUpstreamAdoption.current(plan)
        else requireNotNull(plan.privateUpstream) to requireNotNull(plan.upstreamCa)
        val uri = URI(endpoint)
        require(ForgejoCiTransportSource.validUpstream(uri.toString()) &&
            authorization.length in 20..8192 && !authorization.contains('\r') && !authorization.contains('\n'))
        val ca = GenerationRuntime.privateInput(java.nio.file.Path.of(caPin.path))
        require(ReleaseLocks.sha256(ca) == caPin.sha256)
        val certificates = CertificateFactory.getInstance("X.509").generateCertificates(ca.inputStream())
        require(certificates.isNotEmpty() && certificates.size <= 8)
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            certificates.forEachIndexed { i, cert -> setCertificateEntry("private-forgejo-$i", cert) }
        }
        val manager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        val context = SSLContext.getInstance("TLS").apply { init(null, manager.trustManagers, null) }
        Socket().use { plain ->
            plain.connect(InetSocketAddress(uri.host, uri.port), 10000)
            plain.soTimeout = 15000
            (context.socketFactory.createSocket(plain, "forgejo.datamancy.net", uri.port, true) as SSLSocket).use { tls ->
                tls.soTimeout = 15000
                tls.sslParameters = tls.sslParameters.apply {
                    endpointIdentificationAlgorithm = "HTTPS"
                    serverNames = listOf(SNIHostName("forgejo.datamancy.net"))
                    protocols = arrayOf("TLSv1.3", "TLSv1.2")
                }
                tls.startHandshake()
                val request = "$method $route HTTP/1.1\r\nHost: forgejo.datamancy.net\r\n" +
                    "Authorization: $authorization\r\nAccept: application/json\r\n" +
                    "Connection: close\r\nContent-Type: application/json\r\nContent-Length: ${body.size}\r\n\r\n"
                tls.outputStream.write(request.toByteArray(US_ASCII))
                if (body.isNotEmpty()) tls.outputStream.write(body)
                tls.outputStream.flush()
                val stream = BufferedInputStream(tls.inputStream)
                fun line(): String {
                    val bytes = ByteArrayOutputStream()
                    while (bytes.size() <= 8192) {
                        val next = stream.read()
                        require(next >= 0) { "Incomplete private Forgejo API response" }
                        if (next == 10) {
                            val raw = bytes.toByteArray()
                            require(raw.isNotEmpty() && raw.last() == 13.toByte())
                            return String(raw, 0, raw.size - 1, US_ASCII)
                        }
                        bytes.write(next)
                    }
                    error("Oversized private Forgejo API response header")
                }
                val status = line().split(' ', limit = 3).also {
                    require(it.size == 3 && it[0] == "HTTP/1.1")
                }[1].toInt()
                val headers = linkedMapOf<String, String>()
                while (true) {
                    val value = line()
                    if (value.isEmpty()) break
                    require(headers.size <= 32 && value.length <= 4096)
                    val key = value.substringBefore(':').lowercase()
                    require(key in setOf("content-length", "content-type", "connection", "date", "server",
                        "cache-control", "vary", "x-content-type-options", "x-frame-options", "x-request-id",
                        "strict-transport-security", "x-total-count", "x-page", "x-perpage", "link",
                        "etag", "last-modified", "x-ratelimit-limit", "x-ratelimit-remaining",
                        "x-ratelimit-reset", "access-control-allow-origin", "access-control-expose-headers") && key !in headers)
                    headers[key] = value.substringAfter(':').trim()
                }
                require(headers["transfer-encoding"] == null && headers["location"] == null &&
                    headers["content-encoding"] == null && headers["connection"]?.lowercase() != "keep-alive")
                val length = headers["content-length"]?.toIntOrNull() ?: if (status == 204) 0 else null
                require(length != null && length in 0..65536 && (status != 204 || length == 0))
                val body = stream.readNBytes(length)
                require(body.size == length)
                return Reply(status, body)
            }
        }
    }
}
