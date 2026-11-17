package net.datamancy.platform

import java.net.Proxy
import java.net.ProxySelector
import java.net.CookieManager
import java.net.CookiePolicy
import java.net.HttpCookie
import java.net.Socket
import java.net.URI
import java.net.http.HttpClient
import java.nio.file.Path
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** Client scoped to ONE graph APP or Donetick GROUP route. Only current original Caddy
 * case custody and the actually served leaf can authorize an actor API call.
 */
internal object GenerationOriginalActorHttp {
    private val json = Json { ignoreUnknownKeys = false }
    internal fun scopedGroupCookie(host: String, originalGroupCookie: String): CookieManager {
        require(host == "donetick.datamancy.net" &&
            originalGroupCookie.matches(Regex("_p0v3_edge=[A-Za-z0-9._~-]{24,512}")))
        val manager = CookieManager(null, CookiePolicy.ACCEPT_ORIGINAL_SERVER)
        val cookie = HttpCookie("_p0v3_edge", originalGroupCookie.substringAfter('='))
        cookie.domain = host; cookie.path = "/"; cookie.secure = true; cookie.isHttpOnly = true
        manager.cookieStore.add(URI("https://$host/"), cookie)
        return manager
    }
    fun client(root: Path, bundle: GenerationBundle, expected: String,
        manifest: CanonicalSharedManifest, host: String, originalGroupCookie: String? = null): HttpClient {
        require(root == GenerationRuntime.BASE.resolve(bundle.request.id) &&
            bundle.recoverySourceKopia == null && bundle.recoverySourceArchiveSha256 == null &&
            expected == ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)))
        val binding = CanonicalPrivateIngressTrust.requireRoute(manifest, bundle.members.single().spec,
            if (host == "forgejo.datamancy.net") "forgejo" else "donetick",
            if (host == "donetick.datamancy.net") "GROUP" else "APP", host)
        require(binding.hostname == host)
        val ca = CanonicalCaddyCaseTlsBundle(root, bundle, expected, manifest).verify(setOf(host))
        val bytes = ReleasePrivateFiles.read(Path.of(ca.path), 65536)
        require(ReleaseLocks.sha256(bytes) == ca.sha256)
        val observed = json.decodeFromString<CaddyServedLeafReadback>(ReleasePrivateFiles.read(
            root.resolve("ingress/trust/leaves/$host.json"), 8192).decodeToString(throwOnInvalidSequence = true))
        require(observed.generation == bundle.request.id && observed.bundleSha256 == expected &&
            observed.hostname == host && observed.servedLeafDerSha256.matches(Regex("[a-f0-9]{64}")))
        val certs = CertificateFactory.getInstance("X.509").generateCertificates(bytes.inputStream())
        require(certs.isNotEmpty() && certs.size <= 8)
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            certs.forEachIndexed { index, certificate -> setCertificateEntry("generation-issuer-$index", certificate) }
        }
        val delegates = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        val pkix = delegates.trustManagers.filterIsInstance<X509ExtendedTrustManager>().single()
        val pinned = object : X509ExtendedTrustManager() {
            private fun check(chain: Array<X509Certificate>, verify: () -> Unit) {
                verify()
                require(chain.isNotEmpty() && ReleaseLocks.sha256(chain[0].encoded) == observed.servedLeafDerSha256) {
                    "Native original actor endpoint differs from the current generation Caddy leaf"
                }
            }
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) =
                check(chain) { pkix.checkServerTrusted(chain, authType) }
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket) =
                check(chain) { pkix.checkServerTrusted(chain, authType, socket) }
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine) =
                check(chain) { pkix.checkServerTrusted(chain, authType, engine) }
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
                pkix.checkClientTrusted(chain, authType)
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket) =
                pkix.checkClientTrusted(chain, authType, socket)
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine) =
                pkix.checkClientTrusted(chain, authType, engine)
            override fun getAcceptedIssuers(): Array<X509Certificate> = pkix.acceptedIssuers
        }
        val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(pinned), null) }
        val direct = object : ProxySelector() {
            override fun select(uri: URI): List<Proxy> = listOf(Proxy.NO_PROXY)
            override fun connectFailed(uri: URI?, sa: java.net.SocketAddress?, ioe: java.io.IOException?) = Unit
        }
        val builder = HttpClient.newBuilder().sslContext(context).proxy(direct)
            .sslParameters(javax.net.ssl.SSLParameters().apply { endpointIdentificationAlgorithm = "HTTPS" })
            .followRedirects(HttpClient.Redirect.NEVER).connectTimeout(java.time.Duration.ofSeconds(10))
        if (originalGroupCookie != null) {
            builder.cookieHandler(scopedGroupCookie(host, originalGroupCookie))
        }
        return builder.build()
    }
}
