package net.datamancy.platform

import java.io.ByteArrayInputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.file.Path
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import kotlinx.serialization.json.*

/** Five distinct original-host issuers and selected CID/leaf, copied into one case.
 * A QClient sees only its own 0600 case copies, never a generation-wide trust tree. */
internal object QualificationMatrixTlsProjection {
    private val json = Json { ignoreUnknownKeys = false }
    private val hosts = listOf("auth.datamancy.net", "chat.datamancy.net",
        "matrix-auth.datamancy.net", "matrix.datamancy.net", "matrix-rtc.datamancy.net")
    fun produce(caseDir: Path, bundle: GenerationBundle, pin: GenerationPin,
        bundleSha: String, signedProbeSha: String, tools: JsonObject,
        approvedHosts: Set<String>): Map<String,JsonElement> {
        val issuer = CanonicalCaddyServedLeafReadback(GenerationRuntime.BASE.resolve(bundle.request.id),
            bundle, bundleSha, QualificationPrivateTls.selectedManifest(requireNotNull(pin.spec.fragmentBinding)))
        val tool = tools.getValue("probe").jsonObject
        require(signedProbeSha.matches(Regex("[a-f0-9]{64}")) &&
            tool.getValue("sha256").jsonPrimitive.content == signedProbeSha &&
            hosts.all { it in approvedHosts })
        val certFactory = CertificateFactory.getInstance("X.509")
        val perHost = buildJsonObject {
            for (host in hosts) {
                val receiptPin = issuer.verify(host)
                val receipt = json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(receiptPin.path),8192)
                    .decodeToString(throwOnInvalidSequence = true)).jsonObject
                val trust = QualificationPrivateTls.observe(bundle, setOf(host), bundleSha)
                val ca = trust.roots
                val caCert = certFactory.generateCertificate(ByteArrayInputStream(ca)) as X509Certificate
                caCert.checkValidity()
                val store = KeyStore.getInstance("PKCS12").apply {
                    load(null,null); setCertificateEntry("original-$host",caCert) }
                val manager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                    .apply { init(store) }
                val tls = SSLContext.getInstance("TLS").apply { init(null,manager.trustManagers,null) }
                val endpoint = java.net.URI(issuer.verifiedPrivateEndpoint(host))
                val address = QualificationRssIngressSource.address(endpoint.toString(),
                    NamespaceCaddyTransport.ownedProcessAddress(pin.spec,pin.runtimeFingerprint,
                        "caddy","ingress-control"), receipt.getValue("privateNetwork").jsonPrimitive.content,
                    receipt.getValue("caSha256").jsonPrimitive.content,ReleaseLocks.sha256(ca),
                    receipt.getValue("servedLeafDerSha256").jsonPrimitive.content,
                    trust.leaves.getValue(host))
                val socket = Socket().apply { connect(InetSocketAddress(address,443),7000) }
                val leaf = (tls.socketFactory.createSocket(socket,host,443,true) as SSLSocket).use { secured ->
                    secured.soTimeout = 8000
                    secured.sslParameters = secured.sslParameters.apply {
                        endpointIdentificationAlgorithm = "HTTPS"; serverNames = listOf(SNIHostName(host)) }
                    secured.startHandshake()
                    secured.session.peerCertificates.first() as X509Certificate
                }
                require(ReleaseLocks.sha256(leaf.encoded) == receipt.getValue("servedLeafDerSha256")
                    .jsonPrimitive.content && leaf.subjectAlternativeNames.orEmpty().any {
                        it[0] == 2 && it[1] == host })
                val pem = "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, "\n".toByteArray())
                    .encodeToString(leaf.encoded) + "\n-----END CERTIFICATE-----\n"
                val caCopy = caseDir.resolve("owner-proofs/matrix-$host-ca.pem")
                val leafCopy = caseDir.resolve("owner-proofs/matrix-$host-leaf.pem")
                ReleasePrivateFiles.save(caCopy,ca)
                ReleasePrivateFiles.save(leafCopy,pem.encodeToByteArray())
                val pin = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256")
                    .digest(leaf.publicKey.encoded))
                put(host,buildJsonObject {
                    put("leafFile",leafCopy.toString()); put("caFile",caCopy.toString())
                    put("leafSha256",ReleaseLocks.sha256(leaf.encoded))
                    put("caSha256",ReleaseLocks.sha256(ca))
                    put("spkiSha256Base64",pin)
                })
            }
        }
        return mapOf("hostTls" to perHost,
            "selectedR9MatrixProbeSha256" to JsonPrimitive(signedProbeSha))
    }
}
