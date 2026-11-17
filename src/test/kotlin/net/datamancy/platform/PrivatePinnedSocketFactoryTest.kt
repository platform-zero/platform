package net.datamancy.platform

import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import java.io.ByteArrayInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import javax.net.ssl.SSLSocket
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import org.junit.jupiter.api.Test
import kotlin.test.*

/** Private source-level real sockets only; this is not a selected Caddy/native
 * RSS effect or permission to send a public post. Fixture never leaves host. */
class PrivatePinnedSocketFactoryTest {
    @Test fun `original-host HTTPS GET and direct POST reach only pinned private socket`() {
        val ip=NetworkInterface.getNetworkInterfaces().asSequence().flatMap { it.inetAddresses.asSequence() }
            .firstOrNull { it is java.net.Inet4Address && it.isSiteLocalAddress }
            ?: error("No site-local test interface: cannot prove private socket routing")
        val pem=PrivateWebPki.generate("social",listOf("social","social.datamancy.net"))
        val cf=CertificateFactory.getInstance("X.509")
        val ca=cf.generateCertificate(ByteArrayInputStream(pem.getValue("ca.pem").toByteArray()))
        val leaf=cf.generateCertificate(ByteArrayInputStream(pem.getValue("web.pem").toByteArray()))
        val key=KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(
            pem.getValue("web-key.pem").substringAfter("-----BEGIN PRIVATE KEY-----")
                .substringBefore("-----END PRIVATE KEY-----"))))
        val pass="private-test".toCharArray()
        val keys=KeyStore.getInstance("PKCS12").apply {
            load(null,null);setKeyEntry("leaf",key,pass,arrayOf(leaf,ca))
        }
        val serverKm=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(keys,pass) }
        val serverSsl=SSLContext.getInstance("TLS").apply { init(serverKm.keyManagers,null,null) }
        val trust=KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null,null);setCertificateEntry("original",ca)
        }
        val clientTm=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(trust) }
        val clientSsl=SSLContext.getInstance("TLS").apply { init(null,clientTm.trustManagers,null) }
        val factory=PrivatePinnedSocketFactory(clientSsl.socketFactory,"social.datamancy.net",ip.hostAddress)
        val received=mutableListOf<Pair<String,String>>()
        val server=HttpsServer.create(InetSocketAddress(ip,8443),2).apply {
            httpsConfigurator=HttpsConfigurator(serverSsl)
            createContext("/") { exchange ->
                val body=exchange.requestBody.use { it.readNBytes(1025) }.toString(StandardCharsets.UTF_8)
                received += exchange.requestMethod to body
                val bytes="private-fixture-only".toByteArray()
                exchange.sendResponseHeaders(200,bytes.size.toLong())
                exchange.responseBody.use { it.write(bytes) }
            }
            start()
        }
        try {
            fun open(method:String):String {
                val uri=if(method=="GET") "/api/v1/accounts/verify_credentials" else "/api/v1/statuses"
                val body=if(method=="POST") "{\"status\":\"private\",\"visibility\":\"direct\"}"
                    .toByteArray(StandardCharsets.UTF_8) else ByteArray(0)
                (factory.createSocket("social.datamancy.net",8443) as SSLSocket).use { socket ->
                    assertEquals(ip,socket.inetAddress)
                    assertEquals(8443,socket.port)
                    socket.soTimeout=3000
                    socket.startHandshake()
                    val reply=PinnedRssHttp11.exchange(socket,method,uri,
                        mapOf("Authorization" to "Bearer "+"a".repeat(32)),body)
                    assertEquals(200,reply.status)
                    return reply.body.toString(StandardCharsets.UTF_8)
                }
            }
            assertEquals("private-fixture-only",open("GET"))
            assertEquals("private-fixture-only",open("POST"))
            assertEquals(listOf("GET","POST"),received.map { it.first })
            assertEquals("",received[0].second)
            assertContains(received[1].second,"\"visibility\":\"direct\"")
            assertFailsWith<IllegalArgumentException> { factory.createSocket() }
            assertFailsWith<IllegalArgumentException> { factory.createSocket(
                InetAddress.getByAddress(byteArrayOf(8,8,8,8)),8443) }
            assertFailsWith<IllegalArgumentException> { factory.createSocket("other.datamancy.net",8443) }
        } finally { server.stop(0) }
    }
}
