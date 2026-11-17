package net.datamancy.platform

import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import java.io.ByteArrayInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URI
import java.net.ServerSocket
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyFactory
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import org.junit.jupiter.api.Test
import kotlin.test.*

/** Actual HTTPS GET to a loopback-only test server through the SAME production
 * pinned fixture transport. Not selected r9, no q generation state or native ACK. */
class RssExistingPrivateFixtureSocketTest {
    @Test fun `actual loopback TLS GET fetches all synthetic pack XML and rejects POST and public origins`() {
        val root=Files.createTempDirectory("rss-47-tls-source-", PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------")))
        try {
            val pem=PrivateWebPki.generate("fixture",run={directory,args->
                if("-extfile" in args) Files.writeString(directory.resolve("web.ext"),
                    "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"+
                        "extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n")
                privatePkiOpenSsl(directory,args)
            })
            val caFile=root.resolve("fixture-ca.pem")
            ReleasePrivateFiles.save(caFile,pem.getValue("ca.pem").toByteArray())
            val caSha=ReleaseLocks.sha256(ReleasePrivateFiles.read(caFile,65536))
            val cf=CertificateFactory.getInstance("X.509")
            val ca=cf.generateCertificate(ByteArrayInputStream(pem.getValue("ca.pem").toByteArray()))
            val leaf=cf.generateCertificate(ByteArrayInputStream(pem.getValue("web.pem").toByteArray()))
            val key=KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(
                pem.getValue("web-key.pem").substringAfter("-----BEGIN PRIVATE KEY-----")
                    .substringBefore("-----END PRIVATE KEY-----"))))
            val password="fixture-only".toCharArray()
            val keys=KeyStore.getInstance("PKCS12").apply { load(null,null)
                setKeyEntry("local",key,password,arrayOf(leaf,ca)) }
            val km=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(keys,password) }
            val ssl=SSLContext.getInstance("TLS").apply { init(km.keyManagers,null,null) }
            val localhost=InetAddress.getByAddress(byteArrayOf(127,0,0,1))
            val reviewed=RssPacks.load()
            val requested=mutableListOf<String>()
            val port=(49152..65535).first { candidate -> runCatching {
                ServerSocket(candidate,1,localhost).use { }
            }.isSuccess }
            val server=HttpsServer.create(InetSocketAddress(localhost,port),16).apply {
                httpsConfigurator=HttpsConfigurator(ssl)
                createContext("/") { exchange->
                    try {
                        assertTrue(exchange.localAddress.address.isLoopbackAddress)
                        assertTrue(exchange.remoteAddress.address.isLoopbackAddress)
                        requested+=exchange.requestMethod+" "+exchange.requestURI.rawPath
                        val feed=reviewed.singleOrNull { exchange.requestURI.rawPath=="/feed/pack/${it.feed.id}" }
                        val body=if(exchange.requestMethod=="GET" && feed!=null &&
                            exchange.requestHeaders.getFirst("Authorization")==null)
                            RssQualificationPackSource.xml(feed) else "not a feed".toByteArray()
                        exchange.sendResponseHeaders(if(feed!=null && exchange.requestMethod=="GET") 200 else 404,
                            body.size.toLong())
                        exchange.responseBody.use { it.write(body) }
                    } finally { exchange.close() }
                }
                start()
            }
            try {
                val origin=URI("https://127.0.0.1:${server.address.port}")
                val client=PinnedRssFixtureHttp(origin,caFile,caSha)
                reviewed.forEach { feed->
                    val path="/feed/pack/${feed.feed.id}"
                    val reply=client.request("GET",origin.resolve(path),mapOf("Accept" to "application/rss+xml"),"")
                    assertEquals(200,reply.status)
                    assertEquals(ReleaseLocks.sha256(leaf.encoded),reply.peerLeafDerSha256)
                    assertContentEquals(RssQualificationPackSource.xml(feed),reply.body)
                }
                assertEquals(47,requested.size)
                assertEquals(47,requested.toSet().size)
                for((method,uri,headers) in listOf(
                    Triple("POST",origin.resolve("/feed/pack/${reviewed.first().feed.id}"),emptyMap()),
                    Triple("GET",URI("https://8.8.8.8:${server.address.port}/feed/pack/${reviewed.first().feed.id}"),emptyMap()),
                    Triple("GET",origin.resolve("/feed/pack/${reviewed.first().feed.id}?redirect=true"),emptyMap()),
                    Triple("GET",origin.resolve("/feed/pack/${reviewed.first().feed.id}"),mapOf("Authorization" to "Bearer refused")))) {
                    assertFailsWith<IllegalArgumentException> { client.request(method,uri,headers,"") }
                }
                assertEquals(47,requested.size) // all faults rejected BEFORE socket
            } finally { server.stop(0) }
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
