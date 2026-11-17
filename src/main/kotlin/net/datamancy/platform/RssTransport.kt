package net.datamancy.platform

import java.io.ByteArrayInputStream
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.net.URI
import java.net.Proxy
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption.READ
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.X509TrustManager
import java.time.Duration
import java.util.concurrent.CountDownLatch
import com.sun.net.httpserver.HttpsServer
import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpExchange
import java.util.concurrent.Flow
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.w3c.dom.Element
import org.xml.sax.ErrorHandler
import org.xml.sax.SAXParseException

internal data class RssHttpReply(val status: Int, val body: ByteArray, val headers: Map<String, String> = emptyMap(),
    /** Actual original HTTPS peer DER, if and only if a pinned native client observed it. */
    val peerLeafDerSha256: String? = null)
internal fun interface RssHttp { fun request(method: String, uri: URI, headers: Map<String, String>, body: String): RssHttpReply }

/** Streaming size cap applies even when Content-Length is absent or dishonest. */
internal class BoundedRssBody(private val maximum: Int) : HttpResponse.BodySubscriber<ByteArray> {
    private val delegate = HttpResponse.BodySubscribers.ofByteArray()
    private var subscription: Flow.Subscription? = null
    private var received = 0L
    override fun getBody() = delegate.body
    override fun onSubscribe(value: Flow.Subscription) { subscription = value; delegate.onSubscribe(value) }
    override fun onNext(items: List<ByteBuffer>) {
        received += items.sumOf { it.remaining().toLong() }
        if (received > maximum) {
            subscription?.cancel()
            delegate.onError(IllegalArgumentException("RSS HTTP body exceeds limit"))
        } else delegate.onNext(items)
    }
    override fun onError(error: Throwable) = delegate.onError(error)
    override fun onComplete() = delegate.onComplete()
}

internal class JdkRssHttp : RssHttp {
    private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15))
        .version(HttpClient.Version.HTTP_1_1).followRedirects(HttpClient.Redirect.NEVER).build()
    override fun request(method: String, uri: URI, headers: Map<String, String>, body: String): RssHttpReply {
        require(uri.scheme == "https" && uri.host != null && uri.userInfo == null && uri.fragment == null)
        val builder = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30))
            .header("User-Agent", "Mozilla/5.0 (compatible; PlatformZero-RSS/1.0)")
        headers.forEach { (key, value) -> builder.header(key, value) }
        val request = if (method == "GET") {
            require(body.isEmpty())
            builder.GET().build()
        } else builder.method(method, HttpRequest.BodyPublishers.ofString(body)).build()
        val pending = client.sendAsync(request, HttpResponse.BodyHandler { BoundedRssBody(2_097_152) })
        try {
            val reply = pending.get(30, java.util.concurrent.TimeUnit.SECONDS)
            return RssHttpReply(reply.statusCode(), reply.body(), reply.headers().map().mapValues { it.value.singleOrNull().orEmpty() })
        } catch (interrupted: InterruptedException) {
            pending.cancel(true); Thread.currentThread().interrupt(); throw interrupted
        } catch (error: Exception) {
            pending.cancel(true); throw IllegalStateException("RSS HTTP exchange incomplete; do not retry an attempted send", error)
        }
    }
}

/** Authenticated, no-proxy, loopback-only REAL HTTPS transport for a separately provisioned
 * synthetic FEED fixture. It can never reach Mastodon or send a status.
 * The CA is an exact pinned private input; hostname/IP verification remains enabled. */
internal class PinnedRssFixtureHttp(private val origin: URI, caFile: Path, caSha256: String) : RssHttp {
    private val client: HttpClient
    init {
        require(origin.scheme == "https" && origin.host == "127.0.0.1" && origin.port in 49152..65535 &&
            origin.rawPath in setOf("", "/") && origin.userInfo == null && origin.rawQuery == null && origin.rawFragment == null &&
            caSha256.matches(Regex("[a-f0-9]{64}"))) { "RSS native fixture requires exact loopback HTTPS origin" }
        val ca = ReleasePrivateFiles.read(caFile, 65536)
        require(ReleaseLocks.sha256(ca) == caSha256) { "RSS fixture CA pin changed" }
        val certificate = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(ca))
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null); setCertificateEntry("rss-fixture", certificate)
        }
        val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        val ssl = SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }
        val noProxy = object : ProxySelector() {
            override fun select(uri: URI): List<Proxy> = listOf(Proxy.NO_PROXY)
            override fun connectFailed(uri: URI, sa: SocketAddress, ioe: java.io.IOException) { throw ioe }
        }
        client = HttpClient.newBuilder().sslContext(ssl).sslParameters(SSLParameters().apply {
            endpointIdentificationAlgorithm = "HTTPS"
        }).proxy(noProxy)
            .followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(10)).build()
    }
    override fun request(method: String, uri: URI, headers: Map<String, String>, body: String): RssHttpReply {
        require(method == "GET" && body.isEmpty() && uri.scheme == "https" && uri.host == origin.host &&
            uri.port == origin.port && uri.userInfo == null && uri.rawFragment == null && uri.rawQuery == null &&
            (uri.rawPath in setOf("/feed/baseline", "/feed/new") ||
                uri.rawPath.matches(Regex("/feed/pack/[a-z0-9][a-z0-9-]{0,63}"))) &&
            headers.keys.all { it=="Accept" } &&
            headers.values.all { it.length in 1..128 && it.all { character -> character.code in 32..126 } }) {
            "RSS feed fixture transport cannot send or reach Mastodon endpoints"
        }
        val builder = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(20))
            .header("User-Agent", "PlatformZero-RSS-fixture/1.0")
        headers.forEach { (name, value) -> builder.header(name, value) }
        val request = builder.GET().build()
        val pending = client.sendAsync(request, HttpResponse.BodyHandler { BoundedRssBody(2_097_152) })
        try {
            val reply = pending.get(25, java.util.concurrent.TimeUnit.SECONDS)
            require(reply.statusCode() !in 300..399 && reply.uri()==uri) { "RSS fixture redirects forbidden" }
            val peer=reply.sslSession().orElseThrow { IllegalArgumentException("Private fixture TLS peer missing") }
                .peerCertificates.first() as java.security.cert.X509Certificate
            return RssHttpReply(reply.statusCode(), reply.body(), reply.headers().map()
                .mapValues { it.value.singleOrNull().orEmpty() },ReleaseLocks.sha256(peer.encoded))
        } catch (interrupted: InterruptedException) {
            pending.cancel(true); Thread.currentThread().interrupt(); throw interrupted
        } catch (error: Exception) {
            pending.cancel(true); throw IllegalStateException("RSS native fixture response uncertain; never retry an attempted POST", error)
        }
    }
}

/** The original native synthetic sender reaches ONLY the current audited Caddy
 * ingress-control IPv4. The URL hostname/SNI/PKIX and exact served DER leaf
 * remain social.datamancy.net; no host DNS or process-wide resolver override.
 * RESTORE uses the separately sealed restricted original-host bridge below. */
internal class PinnedRssMastodonHttp(private val origin: URI, caFile: Path, caSha256: String,
    private val privateAddress: String? = null, private val servedLeafSha256: String? = null) : RssHttp {
    private val socketFactory: javax.net.ssl.SSLSocketFactory
    init {
        val octets=privateAddress?.split('.')?.map { it.toIntOrNull() }.orEmpty()
        require(origin.toString() == "https://social.datamancy.net" &&
            caSha256.matches(Regex("[a-f0-9]{64}")) &&
            servedLeafSha256?.matches(Regex("[a-f0-9]{64}")) == true &&
            octets.size==4 && octets.all { it != null && it in 0..255 } &&
            InetAddress.getByAddress(octets.map { requireNotNull(it).toByte() }.toByteArray()).let {
                it.hostAddress==privateAddress && it.isSiteLocalAddress }) {
            "Only an exact selected private original Caddy address and served leaf are eligible"
        }
        val ca = ReleasePrivateFiles.read(caFile, 65536)
        require(ReleaseLocks.sha256(ca) == caSha256) { "Canonical Mastodon CA revision changed" }
        val authority = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(ca)) as java.security.cert.X509Certificate
        authority.checkValidity()
        val anchors = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null); setCertificateEntry("p0v3-canonical-mastodon", authority)
        }
        val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(anchors) }
        val authorityManager=trust.trustManagers.filterIsInstance<X509TrustManager>().single()
        val pinned=object : X509TrustManager {
            override fun getAcceptedIssuers()=authorityManager.acceptedIssuers
            override fun checkClientTrusted(chain:Array<java.security.cert.X509Certificate>,authType:String) =
                authorityManager.checkClientTrusted(chain,authType)
            override fun checkServerTrusted(chain:Array<java.security.cert.X509Certificate>,authType:String) {
                authorityManager.checkServerTrusted(chain,authType)
                require(chain.isNotEmpty() && ReleaseLocks.sha256(chain.first().encoded)==servedLeafSha256) {
                    "Selected original Caddy served leaf changed before credential transfer"
                }
            }
        }
        val ssl = SSLContext.getInstance("TLS").apply { init(null, arrayOf(pinned), null) }
        socketFactory = PrivatePinnedSocketFactory(ssl.socketFactory, origin.host, requireNotNull(privateAddress))
    }
    override fun request(method: String, uri: URI, headers: Map<String, String>, body: String): RssHttpReply {
        val post = if (method == "POST") runCatching { Json.parseToJsonElement(body).jsonObject }.getOrNull() else null
        require(uri.scheme == "https" && uri.host == origin.host && uri.port == -1 &&
            uri.userInfo == null && uri.rawQuery == null && uri.rawFragment == null &&
            ((method == "GET" && body.isEmpty() &&
                (uri.rawPath == "/api/v1/accounts/verify_credentials" ||
                    uri.rawPath.matches(Regex("/api/v1/statuses/[0-9]{1,32}(/source)?")))) ||
                method == "POST" && uri.rawPath == "/api/v1/statuses" && body.length in 1..16384 &&
                post?.keys == setOf("status", "visibility") &&
                post?.get("visibility")?.jsonPrimitive?.content == "direct" &&
                post?.get("status")?.jsonPrimitive?.content?.let { text ->
                    text.codePointCount(0, text.length) in 1..500 && '@' !in text
                } == true) &&
            headers["Authorization"]?.matches(Regex("Bearer [A-Za-z0-9_.-]{20,256}")) == true &&
            (method == "GET" || headers["Idempotency-Key"]?.matches(Regex("[a-f0-9]{64}")) == true &&
                headers["Content-Type"] == "application/json")) {
            "Canonical synthetic Mastodon access is exact direct-status or author-owned readback only"
        }
        require(headers.keys.all { it in setOf("Authorization","Accept","Idempotency-Key","Content-Type") } &&
            headers.values.all { it.length in 1..512 && '\r' !in it && '\n' !in it })
        val postBytes=if(method=="POST") body.toByteArray(Charsets.UTF_8) else ByteArray(0)
        try {
            // HttpsURLConnection calls SSLSocketFactory.createSocket() without
            // a hostname on this JDK; its default then resolves via public
            // DNS. Open the pinned private TCP socket explicitly instead.
            (socketFactory.createSocket(origin.host,443) as javax.net.ssl.SSLSocket).use { tls ->
                require(tls.inetAddress.hostAddress==privateAddress && tls.port==443)
                tls.soTimeout=20_000
                tls.startHandshake() // original-host SNI and PKIX, never a disabled verifier
                val leaf=tls.session.peerCertificates.first() as java.security.cert.X509Certificate
                require(ReleaseLocks.sha256(leaf.encoded)==servedLeafSha256) {
                    "Original Caddy leaf changed before synthetic request"
                }
                return PinnedRssHttp11.exchange(tls,method,uri.rawPath,headers,postBytes)
            }
        } catch (error: Exception) {
            if (error is InterruptedException) Thread.currentThread().interrupt()
            throw IllegalStateException("Private synthetic Mastodon exchange uncertain; never resend",error)
        }
    }
}

/** Strict bounded HTTP/1.1 over the already connected, original-SNI/PKIX and
 * private-address-pinned TLS socket. No URLConnection/resolver/proxy path is
 * involved; no redirect, compression, streaming or unbounded close read. */
internal object PinnedRssHttp11 {
    private const val MAX=2_097_152
    fun exchange(tls:javax.net.ssl.SSLSocket,method:String,path:String,
        headers:Map<String,String>,body:ByteArray):RssHttpReply {
        require(method=="POST" && path=="/api/v1/statuses" || method=="GET" &&
            (path=="/api/v1/accounts/verify_credentials" ||
                path.matches(Regex("/api/v1/statuses/[0-9]{1,32}(/source)?"))))
        require(body.size<=16384 && (method=="POST" || body.isEmpty()))
        val request=buildString {
            append(method).append(' ').append(path).append(" HTTP/1.1\r\n")
            append("Host: social.datamancy.net\r\nConnection: close\r\nAccept-Encoding: identity\r\n")
            append("User-Agent: PlatformZero-RSS-synthetic-qualification/1.0\r\n")
            headers.toSortedMap().forEach { (name,value) ->
                require(name in setOf("Authorization","Accept","Idempotency-Key","Content-Type") &&
                    value.length in 1..512 && value.all { it.code in 32..126 })
                append(name).append(": ").append(value).append("\r\n")
            }
            if(method=="POST") append("Content-Length: ").append(body.size).append("\r\n")
            append("\r\n")
        }.toByteArray(Charsets.US_ASCII)
        require(request.size<=4096)
        tls.outputStream.apply { write(request);if(body.isNotEmpty()) write(body);flush() }
        val input=BufferedInputStream(tls.inputStream)
        var headerBytes=0
        fun line():String {
            val bytes=ByteArrayOutputStream()
            while(true) {
                val b=input.read()
                require(b>=0 && ++headerBytes<=16384 && bytes.size()<=8192) {
                    "Missing or oversized private HTTP header"
                }
                if(b==10) {
                    val raw=bytes.toByteArray()
                    require(raw.isNotEmpty() && raw.last()==13.toByte()) { "Private HTTP requires CRLF" }
                    return String(raw,0,raw.size-1,Charsets.US_ASCII)
                }
                bytes.write(b)
            }
        }
        val first=line()
        val status=Regex("HTTP/1\\.[01] ([1-5][0-9]{2})(?: [^\\r\\n]*)?").matchEntire(first)
            ?.groupValues?.get(1)?.toInt() ?: error("Non-HTTP private response")
        require(status !in 100..199 && status !in 300..399) { "Canonical Mastodon redirect/interim forbidden" }
        val values=linkedMapOf<String,MutableList<String>>()
        while(true) {
            val row=line()
            if(row.isEmpty()) break
            val key=row.substringBefore(':')
            val value=row.substringAfter(':',"").trim()
            require(key.matches(Regex("[A-Za-z0-9-]{1,64}")) && ':' in row && value.length<=8192)
            values.getOrPut(key.lowercase()){mutableListOf()}.add(value)
        }
        require(values["content-encoding"].orEmpty().all { it.equals("identity",true) })
        val transfer=values["transfer-encoding"].orEmpty()
        val length=values["content-length"].orEmpty()
        require(transfer.isEmpty() || transfer.size==1 && transfer.single().equals("chunked",true) && length.isEmpty())
        require(length.size<=1)
        val bytes=when {
            transfer.isNotEmpty()-> {
                val out=ByteArrayOutputStream()
                while(true) {
                    val chunk=line().substringBefore(';').toLongOrNull(16)
                    require(chunk!=null && chunk in 0L..MAX.toLong() && out.size()+chunk<=MAX)
                    if(chunk==0L) { require(line().isEmpty()) { "Private HTTP trailers not admitted" };break }
                    val next=input.readNBytes(chunk.toInt())
                    require(next.size==chunk.toInt() && input.read()==13 && input.read()==10)
                    out.write(next)
                }
                out.toByteArray()
            }
            length.isNotEmpty()-> {
                val size=length.single().toIntOrNull()
                require(size!=null && size in 0..MAX)
                input.readNBytes(size).also { require(it.size==size) }
            }
            else->input.readNBytes(MAX+1).also { require(it.size<=MAX) }
        }
        return RssHttpReply(status,bytes,values.mapValues { it.value.singleOrNull().orEmpty() })
    }
}

internal fun rssOriginalMemberName(sourceGeneration:String,targetGeneration:String):String {
    require(sourceGeneration.matches(Regex("q-[a-f0-9]{12}")) &&
        targetGeneration.matches(Regex("q-[a-f0-9]{12}")) && sourceGeneration!=targetGeneration)
    return GenerationAssembly.memberName(sourceGeneration,CanonicalSharedYamlGraph.R9_ASSEMBLY_RECIPE)
}

/** RESTORE never opens an unaudited socket or borrows a fake persistent client PID. Each GET
 * uses A13's one-use controller-native client inside the sealed target namespace, with the
 * original host/SNI, original leaf, source/target pins and live RSS phase+case claims. */
internal class RssRestoredMastodonHttp(private val generation: Path, private val bridgeFile: Path,
    private val bridgeSha256: String, private val caFile: Path, private val caSha256: String,
    private val tokenFile: Path, private val account: String) : RssHttp {
    private val host = "social.datamancy.net"
    private val bridge: RestoredBridgeBinding
    private val ingress: RestoredIngressClient
    init {
        require(generation == GenerationRuntime.BASE.resolve(generation.fileName) &&
            generation.fileName.toString().matches(Regex("q-[a-f0-9]{12}")) &&
            account.matches(Regex("(?:rss_[a-z0-9_]+|rssq_[a-f0-9]{12})")) &&
            bridgeSha256.matches(Regex("[a-f0-9]{64}")) && caSha256.matches(Regex("[a-f0-9]{64}")))
        val bindingBytes = ReleasePrivateFiles.read(bridgeFile, 1048576)
        require(ReleaseLocks.sha256(bindingBytes) == bridgeSha256) { "Changed original-host bridge binding" }
        val intent = Json.decodeFromString<RestoredBridgeIntent>(bindingBytes.decodeToString(throwOnInvalidSequence = true))
        bridge = intent.binding
        require(intent.action == "install" && bridge.targetGeneration == generation.fileName.toString() &&
            host in bridge.originalHosts && "rss-mastodon" in bridge.nativeClientCapabilities)
        fun bundle(root: Path, expected: String): GenerationBundle {
            require(root == GenerationRuntime.BASE.resolve(expected))
            val parsed = Json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(
                root.resolve("bundle.json"), 4194304).decodeToString(throwOnInvalidSequence = true))
            require(parsed.request.id == expected && parsed.members.isNotEmpty())
            return parsed
        }
        require(bridge.sourceGeneration != bridge.targetGeneration) {
            "RESTORE cannot use the target as its original stopped source"
        }
        val source = bundle(GenerationRuntime.BASE.resolve(bridge.sourceGeneration), bridge.sourceGeneration)
        val target = bundle(generation, bridge.targetGeneration)
        val sourceName = rssOriginalMemberName(bridge.sourceGeneration,bridge.targetGeneration)
        val targetName = GenerationAssembly.memberName(bridge.targetGeneration,
            CanonicalSharedYamlGraph.R9_ASSEMBLY_RECIPE)
        require(sourceName != targetName && source.members.size == 1 && target.members.size == 1 &&
            source.request.store == RuntimeStore.CANONICAL_V2 && target.request.store == RuntimeStore.CANONICAL_V2)
        val sourcePin = source.members.single { it.member.name == sourceName }
        val targetPin = target.members.single { it.member.name == targetName &&
            it.runtimeFingerprint == bridge.targetFingerprint }
        require(sourcePin.spec.name == sourceName && targetPin.spec.name == targetName &&
            sourcePin.spec.fragmentBinding?.recipe == CanonicalSharedYamlGraph.RECIPE &&
            targetPin.spec.fragmentBinding?.recipe == CanonicalSharedYamlGraph.RECIPE &&
            sourcePin.runtimeFingerprint == PrivateDeployment.expectedFingerprint(sourcePin.spec,sourcePin.inputHashes) &&
            targetPin.runtimeFingerprint == PrivateDeployment.expectedFingerprint(targetPin.spec,targetPin.inputHashes) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(PrivateDeployment.BASE.resolve("$sourceName.json"),4194304)) ==
                sourcePin.manifestSha256 &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(PrivateDeployment.BASE.resolve("$targetName.json"),4194304)) ==
                targetPin.manifestSha256) { "RESTORE requires independently sealed original and target graph members" }
        ingress = RestoredIngressClient.real(generation, bridgeFile, bridgeSha256,
            sourcePin.spec, sourcePin.runtimeFingerprint, targetPin.spec)
    }
    override fun request(method: String, uri: URI, headers: Map<String, String>, body: String): RssHttpReply {
        require(method == "GET" && body.isEmpty() && uri.scheme == "https" && uri.host == host && uri.port == -1 &&
            uri.rawQuery == null && uri.rawFragment == null && uri.userInfo == null &&
            (uri.rawPath == "/api/v1/accounts/verify_credentials" ||
                uri.rawPath.matches(Regex("/api/v1/statuses/[0-9]{1,32}(/source)?")))) {
            "Restored source readback is exact author-owned GET only"
        }
        val token = MastodonRssSender.privateToken(tokenFile)
        require(headers["Authorization"] == "Bearer $token" && headers.keys.all { it in setOf("Authorization", "Accept") }) {
            "Foreign restored RSS bearer refused"
        }
        val caBytes = ReleasePrivateFiles.read(caFile, 65536)
        require(ReleaseLocks.sha256(caBytes) == caSha256)
        val tokenBytes = ReleasePrivateFiles.read(tokenFile, 2048)
        val leafInput = bridge.sourceCertificates.getValue(host)
        val leaf = CertificateFactory.getInstance("X.509").generateCertificate(
            ReleasePrivateFiles.read(Path.of(leafInput.path), 65536).inputStream())
        val leafSha256 = ReleaseLocks.sha256(leaf.encoded)
        val phase = requireNotNull(System.getenv("P0V3_RSS_PHASE_CLAIM_SHA256"))
        val claim = requireNotNull(System.getenv("P0V3_RSS_QUALIFICATION_SHA256"))
        val case = requireNotNull(System.getenv("P0V3_CASE_INVOCATION_ID"))
        val operation = ByteArray(6).also { java.security.SecureRandom().nextBytes(it) }
            .joinToString("") { "%02x".format(it.toInt() and 255) }.let { "r-$it" }
        val input = RssIngressClientRequest(operation = operation, generationId = generation.fileName.toString(),
            bridgeBindingFile = bridgeFile.toString(), bridgeBindingSha256 = bridgeSha256,
            targetFingerprint = bridge.targetFingerprint, clientAddress = bridge.clientAddress,
            clientNetwork = bridge.clientNetwork, originalHost = host, originalLeafSha256 = leafSha256,
            ca = ActivationInput(caFile.toString(), caSha256),
            bearer = ActivationInput(tokenFile.toString(), ReleaseLocks.sha256(tokenBytes)),
            phase = "RESTORE", phaseClaimSha256 = phase, caseClaimSha256 = claim,
            invocationId = case, account = account, botAccount = account.takeIf { it.startsWith("rssq_") }.orEmpty(),
            method = method, path = uri.rawPath)
        val receipt = ingress.request(input)
        require(receipt.operation == operation && receipt.bridgeBindingSha256 == bridgeSha256 &&
            receipt.phaseClaimSha256 == phase && receipt.caseClaimSha256 == claim && receipt.invocationId == case &&
            receipt.leafSha256 == leafSha256 && receipt.targetFingerprint == bridge.targetFingerprint &&
            receipt.targetCaddyPid > 1 && receipt.clientProcessId > 1 && receipt.clientNetworkInode > 1 &&
            receipt.clientAddress == bridge.clientAddress && receipt.clientNetwork == bridge.clientNetwork &&
            Path.of(receipt.responseFile) == bridgeFile.parent.resolve("client.$operation.response.bin"))
        val response = ReleasePrivateFiles.read(Path.of(receipt.responseFile), 1048576)
        require(ReleaseLocks.sha256(response) == receipt.responseSha256 && receipt.status !in 300..399)
        return RssHttpReply(receipt.status, response)
    }
}

@Serializable internal data class RssNativeFixtureServerPlan(val schemaVersion: Int = 1, val generation: String,
    val fixtureId: String, val pack: String, val port: Int, val serverRoot: String, val certificateAuthority: String,
    val caSha256: String, val keyStore: String, val keyStorePasswordFile: String,
    val keyStoreSha256: String, val keyStorePasswordSha256: String,
    val packSourceManifestFile: String? = null, val packSourceManifestSha256: String? = null)

/** Feed-only real HTTPS fixture on generation/case-owned loopback, never a Mastodon clone.
 * The single canonical Mastodon instance receives separately scoped synthetic-bot POSTs;
 * this feed fixture neither receives credentials nor accepts any POST. */
internal object RssNativeFixtureServer {
    private val json = Json { ignoreUnknownKeys = false; encodeDefaults = true }
    private fun plan(path: Path): Pair<RssNativeFixtureServerPlan, ReviewedFeed> {
        val config = json.decodeFromString<RssNativeFixtureServerPlan>(
            ReleasePrivateFiles.read(path, 65536).decodeToString(throwOnInvalidSequence = true))
        require(config.schemaVersion == 1 && config.port in 49152..65535 &&
            config.generation.matches(Regex("q-[a-f0-9]{12}")) &&
            config.fixtureId.matches(Regex("[A-Za-z0-9_-]{1,128}")) &&
            listOf(config.caSha256, config.keyStoreSha256, config.keyStorePasswordSha256)
                .all { it.matches(Regex("[a-f0-9]{64}")) })
        val root = Path.of(config.serverRoot)
        val expected = Path.of("/run/user/${com.sun.security.auth.module.UnixSystem().uid}/rss-fixtures")
            .resolve(config.generation).resolve(config.fixtureId)
        require(root == expected && path == root.resolve("server-plan.json") &&
            root.isAbsolute && root.normalize() == root &&
            Path.of(config.keyStore) == root.resolve("fixture-keystore.p12") &&
            Path.of(config.keyStorePasswordFile) == root.resolve("fixture-keystore.pass") &&
            Path.of(config.certificateAuthority) == root.resolve("fixture-ca.pem")) {
            "Synthetic fixture must have a dedicated runtime-only /run custody root"
        }
        ReleasePrivateFiles.directory(root)
        ReleasePrivateFiles.directory(root.parent)
        val selected = RssPacks.load().firstOrNull { it.pack == config.pack }
            ?: error("Unpinned synthetic fixture pack")
        require((config.packSourceManifestFile==null)==(config.packSourceManifestSha256==null))
        if(config.packSourceManifestFile!=null) qualificationManifest(config)
        return config to selected
    }
    internal fun tls(config: RssNativeFixtureServerPlan): SSLContext {
        val ca = ReleasePrivateFiles.read(Path.of(config.certificateAuthority), 65536)
        require(ReleaseLocks.sha256(ca) == config.caSha256) { "Fixture server CA pin changed" }
        val certificate = CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(ca)) as java.security.cert.X509Certificate
        certificate.checkValidity()
        val passwordBytes = ReleasePrivateFiles.read(Path.of(config.keyStorePasswordFile), 1024)
        require(ReleaseLocks.sha256(passwordBytes) == config.keyStorePasswordSha256)
        val password = passwordBytes.decodeToString(throwOnInvalidSequence = true).trimEnd('\n').toCharArray()
        require(password.size in 24..256)
        val store = KeyStore.getInstance("PKCS12")
        try {
            val keyBytes = ReleasePrivateFiles.read(Path.of(config.keyStore), 65536)
            require(ReleaseLocks.sha256(keyBytes) == config.keyStoreSha256)
            keyBytes.inputStream().use { store.load(it, password) }
            val aliases = store.aliases()
            require(aliases.hasMoreElements())
            val alias = aliases.nextElement()
            require(!aliases.hasMoreElements()) { "Fixture PKCS12 must have one exact identity" }
            val leaf = store.getCertificateChain(alias)?.firstOrNull()
                as? java.security.cert.X509Certificate ?: error("Fixture TLS identity missing")
            leaf.checkValidity(); leaf.verify(certificate.publicKey)
            require(leaf.subjectAlternativeNames?.any { entry -> entry[0] == 7 && entry[1] == "127.0.0.1" } == true) {
                "Fixture certificate lacks loopback IP SAN"
            }
            val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, password) }
            return SSLContext.getInstance("TLS").apply { init(keys.keyManagers, null, null) }
        } finally { password.fill('\u0000') }
    }
    private fun write(exchange: HttpExchange, status: Int, body: ByteArray, contentType: String = "application/json") {
        exchange.responseHeaders.set("Content-Type", "$contentType; charset=utf-8")
        exchange.responseHeaders.set("Cache-Control", "no-store")
        exchange.sendResponseHeaders(status, body.size.toLong())
        exchange.responseBody.use { it.write(body) }
    }
    private fun content(feed: ReviewedFeed, fresh: Boolean): ByteArray {
        val items = listOf("synthetic-baseline" to "Original synthetic baseline") +
            (if (fresh) listOf("synthetic-new" to "New synthetic item") else emptyList())
        val payload = items.joinToString("") { (id, title) ->
            "<item><guid>$id</guid><title>$title</title><link>https://fixture.invalid/${if (id == "synthetic-new") "new" else "original"}</link></item>"
        }
        require(feed.pack in RssPacks.load().map { it.pack }.toSet())
        return "<rss><channel>$payload</channel></rss>".toByteArray(Charsets.UTF_8)
    }
    /** Exact social-owned, generation-local XML producer; no new listener,
     * Caddy path, upstream feed request, credential or public route. Reopen
     * immutable files on EVERY GET, so later changes fail without an ACK. */
    private fun qualificationManifest(config:RssNativeFixtureServerPlan):RssQualificationPackManifest {
        val file=Path.of(requireNotNull(config.packSourceManifestFile))
        val root=GenerationRuntime.BASE.resolve(config.generation)
        val caseId=file.parent.fileName.toString()
        require(caseId.matches(Regex("case-[a-f0-9-]{36}")) &&
            file==root.resolve("rss/qualification-pack-source/$caseId/manifest.json") &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(file,65536))==config.packSourceManifestSha256)
        val manifest=json.decodeFromString<RssQualificationPackManifest>(ReleasePrivateFiles.read(file,65536)
            .decodeToString(throwOnInvalidSequence=true))
        val reviewed=RssPacks.load()
        require(manifest.schemaVersion==1 && manifest.generation==config.generation &&
            manifest.invocationId==caseId && manifest.pack==config.pack &&
            manifest.bundleSha256.matches(Regex("[a-f0-9]{64}")) &&
            manifest.phaseClaimSha256.matches(Regex("[a-f0-9]{64}")) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"),4194304))==
                manifest.bundleSha256 && manifest.feeds.size==47 &&
            manifest.feeds.map { it.id }.toSet()==reviewed.map { it.feed.id }.toSet())
        for(feed in reviewed) {
            val entry=manifest.feeds.single { it.id==feed.feed.id }
            val bytes=ReleasePrivateFiles.read(file.parent.resolve("feeds/${entry.id}.xml"),65536)
            require(entry.account==feed.feed.account && entry.originalUrl==feed.feed.url &&
                entry.path=="/feed/pack/${entry.id}" &&
                ReleaseLocks.sha256(bytes)==entry.responseSha256 &&
                bytes.contentEquals(RssQualificationPackSource.xml(feed)))
        }
        return manifest
    }
    internal fun selectedPackFeed(pack:String,id:String):ReviewedFeed? {
        require(pack in RssPacks.load().map { it.pack }.toSet() &&
            id.matches(Regex("[a-z0-9][a-z0-9-]{0,63}")))
        return RssPacks.load().singleOrNull { it.feed.id==id && it.pack==pack }
    }
    private class Handler(private val feed: ReviewedFeed,
        private val config:RssNativeFixtureServerPlan) : com.sun.net.httpserver.HttpHandler {
        override fun handle(exchange: HttpExchange) {
            try { synchronized(this) { respond(exchange) } }
            catch (error: Exception) {
                // Never disclose certificate/key paths or internal fixture exceptions.
                runCatching { write(exchange, 500, "{\"error\":\"feed fixture failed\"}".toByteArray()) }
            } finally { exchange.close() }
        }
        private fun respond(exchange: HttpExchange) {
            require(exchange.remoteAddress.address.isLoopbackAddress &&
                exchange.localAddress.address.hostAddress == "127.0.0.1" && exchange.requestURI.rawQuery == null &&
                exchange.requestURI.rawFragment == null) { "Fixture accepts loopback-only exact paths" }
            val method = exchange.requestMethod
            val path = exchange.requestURI.path
            if (method == "GET" && path in setOf("/feed/baseline", "/feed/new") &&
                exchange.requestHeaders.getFirst("Authorization") == null &&
                exchange.requestHeaders.getFirst("Cookie") == null) {
                write(exchange, 200, content(feed, path == "/feed/new"), "application/rss+xml")
            } else if (method == "GET" && path.matches(Regex("/feed/pack/[a-z0-9][a-z0-9-]{0,63}")) &&
                exchange.requestHeaders.getFirst("Authorization") == null &&
                exchange.requestHeaders.getFirst("Cookie") == null &&
                config.packSourceManifestFile!=null) {
                val manifest=qualificationManifest(config)
                val id=path.removePrefix("/feed/pack/")
                val selected=selectedPackFeed(config.pack,id)
                val entry=manifest.feeds.singleOrNull { it.id==id }
                if(selected==null || entry==null || entry.path!=path)
                    write(exchange,404,"{\"error\":\"not a feed route\"}".toByteArray())
                else {
                    val bytes=ReleasePrivateFiles.read(Path.of(config.packSourceManifestFile).parent
                        .resolve("feeds/$id.xml"),65536)
                    require(ReleaseLocks.sha256(bytes)==entry.responseSha256 &&
                        bytes.contentEquals(RssQualificationPackSource.xml(selected)))
                    write(exchange,200,bytes,"application/rss+xml")
                }
            } else write(exchange, 404, "{\"error\":\"not a feed route\"}".toByteArray())
        }
    }
    fun serve(config: Path): Nothing {
        val (binding, feed) = plan(config)
        val case = System.getenv("P0V3_CASE_INVOCATION_ID")
        val claim = System.getenv("P0V3_RSS_QUALIFICATION_SHA256")
        val phase = System.getenv("P0V3_RSS_PHASE_CLAIM_SHA256")
        require(case?.matches(Regex("case-[a-f0-9-]{36}")) == true && claim?.matches(Regex("[a-f0-9]{64}")) == true &&
            phase?.matches(Regex("[a-f0-9]{64}")) == true &&
            (binding.packSourceManifestFile==null || qualificationManifest(binding).let {
                it.invocationId==case && it.phaseClaimSha256==phase && it.pack==binding.pack
            })) {
            "Feed fixture process must be bound to the exact active generation/case/phase"
        }
        val scope = GenerationRssOperations()
        scope.withExclusion {
            val generation = GenerationRuntime.BASE.resolve(binding.generation)
            scope.requireWritableGeneration(generation, case, claim, phase)
            RssQualificationIntents.requireFixtureBinding(generation, requireNotNull(case), binding.fixtureId, true)
        }
        val ssl = tls(binding)
        val host = InetAddress.getByName("127.0.0.1")
        val server = HttpsServer.create(InetSocketAddress(host, binding.port), 16)
        server.httpsConfigurator = HttpsConfigurator(ssl)
        server.createContext("/", Handler(feed,binding))
        server.start()
        try { CountDownLatch(1).await() } finally { server.stop(0) }
        error("Feed-only TLS fixture server interrupted")
    }
}

/** XML is untrusted. No DTD, external entities, XInclude, schemas or network access during parsing. */
internal object RssXml {
    fun parse(bytes: ByteArray, source: URI): List<FeedItem> {
        require(bytes.size in 1..2_097_152) { "Empty or oversized feed" }
        val factory = DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = true
            isXIncludeAware = false
            isExpandEntityReferences = false
            setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
            setFeature("http://xml.org/sax/features/external-general-entities", false)
            setFeature("http://xml.org/sax/features/external-parameter-entities", false)
            setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")
            setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "")
        }
        val builder = factory.newDocumentBuilder().apply {
            setErrorHandler(object : ErrorHandler {
                override fun warning(e: SAXParseException) { throw IllegalArgumentException("Invalid feed XML") }
                override fun error(e: SAXParseException) { throw IllegalArgumentException("Invalid feed XML") }
                override fun fatalError(e: SAXParseException) { throw IllegalArgumentException("Invalid feed XML") }
            })
        }
        val root = builder.parse(ByteArrayInputStream(bytes)).documentElement
        val atom = root.localName == "feed" && root.namespaceURI == "http://www.w3.org/2005/Atom"
        val rdf = root.localName == "RDF" && root.namespaceURI == "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
        val entries = when {
            atom -> children(root, "entry", "http://www.w3.org/2005/Atom")
            rdf -> children(root, "item", "http://purl.org/rss/1.0/")
            root.tagName == "rss" -> children(children(root, "channel", null).single(), "item", null)
            else -> throw IllegalArgumentException("Unsupported feed format")
        }
        require(entries.size <= 200) { "Too many feed items" }
        val items = entries.map { entry ->
            val ns = when { atom -> "http://www.w3.org/2005/Atom"; rdf -> "http://purl.org/rss/1.0/"; else -> null }
            fun text(name: String) = children(entry, name, ns).singleOrNull()?.textContent?.trim().orEmpty()
            val title = text("title").replace(Regex("<[^>]*>"), "").trim()
            val href = if (atom) children(entry, "link", ns).filter {
                it.getAttribute("rel") in setOf("", "alternate") && it.getAttribute("type") in setOf("", "text/html")
            }.singleOrNull()?.getAttribute("href").orEmpty() else text("link")
            require(href.isNotBlank()) { "Missing or ambiguous article link" }
            val link = source.resolve(href)
            val id = (if (rdf) entry.getAttributeNS("http://www.w3.org/1999/02/22-rdf-syntax-ns#", "about")
                else text(if (atom) "id" else "guid")).ifBlank { link.toString() }
            require(id.length in 1..512 && title.length in 1..1000 && link.toString().length <= 2048 &&
                link.scheme == "https" && link.host != null && link.userInfo == null) { "Unsafe feed item" }
            FeedItem(id, title, link.toString())
        }
        require(items.map { it.id }.distinct().size == items.size) { "Duplicate article identity" }
        return items
    }
    private fun children(element: Element, name: String, namespace: String?): List<Element> =
        (0 until element.childNodes.length).mapNotNull { element.childNodes.item(it) as? Element }
            .filter { it.localName == name && it.namespaceURI == namespace }
}

internal class RssFetcher(private val http: RssHttp) {
    fun fetch(feed: ReviewedFeed): List<FeedItem> {
        require(feed in RssPacks.load()) { "Unpinned feed source" }
        var uri = URI(feed.feed.url)
        val origin = uri
        repeat(4) { hop ->
            val result = http.request("GET", uri, mapOf("Accept" to "application/atom+xml, application/rss+xml, application/xml, text/xml",
                "Accept-Encoding" to "gzip"), "")
            if (result.status in setOf(301, 302, 303, 307, 308)) {
                require(hop < 3) { "Too many feed redirects" }
                val target = uri.resolve(requireNotNull(result.headers["location"]) { "Missing redirect target" })
                val allowedHosts = setOf(origin.host) + if (feed.feed.id == "npr-world") setOf("feeds.npr.org") else emptySet()
                require(target.scheme == "https" && target.host in allowedHosts && target.port == origin.port &&
                    target.userInfo == null && target.fragment == null) { "Unapproved feed redirect" }
                uri = target
            } else {
                require(result.status == 200) { "Feed HTTP request failed: ${result.status}" }
                val bytes = decodeBody(result)
                return RssXml.parse(if (feed.feed.id == "rest-of-world") repairPublisherAmpersands(bytes) else bytes, uri)
            }
        }
        error("Feed redirect loop")
    }
    /** Rest of World's thumbnail URLs contain unescaped query separators. Preserve CDATA/comments and entities. */
    internal fun repairPublisherAmpersands(bytes: ByteArray): ByteArray {
        val text = Charsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(bytes)).toString()
        val pattern = Regex("<!\\[CDATA\\[[\\s\\S]*?]]>|<!--[\\s\\S]*?-->|&(?!amp;|lt;|gt;|quot;|apos;|#[0-9]+;|#x[0-9a-fA-F]+;)")
        return pattern.replace(text) { if (it.value == "&") "&amp;" else it.value }.toByteArray(Charsets.UTF_8)
    }
    internal fun decodeBody(reply: RssHttpReply): ByteArray {
        require(reply.body.size <= 2_097_152)
        return when (reply.headers["content-encoding"]?.lowercase()) {
            null, "", "identity" -> reply.body
            "gzip" -> java.util.zip.GZIPInputStream(ByteArrayInputStream(reply.body)).use {
                it.readNBytes(2_097_153).also { bytes -> require(bytes.size <= 2_097_152) { "Expanded feed exceeds limit" } }
            }
            else -> throw IllegalArgumentException("Unsupported feed compression")
        }
    }
}

internal class MastodonRssSender(private val origin: URI, private val token: (String) -> String, private val http: RssHttp) {
    init {
        require(origin.scheme == "https" && origin.host != null && origin.userInfo == null &&
            origin.rawQuery == null && origin.rawFragment == null && origin.path in setOf("", "/")) { "HTTPS Mastodon origin required" }
    }
    companion object {
        fun privateToken(path: Path): String {
            require(path.isAbsolute && Files.isRegularFile(path, NOFOLLOW_LINKS) && path.toRealPath() == path &&
                Files.size(path) in 20..512 &&
                (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == com.sun.security.auth.module.UnixSystem().uid &&
                (Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong() == 1L && Files.getPosixFilePermissions(path).none {
                    it.name.startsWith("GROUP_") || it.name.startsWith("OTHERS_")
                }) { "Private per-account token file required" }
            return Files.readString(path).trim().also {
                require(it.matches(Regex("[A-Za-z0-9_.-]{20,256}"))) { "Invalid token encoding" }
            }
        }
    }
    fun send(draft: DraftPost, authority: RssPublicationAuthority? = null): String {
        require(RssPacks.reviewedForPublication()) { "RSS publication review pending" }
        val permit = requireNotNull(authority) { "Release-bound RSS publication authority required" }
        permit.verify()
        return sendReviewed(draft, permit::verify)
    }
    /** Read-only readiness check; deliberately usable before publication authorization. */
    fun verifyAccount(account: String): String {
        require(RssPacks.load().any { it.feed.account == account }) { "Unpinned RSS account" }
        return verifiedIdentity(account, bearer(account))
    }
    /** Fresh bootstrap creates a separate read-only observer that follows the
     * 47 feed bots. Never use this credential to publish or treat it as a feed. */
    fun verifyObserver(): String {
        val verify = http.request("GET", origin.resolve("/api/v1/accounts/verify_credentials"),
            mapOf("Authorization" to "Bearer ${bearer("rss_observer")}", "Accept" to "application/json"), "")
        require(verify.status == 200) { "Fresh RSS observer verification failed" }
        val account = Json.parseToJsonElement(verify.body.decodeToString()).jsonObject
        val id = account.getValue("id").jsonPrimitive.content
        require(id.matches(Regex("[0-9]{1,32}")) &&
            account.getValue("acct").jsonPrimitive.content == "rss_observer" &&
            account.getValue("following_count").jsonPrimitive.content.toInt() >= 47) {
            "Foreign or incomplete fresh RSS observer custody"
        }
        return id
    }
    private fun bearer(account: String): String = token(account).also {
        require(it.matches(Regex("[A-Za-z0-9_.-]{20,256}"))) { "Invalid token encoding" }
    }
    private fun verifiedIdentity(expectedAccount: String, bearer: String): String {
        val verify = http.request("GET", origin.resolve("/api/v1/accounts/verify_credentials"),
            mapOf("Authorization" to "Bearer $bearer", "Accept" to "application/json"), "")
        require(verify.status == 200) { "RSS account verification failed" }
        val account = Json.parseToJsonElement(verify.body.decodeToString()).jsonObject
        val accountId = account.getValue("id").jsonPrimitive.content
        require(accountId.matches(Regex("[0-9]{1,32}")) && account.getValue("acct").jsonPrimitive.content == expectedAccount &&
            account.getValue("bot").jsonPrimitive.content == "true") { "RSS token belongs to wrong account or non-bot" }
        return accountId
    }
    /** Explicit, read-only reconciliation. A 404 never clears the claim or permits a retry; no POST occurs here.
     * Requires read:statuses in addition to the existing account verification scope. No token/scope fallback.
     */
    fun reconcile(store: RssStateStore, expectedChecksum: String, feedId: String, itemId: String,
        statusId: String, nowMillis: Long, gate: PollGate): RssReconciledDelivery? {
        require(gate == PollGate.ACTIVE && statusId.matches(Regex("[0-9]{1,32}")) && nowMillis in 0..253402300799999L)
        return store.reconcileConfirmed(expectedChecksum, feedId, itemId) { pending ->
            val attempted = requireNotNull(pending.attemptedAtMillis)
            require(nowMillis >= attempted && attempted <= 253402300679999L) { "RSS reconciliation clock rollback" }
            val draft = pending.draft
            val feed = RssPacks.load().single { it.feed.id == draft.feedId }
            require(draft.account == feed.feed.account && draft.pack == feed.pack &&
                draft.idempotencyKey == ReleaseLocks.sha256("${draft.account}\u0000${draft.itemId}".toByteArray()))
            val bearer = bearer(draft.account)
            val accountId = verifiedIdentity(draft.account, bearer)
            val headers = mapOf("Authorization" to "Bearer $bearer", "Accept" to "application/json")
            val remote = http.request("GET", origin.resolve("/api/v1/statuses/$statusId"), headers, "")
            if (remote.status == 404) return@reconcileConfirmed null
            require(remote.status == 200) { "RSS status observation failed; claim remains uncertain" }
            val status = Json.parseToJsonElement(remote.body.decodeToString()).jsonObject
            require(status.getValue("id").jsonPrimitive.content == statusId &&
                status.getValue("account").jsonObject.getValue("id").jsonPrimitive.content == accountId &&
                status.getValue("visibility").jsonPrimitive.content == "public" &&
                status["reblog"] in listOf(null, kotlinx.serialization.json.JsonNull)) { "Foreign or non-public RSS status" }
            val created = java.time.Instant.parse(status.getValue("created_at").jsonPrimitive.content).toEpochMilli()
            require(created in maxOf(0, attempted - 120000)..minOf(nowMillis + 120000, attempted + 120000)) { "Status does not match attempted-send time window" }
            val source = http.request("GET", origin.resolve("/api/v1/statuses/$statusId/source"), headers, "")
            require(source.status == 200) { "Author-owned status source is required; no HTML guessing" }
            val text = Json.parseToJsonElement(source.body.decodeToString()).jsonObject
            require(text.getValue("id").jsonPrimitive.content == statusId && text.getValue("text").jsonPrimitive.content == draft.text &&
                text.getValue("spoiler_text").jsonPrimitive.content.isEmpty()) { "RSS status source differs from pending attributed draft" }
            val observation = remote.body.size.toString().toByteArray() + byteArrayOf(0) + remote.body + source.body
            RssReconciledDelivery(draft.feedId, draft.itemId, draft.idempotencyKey, draft.account, statusId, nowMillis, ReleaseLocks.sha256(observation))
        }
    }
    internal fun sendReviewed(draft: DraftPost, beforePost: () -> Unit = {}): String {
        val feed = RssPacks.load().single { it.feed.id == draft.feedId }
        require(draft.account == feed.feed.account && draft.pack == feed.pack &&
            draft.idempotencyKey == ReleaseLocks.sha256("${draft.account}\u0000${draft.itemId}".toByteArray()) &&
            draft.text.isNotBlank() && draft.text.codePointCount(0, draft.text.length) <= 500) { "Invalid RSS draft" }
        val bearer = bearer(draft.account)
        val auth = mapOf("Authorization" to "Bearer $bearer", "Accept" to "application/json")
        val accountId = verifiedIdentity(draft.account, bearer)
        val form = listOf("status" to draft.text, "visibility" to "public").joinToString("&") { (key, value) ->
            "$key=${URLEncoder.encode(value, Charsets.UTF_8)}"
        }
        beforePost() // Reobserve after account verification; revoked authority cannot authorize a POST.
        val reply = http.request("POST", origin.resolve("/api/v1/statuses"), auth + mapOf(
            "Content-Type" to "application/x-www-form-urlencoded", "Idempotency-Key" to draft.idempotencyKey), form)
        require(reply.status in setOf(200, 201)) { "RSS post not confirmed; reconcile pending outbox" }
        val status = Json.parseToJsonElement(reply.body.decodeToString()).jsonObject
        val id = status.getValue("id").jsonPrimitive.content
        require(id.matches(Regex("[0-9]{1,32}")) && status.getValue("account").jsonObject.getValue("id").jsonPrimitive.content == accountId) {
            "RSS response account mismatch; reconcile pending outbox"
        }
        return id
    }
}

internal data class RssPollSummary(val feeds: Int, val observed: Int, val confirmed: Int,
    val failedFeeds: List<String> = emptyList(), val failureTypes: Map<String, String> = emptyMap())
internal class RssWorker(private val store: RssStateStore, private val fetch: (ReviewedFeed) -> List<FeedItem>,
    private val send: (DraftPost) -> String, private val clock: () -> Long = System::currentTimeMillis) {
    fun poll(gate: PollGate, authority: RssPublicationAuthority? = null): RssPollSummary {
        val authorize: () -> Unit = if (gate == PollGate.ACTIVE) requireNotNull(authority) {
            "Release-bound RSS publication authority required"
        }::verify else ({})
        return pollReviewed(gate, RssPacks.reviewedForPublication(), authorize)
    }
    internal fun pollReviewed(gate: PollGate, reviewed: Boolean, authorize: () -> Unit = {}): RssPollSummary {
        if (gate == PollGate.RESTORING) return RssPollSummary(0, 0, 0)
        require(gate != PollGate.ACTIVE || reviewed) { "RSS publication review pending" }
        if (gate == PollGate.ACTIVE) authorize()
        var observed = 0
        var confirmed = 0
        val feeds = RssPacks.load()
        val failed = mutableListOf<String>()
        val failureTypes = mutableMapOf<String, String>()
        for (feed in feeds) {
            if (gate == PollGate.ACTIVE) authorize()
            val items = try { fetch(feed) } catch (e: Exception) {
                if (e is InterruptedException) { Thread.currentThread().interrupt(); throw e }
                failed += feed.feed.id
                failureTypes[feed.feed.id] = e.javaClass.simpleName
                continue
            }
            observed += items.size
            val pending = store.checkpointWithReview(feed, items, gate, clock(), reviewed)
            for (post in pending) {
                authorize()
                if (!store.claim(post, clock())) continue
                val id = try { send(post.draft) } catch (interrupted: InterruptedException) {
                    Thread.currentThread().interrupt(); throw interrupted
                }
                store.confirm(post.draft.feedId, post.draft.itemId, post.draft.idempotencyKey, id)
                confirmed++
            }
        }
        return RssPollSummary(feeds.size, observed, confirmed, failed, failureTypes)
    }
}
