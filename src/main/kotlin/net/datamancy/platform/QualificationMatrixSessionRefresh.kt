package net.datamancy.platform

import java.io.ByteArrayInputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URLEncoder
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** One-use MAS refresh chain; a missing acknowledgement is terminal, never retried.
 * Rotated refresh bytes live only in generation-owner custody, not /case or QClient. */
internal object QualificationMatrixSessionRefresh {
    private val json = Json { ignoreUnknownKeys = false }
    private val token = Regex("[A-Za-z0-9._~+/=-]{40,8192}")
    private val hex = Regex("[a-f0-9]{64}")
    private const val host = "matrix-auth.datamancy.net"
    data class Issued(val access: ByteArray, val sourceAccessSha256: String, val sequence: Int)
    /** Pure case boundary: eight distinct four-refresh Android cases share one rotating
     * credential. A partial case cannot be bypassed and an old invocation cannot replay. */
    internal fun nextOrdinal(count: Int, previousActor: String?, actor: String,
        expectedSequence: Int): Int {
        require(count in 0..31 && actor.matches(Regex("case-[a-f0-9-]{36}")) &&
            (count == 0) == (previousActor == null) && expectedSequence in 1..4 &&
            expectedSequence == count % 4 + 1 &&
            (count == 0 || if (count % 4 == 0) previousActor != actor else previousActor == actor)) {
            "Unacknowledged or replayed Android refresh group"
        }
        return count + 1
    }
    private fun root(generation: String, nativeInvocation: String): Path {
        val parent = GenerationRuntime.BASE.resolve(generation).resolve("qualification-matrix-sessions")
        if (!Files.exists(parent, NOFOLLOW_LINKS)) {
            ReleasePrivateFiles.directory(parent.parent)
            Files.createDirectory(parent, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(parent.parent)
        }
        ReleasePrivateFiles.directory(parent)
        val source = parent.resolve(nativeInvocation)
        if (!Files.exists(source, NOFOLLOW_LINKS)) {
            Files.createDirectory(source, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(parent)
        }
        ReleasePrivateFiles.directory(source)
        return source
    }
    fun confirm(generation: String, nativeInvocation: String, androidInvocation: String,
        sequence: Int, accessSha256: String, sourceAccessSha256: String,
        selectedManifestSha256: String) {
        require(sequence in 1..4 && listOf(accessSha256,sourceAccessSha256,selectedManifestSha256)
            .all(hex::matches))
        val dir = root(generation,nativeInvocation)
        val names = Files.list(dir).use { stream -> stream.map { it.fileName.toString() }.toList() }
        require(names.size in 4..128 && names.size % 4 == 0)
        val count = names.size / 4
        require(count in 1..32 && (count - 1) % 4 + 1 == sequence &&
            (1..count).all { n -> listOf("intent","result","access","refresh").all { ext ->
                "%04d.$ext".format(n) in names } }) {
            "Unacknowledged owner refresh effect cannot supply an Android session"
        }
        var previous: String? = null
        var group: String? = null
        val seen = mutableSetOf<String>()
        for (n in 1..count) {
            val prefix = "%04d".format(n)
            val intentBytes = ReleasePrivateFiles.read(dir.resolve("$prefix.intent"),8192)
            val result = json.parseToJsonElement(ReleasePrivateFiles.read(dir.resolve("$prefix.result"),8192)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            val effect = json.parseToJsonElement(intentBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
            val actor = effect.getValue("androidInvocationId").jsonPrimitive.content
            if ((n - 1) % 4 == 0) {
                require(actor.matches(Regex("case-[a-f0-9-]{36}")) && seen.add(actor) &&
                    (n == 1 || previous != null)) { "Android case attempted to replay a prior refresh group" }
                group = actor
            }
            require(actor == group &&
                effect.getValue("nativeInvocationId").jsonPrimitive.content == nativeInvocation &&
                effect.getValue("generationId").jsonPrimitive.content == generation &&
                effect.getValue("sourceAccessSha256").jsonPrimitive.content == sourceAccessSha256 &&
                effect.getValue("selectedManifestSha256").jsonPrimitive.content == selectedManifestSha256 &&
                (previous == null || effect.getValue("priorRefreshSha256").jsonPrimitive.content == previous) &&
                result.getValue("androidInvocationId").jsonPrimitive.content == actor &&
                result.getValue("intentSha256").jsonPrimitive.content == ReleaseLocks.sha256(intentBytes) &&
                result.getValue("accessSha256").jsonPrimitive.content == ReleaseLocks.sha256(
                    ReleasePrivateFiles.read(dir.resolve("$prefix.access"),8192)) &&
                result.getValue("refreshSha256").jsonPrimitive.content == ReleaseLocks.sha256(
                    ReleasePrivateFiles.read(dir.resolve("$prefix.refresh"),8192)))
            previous = result.getValue("refreshSha256").jsonPrimitive.content
        }
        require(group == androidInvocation && json.parseToJsonElement(ReleasePrivateFiles.read(
            dir.resolve("%04d.result".format(count)),8192).decodeToString(throwOnInvalidSequence = true))
            .jsonObject.getValue("accessSha256").jsonPrimitive.content == accessSha256) {
            "Current target bearer is not the last acknowledged owner refresh"
        }
    }
    /** Last acknowledged source refresh under the stopped original generation. Never
     * use the original PKCE refresh after a completed INSTALL Android rotation. */
    fun inheritedRefresh(sourceGeneration: String, nativeInvocation: String,
        originalAccessSha256: String, originalRefresh: ByteArray,
        sourceManifestSha256: String): ByteArray {
        require(originalAccessSha256.matches(hex) && sourceManifestSha256.matches(hex) &&
            token.matches(originalRefresh.decodeToString(
            throwOnInvalidSequence = true)))
        require(sourceGeneration.matches(Regex("q-[a-f0-9]{12}")) &&
            nativeInvocation.matches(Regex("case-[a-f0-9-]{36}")))
        val directory = GenerationRuntime.BASE.resolve(sourceGeneration)
            .resolve("qualification-matrix-sessions").resolve(nativeInvocation)
        if (!Files.exists(directory, NOFOLLOW_LINKS)) return originalRefresh
        ReleasePrivateFiles.directory(directory)
        val names = Files.list(directory).use { it.map { path -> path.fileName.toString() }.toList() }
        if (names.isEmpty()) return originalRefresh
        require(names.size in 16..128 && names.size % 16 == 0)
        val count = names.size / 4
        val first = json.parseToJsonElement(ReleasePrivateFiles.read(directory.resolve("0001.intent"),8192)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        val last = json.parseToJsonElement(ReleasePrivateFiles.read(directory.resolve(
            "%04d.intent".format(count)),8192).decodeToString(throwOnInvalidSequence = true)).jsonObject
        val invocation = last.getValue("androidInvocationId").jsonPrimitive.content
        val manifest = first.getValue("selectedManifestSha256").jsonPrimitive.content
        require(manifest == sourceManifestSha256)
        confirm(sourceGeneration,nativeInvocation,invocation,4,
            json.parseToJsonElement(ReleasePrivateFiles.read(directory.resolve(
                "%04d.result".format(count)),8192).decodeToString(throwOnInvalidSequence = true))
                .jsonObject.getValue("accessSha256").jsonPrimitive.content,
            originalAccessSha256,manifest)
        require(first.getValue("priorRefreshSha256").jsonPrimitive.content ==
            ReleaseLocks.sha256(originalRefresh))
        return ReleasePrivateFiles.read(directory.resolve("%04d.refresh".format(count)),8192)
    }
    private fun post(refresh: ByteArray, roots: ActivationInput, bundle: GenerationBundle,
        generation: String, pin: GenerationPin, bundleSha: String): Pair<ByteArray,ByteArray> {
        val verified = CanonicalCaddyServedLeafReadback(GenerationRuntime.BASE.resolve(generation),
            bundle, bundleSha, QualificationPrivateTls.selectedManifest(
                requireNotNull(pin.spec.fragmentBinding))).verify(host)
        val receipt = json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(verified.path), 8192)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        val endpoint = java.net.URI(CanonicalCaddyServedLeafReadback(GenerationRuntime.BASE.resolve(generation),
            bundle, bundleSha, QualificationPrivateTls.selectedManifest(
                requireNotNull(pin.spec.fragmentBinding))).verifiedPrivateEndpoint(host))
        val masRoot = CanonicalCaddyCaseTlsBundle(GenerationRuntime.BASE.resolve(generation), bundle,
            bundleSha, QualificationPrivateTls.selectedManifest(requireNotNull(pin.spec.fragmentBinding)))
            .verify(setOf(host))
        val caddy = QualificationMatrixActor.selectedProcess(pin.spec, pin.runtimeFingerprint, "caddy")
        val address = QualificationRssIngressSource.address(endpoint.toString(), caddy.getValue("networks")
            .jsonObject.getValue("p0v3-live-${pin.spec.name}-ingress-control").jsonPrimitive.content,
            receipt.getValue("privateNetwork").jsonPrimitive.content, receipt.getValue("caSha256").jsonPrimitive.content,
            masRoot.sha256, receipt.getValue("servedLeafDerSha256").jsonPrimitive.content,
            receipt.getValue("servedLeafDerSha256").jsonPrimitive.content)
        val selectedRoots = ReleasePrivateFiles.read(Path.of(roots.path), 65536)
        require(ReleaseLocks.sha256(selectedRoots) == roots.sha256)
        val ca = ReleasePrivateFiles.read(Path.of(masRoot.path), 65536)
        require(ReleaseLocks.sha256(ca) == masRoot.sha256 &&
            receipt.getValue("caSha256").jsonPrimitive.content == masRoot.sha256 &&
            selectedRoots.decodeToString(throwOnInvalidSequence = true).contains(
                ca.decodeToString(throwOnInvalidSequence = true).trim()))
        val cert = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(ca)) as X509Certificate
        cert.checkValidity()
        val store = KeyStore.getInstance("PKCS12").apply { load(null,null); setCertificateEntry("selected-mas",cert) }
        val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        val tls = SSLContext.getInstance("TLS").apply { init(null,trust.trustManagers,null) }
        val body = "grant_type=refresh_token&client_id=01J00000000000000000000001&refresh_token=" +
            URLEncoder.encode(refresh.decodeToString(throwOnInvalidSequence = true), Charsets.UTF_8)
        require(body.length in 100..16384)
        val socket = Socket().apply { connect(InetSocketAddress(address,443), 7000) }
        (tls.socketFactory.createSocket(socket,host,443,true) as SSLSocket).use { connection ->
            connection.soTimeout = 8000
            connection.sslParameters = connection.sslParameters.apply {
                endpointIdentificationAlgorithm = "HTTPS"; serverNames = listOf(SNIHostName(host))
            }
            connection.startHandshake()
            require(ReleaseLocks.sha256((connection.session.peerCertificates.first() as X509Certificate).encoded) ==
                receipt.getValue("servedLeafDerSha256").jsonPrimitive.content)
            val headers = "POST /oauth2/token HTTP/1.1\r\nHost: $host\r\n" +
                "Content-Type: application/x-www-form-urlencoded\r\nAccept: application/json\r\n" +
                "Accept-Encoding: identity\r\nContent-Length: ${body.toByteArray().size}\r\nConnection: close\r\n\r\n"
            connection.outputStream.write(headers.toByteArray(Charsets.US_ASCII))
            connection.outputStream.write(body.toByteArray(Charsets.US_ASCII)); connection.outputStream.flush()
            val bytes = connection.inputStream.readNBytes(65537)
            require(bytes.size in 20..65536 && connection.inputStream.read() == -1)
            val separator = "\r\n\r\n".toByteArray()
            val pivot = (0..bytes.size - separator.size).firstOrNull { i -> separator.indices.all {
                bytes[i + it] == separator[it] } } ?: error("MAS response framing uncertain")
            require(pivot in 12..8192)
            val headerText = bytes.copyOfRange(0,pivot).decodeToString(throwOnInvalidSequence = true)
            require(headerText.startsWith("HTTP/1.1 200 ")) {
                "MAS refresh response uncertain; original intent retained"
            }
            val lines = headerText.split("\r\n").drop(1)
            require(lines.size in 1..64 && lines.all {
                it.matches(Regex("[A-Za-z0-9-]{1,60}: [^\\r\\n]{0,1024}")) })
            val responseHeaders = lines.associate { it.substringBefore(':').lowercase() to it.substringAfter(':').trim() }
            require(responseHeaders.size == lines.size && responseHeaders["transfer-encoding"] in setOf(null,"chunked") &&
                !("transfer-encoding" in responseHeaders && "content-length" in responseHeaders))
            val wire = bytes.copyOfRange(pivot + 4,bytes.size)
            val bodyBytes = if (responseHeaders["transfer-encoding"] == "chunked") {
                val output = java.io.ByteArrayOutputStream()
                var offset = 0
                while (true) {
                    val end = (offset until wire.size - 1).firstOrNull { i ->
                        wire[i] == 13.toByte() && wire[i+1] == 10.toByte() }
                        ?: error("Uncertain MAS chunk framing")
                    require(end - offset in 1..8)
                    val length = wire.copyOfRange(offset,end).decodeToString().toInt(16)
                    require(length in 0..65536 && output.size() + length <= 65536)
                    offset = end + 2
                    require(offset + length + 2 <= wire.size &&
                        wire[offset+length] == 13.toByte() && wire[offset+length+1] == 10.toByte())
                    if (length == 0) {
                        require(offset + 2 == wire.size)
                        break
                    }
                    output.write(wire,offset,length); offset += length + 2
                }
                output.toByteArray()
            } else wire.also { require(responseHeaders["content-length"] == null ||
                responseHeaders.getValue("content-length").toInt() == it.size) }
            val response = json.parseToJsonElement(bodyBytes
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(response.getValue("token_type").jsonPrimitive.content.equals("Bearer",true) &&
                response.getValue("expires_in").jsonPrimitive.long >= 900) {
                "MAS access lifetime cannot cover a bounded owner-verified Android segment"
            }
            val access = response.getValue("access_token").jsonPrimitive.content
            val next = response.getValue("refresh_token").jsonPrimitive.content
            require(access.matches(token) && next.matches(token) && next != access && next !=
                refresh.decodeToString(throwOnInvalidSequence = true))
            return access.encodeToByteArray() to next.encodeToByteArray()
        }
    }
    fun issue(generation: String, nativeInvocation: String, androidInvocation: String,
        sourceAccess: ByteArray, sourceRefresh: ByteArray, roots: ActivationInput,
        bundle: GenerationBundle, pin: GenerationPin, bundleSha: String,
        expectedSequence: Int = 1): Issued {
        require(nativeInvocation.matches(Regex("case-[a-f0-9-]{36}")) &&
            androidInvocation.matches(Regex("case-[a-f0-9-]{36}")) &&
            sourceAccess.decodeToString(throwOnInvalidSequence = true).matches(token) &&
            sourceRefresh.decodeToString(throwOnInvalidSequence = true).matches(token) &&
            !sourceAccess.contentEquals(sourceRefresh))
        val directory = root(generation, nativeInvocation)
        val names = Files.list(directory).use { listing -> listing.map { it.fileName.toString() }.toList() }
        val indices = names.filter { it.matches(Regex("[0-9]{4}\\.(?:intent|result|access|refresh)")) }
        val count = indices.map { it.substringBefore('.').toInt() }.toSet().size
        require(count < 32 && indices.size == count * 4 &&
            (1..count).all { n -> listOf("intent","result","access","refresh").all { ext ->
                "%04d.$ext".format(n) in indices } } &&
            names.size == indices.size) { "Uncertain prior MAS refresh; no token reuse" }
        val previous = if (count == 0) sourceRefresh else ReleasePrivateFiles.read(directory.resolve(
            "%04d.refresh".format(count)), 8192)
        var previousActor: String? = null
        if (count > 0) {
            val first = json.parseToJsonElement(ReleasePrivateFiles.read(directory.resolve("0001.intent"),8192)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            val lastIntent = json.parseToJsonElement(ReleasePrivateFiles.read(directory.resolve(
                "%04d.intent".format(count)),8192).decodeToString(throwOnInvalidSequence = true)).jsonObject
            val last = json.parseToJsonElement(ReleasePrivateFiles.read(directory.resolve(
                "%04d.result".format(count)),8192).decodeToString(throwOnInvalidSequence = true)).jsonObject
            val lastActor = lastIntent.getValue("androidInvocationId").jsonPrimitive.content
            previousActor = lastActor
            require(first.getValue("priorRefreshSha256").jsonPrimitive.content == ReleaseLocks.sha256(sourceRefresh) &&
                last.getValue("refreshSha256").jsonPrimitive.content == ReleaseLocks.sha256(previous)) {
                "Previous Android case not finished or attempted to replay an old owner session"
            }
            confirm(generation,nativeInvocation,lastActor,(count - 1) % 4 + 1,
                last.getValue("accessSha256").jsonPrimitive.content,
                ReleaseLocks.sha256(sourceAccess),pin.manifestSha256)
        }
        val sequence = nextOrdinal(count,previousActor,androidInvocation,expectedSequence)
        if (count > 0 && count % 4 == 0) {
            val priorActors = (1..count step 4).map { n ->
                json.parseToJsonElement(ReleasePrivateFiles.read(directory.resolve(
                    "%04d.intent".format(n)),8192).decodeToString(throwOnInvalidSequence = true))
                    .jsonObject.getValue("androidInvocationId").jsonPrimitive.content
            }
            require(androidInvocation !in priorActors && priorActors.size == priorActors.toSet().size) {
                "A previously consumed Android invocation cannot start a new refresh group"
            }
        }
        val prefix = "%04d".format(sequence)
        val effect = buildJsonObject {
            put("schemaVersion",1); put("nativeInvocationId",nativeInvocation)
            put("androidInvocationId",androidInvocation); put("generationId",generation)
            put("priorRefreshSha256",ReleaseLocks.sha256(previous))
            put("sourceAccessSha256",ReleaseLocks.sha256(sourceAccess))
            put("selectedManifestSha256",pin.manifestSha256)
        }
        ReleasePrivateFiles.save(directory.resolve("$prefix.intent"),json.encodeToString(effect).encodeToByteArray())
        val (access,refresh) = post(previous,roots,bundle,generation,pin,bundleSha)
        ReleasePrivateFiles.save(directory.resolve("$prefix.access"),access)
        ReleasePrivateFiles.save(directory.resolve("$prefix.refresh"),refresh)
        val result = buildJsonObject { put("intentSha256",ReleaseLocks.sha256(ReleasePrivateFiles.read(
            directory.resolve("$prefix.intent"),8192)))
            put("androidInvocationId",androidInvocation); put("accessSha256",ReleaseLocks.sha256(access))
            put("refreshSha256",ReleaseLocks.sha256(refresh)) }
        ReleasePrivateFiles.save(directory.resolve("$prefix.result"),json.encodeToString(result).encodeToByteArray())
        return Issued(access,ReleaseLocks.sha256(sourceAccess),expectedSequence)
    }
}
