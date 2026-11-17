package net.datamancy.platform

import java.io.ByteArrayInputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URLEncoder
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Actual owner-authenticated Synapse issuer snapshot, before and after official login.
 * No caller-selected ID, URL, credential, PID or native command. An uncertain post-login
 * observation is never adopted/reissued; readback can only reverify its immutable bytes. */
internal object QualificationMatrixDeviceActor {
    private val json = Json { ignoreUnknownKeys = false; encodeDefaults = true }
    private val id = Regex("[A-Z0-9]{8,80}")
    private val hex = Regex("[a-f0-9]{64}")
    private const val host = "matrix.datamancy.net"
    private fun objectFile(path: Path): JsonObject = json.parseToJsonElement(ReleasePrivateFiles.read(path, 1048576)
        .decodeToString(throwOnInvalidSequence = true)).jsonObject
    internal fun oneNew(baseline: Set<String>, current: Set<String>): String {
        require(baseline.isNotEmpty() && baseline.all { it.matches(id) } &&
            current.all { it.matches(id) } && current.containsAll(baseline) &&
            current.size == baseline.size + 1) { "Expected exactly one new issuer-issued Android device" }
        return (current - baseline).single()
    }
    private fun oracle(context: JsonObject) = objectFile(Path.of(context.getValue("originalMatrixOracleFile")
        .jsonPrimitive.content))
    private fun token(context: JsonObject): String {
        val raw = ReleasePrivateFiles.read(Path.of(context.getValue("freshOriginalSessionFile")
            .jsonPrimitive.content), 8192).decodeToString(throwOnInvalidSequence = true).trim()
        require(raw.matches(Regex("[A-Za-z0-9._~+/=-]{40,8192}")))
        return raw
    }
    private fun encode(value: String) = URLEncoder.encode(value, Charsets.UTF_8).replace("+", "%20")
    /** Raw socket is connected ONLY to the current owner-verified ingress-control CID/IP;
     * layered JSSE uses original-host SNI, PKIX and exact served DER leaf. */
    private class Issuer(context: JsonObject, roots: ActivationInput, bundle: GenerationBundle,
        generation: Path, pin: GenerationPin, bundleSha: String, tokenOverride: String? = null) {
        private val oracle = oracle(context)
        private val bearer = tokenOverride ?: token(context)
        private val leaf: String
        private val address: String
        private val tls: SSLContext
        init {
            val issuer = CanonicalCaddyServedLeafReadback(generation, bundle, bundleSha,
                QualificationPrivateTls.selectedManifest(requireNotNull(pin.spec.fragmentBinding)))
            val verified = issuer.verify(host)
            val receipt = objectFile(Path.of(verified.path))
            leaf = receipt.getValue("servedLeafDerSha256").jsonPrimitive.content
            val endpoint = java.net.URI(issuer.verifiedPrivateEndpoint(host))
            val selectedRoot = CanonicalCaddyCaseTlsBundle(GenerationRuntime.BASE.resolve(generation), bundle,
                bundleSha, QualificationPrivateTls.selectedManifest(requireNotNull(pin.spec.fragmentBinding)))
                .verify(setOf(host))
            address = QualificationRssIngressSource.address(endpoint.toString(),
                QualificationMatrixActor.selectedProcess(pin.spec, pin.runtimeFingerprint, "caddy")
                    .getValue("networks").jsonObject.getValue("p0v3-live-${pin.spec.name}-ingress-control")
                    .jsonPrimitive.content, receipt.getValue("privateNetwork").jsonPrimitive.content,
                receipt.getValue("caSha256").jsonPrimitive.content, selectedRoot.sha256,
                receipt.getValue("servedLeafDerSha256").jsonPrimitive.content, leaf)
            require(verified.sha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(verified.path), 8192)))
            val combined = ReleasePrivateFiles.read(Path.of(roots.path), 65536)
            val ca = ReleasePrivateFiles.read(Path.of(selectedRoot.path), 65536)
            require(ReleaseLocks.sha256(combined) == roots.sha256 &&
                ReleaseLocks.sha256(ca) == selectedRoot.sha256 &&
                combined.decodeToString(throwOnInvalidSequence = true).contains(
                    ca.decodeToString(throwOnInvalidSequence = true).trim()))
            val cert = CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(ca)) as X509Certificate
            cert.checkValidity()
            val store = KeyStore.getInstance("PKCS12").apply { load(null, null); setCertificateEntry("selected-matrix", cert) }
            val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                .apply { init(store) }
            tls = SSLContext.getInstance("TLS").apply { init(null, managers.trustManagers, null) }
        }
        fun get(path: String, expected: Set<Int> = setOf(200)): JsonObject {
            require(path.startsWith("/_matrix/client/v3/") && path.length in 25..512 &&
                path.all { it.code in 33..126 && it != '?' && it != '#' } && expected in
                setOf(setOf(200), setOf(403,404)))
            val plain = Socket()
            plain.connect(InetSocketAddress(address, 443), 7000)
            val socket = tls.socketFactory.createSocket(plain, host, 443, true) as SSLSocket
            socket.use { conn ->
                conn.soTimeout = 8000
                conn.sslParameters = conn.sslParameters.apply {
                    endpointIdentificationAlgorithm = "HTTPS"
                    serverNames = listOf(SNIHostName(host))
                }
                conn.startHandshake()
                val peer = conn.session.peerCertificates.first() as X509Certificate
                require(ReleaseLocks.sha256(peer.encoded) == leaf)
                val request = "GET $path HTTP/1.1\r\nHost: $host\r\nAuthorization: Bearer $bearer\r\n" +
                    "Accept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
                conn.outputStream.write(request.toByteArray(Charsets.US_ASCII)); conn.outputStream.flush()
                val raw = conn.inputStream.readNBytes(1048577)
                require(raw.size in 1..1048576 && conn.inputStream.read() == -1)
                val divider = raw.indexOfSlice("\r\n\r\n".toByteArray())
                require(divider in 12..8192)
                val header = raw.copyOfRange(0, divider).decodeToString(throwOnInvalidSequence = true)
                val lines = header.split("\r\n")
                require(lines.size in 2..64 && lines[0].matches(Regex("HTTP/1\\.[01] [0-9]{3} [^\\r\\n]{1,80}")) &&
                    lines.drop(1).all { it.matches(Regex("[A-Za-z0-9-]{1,60}: [^\\r\\n]{0,1024}")) })
                val status = lines[0].substring(9,12).toInt()
                require(status in expected)
                val headers = lines.drop(1).associate { it.substringBefore(':').lowercase() to it.substringAfter(':').trim() }
                require(headers.size == lines.size - 1 &&
                    headers["transfer-encoding"] in setOf(null, "chunked") &&
                    !("transfer-encoding" in headers && "content-length" in headers))
                val wire = raw.copyOfRange(divider + 4, raw.size)
                val body = if (headers["transfer-encoding"] == "chunked") unchunk(wire) else wire.also {
                    require(headers["content-length"] == null ||
                        headers.getValue("content-length").toInt() == it.size)
                }
                val objectValue = json.parseToJsonElement(body.decodeToString(throwOnInvalidSequence = true)).jsonObject
                return if (status == 200) objectValue else JsonObject(objectValue + ("__status" to JsonPrimitive(status)))
            }
        }
        fun devices(): Set<String> {
            val reply = get("/_matrix/client/v3/devices")
            val rows = reply.getValue("devices").jsonArray
            require(rows.size in 1..256)
            val ids = rows.map { it.jsonObject.getValue("device_id").jsonPrimitive.content }
            require(ids.all { it.matches(id) } && ids.size == ids.toSet().size)
            return ids.toSet()
        }
        fun whoami(): String {
            val subject = get("/_matrix/client/v3/account/whoami").getValue("user_id").jsonPrimitive.content
            require(subject == oracle.getValue("matrixUserId").jsonPrimitive.content)
            return subject
        }
        fun originalReadback(device: String, mas: String): JsonObject {
            val result = get("/_matrix/client/v3/devices/${encode(device)}")
            require(result.getValue("device_id").jsonPrimitive.content == device && whoami() ==
                oracle.getValue("matrixUserId").jsonPrimitive.content &&
                mas == oracle.getValue("masSubject").jsonPrimitive.content)
            val room = oracle.getValue("roomId").jsonPrimitive.content
            val event = oracle.getValue("eventId").jsonPrimitive.content
            val encrypted = get("/_matrix/client/v3/rooms/${encode(room)}/event/${encode(event)}")
            val content = encrypted.getValue("content").jsonObject
            require(encrypted.getValue("event_id").jsonPrimitive.content == event &&
                encrypted.getValue("room_id").jsonPrimitive.content == room &&
                encrypted.getValue("sender").jsonPrimitive.content == whoami() &&
                encrypted.getValue("type").jsonPrimitive.content == "m.room.encrypted" &&
                content.getValue("algorithm").jsonPrimitive.content == "m.megolm.v1.aes-sha2" &&
                content.getValue("session_id") == oracle.getValue("sessionId") &&
                ReleaseLocks.sha256(content.getValue("ciphertext").jsonPrimitive.content.encodeToByteArray()) ==
                    oracle.getValue("cipherSha256").jsonPrimitive.content)
            val deniedRoom = oracle.getValue("forbiddenRoomId").jsonPrimitive.content
            val denied = get("/_matrix/client/v3/rooms/${encode(deniedRoom)}/event/${encode(
                oracle.getValue("forbiddenEventId").jsonPrimitive.content)}", setOf(403,404))
            val deniedStatus = denied.getValue("__status").jsonPrimitive.int
            return buildJsonObject {
                put("roomId", room); put("eventId", event)
                put("cipherSha256", oracle.getValue("cipherSha256")); put("masSubject", mas)
                put("deniedRoomId", deniedRoom); put("deniedStatus", deniedStatus)
            }
        }
    }
    private fun unchunk(raw: ByteArray): ByteArray {
        val output = java.io.ByteArrayOutputStream()
        var offset = 0
        while (true) {
            val end = raw.indexOfSlice("\r\n".toByteArray(), offset)
            require(end in offset..(offset + 16))
            val length = raw.copyOfRange(offset, end).decodeToString().toInt(16)
            require(length in 0..1048576 && output.size() + length <= 1048576)
            offset = end + 2
            require(offset + length + 2 <= raw.size && raw[offset + length] == 13.toByte() &&
                raw[offset + length + 1] == 10.toByte())
            if (length == 0) {
                require(offset + 2 == raw.size) // No trailers or injected second response.
                return output.toByteArray()
            }
            output.write(raw, offset, length); offset += length + 2
        }
    }
    private fun ByteArray.indexOfSlice(other: ByteArray, start: Int = 0): Int {
        for (i in start..size - other.size) if (other.indices.all { this[i + it] == other[it] }) return i
        return -1
    }
    /** Owner verifies actual current target token, not a signed hash/receipt alone. */
    internal fun verifyOwnerToken(context: JsonObject, roots: ActivationInput,
        bundle: GenerationBundle, generation: Path, pin: GenerationPin, bundleSha: String,
        rawToken: ByteArray): Int {
        val token = rawToken.decodeToString(throwOnInvalidSequence = true)
        require(token.matches(Regex("[A-Za-z0-9._~+/=-]{40,8192}")))
        val issuer = Issuer(context, roots, bundle, generation, pin, bundleSha, token)
        issuer.whoami()
        return issuer.devices().size
    }
    fun execute(verb: String, action: JsonObject, caseDir: Path, context: JsonObject,
        phase: String, generation: String, invocation: String, pin: GenerationPin,
        roots: ActivationInput, bundle: GenerationBundle, bundleSha: String,
        source: RestoredOwnerScope?): JsonObject {
        val oracle = oracle(context)
        require(phase in setOf("INSTALL", "RESTORE") && oracle.getValue("sourceGenerationId")
            .jsonPrimitive.content == (source?.source?.id ?: generation))
        val baselinePath = caseDir.resolve("owner-proofs/matrix-device-baseline.json")
        val observationPath = caseDir.resolve("owner-proofs/matrix-native-observation.json")
        require(context.getValue("nativeObservationFile").jsonPrimitive.content == observationPath.toString())
        if (verb == "DEVICE_BASELINE") {
            require(action.keys == setOf("action") && !Files.exists(baselinePath, NOFOLLOW_LINKS) &&
                !Files.exists(observationPath, NOFOLLOW_LINKS))
            val issuer = Issuer(context, roots, bundle, GenerationRuntime.BASE.resolve(generation), pin, bundleSha)
            val user = issuer.whoami()
            val devices = issuer.devices().sorted()
            val original = buildJsonObject {
                put("invocationId", invocation); put("phase", phase); put("generationId", generation)
                put("sourceGenerationId", oracle.getValue("sourceGenerationId"))
                put("sourceRecipeSha256", oracle.getValue("sourceRecipeSha256"))
                put("ownerUserId", user); put("devices", JsonArray(devices.map(::JsonPrimitive)))
            }
            val bytes = json.encodeToString(original).encodeToByteArray()
            ReleasePrivateFiles.save(baselinePath, bytes) // O_EXCL + fsync, before any spool ACK.
            return buildJsonObject { put("ownerUserId", user)
                put("sourceGenerationId", oracle.getValue("sourceGenerationId"))
                put("sourceRecipeSha256", oracle.getValue("sourceRecipeSha256"))
                put("deviceCount", devices.size); put("baselineSha256", ReleaseLocks.sha256(bytes)) }
        }
        require(verb == "READ_ANDROID_DEVICE" && action.keys == setOf("action", "baselineSha256"))
        val bytes = ReleasePrivateFiles.read(baselinePath, 65536)
        val baselineSha = ReleaseLocks.sha256(bytes)
        val baseline = json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(baselineSha == action.getValue("baselineSha256").jsonPrimitive.content &&
            baseline.getValue("invocationId").jsonPrimitive.content == invocation &&
            baseline.getValue("generationId").jsonPrimitive.content == generation &&
            baseline.getValue("phase").jsonPrimitive.content == phase &&
            baseline.getValue("sourceGenerationId") == oracle.getValue("sourceGenerationId") &&
            baseline.getValue("sourceRecipeSha256") == oracle.getValue("sourceRecipeSha256"))
        val issuer = Issuer(context, roots, bundle, GenerationRuntime.BASE.resolve(generation), pin, bundleSha)
        val user = issuer.whoami()
        require(user == baseline.getValue("ownerUserId").jsonPrimitive.content)
        val baselineIds = baseline.getValue("devices").jsonArray.map { it.jsonPrimitive.content }.toSet()
        val newDevice = oneNew(baselineIds, issuer.devices())
        val subjects = QualificationMatrixActor.ownerMasSubject(pin.spec, pin.runtimeFingerprint)
        val originalRead = issuer.originalReadback(newDevice, subjects)
        val isolation = if (phase == "RESTORE") {
            val held = requireNotNull(source)
            require(held.listener.sourceStoppedProofSha256.matches(hex))
            mapOf("sourceIsolationProofSha256" to JsonPrimitive(ReleaseLocks.sha256(ReleasePrivateFiles.read(
                Path.of(context.getValue("sourceIsolationReceiptFile").jsonPrimitive.content), 65536))))
        } else emptyMap()
        val observed = JsonObject(originalRead + isolation + mapOf(
            "phase" to JsonPrimitive(phase), "generationId" to JsonPrimitive(generation),
            "matrixUserId" to JsonPrimitive(user), "ownerUserId" to JsonPrimitive(user),
            "deviceId" to JsonPrimitive(newDevice), "baselineSha256" to JsonPrimitive(baselineSha),
            "nativeDeviceSource" to JsonPrimitive("SYNAPSE_AUTHENTICATED_NEW_DEVICE")))
        val encoded = json.encodeToString(observed).encodeToByteArray()
        if (Files.exists(observationPath, NOFOLLOW_LINKS)) {
            require(ReleasePrivateFiles.read(observationPath, 65536).contentEquals(encoded)) {
                "Original owner Android observation changed; no second issuance"
            }
        } else ReleasePrivateFiles.save(observationPath, encoded)
        return buildJsonObject {
            put("ownerUserId", user); put("deviceId", newDevice)
            put("baselineSha256", baselineSha); put("nativeObservationSha256", ReleaseLocks.sha256(encoded))
        }
    }
}
