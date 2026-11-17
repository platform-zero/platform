package net.datamancy.platform

import java.io.ByteArrayInputStream
import java.net.InetSocketAddress
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.Base64
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Serializable internal data class EffectivePublicCertificateHead(val generation: String,
    val bundleSha256: String, val revisions: Map<String, ActivationInput>, val predecessorSha256: String? = null)
@Serializable internal data class ImportedOriginalCertificateIndex(val sourceGeneration: String,
    val targetGeneration: String, val sourceBundleSha256: String, val snapshotId: String,
    val headSha256: String, val originalRevisions: Map<String, ActivationInput>,
    val nativeObservations: Map<String, ActivationInput>)
internal data class NativeCaddyCertificateBytes(val chainPem: ByteArray, val privateKeyPem: ByteArray,
    val containerId: String, val configurationSha256: String, val observedLeafDer: ByteArray)
@Serializable internal data class PublicTurnAdoptionIntent(val generation: String, val bundleSha256: String,
    val operationId: String, val publicRevisionSha256: String, val leafDerSha256: String,
    val chainPemSha256: String, val privateKeyPemSha256: String, val effectiveConfigSha256: String,
    val livekitFingerprint: String)
@Serializable internal data class PublicTurnNativeObservation(val generation: String, val bundleSha256: String,
    val operationId: String, val livekitContainerId: String, val runtimeFingerprint: String,
    val installedChainSha256: String, val installedKeySha256: String, val installedConfigSha256: String,
    val observedCommand: List<String>, val tlsObservedLeafDerSha256: String,
    val observedAtEpochSeconds: Long)
@Serializable internal data class PublicTurnAdoptionResult(val intentSha256: String,
    val revisionSha256: String, val nativeObservation: PublicTurnNativeObservation)
/** A02's generation-owned native actuator MUST mount immutable effective inputs and restart
 * the actual LiveKit process, refusing replay/uncertain acknowledgement. No generic backend
 * callback, pre-existing bootstrap files or fabricated listener observation can satisfy it.
 */
internal fun interface NativeTurnCredentialActuator {
    fun adopt(bundle: GenerationBundle, process: GenerationPin, operationId: String,
        inputs: Map<String, String>): PublicTurnNativeObservation
}

/** Reads the exact generation-owned running Caddy, not an arbitrary path or caller-provided key. */
internal interface PublicCertificateCollector {
    fun observe(pin: GenerationPin, host: String): NativeCaddyCertificateBytes
}
internal class NativeCaddyCertificateCollector(private val trustPem: Path,
    private val trustSha256: String) : PublicCertificateCollector {
    private val json = Json { ignoreUnknownKeys = false }
    private fun command(args: List<String>, maximum: Int, store: RuntimeStore): ByteArray {
        store.verifyConfiguration()
        val process = ProcessBuilder(store.prefix() + args).apply {
            environment().clear()
            environment()["PATH"] = "/usr/bin:/bin"
            environment()["LANG"] = "C.UTF-8"
            environment()["HOME"] = "/home/gerald"
            redirectError(ProcessBuilder.Redirect.DISCARD)
        }.start()
        try {
            val output = java.util.concurrent.CompletableFuture.supplyAsync { process.inputStream.readNBytes(maximum + 1) }
            require(process.waitFor(15, java.util.concurrent.TimeUnit.SECONDS)) { "Caddy certificate read uncertain" }
            val bytes = output.get(5, java.util.concurrent.TimeUnit.SECONDS)
            require(process.exitValue() == 0 && bytes.size in 1..maximum)
            return bytes
        } finally { if (process.isAlive) process.destroyForcibly() }
    }
    override fun observe(pin: GenerationPin, host: String): NativeCaddyCertificateBytes {
        require(host.matches(Regex("[a-z0-9]+(?:-[a-z0-9]+)*(?:\\.[a-z0-9]+(?:-[a-z0-9]+)*)*\\.datamancy\\.net")) &&
            trustSha256.matches(Regex("[a-f0-9]{64}")) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(trustPem, 1048576)) == trustSha256)
        val spec = pin.spec
        require(spec.store == RuntimeStore.CANONICAL_V2 && pin.member.name == spec.name &&
            spec.processes.count { it.id == "caddy" && !it.oneShot } == 1 &&
            pin.runtimeFingerprint == PrivateDeployment.expectedFingerprint(spec, pin.inputHashes))
        val address = if (spec.ingress != null) NamespaceCaddyTransport.ownedPublicAddress(spec, pin.runtimeFingerprint)
            else NamespaceCaddyTransport.ownedProcessAddress(spec, pin.runtimeFingerprint, "caddy",
                "qualification-web")
        val container = "p0v3-live-${spec.name}-caddy"
        val info = json.parseToJsonElement(command(listOf("inspect", "--type", "container", container), 1048576, spec.store)
            .decodeToString(throwOnInvalidSequence = true)).jsonArray.single().jsonObject
        val labels = info.getValue("Config").jsonObject.getValue("Labels").jsonObject
        val id = info.getValue("Id").jsonPrimitive.content
        require(id.matches(Regex("[a-f0-9]{64}")) && labels["io.p0v3.private-deployment"]?.jsonPrimitive?.content == spec.name &&
            labels["io.p0v3.runtime-fingerprint"]?.jsonPrimitive?.content == pin.runtimeFingerprint &&
            info.getValue("State").jsonObject.getValue("Running").jsonPrimitive.content == "true")
        val config = NamespaceCaddyTransport.real(spec, pin.runtimeFingerprint).exchange("GET", "/config/", null, null)
        require(config.status == 200 && config.body.size in 1..1048576)
        val body = json.parseToJsonElement(config.body.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val tls = body.getValue("apps").jsonObject.getValue("tls").jsonObject
        require(body.getValue("storage").jsonObject.getValue("root").jsonPrimitive.content == "/data/caddy")
        if (spec.ingress != null) require(tls.getValue("certificates").jsonObject.getValue("automate").jsonArray.any {
            it.jsonPrimitive.content == host
        } && tls.getValue("automation").jsonObject.getValue("policies").jsonArray.any { entry ->
            entry.jsonObject.getValue("subjects").jsonArray.any { it.jsonPrimitive.content == host } &&
                entry.jsonObject.getValue("issuers").jsonArray.single().jsonObject.let {
                    it["module"]?.jsonPrimitive?.content == "acme" &&
                        it["ca"]?.jsonPrimitive?.content == "https://acme-v02.api.letsencrypt.org/directory"
                }
        }) else require(tls["automation"]?.jsonObject?.get("policies")?.jsonArray?.isEmpty() != false &&
            tls.getValue("certificates").jsonObject.getValue("load_files").jsonArray.isNotEmpty()) {
            "Private recovered Caddy cannot issue a new ACME certificate"
        }
        // Caddy's fixed file-system storage layout. The path is constructed exclusively from
        // the approved hostname and production ACME directory, never from a caller path.
        val stem = "/data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/$host/$host"
        val cert = command(listOf("exec", container, "/bin/cat", "$stem.crt"), 65536, spec.store)
        val key = command(listOf("exec", container, "/bin/cat", "$stem.key"), 65536, spec.store)
        val factory = CertificateFactory.getInstance("X.509")
        val anchors = factory.generateCertificates(ByteArrayInputStream(ReleasePrivateFiles.read(trustPem, 1048576)))
        require(anchors.isNotEmpty())
        val store = java.security.KeyStore.getInstance("PKCS12")
        store.load(null, null)
        anchors.forEachIndexed { index, certificate -> store.setCertificateEntry("webpki-$index", certificate) }
        val manager = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        val context = SSLContext.getInstance("TLS").apply { init(null, manager.trustManagers, null) }
        val underlying = java.net.Socket()
        val observed = try {
            underlying.connect(InetSocketAddress(address, 443), 2500)
            val socket = context.socketFactory.createSocket(underlying, host, 443, true) as SSLSocket
            socket.use {
                it.soTimeout = 2500
                it.sslParameters = it.sslParameters.apply {
                    serverNames = listOf(javax.net.ssl.SNIHostName(host))
                    endpointIdentificationAlgorithm = "HTTPS"
                }
                it.startHandshake()
                it.session.peerCertificates.first().encoded
            }
        } finally { underlying.close() }
        return NativeCaddyCertificateBytes(cert, key, id, ReleaseLocks.sha256(config.body), observed)
    }
}

/** Release-bound effective credentials. Pre-seal generation inputs never contain this future head. */
internal object NativeCredentialRevision {
    private val json = Json { ignoreUnknownKeys = false; encodeDefaults = true }
    private val hash = Regex("[a-f0-9]{64}")
    private val publicId = Regex("cert-[a-f0-9]{24}")
    private fun publicRoot(generationRoot: Path): Path {
        require(generationRoot == GenerationRuntime.BASE.resolve(generationRoot.fileName.toString()) &&
            generationRoot.fileName.toString().matches(Regex("q-[a-f0-9]{12}")))
        return generationRoot.resolve("credential-revisions/public")
    }
    internal fun readHead(generationRoot: Path): EffectivePublicCertificateHead? {
        val root = publicRoot(generationRoot)
        if (!Files.exists(root.resolve("head.json"), NOFOLLOW_LINKS)) return null
        val bytes = ReleasePrivateFiles.read(root.resolve("head.json"), 65536)
        val immutableHead = root.resolve("head-history/${ReleaseLocks.sha256(bytes)}.json")
        require(ReleasePrivateFiles.read(immutableHead, 65536).contentEquals(bytes)) {
            "Effective head lacks immutable append-only ancestry"
        }
        val value = json.decodeFromString<EffectivePublicCertificateHead>(bytes.decodeToString(throwOnInvalidSequence = true))
        require(value.generation == generationRoot.fileName.toString() && hash.matches(value.bundleSha256) &&
            value.bundleSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"))) &&
            value.revisions.isNotEmpty() && value.revisions.size <= 64 &&
            value.revisions.keys.all { it.matches(Regex("[a-z0-9.-]+\\.datamancy\\.net")) } &&
            (value.predecessorSha256 == null || hash.matches(value.predecessorSha256)))
        value.revisions.forEach { (host, binding) ->
            val path = Path.of(binding.path)
            require(path.parent == root && path.fileName.toString().endsWith(".json") &&
                path.fileName.toString().removeSuffix(".json").matches(publicId) &&
                hash.matches(binding.sha256) && ReleaseLocks.sha256(ReleasePrivateFiles.read(path, 65536)) == binding.sha256)
            val record = json.decodeFromString<PublicCertificateRevision>(ReleasePrivateFiles.read(path, 65536)
                .decodeToString(throwOnInvalidSequence = true))
            require(record.host == host && record.revisionId == path.fileName.toString().removeSuffix(".json") &&
                record.generation == value.generation && record.bundleSha256 == value.bundleSha256 &&
                Path.of(record.nativeObservation.path) == root.resolve("observations/${record.revisionId}.json") &&
                ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(record.nativeObservation.path), 65536)) ==
                    record.nativeObservation.sha256)
        }
        return value
    }
    fun expectedCaptureHeadSha256(generationRoot: Path): String? {
        val head = readHead(generationRoot) ?: return null
        require(head.revisions.isNotEmpty())
        return ReleaseLocks.sha256(ReleasePrivateFiles.read(publicRoot(generationRoot).resolve("head.json"), 65536))
    }
    fun expectedCapturePaths(generationRoot: Path): Set<String> {
        val head = readHead(generationRoot) ?: run {
            val bundle = json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"))
                .decodeToString(throwOnInvalidSequence = true))
            require(bundle.members.none { member -> member.spec.ingress != null &&
                member.spec.processes.any { it.id == "caddy" } }) {
                "Public original source cannot be captured before actual ACME credential adoption"
            }
            return emptySet()
        }
        val root = publicRoot(generationRoot)
        val history = historyPaths(head) { name -> ReleasePrivateFiles.read(generationRoot.resolve(name), 65536) }
        val turn = turnPaths(generationRoot, head, history)
        return (history + turn).also { paths -> require(paths.all { name ->
            root.parent.parent.resolve(name).normalize().startsWith(root)
        }) }
    }
    fun captureEffective(generationRoot: Path, captureRoot: Path, payloads: MutableMap<String, Path>,
        maximumBytes: Long, expectedHeadSha256: String? = expectedCaptureHeadSha256(generationRoot)): List<String> {
        ReleasePrivateFiles.directory(captureRoot)
        val expected = expectedCapturePaths(generationRoot)
        require(payloads.keys.intersect(expected).isEmpty() && maximumBytes >= 0 &&
            expectedHeadSha256 == expectedCaptureHeadSha256(generationRoot))
        val files = expected.sorted().associateWith { name ->
            val original = generationRoot.resolve(name)
            val bytes = ReleasePrivateFiles.read(original, 65536)
            name to bytes
        }
        val size = files.values.fold(0L) { sum, (_, bytes) -> Math.addExact(sum, bytes.size.toLong()) }
        require(size <= maximumBytes)
        // Snapshot uses an immutable capture-private copy, not a mutable live HEAD pointer.
        // The planned head SHA is pinned in the caller's pre-effect capture intent.
        val scratch = captureRoot.resolve("credential-capture")
        require(!Files.exists(scratch, NOFOLLOW_LINKS))
        Files.createDirectory(scratch, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
            java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(captureRoot)
        val copies = files.mapValues { (_, pair) ->
            val (name, bytes) = pair
            val dest = scratch.resolve(name)
            var parent = scratch
            name.split('/').dropLast(1).forEach { component ->
                parent = parent.resolve(component)
                if (!Files.exists(parent, NOFOLLOW_LINKS)) {
                    Files.createDirectory(parent, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                        java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
                    ReleasePrivateFiles.sync(parent.parent)
                }
                ReleasePrivateFiles.directory(parent)
            }
            ReleasePrivateFiles.save(dest, bytes)
            dest
        }
        require(expected == expectedCapturePaths(generationRoot) &&
            expectedHeadSha256 == expectedCaptureHeadSha256(generationRoot) &&
            copies["credential-revisions/public/head.json"]?.let {
                ReleaseLocks.sha256(ReleasePrivateFiles.read(it, 65536))
            } == expectedHeadSha256) { "Effective HEAD rotated during copy; retain uncertain capture" }
        payloads.putAll(copies)
        return copies.keys.sorted()
    }

    /** Intents with unknown native outcomes remain in capture and are NEVER replayed;
     * complete TURN adoption records must bind an actual historical public revision.
     */
    private fun turnPaths(generationRoot: Path, head: EffectivePublicCertificateHead,
        history: Set<String>): Set<String> = turnPathsFrom(
        publicRoot(generationRoot).resolve("turn"), head, history) { relative ->
            ReleasePrivateFiles.read(generationRoot.resolve(relative), 65536)
        }
    private fun importedTurnPaths(recovered: Path, head: EffectivePublicCertificateHead,
        history: Set<String>): Set<String> = turnPathsFrom(
        recovered.resolve("credential-revisions/public/turn"), head, history) { relative ->
            ReleasePrivateFiles.read(recovered.resolve(relative), 65536)
        }
    private fun turnPathsFrom(directory: Path, head: EffectivePublicCertificateHead,
        history: Set<String>, readCertificate: (String) -> ByteArray): Set<String> {
        if (!Files.exists(directory, NOFOLLOW_LINKS)) return emptySet()
        ReleasePrivateFiles.directory(directory)
        val available = Files.list(directory).use { paths -> paths.limit(513).toList() }
        require(available.size <= 512 && available.all { it.fileName.toString()
            .matches(Regex("[a-z0-9-]{1,64}\\.(intent|result)\\.json")) })
        val revisionsBySha = history.filter { it.matches(Regex(
            "credential-revisions/public/cert-[a-f0-9]{24}\\.json")) }.associate { relative ->
            ReleaseLocks.sha256(readCertificate(relative)) to relative.substringAfterLast('/').removeSuffix(".json")
        }
        val paths = linkedSetOf<String>()
        available.filter { it.fileName.toString().endsWith(".intent.json") }.forEach { path ->
            val name = path.fileName.toString()
            val operation = name.removeSuffix(".intent.json")
            val raw = ReleasePrivateFiles.read(path, 65536)
            val intent = json.decodeFromString<PublicTurnAdoptionIntent>(raw.decodeToString(throwOnInvalidSequence = true))
            require(intent.generation == head.generation && intent.bundleSha256 == head.bundleSha256 &&
                intent.operationId == operation && intent.publicRevisionSha256 in revisionsBySha &&
                listOf(intent.leafDerSha256, intent.chainPemSha256, intent.privateKeyPemSha256,
                    intent.effectiveConfigSha256, intent.livekitFingerprint).all(hash::matches))
            paths += "credential-revisions/public/turn/$name"
            val resultPath = directory.resolve("$operation.result.json")
            if (Files.exists(resultPath, NOFOLLOW_LINKS)) {
                val result = json.decodeFromString<PublicTurnAdoptionResult>(
                    ReleasePrivateFiles.read(resultPath, 65536).decodeToString(throwOnInvalidSequence = true))
                require(result.intentSha256 == ReleaseLocks.sha256(raw) &&
                    result.revisionSha256 == intent.publicRevisionSha256 &&
                    result.nativeObservation.generation == head.generation &&
                    result.nativeObservation.operationId == operation &&
                    result.nativeObservation.installedChainSha256 == intent.chainPemSha256 &&
                    result.nativeObservation.installedKeySha256 == intent.privateKeyPemSha256 &&
                    result.nativeObservation.installedConfigSha256 == intent.effectiveConfigSha256 &&
                    result.nativeObservation.tlsObservedLeafDerSha256 == intent.leafDerSha256 &&
                    result.nativeObservation.observedCommand == listOf("--config",
                        "/run/turn-revisions/${revisionsBySha.getValue(intent.publicRevisionSha256)}/livekit.yaml"))
                paths += "credential-revisions/public/turn/$operation.result.json"
            }
        }
        require(paths.size == available.size) { "Unlinked TURN native result or unknown authority in capture" }
        return paths
    }

    /** Import authenticated original certificate provenance as INERT source bytes. Neither
     * this copy nor a recovered effective HEAD grants site authority. The A02 caller has
     * already authenticated/decrypted Kopia and holds both source/target locks.
     */
    fun importOriginal(source: GenerationBundle, target: GenerationBundle, manifest: CapsuleManifest,
        recovered: Path, targetRoot: Path): ImportedOriginalCertificateIndex? {
        val snapshot = requireNotNull(target.recoverySourceKopia ?: target.ownedUpdate?.snapshot)
        require(targetRoot == GenerationRuntime.BASE.resolve(target.request.id) &&
            target.request.id != source.request.id && snapshot.id == manifest.id &&
            snapshot.bundleSha256 == manifest.bundleSha256 &&
            (target.ownedUpdate == null || OwnedReleaseUpdates.original(target.ownedUpdate) == source) &&
            manifest.generation == source.request.id && manifest.bundleSha256 ==
                ReleaseLocks.sha256(json.encodeToString(source).toByteArray()) &&
            recovered.isAbsolute && recovered.toRealPath() == recovered)
        RecoveryCredentialFiles.validate(manifest)
        val names = manifest.credentialFiles
        require(names == manifest.files.filter { it.name.startsWith("credential-revisions/") })
        if (names.isEmpty()) {
            require(manifest.files.none { it.name.startsWith("credential-revisions/") } &&
                source.members.none { pin -> pin.spec.ingress != null &&
                    pin.spec.processes.any { it.id == "caddy" } }) {
                "Public original Caddy cannot be restored without authenticated effective certificate custody"
            }
            return null
        }
        val head = names.single { it.name == "credential-revisions/public/head.json" }
        val headBytes = ReleasePrivateFiles.read(recovered.resolve(head.name), 65536)
        require(head.bytes == headBytes.size.toLong() && head.sha256 == ReleaseLocks.sha256(headBytes))
        val original = json.decodeFromString<EffectivePublicCertificateHead>(
            headBytes.decodeToString(throwOnInvalidSequence = true))
        val historical = historyPaths(original) { relative ->
            ReleasePrivateFiles.read(recovered.resolve(relative), 65536)
        }
        require(original.generation == source.request.id && original.bundleSha256 == manifest.bundleSha256 &&
            names.map { it.name }.toSet() == historical + importedTurnPaths(recovered, original, historical) &&
            names.map { it.name }.distinct().size == names.size)
        val root = publicRoot(targetRoot)
        val originalRoot = root.resolve("original")
        require(!Files.exists(originalRoot, NOFOLLOW_LINKS))
        for (directory in listOf(root.parent, root, originalRoot, originalRoot.resolve("observations"),
            originalRoot.resolve("head-history"), originalRoot.resolve("turn"))) {
            if (!Files.exists(directory, NOFOLLOW_LINKS)) {
                ReleasePrivateFiles.directory(directory.parent)
                Files.createDirectory(directory, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                    java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
                ReleasePrivateFiles.sync(directory.parent)
            }
            ReleasePrivateFiles.directory(directory)
        }
        val revisions = linkedMapOf<String, ActivationInput>()
        val observations = linkedMapOf<String, ActivationInput>()
        for (host in original.revisions.keys.sorted()) {
            val binding = original.revisions.getValue(host)
            val name = Path.of(binding.path).fileName.toString()
            require(name.matches(Regex("cert-[a-f0-9]{24}\\.json")))
            val file = names.single { it.name == "credential-revisions/public/$name" }
            val content = ReleasePrivateFiles.read(recovered.resolve(file.name), 65536)
            require(file.sha256 == binding.sha256 && file.sha256 == ReleaseLocks.sha256(content) &&
                file.bytes == content.size.toLong())
            val cert = json.decodeFromString<PublicCertificateRevision>(content.decodeToString(throwOnInvalidSequence = true))
            require(cert.host == host && cert.generation == source.request.id && cert.bundleSha256 == manifest.bundleSha256 &&
                cert.revisionId == name.removeSuffix(".json"))
            val nativeName = "credential-revisions/public/observations/$name"
            val observationFile = names.single { it.name == nativeName }
            val observation = ReleasePrivateFiles.read(recovered.resolve(nativeName), 65536)
            require(observationFile.sha256 == cert.nativeObservation.sha256 &&
                observationFile.sha256 == ReleaseLocks.sha256(observation) &&
                observationFile.bytes == observation.size.toLong())
            val destination = originalRoot.resolve(name)
            ReleasePrivateFiles.save(destination, content)
            revisions[host] = ActivationInput(destination.toString(), file.sha256)
            val nativeDest = originalRoot.resolve("observations/$name")
            ReleasePrivateFiles.save(nativeDest, observation)
            observations[host] = ActivationInput(nativeDest.toString(), observationFile.sha256)
        }
        ReleasePrivateFiles.save(originalRoot.resolve("head.json"), headBytes)
        // Preserve every superseded immutable head/cert/native record, not just active
        // host aliases, before the index is published. The authenticated manifest
        // supplies SHA and byte length for EACH original historical source file.
        for (entry in names.sortedBy { it.name }) {
            val relative = entry.name.removePrefix("credential-revisions/public/")
            val destination = originalRoot.resolve(relative)
            if (Files.exists(destination, NOFOLLOW_LINKS)) {
                require(ReleaseLocks.sha256(ReleasePrivateFiles.read(destination, 65536)) == entry.sha256)
                continue
            }
            require(destination.parent in setOf(originalRoot, originalRoot.resolve("observations"),
                originalRoot.resolve("head-history"), originalRoot.resolve("turn")))
            val bytes = ReleasePrivateFiles.read(recovered.resolve(entry.name), 65536)
            require(bytes.size.toLong() == entry.bytes && ReleaseLocks.sha256(bytes) == entry.sha256)
            ReleasePrivateFiles.save(destination, bytes)
        }
        val index = ImportedOriginalCertificateIndex(source.request.id, target.request.id,
            manifest.bundleSha256, manifest.id, head.sha256, revisions, observations)
        ReleasePrivateFiles.save(originalRoot.resolve("index.json"), json.encodeToString(index).toByteArray())
        return index
    }
    fun readOriginal(target: GenerationBundle, host: String): ByteArray {
        val root = publicRoot(GenerationRuntime.BASE.resolve(target.request.id)).resolve("original")
        val index = json.decodeFromString<ImportedOriginalCertificateIndex>(
            ReleasePrivateFiles.read(root.resolve("index.json"), 65536).decodeToString(throwOnInvalidSequence = true))
        val snapshot = requireNotNull(target.recoverySourceKopia ?: target.ownedUpdate?.snapshot)
        require(index.targetGeneration == target.request.id && index.sourceGeneration == snapshot.generation &&
            index.sourceBundleSha256 == snapshot.bundleSha256 && index.snapshotId == snapshot.id &&
            index.headSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("head.json"), 65536)))
        val head = json.decodeFromString<EffectivePublicCertificateHead>(
            ReleasePrivateFiles.read(root.resolve("head.json"), 65536).decodeToString(throwOnInvalidSequence = true))
        val complete = historyPaths(head) { relative -> ReleasePrivateFiles.read(
            root.resolve(relative.removePrefix("credential-revisions/public/")), 65536) }
        turnPathsFrom(root.resolve("turn"), head, complete) { relative ->
            ReleasePrivateFiles.read(root.resolve(relative.removePrefix("credential-revisions/public/")), 65536)
        }
        require("credential-revisions/public/head.json" in complete &&
            "credential-revisions/public/${Path.of(index.originalRevisions.getValue(host).path).fileName}" in complete)
        val binding = requireNotNull(index.originalRevisions[host])
        val original = head.revisions.getValue(host)
        require(head.generation == index.sourceGeneration && head.bundleSha256 == index.sourceBundleSha256 &&
            binding.sha256 == original.sha256 && Path.of(binding.path).parent == root &&
            Path.of(binding.path).fileName == Path.of(original.path).fileName)
        val bytes = ReleasePrivateFiles.read(Path.of(binding.path), 65536)
        require(ReleaseLocks.sha256(bytes) == binding.sha256 &&
            index.nativeObservations[host]?.let { pin ->
                val record = json.decodeFromString<PublicCertificateRevision>(bytes.decodeToString(throwOnInvalidSequence = true))
                pin.sha256 == record.nativeObservation.sha256 && Path.of(pin.path).parent == root.resolve("observations") &&
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(pin.path), 65536)) == pin.sha256
            } == true)
        return bytes
    }

    /** Append an observed native ACME identity or an exact original restored identity.
     * The old HEAD stays intact on collection/crypto failure. Renewal must change the
     * observed leaf and move its expiry forward; a failed due renewal keeps prior bytes.
     * Caller holds controller, generation and Caddy native locks across observe+publish.
     */
    fun publish(bundle: GenerationBundle, host: String, approvedHosts: Set<String>,
        trust: ActivationInput, collector: PublicCertificateCollector,
        originalBundle: GenerationBundle? = null, originalManifest: CapsuleManifest? = null,
        recovered: Path? = null): ActivationInput {
        val generationRoot = GenerationRuntime.BASE.resolve(bundle.request.id)
        val root = publicRoot(generationRoot)
        val bundleBytes = ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"))
        val bundleSha = ReleaseLocks.sha256(bundleBytes)
        require(json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true)) == bundle)
        SiteOwnerships.checkSealed(bundle)
        require(host in approvedHosts && approvedHosts.all { it.matches(
            Regex("[a-z0-9]+(?:-[a-z0-9]+)*(?:\\.[a-z0-9]+(?:-[a-z0-9]+)*)*\\.datamancy\\.net")) } &&
            Path.of(trust.path).isAbsolute && trust.sha256.matches(hash) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(trust.path), 1048576)) == trust.sha256)
        val restored = bundle.recoverySourceKopia != null
        val adoptingOriginal = restored || bundle.ownedUpdate != null && originalBundle != null
        require(if (adoptingOriginal) originalBundle != null && originalManifest != null && recovered != null &&
            (if (restored) bundle.ownership == null && bundle.ownedUpdate == null
             else bundle.ownership != null && bundle.ownedUpdate != null &&
                OwnedReleaseUpdates.original(bundle.ownedUpdate) == originalBundle)
        else originalBundle == null && originalManifest == null && recovered == null &&
            bundle.ownership != null && bundle.ownedUpdate == null)
        val sourceRecord = if (adoptingOriginal) {
            val source = requireNotNull(originalBundle)
            val manifest = requireNotNull(originalManifest)
            val originalRoot = requireNotNull(recovered)
            require(manifest.generation == source.request.id && manifest.bundleSha256 ==
                ReleaseLocks.sha256(json.encodeToString(source).toByteArray()) &&
                (bundle.recoverySourceKopia ?: bundle.ownedUpdate?.snapshot)?.id == manifest.id &&
                (bundle.recoverySourceKopia ?: bundle.ownedUpdate?.snapshot)?.bundleSha256 == manifest.bundleSha256 &&
                originalRoot.isAbsolute && originalRoot.toRealPath() == originalRoot)
            val originalHeadPath = "credential-revisions/public/head.json"
            RecoveryCredentialFiles.validate(manifest)
            val headFile = manifest.credentialFiles.single { it.name == originalHeadPath }
            val originalHeadBytes = ReleasePrivateFiles.read(originalRoot.resolve(originalHeadPath), 65536)
            require(ReleaseLocks.sha256(originalHeadBytes) == headFile.sha256 &&
                headFile.bytes == originalHeadBytes.size.toLong())
            val originalHead = json.decodeFromString<EffectivePublicCertificateHead>(
                originalHeadBytes.decodeToString(throwOnInvalidSequence = true))
            require(originalHead.generation == source.request.id && originalHead.bundleSha256 == manifest.bundleSha256)
            val binding = originalHead.revisions.getValue(host)
            val path = "credential-revisions/public/${Path.of(binding.path).fileName}"
            val entry = manifest.credentialFiles.single { it.name == path }
            val bytes = ReleasePrivateFiles.read(originalRoot.resolve(path), 65536)
            require(entry.sha256 == binding.sha256 && ReleaseLocks.sha256(bytes) == entry.sha256 &&
                entry.bytes == bytes.size.toLong() && path in expectedCapturePathsFromHead(originalHead))
            bytes to json.decodeFromString<PublicCertificateRevision>(bytes.decodeToString(throwOnInvalidSequence = true))
        } else null
        val pin = bundle.members.single { candidate -> candidate.spec.processes.any {
            it.id == "caddy" && !it.oneShot
        } }
        val native = collector.observe(pin, host)
        val chain = inspectCrypto(native.chainPem, native.privateKeyPem,
            ReleasePrivateFiles.read(Path.of(trust.path), 1048576), native.observedLeafDer, host, Instant.now())
        val leaf = chain.first()
        val leafSha = ReleaseLocks.sha256(leaf.encoded)
        val chainSha = ReleaseLocks.sha256(native.chainPem)
        val keySha = ReleaseLocks.sha256(native.privateKeyPem)
        val names = leaf.subjectAlternativeNames.orEmpty().filter { it[0] == 2 }.map { it[1] as String }.toSet()
        require(names.isNotEmpty() && approvedHosts.containsAll(names) &&
            native.containerId.matches(hash) && native.configurationSha256.matches(hash))
        val before = readHead(generationRoot)
        require(before == null || before.generation == bundle.request.id && before.bundleSha256 == bundleSha)
        before?.revisions?.get(host)?.let { current ->
            val previous = json.decodeFromString<PublicCertificateRevision>(ReleasePrivateFiles.read(Path.of(current.path), 65536)
                .decodeToString(throwOnInvalidSequence = true))
            require(!adoptingOriginal && !restored && previous.leafDerSha256 != leafSha &&
                leaf.notAfter.toInstant().epochSecond > previous.notAfterEpochSeconds &&
                previous.kind == "ACME_PUBLIC") {
                "Renewal must observe a changed native public identity with later expiry"
            }
        }
        val original = sourceRecord?.second
        if (adoptingOriginal) require(original?.host == host && original.leafDerSha256 == leafSha &&
            original.chainPemSha256 == chainSha && original.privateKeyPemSha256 == keySha &&
            original.dnsNames == names && original.publicTrustStoreSha256 == trust.sha256 &&
            original.notBeforeEpochSeconds == leaf.notBefore.toInstant().epochSecond &&
            original.notAfterEpochSeconds == leaf.notAfter.toInstant().epochSecond) {
            "Restored public certificate must retain exact original private key, leaf and trust root"
        }
        val revisionId = "cert-" + ReleaseLocks.sha256(
            "${bundle.request.id}|$host|$leafSha|${Instant.now().toEpochMilli()}".toByteArray()).take(24)
        val observations = root.resolve("observations")
        for (dir in listOf(root.parent, root, observations, root.resolve("head-history"))) {
            if (!Files.exists(dir, NOFOLLOW_LINKS)) {
                ReleasePrivateFiles.directory(dir.parent)
                Files.createDirectory(dir, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                    java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
                ReleasePrivateFiles.sync(dir.parent)
            }
            ReleasePrivateFiles.directory(dir)
        }
        val observationPath = observations.resolve("$revisionId.json")
        val observation = PublicCertificateNativeObservation(generation = bundle.request.id,
            bundleSha256 = bundleSha, host = host, caddyDeployment = pin.member.name,
            runtimeFingerprint = pin.runtimeFingerprint, containerId = native.containerId,
            configurationSha256 = native.configurationSha256, leafDerSha256 = leafSha,
            chainPemSha256 = chainSha, privateKeyPemSha256 = keySha,
            tlsObservedLeafDerSha256 = ReleaseLocks.sha256(native.observedLeafDer),
            publicTrustStoreSha256 = trust.sha256,
            acmeDirectory = "https://acme-v02.api.letsencrypt.org/directory", dnsNames = names,
            notBeforeEpochSeconds = leaf.notBefore.toInstant().epochSecond,
            notAfterEpochSeconds = leaf.notAfter.toInstant().epochSecond)
        val observationBytes = json.encodeToString(observation).toByteArray()
        val record = PublicCertificateRevision(revisionId = revisionId, generation = bundle.request.id,
            bundleSha256 = bundleSha, host = host,
            origin = if (adoptingOriginal) PublicCertificateRevisionOrigin.SEALED_RESTORE else PublicCertificateRevisionOrigin.ACME_ISSUANCE,
            sourceGeneration = original?.generation ?: bundle.request.id,
            sourceRevisionSha256 = sourceRecord?.first?.let(ReleaseLocks::sha256),
            leafDerSha256 = leafSha, chainPemSha256 = chainSha, privateKeyPemSha256 = keySha,
            dnsNames = names, notBeforeEpochSeconds = observation.notBeforeEpochSeconds,
            notAfterEpochSeconds = observation.notAfterEpochSeconds,
            acmeDirectory = observation.acmeDirectory, publicTrustStoreSha256 = trust.sha256,
            nativeObservation = ActivationInput(observationPath.toString(), ReleaseLocks.sha256(observationBytes)))
        GenerationCredentialRevisions.validatePublicCertificate(record, observation, bundle.request.id, bundleSha,
            approvedHosts, Instant.now().epochSecond, original, sourceRecord?.first?.let(ReleaseLocks::sha256))
        // A failed publication leaves an unreferenced immutable observation/revision; never
        // mark success in HEAD until both files are fsynced. No synthetic cert or key is written.
        ReleasePrivateFiles.save(observationPath, observationBytes)
        val path = root.resolve("$revisionId.json")
        val bytes = json.encodeToString(record).toByteArray()
        ReleasePrivateFiles.save(path, bytes)
        val binding = ActivationInput(path.toString(), ReleaseLocks.sha256(bytes))
        val predecessor = before?.let { ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("head.json"), 65536)) }
        val next = EffectivePublicCertificateHead(bundle.request.id, bundleSha,
            before?.revisions.orEmpty() + (host to binding), predecessor)
        val nextBytes = json.encodeToString(next).toByteArray()
        ReleasePrivateFiles.save(root.resolve("head-history/${ReleaseLocks.sha256(nextBytes)}.json"), nextBytes)
        val headPath = root.resolve("head.json")
        if (before == null) ReleasePrivateFiles.save(headPath, nextBytes)
        else {
            require(ReleaseLocks.sha256(ReleasePrivateFiles.read(headPath, 65536)) == predecessor)
            val staging = root.resolve("$revisionId.head.pending")
            ReleasePrivateFiles.save(staging, nextBytes)
            Files.move(staging, headPath, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                java.nio.file.StandardCopyOption.REPLACE_EXISTING)
            ReleasePrivateFiles.sync(root)
        }
        return binding
    }
    private fun expectedCapturePathsFromHead(head: EffectivePublicCertificateHead): Set<String> =
        setOf("credential-revisions/public/head.json") + head.revisions.values.flatMap { binding ->
            val name = Path.of(binding.path).fileName.toString()
            require(name.matches(Regex("cert-[a-f0-9]{24}\\.json")))
            listOf("credential-revisions/public/$name",
                "credential-revisions/public/observations/$name")
        }

    /** Complete append-only previous-head graph, including superseded certificate bytes.
     * No dangling, repeated, foreign-generation or unanchored historical revision is
     * silently dropped from a later snapshot. Bounded for source-capture admission.
     */
    internal fun historyPaths(latest: EffectivePublicCertificateHead,
        read: (String) -> ByteArray): Set<String> {
        val paths = linkedSetOf("credential-revisions/public/head.json")
        val visited = mutableSetOf<String>()
        var head = latest
        repeat(256) {
            val encoded = read("credential-revisions/public/head-history/${ReleaseLocks.sha256(
                json.encodeToString(head).toByteArray())}.json")
            val headHash = ReleaseLocks.sha256(encoded)
            require(headHash !in visited &&
                json.decodeFromString<EffectivePublicCertificateHead>(encoded.decodeToString(throwOnInvalidSequence = true)) == head &&
                head.generation == latest.generation && head.bundleSha256 == latest.bundleSha256)
            visited += headHash
            paths += "credential-revisions/public/head-history/$headHash.json"
            head.revisions.forEach { (host, binding) ->
                val name = Path.of(binding.path).fileName.toString()
                require(name.matches(Regex("cert-[a-f0-9]{24}\\.json")))
                val certPath = "credential-revisions/public/$name"
                val bytes = read(certPath)
                require(ReleaseLocks.sha256(bytes) == binding.sha256)
                val record = json.decodeFromString<PublicCertificateRevision>(bytes.decodeToString(throwOnInvalidSequence = true))
                require(record.revisionId == name.removeSuffix(".json") && record.host == host &&
                    record.generation == latest.generation && record.bundleSha256 == latest.bundleSha256)
                val observationPath = "credential-revisions/public/observations/$name"
                require(ReleaseLocks.sha256(read(observationPath)) == record.nativeObservation.sha256)
                paths += certPath; paths += observationPath
            }
            val predecessor = head.predecessorSha256 ?: return paths
            require(predecessor.matches(hash) && predecessor !in visited)
            val previous = read("credential-revisions/public/head-history/$predecessor.json")
            require(ReleaseLocks.sha256(previous) == predecessor)
            head = json.decodeFromString(previous.decodeToString(throwOnInvalidSequence = true))
        }
        error("Unbounded effective certificate predecessor chain")
    }

    /** Read-only pre-client/current-owner probe. Reopens the effective HEAD, protected
     * native issuance record, live Caddy admin config, immutable storage chain/key and
     * independent SNI WebPKI handshake; no cached health or case-provided leaf assertion.
     */
    fun observeCurrentPublic(bundle: GenerationBundle, host: String, approvedHosts: Set<String>,
        trust: ActivationInput, collector: PublicCertificateCollector): PublicCertificateRevision {
        val root = GenerationRuntime.BASE.resolve(bundle.request.id)
        val current = requireNotNull(readHead(root)).revisions.getValue(host)
        val selected = json.decodeFromString<PublicCertificateRevision>(
            ReleasePrivateFiles.read(Path.of(current.path), 65536).decodeToString(throwOnInvalidSequence = true))
        val source = if (selected.origin == PublicCertificateRevisionOrigin.SEALED_RESTORE)
            readOriginal(bundle, host) else null
        val record = GenerationCredentialRevisions.readPublicCertificate(current, bundle.request.id,
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"))), approvedHosts, source)
        require(trust.sha256 == record.publicTrustStoreSha256 &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(trust.path), 1048576)) == trust.sha256)
        val pin = bundle.members.single { it.spec.processes.any { process -> process.id == "caddy" } }
        val observed = collector.observe(pin, host)
        val chain = inspectCrypto(observed.chainPem, observed.privateKeyPem,
            ReleasePrivateFiles.read(Path.of(trust.path), 1048576), observed.observedLeafDer, host, Instant.now())
        val nativePath = Path.of(record.nativeObservation.path)
        val originalNative = json.decodeFromString<PublicCertificateNativeObservation>(
            ReleasePrivateFiles.read(nativePath, 65536).decodeToString(throwOnInvalidSequence = true))
        require(ReleaseLocks.sha256(chain.first().encoded) == record.leafDerSha256 &&
            ReleaseLocks.sha256(observed.chainPem) == record.chainPemSha256 &&
            ReleaseLocks.sha256(observed.privateKeyPem) == record.privateKeyPemSha256 &&
            // Native restart or authorized namespace-local ETag/CAS may change CID
            // and routing config without changing public leaf. The collector freshly
            // audits exact sealed Caddy fingerprint/labels, ACME policy, storage,
            // chain/key and WebPKI SNI, retaining historical issuance observation.
            originalNative.containerId.matches(hash) && observed.containerId.matches(hash) &&
            observed.configurationSha256.matches(hash) &&
            readHead(root)?.revisions?.get(host) == current) {
            "Caddy active public TLS differs from sealed effective credential head"
        }
        return record
    }

    /** A Caddy identity is NOT a TURN authority. A02's actuator installs effective
     * inputs/restarts LiveKit under the same generation/member locks. This method then
     * independently re-reads the actual LiveKit TLS listener and stores a typed result;
     * :5349 ingress must remain closed until the result is reopened by the ingress actor.
     */
    fun adoptTurn(bundle: GenerationBundle, revision: ActivationInput, approvedHosts: Set<String>,
        trust: ActivationInput, collector: PublicCertificateCollector,
        actuator: NativeTurnCredentialActuator, operationId: String): PublicTurnAdoptionResult {
        require(operationId.matches(Regex("[a-z0-9-]{1,64}")) &&
            "rtc.datamancy.net" in approvedHosts && trust.sha256.matches(hash))
        val generationRoot = GenerationRuntime.BASE.resolve(bundle.request.id)
        require(readHead(generationRoot)?.revisions?.get("rtc.datamancy.net") == revision) {
            "TURN cannot adopt a superseded or caller-selected Caddy certificate"
        }
        val selected = json.decodeFromString<PublicCertificateRevision>(
            ReleasePrivateFiles.read(Path.of(revision.path), 65536).decodeToString(throwOnInvalidSequence = true))
        val public = GenerationCredentialRevisions.readPublicCertificate(revision, bundle.request.id,
            ReleaseLocks.sha256(ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"))), approvedHosts,
            if (selected.origin == PublicCertificateRevisionOrigin.SEALED_RESTORE)
                readOriginal(bundle, "rtc.datamancy.net") else null)
        require(public.host == "rtc.datamancy.net" && public.publicTrustStoreSha256 == trust.sha256 &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(trust.path), 1048576)) == trust.sha256)
        val caddy = bundle.members.single { pin -> pin.spec.processes.any { it.id == "caddy" } }
        val livekit = bundle.members.single { pin -> pin.spec.processes.any { it.id == "livekit" } }
        val native = collector.observe(caddy, "rtc.datamancy.net")
        val chain = inspectCrypto(native.chainPem, native.privateKeyPem,
            ReleasePrivateFiles.read(Path.of(trust.path), 1048576), native.observedLeafDer,
            "rtc.datamancy.net", Instant.now())
        require(ReleaseLocks.sha256(chain.first().encoded) == public.leafDerSha256 &&
            ReleaseLocks.sha256(native.chainPem) == public.chainPemSha256 &&
            ReleaseLocks.sha256(native.privateKeyPem) == public.privateKeyPemSha256)
        val inputs = LiveKitRuntime.effectivePublicTurnInputs(bundle.request.id, public,
            native.chainPem.decodeToString(throwOnInvalidSequence = true),
            native.privateKeyPem.decodeToString(throwOnInvalidSequence = true))
        require(inputs.keys == setOf("rtc-turn.pem", "rtc-turn-key.pem") &&
            ReleaseLocks.sha256(inputs.getValue("rtc-turn.pem").toByteArray()) == public.chainPemSha256 &&
            ReleaseLocks.sha256(inputs.getValue("rtc-turn-key.pem").toByteArray()) == public.privateKeyPemSha256)
        val sourceInputs = PrivateDeployment.BASE.resolve(livekit.spec.name)
        val bootstrap = ReleasePrivateFiles.read(sourceInputs.resolve("livekit.yaml"), 1048576)
        val template = ReleasePrivateFiles.read(sourceInputs.resolve("livekit-turn-template.yaml"), 1048576)
        require(livekit.inputHashes["livekit.yaml"] == ReleaseLocks.sha256(bootstrap) &&
            livekit.inputHashes["livekit-turn-template.yaml"] == ReleaseLocks.sha256(template) &&
            livekit.spec.processes.single { it.id == "livekit" }.files.map { it.file }.containsAll(
                setOf("livekit.yaml", "livekit-turn-template.yaml", "rtc-turn.pem", "rtc-turn-key.pem")))
        val effectiveConfig = LiveKitRuntime.effectivePublicTurnConfig(bundle.request.id, public,
            bootstrap.decodeToString(throwOnInvalidSequence = true),
            template.decodeToString(throwOnInvalidSequence = true))
        val effective = inputs + ("livekit.yaml" to effectiveConfig)
        val configSha = ReleaseLocks.sha256(effectiveConfig.toByteArray())
        val root = publicRoot(generationRoot).resolve("turn")
        if (!Files.exists(root, NOFOLLOW_LINKS)) {
            ReleasePrivateFiles.directory(root.parent)
            Files.createDirectory(root, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root.parent)
        }
        ReleasePrivateFiles.directory(root)
        val intent = PublicTurnAdoptionIntent(bundle.request.id, public.bundleSha256, operationId,
            revision.sha256, public.leafDerSha256, public.chainPemSha256, public.privateKeyPemSha256,
            configSha, livekit.runtimeFingerprint)
        val raw = json.encodeToString(intent).toByteArray()
        ReleasePrivateFiles.save(root.resolve("$operationId.intent.json"), raw)
        // A failure at or beyond this boundary leaves an uncertain intent, never a
        // claimed native adoption. The actuator owns actual overlay+atomic restart.
        val observed = actuator.adopt(bundle, livekit, operationId, effective)
        val address = NamespaceCaddyTransport.ownedProcessAddress(livekit.spec, livekit.runtimeFingerprint,
            "livekit", "rtc-turn")
        val factory = CertificateFactory.getInstance("X.509")
        val trusted = factory.generateCertificates(ByteArrayInputStream(ReleasePrivateFiles.read(Path.of(trust.path), 1048576)))
        val store = java.security.KeyStore.getInstance("PKCS12").apply { load(null, null) }
        trusted.forEachIndexed { index, certificate -> store.setCertificateEntry("webpki-$index", certificate) }
        val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
        val context = SSLContext.getInstance("TLS").apply { init(null, managers.trustManagers, null) }
        val socket = java.net.Socket()
        val nativeLeaf = try {
            socket.connect(InetSocketAddress(address, 5349), 2500)
            (context.socketFactory.createSocket(socket, "rtc.datamancy.net", 5349, true) as SSLSocket).use {
                it.soTimeout = 2500
                it.sslParameters = it.sslParameters.apply {
                    serverNames = listOf(javax.net.ssl.SNIHostName("rtc.datamancy.net"))
                    endpointIdentificationAlgorithm = "HTTPS"
                }
                it.startHandshake()
                it.session.peerCertificates.first().encoded
            }
        } finally { socket.close() }
        validateTurnObservation(intent, observed, public, ReleaseLocks.sha256(nativeLeaf))
        val result = PublicTurnAdoptionResult(ReleaseLocks.sha256(raw), revision.sha256, observed)
        ReleasePrivateFiles.save(root.resolve("$operationId.result.json"), json.encodeToString(result).toByteArray())
        return result
    }

    /** Current read-only TURN gate, not a saved-result boolean. Requires the same native
     * LiveKit container, effective secret/argv receipt and fresh SNI listener leaf.
     */
    fun requireTurnAdopted(bundle: GenerationBundle, approvedHosts: Set<String>, trust: ActivationInput,
        collector: PublicCertificateCollector): PublicTurnAdoptionResult {
        val root = GenerationRuntime.BASE.resolve(bundle.request.id)
        val binding = requireNotNull(readHead(root)).revisions.getValue("rtc.datamancy.net")
        val certificate = observeCurrentPublic(bundle, "rtc.datamancy.net", approvedHosts, trust, collector)
        val turnRoot = publicRoot(root).resolve("turn")
        ReleasePrivateFiles.directory(turnRoot)
        val results = Files.list(turnRoot).use { stream -> stream.filter { it.fileName.toString()
            .matches(Regex("[a-z0-9-]{1,64}\\.result\\.json")) }.limit(257).toList() }
        require(results.size in 1..256)
        val matched = results.mapNotNull { file ->
            val result = json.decodeFromString<PublicTurnAdoptionResult>(
                ReleasePrivateFiles.read(file, 65536).decodeToString(throwOnInvalidSequence = true))
            if (result.revisionSha256 != binding.sha256) null else file to result
        }
        require(matched.size == 1)
        val (resultFile, result) = matched.single()
        val operation = resultFile.fileName.toString().removeSuffix(".result.json")
        val intentBytes = ReleasePrivateFiles.read(turnRoot.resolve("$operation.intent.json"), 65536)
        val intent = json.decodeFromString<PublicTurnAdoptionIntent>(intentBytes.decodeToString(throwOnInvalidSequence = true))
        val livekit = bundle.members.single { pin -> pin.spec.processes.any { it.id == "livekit" } }
        require(result.intentSha256 == ReleaseLocks.sha256(intentBytes) && intent.operationId == operation &&
            intent.publicRevisionSha256 == binding.sha256 && intent.livekitFingerprint == livekit.runtimeFingerprint)
        val nativeResult = PrivateDeployment.BASE.resolve(livekit.spec.name)
            .resolve("turn-revisions/operations/$operation.result.json")
        require(json.decodeFromString<PublicTurnNativeObservation>(ReleasePrivateFiles.read(nativeResult, 65536)
            .decodeToString(throwOnInvalidSequence = true)) == result.nativeObservation)
        val inspected = PrivateRootfulCommands(20, livekit.spec.store).run(listOf("inspect", "--type", "container",
            "p0v3-live-${livekit.spec.name}-livekit"))
        require(inspected.exitCode == 0 && inspected.output.length in 1..1048576)
        val container = json.parseToJsonElement(inspected.output).jsonArray.single().jsonObject
        val labels = container.getValue("Config").jsonObject.getValue("Labels").jsonObject
        require(container.getValue("Id").jsonPrimitive.content.removePrefix("sha256:") ==
            result.nativeObservation.livekitContainerId &&
            container.getValue("State").jsonObject.getValue("Running").jsonPrimitive.content == "true" &&
            labels["io.p0v3.private-deployment"]?.jsonPrimitive?.content == livekit.spec.name &&
            labels["io.p0v3.runtime-fingerprint"]?.jsonPrimitive?.content == livekit.runtimeFingerprint &&
            labels["io.p0v3.effective-turn"]?.jsonPrimitive?.content == certificate.revisionId)
        val address = NamespaceCaddyTransport.ownedProcessAddress(livekit.spec, livekit.runtimeFingerprint,
            "livekit", "rtc-turn")
        val factory = CertificateFactory.getInstance("X.509")
        val anchors = factory.generateCertificates(ByteArrayInputStream(ReleasePrivateFiles.read(Path.of(trust.path), 1048576)))
        val keys = java.security.KeyStore.getInstance("PKCS12").apply { load(null, null) }
        anchors.forEachIndexed { index, cert -> keys.setCertificateEntry("webpki-$index", cert) }
        val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(keys) }
        val tls = SSLContext.getInstance("TLS").apply { init(null, managers.trustManagers, null) }
        val socket = java.net.Socket()
        val observed = try {
            socket.connect(InetSocketAddress(address, 5349), 2500)
            (tls.socketFactory.createSocket(socket, "rtc.datamancy.net", 5349, true) as SSLSocket).use {
                it.soTimeout = 2500
                it.sslParameters = it.sslParameters.apply {
                    serverNames = listOf(javax.net.ssl.SNIHostName("rtc.datamancy.net"))
                    endpointIdentificationAlgorithm = "HTTPS"
                }
                it.startHandshake()
                it.session.peerCertificates.first().encoded
            }
        } finally { socket.close() }
        validateTurnObservation(intent, result.nativeObservation, certificate, ReleaseLocks.sha256(observed))
        return result
    }

    internal fun validateTurnObservation(intent: PublicTurnAdoptionIntent, observation: PublicTurnNativeObservation,
        revision: PublicCertificateRevision, independentlyObservedTlsLeafSha256: String) {
        require(intent.generation == revision.generation && intent.bundleSha256 == revision.bundleSha256 &&
            intent.publicRevisionSha256.matches(hash) &&
            intent.leafDerSha256 == revision.leafDerSha256 &&
            intent.chainPemSha256 == revision.chainPemSha256 &&
            intent.privateKeyPemSha256 == revision.privateKeyPemSha256 &&
            intent.effectiveConfigSha256.matches(hash) && intent.livekitFingerprint.matches(hash) &&
            revision.host == "rtc.datamancy.net" && revision.kind == "ACME_PUBLIC" &&
            observation.generation == intent.generation && observation.bundleSha256 == intent.bundleSha256 &&
            observation.operationId == intent.operationId && observation.runtimeFingerprint == intent.livekitFingerprint &&
            observation.livekitContainerId.matches(hash) &&
            observation.installedChainSha256 == intent.chainPemSha256 &&
            observation.installedKeySha256 == intent.privateKeyPemSha256 &&
            observation.installedConfigSha256 == intent.effectiveConfigSha256 &&
            observation.observedCommand == listOf("--config", "/run/turn-revisions/${revision.revisionId}/livekit.yaml") &&
            observation.tlsObservedLeafDerSha256 == independentlyObservedTlsLeafSha256 &&
            observation.tlsObservedLeafDerSha256 == intent.leafDerSha256 &&
            observation.observedAtEpochSeconds > 0) {
            "Native TURN effective config, public leaf and LiveKit deployment do not match"
        }
    }

    /** Decode only a PKCS#8 key; never export private bytes to a revision or acceptance context. */
    internal fun inspectCrypto(chainPem: ByteArray, keyPem: ByteArray, trustPem: ByteArray,
        observedLeafDer: ByteArray, host: String, now: Instant): List<X509Certificate> {
        require(chainPem.size in 1..65536 && keyPem.size in 1..65536 && trustPem.size in 1..1048576)
        val factory = CertificateFactory.getInstance("X.509")
        val chain = factory.generateCertificates(ByteArrayInputStream(chainPem)).map { it as X509Certificate }
        require(chain.size in 2..8 && chain.map { Base64.getEncoder().encodeToString(it.encoded) }.distinct().size == chain.size)
        val leaf = chain.first()
        chain.forEach { it.checkValidity(java.util.Date.from(now)) }
        require(MessageDigest.isEqual(leaf.encoded, observedLeafDer) &&
            leaf.subjectAlternativeNames.orEmpty().filter { it[0] == 2 }.map { it[1] as String }.contains(host) &&
            leaf.subjectAlternativeNames.orEmpty().filter { it[0] == 2 }.all { name ->
                (name[1] as String).matches(Regex("[a-z0-9]+(?:-[a-z0-9]+)*(?:\\.[a-z0-9]+(?:-[a-z0-9]+)*)*\\.datamancy\\.net"))
            } && leaf.basicConstraints == -1)
        val encoded = keyPem.decodeToString(throwOnInvalidSequence = true)
        val base64 = Regex("^-----BEGIN PRIVATE KEY-----\\s+([A-Za-z0-9+/=\\s]+)-----END PRIVATE KEY-----\\s*$",
            RegexOption.DOT_MATCHES_ALL).matchEntire(encoded)?.groupValues?.get(1) ?: error("Expected Caddy PKCS#8 private key")
        val der = Base64.getMimeDecoder().decode(base64)
        val key = try { KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(der)) }
            catch (_: java.security.spec.InvalidKeySpecException) {
                KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(der))
            }
        val algorithm = if (key.algorithm == "RSA") "SHA256withRSA" else "SHA256withECDSA"
        val challenge = "p0v3:public-certificate-key-match:$host".toByteArray()
        val signature = Signature.getInstance(algorithm).apply { initSign(key); update(challenge) }.sign()
        require(Signature.getInstance(algorithm).run { initVerify(leaf.publicKey); update(challenge); verify(signature) })
        val anchors = factory.generateCertificates(ByteArrayInputStream(trustPem))
        require(anchors.isNotEmpty())
        val system = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            init(null as java.security.KeyStore?)
        }.trustManagers.filterIsInstance<javax.net.ssl.X509TrustManager>()
            .flatMap { it.acceptedIssuers.toList() }.map { ReleaseLocks.sha256(it.encoded) }.toSet()
        require(anchors.all { ReleaseLocks.sha256(it.encoded) in system }) {
            "The mounted CA must be an installed public WebPKI trust anchor, never a private recovery CA"
        }
        val selector = java.security.cert.X509CertSelector().apply { certificate = leaf }
        val parameters = java.security.cert.PKIXBuilderParameters(
            anchors.map { java.security.cert.TrustAnchor(it as X509Certificate, null) }.toSet(), selector)
        parameters.isRevocationEnabled = false
        parameters.addCertStore(java.security.cert.CertStore.getInstance("Collection",
            java.security.cert.CollectionCertStoreParameters(chain)))
        require(java.security.cert.CertPathBuilder.getInstance("PKIX").build(parameters) != null)
        return chain
    }
}
