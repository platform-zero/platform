package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.net.URI
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

@Serializable internal data class QualificationRootProvenance(val sourceUri: String,
    val sourceRevision: String, val sourceSha256: String, val rootsSha256: String)
@Serializable internal data class QualificationRootAsset(val pemBase64: String, val sha256: String,
    val provenance: QualificationRootProvenance)
@Serializable internal data class QualificationInputBody(val schemaVersion: Int = 2,
    val qualificationClient: AcquiredInventory, val publicRoots: QualificationRootAsset,
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val seafileToolPins: NativeSeafileToolPins? = null)
@Serializable internal data class QualificationSignedInputs(val schemaVersion: Int = 2,
    val body: QualificationInputBody, val producerKeySha256: String, val signatureBase64: String)
@Serializable internal data class QualificationStageInputsRequest(val schemaVersion: Int = 1,
    val envelope: ActivationInput, val controllerStage: String)
@Serializable internal data class QualificationPublishArtifactsRequest(val schemaVersion: Int = 1,
    val closure: ActivationInput, val acceptanceControllerSha256: String)
internal data class QualificationOriginalInputs(val closure: ActivationArtifactClosure,
    val inventory: AcquiredInventory, val roots: ByteArray, val rootsSha256: String,
    val provenance: QualificationRootProvenance, val suite: QualificationSuitePin,
    val seafileToolPins: NativeSeafileToolPins? = null, val reviewedSeafileProducerKeySha256: String? = null)

/** Reads original signed bytes; never mints a key, root, image pin or acquisition receipt. */
internal object QualificationPrerequisites {
    private val json = Json { encodeDefaults = true; explicitNulls = true; ignoreUnknownKeys = false }
    private val hex = Regex("[a-f0-9]{64}")
    private val registry = Path.of("/mnt/media/p0-v3/release-artifacts")
    private val trust = Path.of("/mnt/media/p0-v3/release-trust/qualification-producer-ed25519.pub")
    // A separately reviewed, candidate-pinned signer fingerprint; never mint a signer here.
    private val seafileReviewer = Path.of("/mnt/media/p0-v3/release-trust/seafile-reviewed-producer-key.sha256")
    private val platform = Path.of("/mnt/media/p0-v3/runtime-supervision/releases")
    private val acceptance = Path.of("/mnt/media/p0-v3/runtime-supervision/acceptance-releases")
    private val assets = setOf("qualification-inputs-v2", "qualification-producer-key",
        "mozilla-public-roots", "mozilla-public-roots-provenance")
    private fun ownedFile(path: Path, owner: Long, mode: Int, limit: Int): ByteArray {
        require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path &&
            Files.isRegularFile(path, NOFOLLOW_LINKS) && Files.size(path) in 1..limit &&
            (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == owner &&
            (Files.getAttribute(path, "unix:mode", NOFOLLOW_LINKS) as Number).toInt().and(4095) == mode &&
            (Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong() == 1L)
        return Files.readAllBytes(path)
    }
    private fun canonical(bytes: ByteArray): JsonObject {
        require(bytes.size in 1..4 * 1024 * 1024)
        val text = bytes.decodeToString(throwOnInvalidSequence = true)
        val objectValue = json.parseToJsonElement(text).jsonObject
        require(objectValue.toString() == text) { "Signed source must not contain duplicate or noncanonical fields" }
        return objectValue
    }
    private fun publicKey(bytes: ByteArray): java.security.PublicKey {
        // These are encodings of an already approved, hash-pinned ORIGINAL public key,
        // never an alternate trust anchor or a generated signing identity.
        val prefix = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
        val der = if (bytes.size == 32) prefix + bytes else {
            val text = bytes.decodeToString(throwOnInvalidSequence = true).trim()
            when {
                text.startsWith("-----BEGIN PUBLIC KEY-----\n") &&
                    text.endsWith("\n-----END PUBLIC KEY-----") -> {
                    val body = text.removePrefix("-----BEGIN PUBLIC KEY-----\n")
                        .removeSuffix("\n-----END PUBLIC KEY-----")
                    require(body.matches(Regex("[A-Za-z0-9+/=\\r\\n]{40,512}")))
                    Base64.getMimeDecoder().decode(body)
                }
                text.matches(Regex("ssh-ed25519 [A-Za-z0-9+/=]{60,128}(?: [A-Za-z0-9_.@-]{1,96})?")) -> {
                    val blob = Base64.getDecoder().decode(text.split(' ')[1])
                    val header = byteArrayOf(0, 0, 0, 11) + "ssh-ed25519".encodeToByteArray() +
                        byteArrayOf(0, 0, 0, 32)
                    require(blob.size == header.size + 32 && blob.take(header.size) == header.toList())
                    prefix + blob.copyOfRange(header.size, blob.size)
                }
                else -> throw IllegalArgumentException("Original producer key format refused")
            }
        }
        return KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(der))
    }
    /** Synthetic fixtures may supply only a verified original key and exact signed bytes. */
    internal fun verifySigned(envelopeBytes: ByteArray, keyBytes: ByteArray): Pair<QualificationInputBody, ByteArray> {
        val original = canonical(envelopeBytes)
        require(original.keys == setOf("schemaVersion", "body", "producerKeySha256", "signatureBase64"))
        val signed = json.decodeFromJsonElement<QualificationSignedInputs>(original)
        require(signed.schemaVersion == 2 && signed.body.schemaVersion == 2 &&
            signed.producerKeySha256 == ReleaseLocks.sha256(keyBytes) && hex.matches(signed.producerKeySha256) &&
            original.getValue("body").jsonObject.keys == setOf("schemaVersion", "qualificationClient", "publicRoots") +
                (if (signed.body.seafileToolPins == null) emptySet() else setOf("seafileToolPins")) &&
            original.getValue("body").toString() == json.encodeToString(signed.body))
        val signature = Base64.getDecoder().decode(signed.signatureBase64)
        require(signature.size == 64 && Signature.getInstance("Ed25519").let {
            it.initVerify(publicKey(keyBytes)); it.update(original.getValue("body").toString().encodeToByteArray())
            it.verify(signature)
        }) { "Original qualification producer signature refused" }
        val inventory = signed.body.qualificationClient
        require(inventory.schemaVersion == 1 && inventory.status == "acquired" &&
            inventory.images.size == 1 && inventory.images.single().let { image ->
                image.product == "qualification-client" && image.os == "linux" && image.architecture == "amd64" &&
                    hex.matches(image.imageId) && image.selectedManifestDigest.matches(Regex("sha256:[a-f0-9]{64}")) &&
                    image.pinnedImage.endsWith("@${image.selectedManifestDigest}") &&
                    image.pinnedImage.matches(Regex("[a-z0-9.-]+/[a-zA-Z0-9/_.-]+@sha256:[a-f0-9]{64}"))
            }) { "Only actually acquired pinned native QClient image is admitted" }
        val root = signed.body.publicRoots
        val provenance = root.provenance
        val uri = URI(provenance.sourceUri)
        require(uri.scheme == "https" && uri.host in setOf("hg.mozilla.org", "raw.githubusercontent.com") &&
            uri.rawUserInfo == null && uri.port == -1 && uri.fragment == null &&
            provenance.sourceRevision.matches(Regex("[a-fA-F0-9]{12,64}")) &&
            hex.matches(provenance.sourceSha256) && hex.matches(root.sha256) &&
            root.sha256 == provenance.rootsSha256)
        val roots = Base64.getDecoder().decode(root.pemBase64)
        require(roots.size in 1..1048576 && ReleaseLocks.sha256(roots) == root.sha256 &&
            roots.decodeToString(throwOnInvalidSequence = true).contains("-----BEGIN CERTIFICATE-----")) {
            "Mozilla original public roots or signed provenance changed"
        }
        return signed.body to roots
    }
    private fun rootFile(path: Path, maximum: Int): ByteArray {
        val parent = path.parent
        require(parent.toRealPath() == parent && Files.isDirectory(parent, NOFOLLOW_LINKS) &&
            (Files.getAttribute(parent, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == 0L &&
            (Files.getAttribute(parent, "unix:mode", NOFOLLOW_LINKS) as Number).toInt().and(4095) == 493)
        return ownedFile(path, 0, 420, maximum)
    }
    fun read(scope: QualificationControlScope): QualificationOriginalInputs {
        require(scope.schemaVersion == 1 && scope.controllerSha256.matches(hex))
        // Actual requested candidate and source suite, not installed bin/lib controller custody.
        val suite = QualificationSuiteClosure.read(scope)
        val binding = Json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(scope.binding.path), 1048576)
            .also { require(ReleaseLocks.sha256(it) == scope.binding.sha256) }.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val candidate = binding.getValue("candidate").jsonObject
        val hash = candidate.getValue("artifactsSha256").jsonPrimitive.content
        require(hash.matches(hex))
        val closureBytes = rootFile(registry.resolve("$hash.json"), 4 * 1024 * 1024)
        require(ReleaseLocks.sha256(closureBytes) == hash)
        val closure = json.decodeFromJsonElement<ActivationArtifactClosure>(canonical(closureBytes))
        require(closure.schemaVersion == 1 && closure.controllers.keys == setOf("platform", "acceptance") &&
            closure.controllers.getValue("acceptance") == scope.controllerSha256 &&
            assets.all { it in closure.assets } && closure.images.containsKey("qualification-client"))
        val platformSha = closure.controllers.getValue("platform")
        require(platformSha.matches(hex))
        PinnedBackupController.verify(platformSha)
        PinnedBackupController.verifyDistribution(acceptance.resolve(scope.controllerSha256),
            scope.controllerSha256, "p0-v3-acceptance")
        val source = platform.resolve(platformSha).resolve("lib/qualification-inputs-v2.json")
        val envelope = ownedFile(source, 0, 420, 4 * 1024 * 1024)
        require(ReleaseLocks.sha256(envelope) == closure.assets.getValue("qualification-inputs-v2"))
        val key = rootFile(trust, 4096)
        require(ReleaseLocks.sha256(key) == closure.assets.getValue("qualification-producer-key"))
        val (body, roots) = verifySigned(envelope, key)
        val image = body.qualificationClient.images.single()
        require(closure.images.getValue("qualification-client") == ActivationImagePin(image.pinnedImage, image.imageId) &&
            closure.assets.getValue("mozilla-public-roots") == body.publicRoots.sha256 &&
            closure.assets.getValue("mozilla-public-roots-provenance") ==
                ReleaseLocks.sha256(json.encodeToString(body.publicRoots.provenance).encodeToByteArray()))
        val reviewed = body.seafileToolPins?.let { pins ->
            val key = rootFile(seafileReviewer, 128)
            require(closure.assets.getValue("seafile-reviewed-producer-key") == ReleaseLocks.sha256(key))
            val digest = key.decodeToString(throwOnInvalidSequence = true).trimEnd('\n')
            require(digest.matches(hex) && key.contentEquals("$digest\n".encodeToByteArray()) &&
                pins.producerPublicKeySha256 == digest)
            digest
        }
        return QualificationOriginalInputs(closure, body.qualificationClient, roots,
            body.publicRoots.sha256, body.publicRoots.provenance, suite, body.seafileToolPins, reviewed)
    }
    /** Explicit privileged publication by the pinned Platform controller itself, not a
     * chmod assumption, helper shell, overwrite, or operator-authored closure trust claim. */
    fun publish(request: QualificationPublishArtifactsRequest): ActivationInput {
        require(request.schemaVersion == 1 && UnixSystem().uid == 0L &&
            request.closure.sha256.matches(hex) && request.acceptanceControllerSha256.matches(hex))
        val source = ReleasePrivateFiles.read(Path.of(request.closure.path), 4 * 1024 * 1024)
        require(ReleaseLocks.sha256(source) == request.closure.sha256)
        val closure = json.decodeFromJsonElement<ActivationArtifactClosure>(canonical(source))
        require(closure.schemaVersion == 1 && closure.controllers.keys == setOf("platform", "acceptance") &&
            closure.controllers.getValue("acceptance") == request.acceptanceControllerSha256 &&
            assets.all { it in closure.assets } && "qualification-client" in closure.images)
        val platformSha = closure.controllers.getValue("platform")
        PinnedBackupController.verify(platformSha)
        PinnedBackupController.verifyDistribution(acceptance.resolve(request.acceptanceControllerSha256),
            request.acceptanceControllerSha256, "p0-v3-acceptance")
        val envelope = ownedFile(platform.resolve(platformSha).resolve("lib/qualification-inputs-v2.json"),
            0, 420, 4 * 1024 * 1024)
        val key = rootFile(trust, 4096)
        require(closure.assets.getValue("qualification-inputs-v2") == ReleaseLocks.sha256(envelope) &&
            closure.assets.getValue("qualification-producer-key") == ReleaseLocks.sha256(key))
        val (body, roots) = verifySigned(envelope, key)
        if (body.seafileToolPins != null) {
            val reviewed = rootFile(seafileReviewer, 128)
            require(closure.assets.getValue("seafile-reviewed-producer-key") == ReleaseLocks.sha256(reviewed) &&
                reviewed.decodeToString(throwOnInvalidSequence = true) ==
                    "${body.seafileToolPins.producerPublicKeySha256}\n")
        }
        require(closure.images.getValue("qualification-client") == body.qualificationClient.images.single().let {
            ActivationImagePin(it.pinnedImage, it.imageId)
        } && closure.assets.getValue("mozilla-public-roots") == ReleaseLocks.sha256(roots) &&
            closure.assets.getValue("mozilla-public-roots-provenance") ==
                ReleaseLocks.sha256(json.encodeToString(body.publicRoots.provenance).encodeToByteArray()))
        val parent = registry.parent
        require(parent.toRealPath() == parent && Files.isDirectory(parent, NOFOLLOW_LINKS) &&
            (Files.getAttribute(parent, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == 0L)
        if (!Files.exists(registry, NOFOLLOW_LINKS)) {
            Files.createDirectory(registry,
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwxr-xr-x")))
            ReleasePrivateFiles.sync(parent)
        }
        require(registry.toRealPath() == registry && Files.isDirectory(registry, NOFOLLOW_LINKS) &&
            (Files.getAttribute(registry, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == 0L &&
            (Files.getAttribute(registry, "unix:mode", NOFOLLOW_LINKS) as Number).toInt().and(4095) == 493)
        val target = registry.resolve("${request.closure.sha256}.json")
        FileChannel.open(target, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-r--r--"))).use { channel ->
            val buffer = ByteBuffer.wrap(source); while (buffer.hasRemaining()) channel.write(buffer)
            channel.force(true)
        }
        ReleasePrivateFiles.sync(registry)
        require(rootFile(target, 4 * 1024 * 1024).contentEquals(source))
        return ActivationInput(target.toString(), request.closure.sha256)
    }
    fun stageRoots(case: Path, inputs: QualificationOriginalInputs): ActivationInput {
        ReleasePrivateFiles.directory(case)
        require(inputs.roots.size in 1..1048576 && ReleaseLocks.sha256(inputs.roots) == inputs.rootsSha256)
        val destination = case.resolve("controller-mozilla-roots.pem")
        ReleasePrivateFiles.save(destination, inputs.roots)
        return ActivationInput(destination.toString(), inputs.rootsSha256)
    }
    fun stage(request: QualificationStageInputsRequest): Path {
        require(request.schemaVersion == 1 && request.envelope.sha256.matches(hex))
        val source = Path.of(request.envelope.path)
        val bytes = ReleasePrivateFiles.read(source, 4 * 1024 * 1024)
        require(ReleaseLocks.sha256(bytes) == request.envelope.sha256)
        verifySigned(bytes, rootFile(trust, 4096))
        val target = Path.of(request.controllerStage)
        require(target.isAbsolute && target.normalize() == target && target.toRealPath() == target &&
            (Files.getAttribute(target, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == UnixSystem().uid &&
            !Files.exists(target.resolve("controller.json"), NOFOLLOW_LINKS) &&
            !target.startsWith(platform) && !target.startsWith(acceptance))
        val lib = target.resolve("lib")
        require(lib.toRealPath() == lib && Files.isDirectory(lib, NOFOLLOW_LINKS) &&
            (Files.getAttribute(lib, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == UnixSystem().uid &&
            !Files.exists(lib.resolve("qualification-inputs-v2.json"), NOFOLLOW_LINKS))
        val file = lib.resolve("qualification-inputs-v2.json")
        FileChannel.open(file, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-r--r--"))).use { channel ->
            val buffer = ByteBuffer.wrap(bytes); while (buffer.hasRemaining()) channel.write(buffer)
            channel.force(true)
        }
        ReleasePrivateFiles.sync(lib)
        return file
    }
}
