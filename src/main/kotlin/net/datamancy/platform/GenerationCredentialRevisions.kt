package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Public identity provenance is not a caller boolean or a private-CA trust installation.
 * No private key bytes are exposed to qualification clients. The native certificate exporter
 * and revision publisher must supply the protected observations before this reader can succeed.
 */
@Serializable internal enum class PublicCertificateRevisionOrigin { ACME_ISSUANCE, SEALED_RESTORE }
@Serializable internal data class PublicCertificateRevision(
    val schemaVersion: Int = 1,
    val kind: String = "ACME_PUBLIC",
    val revisionId: String,
    val generation: String,
    val bundleSha256: String,
    val host: String,
    val origin: PublicCertificateRevisionOrigin,
    val sourceGeneration: String,
    val sourceRevisionSha256: String?,
    val leafDerSha256: String,
    val chainPemSha256: String,
    val privateKeyPemSha256: String,
    val dnsNames: Set<String>,
    val notBeforeEpochSeconds: Long,
    val notAfterEpochSeconds: Long,
    val acmeDirectory: String,
    val publicTrustStoreSha256: String,
    val nativeObservation: ActivationInput)

/** Native storage export + independent TLS observation, emitted only after real chain, SAN,
 * validity and private-key congruence verification. A parser accepting this record is not its
 * producer, nor does publication of a certificate authorize site activation or TURN binding.
 */
@Serializable internal data class PublicCertificateNativeObservation(
    val schemaVersion: Int = 1,
    val generation: String,
    val bundleSha256: String,
    val host: String,
    val caddyDeployment: String,
    val runtimeFingerprint: String,
    val containerId: String,
    val configurationSha256: String,
    val leafDerSha256: String,
    val chainPemSha256: String,
    val privateKeyPemSha256: String,
    val tlsObservedLeafDerSha256: String,
    val publicTrustStoreSha256: String,
    val acmeDirectory: String,
    val dnsNames: Set<String>,
    val notBeforeEpochSeconds: Long,
    val notAfterEpochSeconds: Long)

internal object GenerationCredentialRevisions {
    private val json = Json { ignoreUnknownKeys = false }
    private val digest = Regex("[a-f0-9]{64}")
    private val generation = Regex("q-[a-f0-9]{12}")
    private val revision = Regex("cert-[a-f0-9]{24}")

    /** Pure binding checks, also used by source tests. Does not assert native observation occurred. */
    fun validatePublicCertificate(record: PublicCertificateRevision, native: PublicCertificateNativeObservation,
        expectedGeneration: String, expectedBundleSha256: String, approvedHosts: Set<String>, nowEpochSeconds: Long,
        original: PublicCertificateRevision? = null, originalSha256: String? = null) {
        require(record.schemaVersion == 1 && record.kind == "ACME_PUBLIC" && native.schemaVersion == 1 &&
            generation.matches(expectedGeneration) && record.generation == expectedGeneration &&
            record.bundleSha256 == expectedBundleSha256 && digest.matches(expectedBundleSha256) &&
            revision.matches(record.revisionId) && generation.matches(record.sourceGeneration))
        require(approvedHosts.isNotEmpty() && approvedHosts.all {
            it.matches(Regex("[a-z0-9]+(?:-[a-z0-9]+)*(?:\\.[a-z0-9]+(?:-[a-z0-9]+)*)*\\.datamancy\\.net"))
        } && record.host in approvedHosts && record.host in record.dnsNames &&
            record.dnsNames.isNotEmpty() && approvedHosts.containsAll(record.dnsNames)) {
            "Certificate must name only the exact approved non-apex, non-wildcard hosts"
        }
        require(listOf(record.leafDerSha256, record.chainPemSha256, record.privateKeyPemSha256,
            record.publicTrustStoreSha256, record.nativeObservation.sha256, native.runtimeFingerprint,
            native.containerId, native.configurationSha256).all(digest::matches) &&
            record.acmeDirectory == "https://acme-v02.api.letsencrypt.org/directory" &&
            nowEpochSeconds >= record.notBeforeEpochSeconds && nowEpochSeconds < record.notAfterEpochSeconds) {
            "Missing production ACME identity, native bindings or current validity"
        }
        require(native.generation == record.generation && native.bundleSha256 == record.bundleSha256 &&
            native.host == record.host && native.caddyDeployment.startsWith("${record.generation}-") &&
            native.leafDerSha256 == record.leafDerSha256 && native.tlsObservedLeafDerSha256 == record.leafDerSha256 &&
            native.chainPemSha256 == record.chainPemSha256 && native.privateKeyPemSha256 == record.privateKeyPemSha256 &&
            native.publicTrustStoreSha256 == record.publicTrustStoreSha256 && native.acmeDirectory == record.acmeDirectory &&
            native.dnsNames == record.dnsNames && native.notBeforeEpochSeconds == record.notBeforeEpochSeconds &&
            native.notAfterEpochSeconds == record.notAfterEpochSeconds) { "Native certificate observation differs from revision" }
        when (record.origin) {
            PublicCertificateRevisionOrigin.ACME_ISSUANCE -> require(record.sourceGeneration == record.generation &&
                record.sourceRevisionSha256 == null && original == null && originalSha256 == null)
            PublicCertificateRevisionOrigin.SEALED_RESTORE -> {
                val source = requireNotNull(original) { "Authenticated original public certificate revision required" }
                require(originalSha256 != null && digest.matches(originalSha256) &&
                    record.sourceRevisionSha256 == originalSha256 && record.sourceGeneration == source.generation &&
                    source.generation != record.generation && source.kind == "ACME_PUBLIC" && source.schemaVersion == 1 &&
                    source.host == record.host && source.leafDerSha256 == record.leafDerSha256 &&
                    source.chainPemSha256 == record.chainPemSha256 && source.privateKeyPemSha256 == record.privateKeyPemSha256 &&
                    source.dnsNames == record.dnsNames && source.notBeforeEpochSeconds == record.notBeforeEpochSeconds &&
                    source.notAfterEpochSeconds == record.notAfterEpochSeconds && source.acmeDirectory == record.acmeDirectory &&
                    source.publicTrustStoreSha256 == record.publicTrustStoreSha256) {
                    "Private restore cannot mint or substitute the original public certificate identity"
                }
            }
        }
    }

    /** Only fixed generation-private locations, never a case-mounted receipt or arbitrary key path.
     * For RESTORE, the caller obtains original bytes from authenticated Kopia materialization.
     */
    fun readPublicCertificate(binding: ActivationInput, expectedGeneration: String, expectedBundleSha256: String,
        approvedHosts: Set<String>, originalBytes: ByteArray? = null,
        nowEpochSeconds: Long = java.time.Instant.now().epochSecond): PublicCertificateRevision {
        require(generation.matches(expectedGeneration) && digest.matches(binding.sha256))
        val root = GenerationRuntime.BASE.resolve(expectedGeneration).resolve("credential-revisions/public")
        ReleasePrivateFiles.directory(root)
        val file = Path.of(binding.path)
        require(file.parent == root && file.fileName.toString().matches(Regex("cert-[a-f0-9]{24}\\.json")))
        val bytes = ReleasePrivateFiles.read(file, 65536)
        require(ReleaseLocks.sha256(bytes) == binding.sha256)
        val record = json.decodeFromString<PublicCertificateRevision>(bytes.decodeToString(throwOnInvalidSequence = true))
        require(file.fileName.toString() == "${record.revisionId}.json")
        val nativePath = root.resolve("observations/${record.revisionId}.json")
        require(Path.of(record.nativeObservation.path) == nativePath)
        val nativeBytes = ReleasePrivateFiles.read(nativePath, 65536)
        require(ReleaseLocks.sha256(nativeBytes) == record.nativeObservation.sha256)
        val native = json.decodeFromString<PublicCertificateNativeObservation>(nativeBytes.decodeToString(throwOnInvalidSequence = true))
        val bundleBytes = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(expectedGeneration).resolve("bundle.json"))
        require(ReleaseLocks.sha256(bundleBytes) == expectedBundleSha256)
        val bundle = json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
        require(bundle.request.id == expectedGeneration)
        SiteOwnerships.checkSealed(bundle)
        val caddy = bundle.members.single { it.member.name == native.caddyDeployment }
        require(caddy.spec.name == caddy.member.name && caddy.runtimeFingerprint == native.runtimeFingerprint &&
            PrivateDeployment.expectedFingerprint(caddy.spec, caddy.inputHashes) == caddy.runtimeFingerprint &&
            caddy.spec.processes.count { it.id == "caddy" && !it.oneShot } == 1) {
            "Certificate observation is not the sealed generation Caddy owner"
        }
        val original = originalBytes?.let {
            require(it.size in 1..65536)
            json.decodeFromString<PublicCertificateRevision>(it.decodeToString(throwOnInvalidSequence = true))
        }
        validatePublicCertificate(record, native, expectedGeneration, expectedBundleSha256, approvedHosts,
            nowEpochSeconds, original, originalBytes?.let(ReleaseLocks::sha256))
        return record
    }
}
