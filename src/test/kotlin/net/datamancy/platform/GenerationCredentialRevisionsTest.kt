package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertFailsWith

/** DTO/admission tests only. These fabricated unit records are not certificates or native proof. */
class GenerationCredentialRevisionsTest {
    private val hash = "a".repeat(64)
    private val source = "q-0123456789ab"
    private val target = "q-fedcba987654"
    private val host = "social.datamancy.net"
    private fun revision(generation: String = source) = PublicCertificateRevision(
        revisionId = "cert-" + "b".repeat(24), generation = generation, bundleSha256 = hash,
        host = host, origin = PublicCertificateRevisionOrigin.ACME_ISSUANCE,
        sourceGeneration = generation, sourceRevisionSha256 = null, leafDerSha256 = hash,
        chainPemSha256 = hash, privateKeyPemSha256 = hash, dnsNames = setOf(host),
        notBeforeEpochSeconds = 100, notAfterEpochSeconds = 1000,
        acmeDirectory = "https://acme-v02.api.letsencrypt.org/directory", publicTrustStoreSha256 = hash,
        nativeObservation = ActivationInput("/unit/observation.json", hash))
    private fun observation(record: PublicCertificateRevision) = PublicCertificateNativeObservation(
        generation = record.generation, bundleSha256 = hash, host = host,
        caddyDeployment = "${record.generation}-canonical-providers", runtimeFingerprint = hash,
        containerId = hash, configurationSha256 = hash, leafDerSha256 = record.leafDerSha256,
        chainPemSha256 = record.chainPemSha256, privateKeyPemSha256 = record.privateKeyPemSha256,
        tlsObservedLeafDerSha256 = record.leafDerSha256, publicTrustStoreSha256 = hash,
        acmeDirectory = record.acmeDirectory, dnsNames = record.dnsNames,
        notBeforeEpochSeconds = record.notBeforeEpochSeconds, notAfterEpochSeconds = record.notAfterEpochSeconds)

    @Test fun originalRevisionRequiresMatchingNativeFieldsAndCurrentValidity(): Unit {
        val record = revision()
        val native = observation(record)
        GenerationCredentialRevisions.validatePublicCertificate(record, native, source, hash, setOf(host), 500)
        for (wrong in listOf(native.copy(tlsObservedLeafDerSha256 = "c".repeat(64)),
            native.copy(privateKeyPemSha256 = "c".repeat(64)),
            native.copy(publicTrustStoreSha256 = "c".repeat(64)), native.copy(generation = target))) {
            assertFailsWith<IllegalArgumentException> {
                GenerationCredentialRevisions.validatePublicCertificate(record, wrong, source, hash, setOf(host), 500)
            }
        }
        for (time in listOf(99L, 1000L)) assertFailsWith<IllegalArgumentException> {
            GenerationCredentialRevisions.validatePublicCertificate(record, native, source, hash, setOf(host), time)
        }
    }

    @Test fun privateBootstrapStagingWildcardAndApexAreNotPublicIdentity(): Unit {
        for (wrong in listOf(revision().copy(kind = "PRIVATE_CA"),
            revision().copy(acmeDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"),
            revision().copy(dnsNames = setOf(host, "*.datamancy.net")),
            revision().copy(dnsNames = setOf(host, "datamancy.net")))) {
            assertFailsWith<IllegalArgumentException> {
                GenerationCredentialRevisions.validatePublicCertificate(wrong, observation(wrong), source, hash, setOf(host), 500)
            }
        }
    }

    @Test fun sealedRestoreMustRetainExactOriginalLeafChainKeyAndProvenance(): Unit {
        val original = revision()
        val restored = revision(target).copy(origin = PublicCertificateRevisionOrigin.SEALED_RESTORE,
            sourceGeneration = source, sourceRevisionSha256 = hash)
        GenerationCredentialRevisions.validatePublicCertificate(restored, observation(restored), target,
            hash, setOf(host), 500, original, hash)
        for (wrong in listOf(restored.copy(privateKeyPemSha256 = "c".repeat(64)),
            restored.copy(leafDerSha256 = "c".repeat(64)), restored.copy(sourceRevisionSha256 = "c".repeat(64)),
            restored.copy(publicTrustStoreSha256 = "c".repeat(64)))) {
            assertFailsWith<IllegalArgumentException> {
                GenerationCredentialRevisions.validatePublicCertificate(wrong, observation(wrong), target,
                    hash, setOf(host), 500, original, hash)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            GenerationCredentialRevisions.validatePublicCertificate(restored, observation(restored), target, hash, setOf(host), 500)
        }
    }
}
