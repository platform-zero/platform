package net.datamancy.platform

import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** Pure source regressions: fake hashes are NOT certificate or native observation evidence. */
class NativeCredentialRevisionTest {
    @Test fun turnPublicAuthorityNeedsExactNativeEffectiveConfigAndIndependentTlsReadback(): Unit {
        val hash = "a".repeat(64)
        val generation = "q-0123456789ab"
        val id = "cert-" + "b".repeat(24)
        val revision = PublicCertificateRevision(revisionId = id, generation = generation, bundleSha256 = hash,
            host = "rtc.datamancy.net", origin = PublicCertificateRevisionOrigin.ACME_ISSUANCE,
            sourceGeneration = generation, sourceRevisionSha256 = null, leafDerSha256 = hash,
            chainPemSha256 = hash, privateKeyPemSha256 = hash, dnsNames = setOf("rtc.datamancy.net"),
            notBeforeEpochSeconds = 1, notAfterEpochSeconds = 1000,
            acmeDirectory = "https://acme-v02.api.letsencrypt.org/directory", publicTrustStoreSha256 = hash,
            nativeObservation = ActivationInput("/protected/native.json", hash))
        val intent = PublicTurnAdoptionIntent(generation, hash, "turn-first", hash,
            hash, hash, hash, hash, hash)
        val observed = PublicTurnNativeObservation(generation, hash, "turn-first", hash, hash,
            hash, hash, hash, listOf("--config", "/run/turn-revisions/$id/livekit.yaml"), hash, 100)
        NativeCredentialRevision.validateTurnObservation(intent, observed, revision, hash)
        for (bad in listOf(observed.copy(installedConfigSha256 = "c".repeat(64)),
            observed.copy(observedCommand = listOf("--config", "/run/secrets/livekit.yaml")),
            observed.copy(tlsObservedLeafDerSha256 = "d".repeat(64)),
            observed.copy(runtimeFingerprint = "e".repeat(64)))) {
            assertFails { NativeCredentialRevision.validateTurnObservation(intent, bad, revision, hash) }
        }
        assertFails { NativeCredentialRevision.validateTurnObservation(intent, observed, revision, "f".repeat(64)) }
    }

    @Test fun invalidPrivateKeyAndFabricatedChainCannotBecomeAcmeRevision(): Unit {
        val fake = "-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n".toByteArray()
        val key = "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n".toByteArray()
        assertFails { NativeCredentialRevision.inspectCrypto(fake, key, fake, byteArrayOf(1, 2, 3),
            "rtc.datamancy.net", Instant.ofEpochSecond(1700000000)) }
        assertFails { NativeCredentialRevision.inspectCrypto(ByteArray(0), key, fake, byteArrayOf(1),
            "rtc.datamancy.net", Instant.ofEpochSecond(1700000000)) }
        assertFails { NativeCredentialRevision.inspectCrypto(fake, key, fake, byteArrayOf(1),
            "*.datamancy.net", Instant.ofEpochSecond(1700000000)) }
    }

    @Test fun immutableHeadHistoryRetainsSupersededOriginalBytesAndRejectsMissingPredecessor(): Unit {
        val generation = "q-0123456789ab"
        val bundle = "a".repeat(64)
        val root = "credential-revisions/public/"
        val native = "b".repeat(64)
        val json = Json { encodeDefaults = true }
        fun previous(index: Int, prior: String?): Pair<EffectivePublicCertificateHead, Map<String, ByteArray>> {
            val id = "cert-" + index.toString(16).padStart(24, '0')
            val observation = "native-observation-$index".toByteArray()
            val observationSha = ReleaseLocks.sha256(observation)
            val record = PublicCertificateRevision(revisionId = id, generation = generation, bundleSha256 = bundle,
                host = "rtc.datamancy.net", origin = PublicCertificateRevisionOrigin.ACME_ISSUANCE,
                sourceGeneration = generation, sourceRevisionSha256 = null, leafDerSha256 = native,
                chainPemSha256 = native, privateKeyPemSha256 = native, dnsNames = setOf("rtc.datamancy.net"),
                notBeforeEpochSeconds = 1, notAfterEpochSeconds = 1000, acmeDirectory =
                    "https://acme-v02.api.letsencrypt.org/directory", publicTrustStoreSha256 = native,
                nativeObservation = ActivationInput("/native/$id.json", observationSha))
            val bytes = json.encodeToString(record).toByteArray()
            val head = EffectivePublicCertificateHead(generation, bundle,
                mapOf("rtc.datamancy.net" to ActivationInput("/original/$id.json", ReleaseLocks.sha256(bytes))), prior)
            val encoded = json.encodeToString(head).toByteArray()
            return head to mapOf(
                "$root$id.json" to bytes,
                "${root}observations/$id.json" to observation,
                "${root}head-history/${ReleaseLocks.sha256(encoded)}.json" to encoded)
        }
        val (first, firstBytes) = previous(1, null)
        val firstHash = ReleaseLocks.sha256(json.encodeToString(first).toByteArray())
        val (second, laterBytes) = previous(2, firstHash)
        val originals = firstBytes + laterBytes
        val paths = NativeCredentialRevision.historyPaths(second) { originals.getValue(it) }
        assertEquals(7, paths.size) // active head + 2 immutable heads + 2 cert/native pairs.
        assertTrue(paths.containsAll(originals.keys))
        assertFails { NativeCredentialRevision.historyPaths(second) { laterBytes.getValue(it) } }
        val replaced = originals + ("${root}head-history/$firstHash.json" to "foreign".toByteArray())
        assertFails { NativeCredentialRevision.historyPaths(second) { replaced.getValue(it) } }
    }

    @Test fun effectiveHeadHasNoAuthorityOrFutureSealedCertificateByDefault(): Unit {
        val source = EffectivePublicCertificateHead("q-0123456789ab", "a".repeat(64),
            mapOf("rtc.datamancy.net" to ActivationInput("/private/source/cert-" + "b".repeat(24) + ".json",
                "c".repeat(64))))
        assertEquals(null, source.predecessorSha256)
        assertTrue(source.revisions.keys == setOf("rtc.datamancy.net"))
        assertFalse(source.revisions.values.any { it.path.contains("key.pem") || it.path.contains("bootstrap") })
    }
}
