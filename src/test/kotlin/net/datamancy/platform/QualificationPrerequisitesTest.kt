package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Synthetic signatures only; this test never creates a production trust anchor or acquisition. */
class QualificationPrerequisitesTest {
    private val json = Json { encodeDefaults = true; explicitNulls = true }
    private val original = "-----BEGIN CERTIFICATE-----\nUNIT-ONLY-NOT-A-REAL-ROOT\n-----END CERTIFICATE-----\n".encodeToByteArray()
    private val hash = ReleaseLocks.sha256(original)
    private val image = AcquiredImage("qualification-client", "https://example.invalid/unit", "example.invalid/client:v1",
        "example.invalid/client@sha256:${"b".repeat(64)}", "a".repeat(64),
        listOf("example.invalid/client@sha256:${"b".repeat(64)}"), "sha256:${"b".repeat(64)}", "amd64", "linux")
    private val body = QualificationInputBody(qualificationClient = AcquiredInventory(1, "acquired", listOf(image)),
        publicRoots = QualificationRootAsset(Base64.getEncoder().encodeToString(original), hash,
            QualificationRootProvenance("https://hg.mozilla.org/projects/nss/file/certdata.txt",
                "a".repeat(40), "c".repeat(64), hash)))
    private val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
    private val publicKey = ("-----BEGIN PUBLIC KEY-----\n" + Base64.getEncoder().encodeToString(keyPair.public.encoded) +
        "\n-----END PUBLIC KEY-----\n").encodeToByteArray()
    private fun signed(value: QualificationInputBody = body): ByteArray {
        val message = json.encodeToString(value).encodeToByteArray()
        val signature = Signature.getInstance("Ed25519").apply { initSign(keyPair.private); update(message) }.sign()
        return json.encodeToString(QualificationSignedInputs(body = value,
            producerKeySha256 = ReleaseLocks.sha256(publicKey),
            signatureBase64 = Base64.getEncoder().encodeToString(signature))).encodeToByteArray()
    }
    @Test fun `early prerequisite refuses absent candidate definition preimage before signed asset selection`() {
        val control = Files.createTempDirectory("synthetic-suite-prerequisite-")
        Files.setPosixFilePermissions(control, PosixFilePermissions.fromString("rwx------"))
        val binding = control.resolve("binding.json")
        try {
            val original = buildJsonObject {
                put("trialId", "trial-one"); put("phase", "RESTORE")
                put("generationId", "q-111111111111")
                put("candidate", buildJsonObject { put("acceptanceSha256", "d".repeat(64)) })
            }.toString().encodeToByteArray()
            Files.write(binding, original)
            Files.setPosixFilePermissions(binding, PosixFilePermissions.fromString("rw-------"))
            val scope = QualificationControlScope(suiteId = "a".repeat(24), generationId = "q-111111111111",
                bundleSha256 = "b".repeat(64), operation = "execute-qualified", controllerSha256 = "c".repeat(64),
                products = ActivationInput(control.resolve("inventory.json").toString(), "d".repeat(64)),
                manifest = ActivationInput(control.resolve("cases/manifest.json").toString(), "d".repeat(64)),
                binding = ActivationInput(binding.toString(), ReleaseLocks.sha256(original)),
                journalFile = control.resolve("qualification.jsonl").toString(),
                journalHeadSha256 = "e".repeat(64), artifactRoot = control.resolve("artifacts").toString(),
                contexts = null)
            val absent = assertFailsWith<NoSuchFileException> { QualificationPrerequisites.read(scope) }
            assertTrue(absent.file.endsWith("phase-trial-one-restore.definition-v2.json"))
        } finally {
            Files.deleteIfExists(binding); Files.delete(control)
        }
    }
    @Test fun `reviewed immutable synthetic asset binds exact signed bytes image roots and provenance`(): Unit {
        val (decoded, roots) = QualificationPrerequisites.verifySigned(signed(), publicKey)
        assertEquals(body, decoded)
        assertEquals(hash, ReleaseLocks.sha256(roots))
    }
    @Test fun `signed Seafile tool hashes remain inside the candidate acquisition envelope`() {
        val pins = NativeSeafileToolPins("a".repeat(64), "b".repeat(64), "c".repeat(64),
            "d".repeat(64), "e".repeat(64), "f".repeat(64), "1".repeat(64),
            "2".repeat(64), "3".repeat(64))
        val acquired = body.copy(seafileToolPins = pins)
        assertEquals(pins, QualificationPrerequisites.verifySigned(signed(acquired), publicKey).first.seafileToolPins)
        assertFails { QualificationPrerequisites.verifySigned(signed(acquired).decodeToString()
            .replace("\"producerPublicKeySha256\":\"${"1".repeat(64)}\"",
                "\"producerPublicKeySha256\":\"${"4".repeat(64)}\"").encodeToByteArray(), publicKey) }
    }
    @Test fun `unknown signer changed signed bytes substituted roots or extra image refuse`(): Unit {
        val raw = signed()
        assertFails { QualificationPrerequisites.verifySigned(raw, "other key".encodeToByteArray()) }
        assertFails { QualificationPrerequisites.verifySigned(raw + byteArrayOf(32), publicKey) }
        assertFails { QualificationPrerequisites.verifySigned(raw.decodeToString().replace("acquired", "unsigned").encodeToByteArray(), publicKey) }
        assertFails { QualificationPrerequisites.verifySigned(signed(body.copy(publicRoots = body.publicRoots.copy(sha256 = "d".repeat(64)))), publicKey) }
        assertFails { QualificationPrerequisites.verifySigned(signed(body.copy(qualificationClient =
            body.qualificationClient.copy(images = listOf(image, image.copy(product = "other"))))), publicKey) }
        assertFails { QualificationPrerequisites.verifySigned(signed(body.copy(publicRoots = body.publicRoots.copy(
            provenance = body.publicRoots.provenance.copy(sourceUri = "https://other.example/certdata.txt")))), publicKey) }
    }
}
