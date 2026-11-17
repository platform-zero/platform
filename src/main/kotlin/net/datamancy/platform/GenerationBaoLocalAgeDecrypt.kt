package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** Host-owner-only decryption boundary for a REAL original Bao encrypted
 * export. This is temporary local RESTORE authority, never offline custody or
 * an unseal/readback ACK. Caller must zero plaintext after actual target use. */
internal object GenerationBaoLocalAgeDecrypt {
    private val json = Json { ignoreUnknownKeys = false }
    private val age = Path.of("/home/gerald/.local/bin/age")
    private const val ageSha = "2e305637f2a0555305e21c17fb74446acbb39b53135d43d4b744e50c287133a5"

    fun decryptOriginal(sourceGeneration: String, ciphertext: ActivationInput,
        originalInitSha256: String, originalIssuerResultSha256: String): ByteArray {
        require(sourceGeneration.matches(Regex("q-[a-f0-9]{12}")) &&
            originalInitSha256.matches(Regex("[a-f0-9]{64}")) &&
            originalIssuerResultSha256.matches(Regex("[a-f0-9]{64}")))
        val recipient = OwnerRecoveryAgeIdentity.verifyLocal(sourceGeneration)
        val root = GenerationRuntime.BASE.resolve(sourceGeneration).resolve("bao-custody")
        val envelope = root.resolve("$sourceGeneration-original-init.age")
        val issuerBytes = ReleasePrivateFiles.read(root.resolve(
            "$sourceGeneration-original-issuer.result.json"), 8192)
        require(ReleaseLocks.sha256(issuerBytes) == originalIssuerResultSha256)
        val sourceBundleBytes = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(sourceGeneration)
            .resolve("bundle.json"), 4194304)
        val sourceBundle = json.decodeFromString<GenerationBundle>(sourceBundleBytes
            .decodeToString(throwOnInvalidSequence = true))
        json.decodeFromString<GenerationFreshBaoNativeResult>(issuerBytes
            .decodeToString(throwOnInvalidSequence = true)).also { native ->
            native.validate(sourceGeneration, sourceBundle)
            require(native.originalInit.sha256 == originalInitSha256 &&
                native.bundleSha256 == ReleaseLocks.sha256(sourceBundleBytes))
        }
        val receipt = root.resolve("$sourceGeneration-original-init-export.result.json")
        val intentFile = root.resolve("$sourceGeneration-original-init-export.intent.json")
        require(ciphertext.path == envelope.toString() &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(envelope, 131073)) == ciphertext.sha256)
        val claim = json.decodeFromString<BaoEncryptedExportIntent>(
            ReleasePrivateFiles.read(intentFile, 8192).decodeToString(throwOnInvalidSequence = true))
        val result = json.decodeFromString<BaoEncryptedExportResult>(
            ReleasePrivateFiles.read(receipt, 8192).decodeToString(throwOnInvalidSequence = true))
        require(claim.generation == sourceGeneration && claim.recipientSha256 == recipient.sha256 &&
            claim.originalInitSha256 == originalInitSha256 &&
            claim.originalIssuerResultSha256 == originalIssuerResultSha256 &&
            result.intentSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(intentFile, 8192)) &&
            result.encryptedArchive == ciphertext && result.originalInitSha256 == originalInitSha256 &&
            result.originalIssuerResultSha256 == originalIssuerResultSha256 &&
            !result.operatorOfflineHandoffAcknowledged && !result.qualificationEvidence) {
            "Local owner key cannot adopt an unbound original Bao export or invent offline custody"
        }
        require(Files.isRegularFile(age, NOFOLLOW_LINKS) && Files.size(age) in 1..8388608 &&
            ReleaseLocks.sha256(Files.readAllBytes(age)) == ageSha)
        val identity = Path.of("/home/gerald/.local/share/p0-v3-recovery/age/$sourceGeneration/identity.txt")
        val process = ProcessBuilder(age.toString(), "-d", "-i", identity.toString(), envelope.toString())
            .redirectInput(ProcessBuilder.Redirect.from(java.io.File("/dev/null")))
            .redirectError(ProcessBuilder.Redirect.DISCARD).apply {
                environment().clear(); environment().putAll(mapOf("PATH" to "/usr/bin:/bin", "LANG" to "C"))
            }.start()
        try {
            val bytes = process.inputStream.use { it.readNBytes(65537) }
            if (bytes.size !in 128..65536 || !process.waitFor(60, TimeUnit.SECONDS) ||
                process.exitValue() != 0 || ReleaseLocks.sha256(bytes) != originalInitSha256) {
                bytes.fill(0)
                error("Original local age decryption/refingerprint refused; no target unseal ACK")
            }
            return bytes
        } finally { if (process.isAlive) process.destroyForcibly() }
    }
}
