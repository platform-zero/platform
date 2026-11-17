package net.datamancy.platform

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** One-use encrypted ORIGINAL Bao init export after native issuance and before
 * late Keeper admission. This local encrypted artifact is not an independent
 * offsite handoff/ACK. Current local qualification requires its actual age
 * decryption plus isolated target unseal and policy readback; independent offsite
 * custody is deferred. Root token and shares never enter argv or journals.
 */
@Serializable internal data class BaoEncryptedExportIntent(val generation: String,
    val originalInitSha256: String, val recipientSha256: String,
    val originalIssuerResultSha256: String, val scope: String = "original-fresh-bao-init-custody-export")
@Serializable internal data class BaoEncryptedExportResult(val intentSha256: String,
    val encryptedArchive: ActivationInput, val originalInitSha256: String,
    val originalIssuerResultSha256: String, val operatorOfflineHandoffAcknowledged: Boolean = false,
    val qualificationEvidence: Boolean = false)
internal object GenerationBaoOfflineCustody {
    private val json = Json { encodeDefaults = true }
    /** The caller must first independently verify the native Bao issuer's
     * original result and exact sealed source generation under owner locks. */
    fun encryptOriginal(generation: String, issuer: FreshOpenBaoBootstrap.Issued,
        recipient: ActivationInput): BaoEncryptedExportResult {
        require(generation.matches(Regex("q-[a-f0-9]{12}")))
        val root=GenerationRuntime.BASE.resolve(generation).resolve("bao-custody")
        ReleasePrivateFiles.directory(root)
        val original=issuer.originalInitFile
        val bytes=ReleasePrivateFiles.read(original,65536)
        require(original.parent == root.resolve(generation) &&
            ReleaseLocks.sha256(bytes)==issuer.originalInitSha256 &&
            issuer.keykeeperTokenFile.parent==original.parent &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(issuer.keykeeperTokenFile,8192))==
                issuer.keykeeperTokenSha256)
        // Original unseal/root bytes stay in the protected issuer directory.
        bytes.fill(0)
        val recipients=Path.of(recipient.path)
        require(recipients.isAbsolute && recipients.normalize()==recipients &&
            recipients.startsWith(Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/bao/owner-recipients")) &&
            recipients.fileName.toString()=="$generation.agepub")
        val public=ReleasePrivateFiles.read(recipients,8192)
        require(ReleaseLocks.sha256(public)==recipient.sha256 &&
            public.decodeToString(throwOnInvalidSequence=true).trim()
                .matches(Regex("age1[023456789acdefghjklmnpqrstuvwxyz]{50,120}")))
        val bundleBytes=ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(generation).resolve("bundle.json"))
        val bundle=json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence=true))
        val issuerResult=root.resolve("$generation-original-issuer.result.json")
        val resultBytes=ReleasePrivateFiles.read(issuerResult,8192)
        val native=json.decodeFromString<GenerationFreshBaoNativeResult>(
            resultBytes.decodeToString(throwOnInvalidSequence=true))
        native.validate(generation,bundle)
        require(native.originalInit == ActivationInput(original.toString(),issuer.originalInitSha256) &&
            native.derivedKeykeeperToken == ActivationInput(issuer.keykeeperTokenFile.toString(),
                issuer.keykeeperTokenSha256) &&
            native.bundleSha256==ReleaseLocks.sha256(bundleBytes))
        val claim=BaoEncryptedExportIntent(generation,issuer.originalInitSha256,recipient.sha256,
            ReleaseLocks.sha256(resultBytes))
        val target=root.resolve("$generation-original-init.age")
        val intent=root.resolve("$generation-original-init-export.intent.json")
        val result=root.resolve("$generation-original-init-export.result.json")
        require(listOf(target,intent,result).none { Files.exists(it,NOFOLLOW_LINKS) }) {
            "Original encrypted custody export may be uncertain; never replay"
        }
        val age=Path.of("/home/gerald/.local/bin/age")
        require(Files.isRegularFile(age,NOFOLLOW_LINKS) && Files.size(age) in 1..8388608 &&
            ReleaseLocks.sha256(Files.readAllBytes(age))==
                "2e305637f2a0555305e21c17fb74446acbb39b53135d43d4b744e50c287133a5") {
            "Operator encrypted export needs the exact reviewed age binary"
        }
        val intentBytes=json.encodeToString(claim).toByteArray()
        ReleasePrivateFiles.save(intent,intentBytes)
        FileChannel.open(target,setOf(CREATE_NEW,WRITE,NOFOLLOW_LINKS),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use { out ->
            val process=ProcessBuilder(age.toString(),"-R",recipients.toString(),
                original.toString()).redirectError(ProcessBuilder.Redirect.DISCARD).start()
            var count=0
            try {
                process.inputStream.use { stream ->
                    val buffer=ByteArray(8192)
                    while (true) {
                        val n=stream.read(buffer)
                        if (n<0) break
                        count=Math.addExact(count,n)
                        require(count<=131072) { "Encrypted owner export exceeds protected bound" }
                        val value=ByteBuffer.wrap(buffer,0,n)
                        while (value.hasRemaining()) out.write(value)
                    }
                }
                require(process.waitFor(60,TimeUnit.SECONDS) && process.exitValue()==0 && count in 128..131072) {
                    "Original encrypted export has no native age ACK; preserve intent/output"
                }
                out.force(true)
            } finally { if (process.isAlive) process.destroyForcibly() }
        }
        ReleasePrivateFiles.sync(root)
        val pin=ActivationInput(target.toString(),RecoveryCapsule.fileHash(target))
        return BaoEncryptedExportResult(ReleaseLocks.sha256(intentBytes),pin,
            issuer.originalInitSha256,claim.originalIssuerResultSha256).also {
            ReleasePrivateFiles.save(result,json.encodeToString(it).toByteArray())
        }
    }
}
