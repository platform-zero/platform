package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** Local owner-only recovery key bootstrap, NOT an offline-key receipt.
 * The private identity lives outside the generation, Kopia repository and all app mounts.
 * Export/verification on another failure domain is a separate qualification gate.
 */
@Serializable internal data class OwnerRecoveryRecipientInventory(val schemaVersion: Int = 1,
    val generation: String, val recipient: String, val recipientFile: ActivationInput,
    val toolSha256: String, val localIdentityOnly: Boolean = true,
    val independentExportVerified: Boolean = false)
@Serializable internal data class OwnerRecoveryIdentityBinding(val schemaVersion: Int = 1,
    val generation: String, val identityPath: String, val identitySha256: String,
    val recipientInventorySha256: String, val recipientSha256: String,
    val toolSha256: String, val independentExportVerified: Boolean = false)

internal object OwnerRecoveryAgeIdentity {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val generation = Regex("q-[a-f0-9]{12}")
    private val recipient = Regex("age1[023456789acdefghjklmnpqrstuvwxyz]{50,120}")
    private const val toolHash = "c56ef69834e18ca4d3b953117f4481522c35fb6862a5d2871685aa4685893664"
    private val tool = Path.of("/home/gerald/.local/bin/age-keygen")
    private val privateBase = Path.of("/home/gerald/.local/share/p0-v3-recovery/age")
    private val publicBase = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/bao/owner-recipients")
    private val mode = PosixFilePermissions.fromString("rwx------")

    private fun owned(path: Path) {
        ReleasePrivateFiles.directory(path)
        require((Files.getAttribute(path,"unix:nlink",NOFOLLOW_LINKS) as Number).toLong() >= 2L)
    }
    private fun ensure(parent: Path, child: Path) {
        owned(parent)
        require(child.parent == parent && !Files.isSymbolicLink(child))
        if (!Files.exists(child, NOFOLLOW_LINKS)) {
            Files.createDirectory(child, PosixFilePermissions.asFileAttribute(mode))
            ReleasePrivateFiles.sync(parent)
        }
        owned(child)
    }
    private fun binary() {
        require(Files.isRegularFile(tool,NOFOLLOW_LINKS) && Files.size(tool) in 1..8388608 &&
            ReleaseLocks.sha256(Files.readAllBytes(tool)) == toolHash) { "Pinned age-keygen unavailable" }
    }
    private fun run(vararg arguments: String): ByteArray {
        binary()
        val p = ProcessBuilder(listOf(tool.toString()) + arguments)
            .redirectInput(ProcessBuilder.Redirect.from(java.io.File("/dev/null")))
            .redirectError(ProcessBuilder.Redirect.DISCARD)
            .apply { environment().clear(); environment().putAll(mapOf("PATH" to "/usr/bin:/bin", "LANG" to "C", "HOME" to privateBase.toString())) }
            .start()
        try {
            val output = p.inputStream.use { it.readNBytes(4097) }
            require(output.size in 1..4096 && p.waitFor(30, TimeUnit.SECONDS) && p.exitValue() == 0) {
                "Pinned age-keygen did not acknowledge a bounded result"
            }
            return output
        } finally { if (p.isAlive) p.destroyForcibly() }
    }
    private fun parsePublic(bytes: ByteArray): String {
        val text = bytes.decodeToString(throwOnInvalidSequence = true).trim()
        require(recipient.matches(text)) { "age-keygen recipient is not canonical" }
        return text
    }
    /** Must be invoked by core under its original owner lock. An attempted or partial
     * identity is never silently regenerated. No private bytes enter a result/log/argv.
     */
    fun issue(id: String): ActivationInput {
        require(id.matches(generation))
        ensure(Path.of("/home/gerald/.local/share"), privateBase.parent)
        ensure(privateBase.parent, privateBase)
        ensure(Path.of("/mnt/media/p0-v3/release-bootstrap-anchors"), publicBase.parent)
        ensure(publicBase.parent, publicBase)
        return ReleasePrivateFiles.locked(privateBase) {
            val dir = privateBase.resolve(id)
            require(!Files.exists(dir, NOFOLLOW_LINKS) &&
                !Files.exists(publicBase.resolve("$id.agepub"), NOFOLLOW_LINKS) &&
                !Files.exists(publicBase.resolve("$id.inventory.json"), NOFOLLOW_LINKS)) {
                "Owner identity already attempted; inspect custody, never regenerate"
            }
            ensure(privateBase, dir)
            val intent = dir.resolve("issue.intent.json")
            ReleasePrivateFiles.save(intent, json.encodeToString(mapOf("generation" to id,
                "toolSha256" to toolHash, "scope" to "owner-local-recovery-identity")).encodeToByteArray())
            val identity = dir.resolve("identity.txt")
            val key = run()
            try {
                val lines = key.decodeToString(throwOnInvalidSequence = true).lines()
                require(lines.count { it.startsWith("AGE-SECRET-KEY-1") } == 1 &&
                    lines.filter { it.isNotBlank() && !it.startsWith('#') }.size == 1 &&
                    lines.any { it.startsWith("# public key: age1") }) {
                    "Pinned age-keygen did not produce one owner identity"
                }
                ReleasePrivateFiles.save(identity, key)
            } finally { key.fill(0) }
            val public = parsePublic(run("-y", identity.toString()))
            val pubPath = publicBase.resolve("$id.agepub")
            ReleasePrivateFiles.save(pubPath, "$public\n".encodeToByteArray())
            val pin = ActivationInput(pubPath.toString(), ReleaseLocks.sha256(ReleasePrivateFiles.read(pubPath,8192)))
            val inventory = OwnerRecoveryRecipientInventory(generation = id, recipient = public,
                recipientFile = pin, toolSha256 = toolHash)
            val inventoryBytes = json.encodeToString(inventory).encodeToByteArray()
            ReleasePrivateFiles.save(publicBase.resolve("$id.inventory.json"), inventoryBytes)
            val binding = OwnerRecoveryIdentityBinding(generation = id, identityPath = identity.toString(),
                identitySha256 = ReleaseLocks.sha256(ReleasePrivateFiles.read(identity,4096)),
                recipientInventorySha256 = ReleaseLocks.sha256(inventoryBytes), recipientSha256 = pin.sha256,
                toolSha256 = toolHash)
            ReleasePrivateFiles.save(dir.resolve("binding.json"), json.encodeToString(binding).encodeToByteArray())
            require(verifyLocal(id) == pin) { "Local identity/recipient readback changed" }
            pin
        }
    }
    /** Separate versioned issuance after the original v1 intent failed BEFORE
     * starting keygen: Java rejects redirectInput(DISCARD) at builder construction.
     * Preserve the original intent, refuse if any private/public effect appeared.
     * This is not a replay or an ACK for the original attempt.
     */
    fun issueAfterInvalidRedirect(id: String): ActivationInput {
        require(id.matches(generation))
        ensure(Path.of("/home/gerald/.local/share"), privateBase.parent)
        ensure(privateBase.parent, privateBase)
        ensure(Path.of("/mnt/media/p0-v3/release-bootstrap-anchors"), publicBase.parent)
        ensure(publicBase.parent, publicBase)
        return ReleasePrivateFiles.locked(privateBase) {
            val dir=privateBase.resolve(id)
            owned(dir)
            val original=json.encodeToString(mapOf("generation" to id,"toolSha256" to toolHash,
                "scope" to "owner-local-recovery-identity")).encodeToByteArray()
            require(ReleasePrivateFiles.read(dir.resolve("issue.intent.json"),8192).contentEquals(original) &&
                !Files.exists(dir.resolve("identity.txt"),NOFOLLOW_LINKS) &&
                !Files.exists(dir.resolve("binding.json"),NOFOLLOW_LINKS) &&
                !Files.exists(dir.resolve("issue-v2.intent.json"),NOFOLLOW_LINKS) &&
                !Files.exists(publicBase.resolve("$id.agepub"),NOFOLLOW_LINKS) &&
                !Files.exists(publicBase.resolve("$id.inventory.json"),NOFOLLOW_LINKS)) {
                "Original pre-effect age failure not safely disposed; preserve all intents"
            }
            val intent=json.encodeToString(mapOf("generation" to id,
                "priorIntentSha256" to ReleaseLocks.sha256(original),
                "disposition" to "redirectInput-DISCARD-rejected-before-ProcessBuilder-start",
                "sourceObservation" to "core-q5962-age-invalid-input-redirect-disposition-619.json")).encodeToByteArray()
            ReleasePrivateFiles.save(dir.resolve("issue-v2.intent.json"),intent)
            val identity=dir.resolve("identity.txt")
            val key=run()
            try {
                val lines=key.decodeToString(throwOnInvalidSequence=true).lines()
                require(lines.count { it.startsWith("AGE-SECRET-KEY-1") }==1 &&
                    lines.filter { it.isNotBlank() && !it.startsWith('#') }.size==1 &&
                    lines.any { it.startsWith("# public key: age1") })
                ReleasePrivateFiles.save(identity,key)
            } finally { key.fill(0) }
            val public=parsePublic(run("-y",identity.toString()))
            val pubPath=publicBase.resolve("$id.agepub")
            ReleasePrivateFiles.save(pubPath,"$public\n".encodeToByteArray())
            val pin=ActivationInput(pubPath.toString(),ReleaseLocks.sha256(ReleasePrivateFiles.read(pubPath,8192)))
            val inventory=OwnerRecoveryRecipientInventory(generation=id,recipient=public,recipientFile=pin,toolSha256=toolHash)
            val inventoryBytes=json.encodeToString(inventory).encodeToByteArray()
            ReleasePrivateFiles.save(publicBase.resolve("$id.inventory.json"),inventoryBytes)
            val binding=OwnerRecoveryIdentityBinding(generation=id,identityPath=identity.toString(),
                identitySha256=ReleaseLocks.sha256(ReleasePrivateFiles.read(identity,4096)),
                recipientInventorySha256=ReleaseLocks.sha256(inventoryBytes),recipientSha256=pin.sha256,toolSha256=toolHash)
            ReleasePrivateFiles.save(dir.resolve("binding.json"),json.encodeToString(binding).encodeToByteArray())
            require(verifyLocal(id)==pin)
            pin
        }
    }
    /** A NEW generation's first attempt, separate from the old generation's v1
     * invalid-redirect intent and its pre-effect-only v2 disposition. This
     * correct stdin path is not an offline/export receipt. Failed/partial v3
     * issuance is terminal for this source path: never regenerate or replay. */
    fun issueFreshV3(id: String): ActivationInput {
        require(id.matches(generation) && id != "q-5962a9fda75b")
        ensure(Path.of("/home/gerald/.local/share"), privateBase.parent)
        ensure(privateBase.parent, privateBase)
        ensure(Path.of("/mnt/media/p0-v3/release-bootstrap-anchors"), publicBase.parent)
        ensure(publicBase.parent, publicBase)
        return ReleasePrivateFiles.locked(privateBase) {
            val dir = privateBase.resolve(id)
            require(!Files.exists(dir, NOFOLLOW_LINKS) &&
                !Files.exists(publicBase.resolve("$id.agepub"), NOFOLLOW_LINKS) &&
                !Files.exists(publicBase.resolve("$id.inventory.json"), NOFOLLOW_LINKS)) {
                "Fresh owner age recipient already attempted; do not regenerate"
            }
            ensure(privateBase, dir)
            ReleasePrivateFiles.save(dir.resolve("issue-v3.intent.json"), json.encodeToString(mapOf(
                "generation" to id, "toolSha256" to toolHash,
                "scope" to "new-owner-local-recovery-identity",
                "predecessorDisposition" to "q-5962a9fda75b-v3-terminal-only"
            )).encodeToByteArray())
            val identity = dir.resolve("identity.txt")
            val key = run()
            try {
                val lines = key.decodeToString(throwOnInvalidSequence = true).lines()
                require(lines.count { it.startsWith("AGE-SECRET-KEY-1") } == 1 &&
                    lines.filter { it.isNotBlank() && !it.startsWith('#') }.size == 1 &&
                    lines.any { it.startsWith("# public key: age1") })
                ReleasePrivateFiles.save(identity, key)
            } finally { key.fill(0) }
            val public = parsePublic(run("-y", identity.toString()))
            val pubPath = publicBase.resolve("$id.agepub")
            ReleasePrivateFiles.save(pubPath, "$public\n".encodeToByteArray())
            val pin = ActivationInput(pubPath.toString(), ReleaseLocks.sha256(ReleasePrivateFiles.read(pubPath, 8192)))
            val inventory = OwnerRecoveryRecipientInventory(generation = id, recipient = public,
                recipientFile = pin, toolSha256 = toolHash)
            val inventoryBytes = json.encodeToString(inventory).encodeToByteArray()
            ReleasePrivateFiles.save(publicBase.resolve("$id.inventory.json"), inventoryBytes)
            val binding = OwnerRecoveryIdentityBinding(generation = id, identityPath = identity.toString(),
                identitySha256 = ReleaseLocks.sha256(ReleasePrivateFiles.read(identity, 4096)),
                recipientInventorySha256 = ReleaseLocks.sha256(inventoryBytes),
                recipientSha256 = pin.sha256, toolSha256 = toolHash)
            ReleasePrivateFiles.save(dir.resolve("binding.json"), json.encodeToString(binding).encodeToByteArray())
            require(verifyLocal(id) == pin)
            pin
        }
    }

    /** Validate the public input automatically before Bao encryption; only owner-private
     * storage can perform the stronger key/recipient consistency readback. Neither is offline custody.
     */
    fun publicRecipient(id: String): ActivationInput {
        require(id.matches(generation))
        owned(publicBase)
        val inventory = json.decodeFromString<OwnerRecoveryRecipientInventory>(ReleasePrivateFiles.read(
            publicBase.resolve("$id.inventory.json"),8192).decodeToString(throwOnInvalidSequence=true))
        val pub = publicBase.resolve("$id.agepub")
        require(inventory.schemaVersion == 1 && inventory.generation == id &&
            inventory.toolSha256 == toolHash && inventory.localIdentityOnly &&
            !inventory.independentExportVerified && inventory.recipient.matches(recipient) &&
            inventory.recipientFile.path == pub.toString() &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(pub,8192)) == inventory.recipientFile.sha256 &&
            ReleasePrivateFiles.read(pub,8192).decodeToString(throwOnInvalidSequence=true) == inventory.recipient + "\n") {
            "Owner recipient inventory or exact public bytes changed"
        }
        return inventory.recipientFile
    }
    fun verifyLocal(id: String): ActivationInput {
        val pin = publicRecipient(id)
        val dir = privateBase.resolve(id)
        owned(dir)
        val binding = json.decodeFromString<OwnerRecoveryIdentityBinding>(ReleasePrivateFiles.read(
            dir.resolve("binding.json"),8192).decodeToString(throwOnInvalidSequence=true))
        require(binding.schemaVersion == 1 && binding.generation == id &&
            binding.identityPath == dir.resolve("identity.txt").toString() &&
            binding.toolSha256 == toolHash && !binding.independentExportVerified &&
            binding.recipientSha256 == pin.sha256 &&
            binding.recipientInventorySha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(
                publicBase.resolve("$id.inventory.json"),8192)) &&
            binding.identitySha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(dir.resolve("identity.txt"),4096)) &&
            parsePublic(run("-y",binding.identityPath)) ==
                ReleasePrivateFiles.read(Path.of(pin.path),8192).decodeToString(throwOnInvalidSequence=true).trim()) {
            "Owner local age identity does not match the public recipient"
        }
        return pin
    }
}
