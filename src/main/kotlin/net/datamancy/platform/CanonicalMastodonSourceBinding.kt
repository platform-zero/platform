package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.decodeFromString

/** Exact already-restored ORIGINAL capsule plus the one original-copy SQL
 * readback. These are evidence INPUTS, never permission to replay a native
 * source stop, restore, SQL mutation, queue publication or token issuance.
 */
@Serializable internal data class CanonicalMastodonSourceBinding(
    val recoveredRoot: String, val kopiaReceipt: ActivationInput,
    val originalSqlReadback: ActivationInput, val originalCopyReceipt: ActivationInput,
    val originalUsers: ActivationInput, val qualificationFixtureIds: Set<String>) {
    private val decoder: Json get() = Json { ignoreUnknownKeys = false }
    private fun bytes(pin: ActivationInput): ByteArray = GenerationRuntime.privateInput(Path.of(pin.path)).also {
        require(ReleaseLocks.sha256(it) == pin.sha256 && it.size <= 1048576)
    }
    fun original(inventory: AcquiredInventory, generation: String): Triple<MastodonRecovery.CanonicalSource,
        MastodonRecovery.OriginalSqlReadback, Map<String, String>> {
        validatePaths()
        val receipt = decoder.decodeFromString<KopiaSnapshotReceipt>(bytes(kopiaReceipt).decodeToString(
            throwOnInvalidSequence = true))
        KopiaGenerationStore.validate(receipt)
        val recovered = GenerationRecovery.validateKopia(Path.of(recoveredRoot), receipt)
        val source = MastodonRecovery.canonicalSource(recovered, inventory)
        val readback = decoder.decodeFromString<MastodonRecovery.OriginalSqlReadback>(
            bytes(originalSqlReadback).decodeToString(throwOnInvalidSequence = true))
        val copy = bytes(originalCopyReceipt)
        val copied = decoder.parseToJsonElement(copy.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(copied.keys == setOf("sourceGenerationId", "targetGenerationId", "sourceMember",
            "sourceBundleSha256", "copyDeployment", "copyFingerprint", "copyPostgresContainerId",
            "originalArchiveHashes", "nativeImportedArchiveHashes", "sourceKopiaReceiptSha256",
            "postImportIsolationSha256", "originalTokenCustodySha256") &&
            copied.getValue("sourceGenerationId").jsonPrimitive.content == source.generation &&
            copied.getValue("targetGenerationId").jsonPrimitive.content == generation &&
            copied.getValue("copyDeployment").jsonPrimitive.content.startsWith("$generation-mastodon-source-copy") &&
            copied.getValue("copyFingerprint").jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")) &&
            copied.getValue("postImportIsolationSha256").jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")) &&
            copied.getValue("copyPostgresContainerId").jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")) &&
            copied.getValue("sourceMember").jsonPrimitive.content == source.member &&
            copied.getValue("sourceBundleSha256").jsonPrimitive.content == source.originalBundleSha256 &&
            copied.getValue("sourceKopiaReceiptSha256").jsonPrimitive.content == kopiaReceipt.sha256 &&
            copied.getValue("originalArchiveHashes").jsonObject.mapValues { it.value.jsonPrimitive.content } ==
                source.archiveHashes &&
            copied.getValue("nativeImportedArchiveHashes").jsonObject.mapValues { it.value.jsonPrimitive.content } ==
                source.archiveHashes &&
            copied.getValue("originalTokenCustodySha256").jsonPrimitive.content ==
                readback.originalTokenCustodySha256 &&
            readback.sourceBundleSha256 == source.originalBundleSha256 &&
            readback.sourceCopyReceiptSha256 == ReleaseLocks.sha256(copy) &&
            readback.original47SqlSha256.matches(Regex("[a-f0-9]{64}")) &&
            readback.originalTokenCustodySha256.matches(Regex("[a-f0-9]{64}")) &&
            readback.dumpSha256.matches(Regex("[a-f0-9]{64}")) &&
            listOf(readback.ownerId, readback.readerId).all { it.matches(Regex("[1-9][0-9]{0,19}")) } &&
            readback.ownerId != readback.readerId)
        val users = decoder.parseToJsonElement(bytes(originalUsers).decodeToString(
            throwOnInvalidSequence = true)).jsonObject.mapValues { it.value.jsonPrimitive.content }
        require(users.keys == setOf("owner", "reader") && users.values.toSet().size == 2 &&
            users.values.all { it.matches(Regex("[a-zA-Z0-9!@#%^&*_-]{12,128}")) })
        return Triple(source, readback, users)
    }

    fun validatePaths() {
        val root = Path.of(recoveredRoot)
        require(root.isAbsolute && root.normalize() == root &&
            recoveredRoot.startsWith("/mnt/media/p0-v3/release-bootstrap-anchors/mastodon/") &&
            qualificationFixtureIds.size == 2 && qualificationFixtureIds.all {
                it.matches(Regex("rssq-[0-9a-f]{12}"))
            })
        listOf(kopiaReceipt, originalSqlReadback, originalCopyReceipt, originalUsers).forEach { pin ->
            val path = Path.of(pin.path)
            require(path.isAbsolute && path.normalize() == path &&
                pin.sha256.matches(Regex("[a-f0-9]{64}")) &&
                path.startsWith(root.parent) && path != root)
        }
    }
}
