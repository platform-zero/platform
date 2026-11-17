package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Projection ONLY of an independently obtained, one-use original Keycloak
 * SQL-copy readback. Neither the OLD group declarations nor the subject UUID
 * pins authorize a membership. The producer must supply its ORIGINAL Kopia,
 * isolated-copy and read-only SQL query receipts; missing inputs stop source
 * materialization instead of silently assigning admin/owner privileges.
 */
@Serializable internal data class OriginalIdentityMembershipReadback(
    val schemaVersion: Int = 1, val originalGeneration: String,
    val originalBundleSha256: String, val originalKopiaReceiptSha256: String,
    val isolatedCopyResultSha256: String, val isolatedCopyContainerId: String,
    val nativeQueryIntentSha256: String, val nativeQueryResultSha256: String,
    val nativeQueryResult: ActivationInput,
    val ownerUuid: String, val outsiderUuid: String,
    val members: Map<String, Set<String>>)

@Serializable internal data class OriginalIdentityGroupQueryResult(val schemaVersion: Int = 1,
    val copyContainerId: String, val sourceBundleSha256: String, val queryIntentSha256: String,
    val arguments: List<String>, val exitCode: Int, val output: String)

internal object OriginalIdentityMembershipSource {
    private val hash = Regex("[a-f0-9]{64}")
    private val generation = Regex("q-[a-f0-9]{12}")
    private val groups = setOf("admins", "operators", "users", "developers", "agents")
    private val json = Json { ignoreUnknownKeys = false }
    fun queryArguments(cid: String, owner: String, outsider: String): List<String> {
        require(hash.matches(cid) && listOf(owner, outsider).all {
            runCatching { java.util.UUID.fromString(it).toString() == it }.getOrDefault(false) } && owner != outsider)
        val sql = "SELECT u.id || E'\\t' || COALESCE(g.name,'') FROM user_entity u " +
            "LEFT JOIN user_group_membership m ON m.user_id=u.id " +
            "LEFT JOIN keycloak_group g ON g.id=m.group_id " +
            "WHERE u.id IN ('$owner','$outsider') " +
            "AND u.realm_id=(SELECT id FROM realm WHERE name='webservices') ORDER BY u.id,g.name"
        return listOf("exec", "--user", "postgres", cid,
            "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-d", "keycloak", "-c", sql)
    }

    fun project(binding: OriginalIdentityBinding, originalMastodon: CanonicalMastodonSourceBinding,
        inventory: AcquiredInventory, targetGeneration: String): Map<String, Set<String>> {
        binding.validate()
        val pin = requireNotNull(binding.membershipReadback) {
            "Original Keycloak group membership readback required; OLD groups are declarations, not grants"
        }
        val path = Path.of(pin.path)
        require(path.isAbsolute && path.normalize() == path &&
            path.startsWith(Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/identity/")) &&
            hash.matches(pin.sha256))
        val bytes = GenerationRuntime.privateInput(path)
        require(bytes.size in 1..1048576 && ReleaseLocks.sha256(bytes) == pin.sha256)
        val readback = json.decodeFromString<OriginalIdentityMembershipReadback>(bytes.decodeToString(throwOnInvalidSequence = true))
        val (source, _, _) = originalMastodon.original(inventory, targetGeneration)
        val copy = Json.parseToJsonElement(GenerationRuntime.privateInput(
            Path.of(originalMastodon.originalCopyReceipt.path)).decodeToString()).jsonObject
        require(readback.schemaVersion == 1 && generation.matches(readback.originalGeneration) &&
            readback.originalGeneration == source.generation &&
            readback.originalBundleSha256 == source.originalBundleSha256 &&
            readback.originalKopiaReceiptSha256 == originalMastodon.kopiaReceipt.sha256 &&
            readback.isolatedCopyResultSha256 == originalMastodon.originalCopyReceipt.sha256 &&
            readback.isolatedCopyContainerId == copy.getValue("copyPostgresContainerId").jsonPrimitive.content &&
            listOf(readback.originalBundleSha256, readback.originalKopiaReceiptSha256,
                readback.isolatedCopyResultSha256, readback.isolatedCopyContainerId,
                readback.nativeQueryIntentSha256, readback.nativeQueryResultSha256).all(hash::matches) &&
            readback.ownerUuid == binding.ownerUuid && readback.outsiderUuid == binding.outsiderUuid &&
            readback.members.keys == setOf(binding.ownerUuid, binding.outsiderUuid) &&
            readback.members.values.all { names -> names.all { it in groups } } &&
            readback.members.values.any { it.isNotEmpty() }) {
            "Original Keycloak membership custody, group boundary or subjects differ"
        }
        // The copy's final receipt includes its post-import ISOLATION. Do not
        // re-start its CID to query it now: bind the original one-use query
        // result captured while the isolated copy was still live instead.
        val resultPath = Path.of(readback.nativeQueryResult.path)
        require(resultPath.isAbsolute && resultPath.normalize() == resultPath &&
            resultPath.startsWith(Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/identity/")) &&
            hash.matches(readback.nativeQueryResult.sha256))
        val resultBytes = GenerationRuntime.privateInput(resultPath)
        require(resultBytes.size in 1..16384 && ReleaseLocks.sha256(resultBytes) == readback.nativeQueryResult.sha256 &&
            readback.nativeQueryResult.sha256 == readback.nativeQueryResultSha256)
        val result = json.decodeFromString<OriginalIdentityGroupQueryResult>(resultBytes.decodeToString(
            throwOnInvalidSequence = true))
        require(result.schemaVersion == 1 && result.copyContainerId == readback.isolatedCopyContainerId &&
            result.arguments == queryArguments(readback.isolatedCopyContainerId,
                binding.ownerUuid, binding.outsiderUuid) &&
            result.queryIntentSha256 == ReleaseLocks.sha256(result.arguments.joinToString("\\u0000").toByteArray()) &&
            result.queryIntentSha256 == readback.nativeQueryIntentSha256 && result.exitCode == 0 &&
            result.output.length in 1..8192 && result.sourceBundleSha256 == source.originalBundleSha256)
        val rows = result.output.trimEnd('\n').lines().map { it.split('\t') }
        require(rows.all { it.size == 2 && it[0] in setOf(binding.ownerUuid, binding.outsiderUuid) })
        val observed = rows.groupBy({ it[0] }, { it[1] }).mapValues { (_, names) -> names.filter { it.isNotEmpty() }.toSet() }
        require(observed == readback.members) { "Original group query differs from the claimed readback" }
        return observed
    }
}
