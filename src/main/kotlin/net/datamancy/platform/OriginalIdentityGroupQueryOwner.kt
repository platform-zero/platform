package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Read-only native SQL producer for the ORIGINAL Keycloak group relation.
 * Invoke while the independently admitted isolated PostgreSQL copy is STILL
 * running, before its one-use isolation. Never start the fenced source or
 * revive the copy after its isolation. The result can later be bound to the
 * copy's original stop/result by OriginalIdentityMembershipSource.project.
 */
@Serializable internal data class OriginalIdentityGroupQueryRequest(val schemaVersion: Int = 1,
    val generation: String, val sourceBundleSha256: String, val sourceGeneration: String,
    val copyContainerId: String, val copyImportResult: ActivationInput,
    val ownerUuid: String, val outsiderUuid: String)
@Serializable internal data class OriginalIdentityGroupSealRequest(
    val originalIdentity: OriginalIdentityBinding, val originalMastodon: CanonicalMastodonSourceBinding,
    val inventory: ActivationInput, val targetGeneration: String, val queryResult: ActivationInput)

internal object OriginalIdentityGroupQueryOwner {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val hash = Regex("[a-f0-9]{64}")
    private fun source(pin: ActivationInput): ByteArray {
        val path = Path.of(pin.path)
        require(path.isAbsolute && path.normalize() == path && hash.matches(pin.sha256) &&
            path.startsWith(Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/mastodon/")))
        return GenerationRuntime.privateInput(path).also { require(ReleaseLocks.sha256(it) == pin.sha256) }
    }
    fun seal(request: OriginalIdentityGroupSealRequest): ActivationInput {
        val generation = request.targetGeneration
        require(generation.matches(Regex("q-[a-f0-9]{12}")))
        request.originalIdentity.validate()
        require(request.originalIdentity.membershipReadback == null)
        val inventory = json.decodeFromString<AcquiredInventory>(GenerationRuntime.privateInput(
            Path.of(request.inventory.path)).also { require(ReleaseLocks.sha256(it) == request.inventory.sha256) }
            .decodeToString(throwOnInvalidSequence = true))
        val (source, _, _) = request.originalMastodon.original(inventory, generation)
        val copy = Json.parseToJsonElement(GenerationRuntime.privateInput(Path.of(
            request.originalMastodon.originalCopyReceipt.path)).decodeToString()).jsonObject
        val resultPath = Path.of(request.queryResult.path)
        val dir = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/identity/$generation")
        require(resultPath == dir.resolve("original-group-query.result.json") &&
            hash.matches(request.queryResult.sha256))
        val resultBytes = GenerationRuntime.privateInput(resultPath)
        require(ReleaseLocks.sha256(resultBytes) == request.queryResult.sha256)
        val result = json.decodeFromString<OriginalIdentityGroupQueryResult>(resultBytes.decodeToString(
            throwOnInvalidSequence = true))
        val expected = OriginalIdentityMembershipSource.queryArguments(result.copyContainerId,
            request.originalIdentity.ownerUuid, request.originalIdentity.outsiderUuid)
        require(result.schemaVersion == 1 && result.exitCode == 0 && result.arguments == expected &&
            result.queryIntentSha256 == ReleaseLocks.sha256(expected.joinToString("\\u0000").toByteArray()) &&
            result.sourceBundleSha256 == source.originalBundleSha256 &&
            result.copyContainerId == copy.getValue("copyPostgresContainerId").jsonPrimitive.content &&
            result.output.length in 1..8192)
        val rows = result.output.trimEnd('\n').lines().map { it.split('\t') }
        val subjects = setOf(request.originalIdentity.ownerUuid, request.originalIdentity.outsiderUuid)
        val names = setOf("admins", "operators", "users", "developers", "agents")
        require(rows.all { it.size == 2 && it[0] in subjects && (it[1].isEmpty() || it[1] in names) } &&
            rows.map { it[0] }.toSet() == subjects)
        val members = rows.groupBy({ it[0] }, { it[1] }).mapValues { (_, groups) ->
            groups.filter { it.isNotEmpty() }.toSet()
        }
        require(members.values.any { it.isNotEmpty() })
        val binding = OriginalIdentityMembershipReadback(originalGeneration = source.generation,
            originalBundleSha256 = source.originalBundleSha256,
            originalKopiaReceiptSha256 = request.originalMastodon.kopiaReceipt.sha256,
            isolatedCopyResultSha256 = request.originalMastodon.originalCopyReceipt.sha256,
            isolatedCopyContainerId = result.copyContainerId,
            nativeQueryIntentSha256 = result.queryIntentSha256,
            nativeQueryResultSha256 = request.queryResult.sha256,
            nativeQueryResult = request.queryResult,
            ownerUuid = request.originalIdentity.ownerUuid, outsiderUuid = request.originalIdentity.outsiderUuid,
            members = members)
        val path = dir.resolve("original-groups.readback.json")
        require(!Files.exists(path, NOFOLLOW_LINKS) &&
            ReleasePrivateFiles.read(dir.resolve("original-group-query.result.json")).contentEquals(resultBytes))
        val bytes = json.encodeToString(binding).toByteArray()
        ReleasePrivateFiles.save(path, bytes)
        return ActivationInput(path.toString(), ReleaseLocks.sha256(bytes))
    }

    fun capture(request: OriginalIdentityGroupQueryRequest, dir: Path): ActivationInput {
        require(request.schemaVersion == 1 && request.generation.matches(Regex("q-[a-f0-9]{12}")) &&
            request.sourceGeneration.matches(Regex("q-[a-f0-9]{12}")) &&
            request.sourceGeneration != request.generation && hash.matches(request.sourceBundleSha256) &&
            hash.matches(request.copyContainerId) &&
            dir == Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/identity/${request.generation}") &&
            !Files.exists(dir, NOFOLLOW_LINKS))
        val imported = Json.parseToJsonElement(source(request.copyImportResult).decodeToString(
            throwOnInvalidSequence = true)).jsonObject
        require(imported.keys == setOf("schemaVersion", "sourceGenerationId", "targetGenerationId",
            "sourceBundleSha256", "copyDeployment", "copyPostgresContainerId", "importResultSha256") &&
            imported.getValue("schemaVersion").jsonPrimitive.int == 1 &&
            imported.getValue("sourceGenerationId").jsonPrimitive.content == request.sourceGeneration &&
            imported.getValue("targetGenerationId").jsonPrimitive.content == request.generation &&
            imported.getValue("sourceBundleSha256").jsonPrimitive.content == request.sourceBundleSha256 &&
            imported.getValue("copyDeployment").jsonPrimitive.content.startsWith(
                "${request.generation}-mastodon-source-copy") &&
            imported.getValue("copyPostgresContainerId").jsonPrimitive.content == request.copyContainerId &&
            hash.matches(imported.getValue("importResultSha256").jsonPrimitive.content))
        val args = OriginalIdentityMembershipSource.queryArguments(request.copyContainerId,
            request.ownerUuid, request.outsiderUuid)
        // Preflight the exact private-store original CID, not a mutable name.
        val native = PrivateRootfulCommands(store = RuntimeStore.CANONICAL_V2)
        val inspection = native.run(listOf("inspect", "--type", "container", request.copyContainerId))
        require(inspection.exitCode == 0 && inspection.output.length in 1..65536)
        val container = Json.parseToJsonElement(inspection.output).jsonArray.single().jsonObject
        require(container.getValue("Id").jsonPrimitive.content == request.copyContainerId &&
            container.getValue("State").jsonObject.getValue("Running").jsonPrimitive.boolean &&
            container.getValue("Name").jsonPrimitive.content.contains(
                "${request.generation}-mastodon-source-copy"))
        Files.createDirectory(dir, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
            java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(dir.parent)
        val intentHash = ReleaseLocks.sha256(args.joinToString("\\u0000").toByteArray())
        ReleasePrivateFiles.save(dir.resolve("original-group-query.intent.json"), json.encodeToString(
            buildJsonObject {
                put("request", json.encodeToJsonElement(request)); put("arguments", json.encodeToJsonElement(args))
                put("queryIntentSha256", intentHash); put("copyImportResultSha256", request.copyImportResult.sha256)
            }).toByteArray())
        val reply = native.run(args) // SELECT ONLY; one original intent, never retry an uncertain result.
        require(reply.exitCode == 0 && reply.output.length in 1..8192)
        val record = OriginalIdentityGroupQueryResult(copyContainerId = request.copyContainerId,
            sourceBundleSha256 = request.sourceBundleSha256, queryIntentSha256 = intentHash,
            arguments = args, exitCode = reply.exitCode, output = reply.output)
        val bytes = json.encodeToString(record).toByteArray()
        val result = dir.resolve("original-group-query.result.json")
        ReleasePrivateFiles.save(result, bytes)
        return ActivationInput(result.toString(), ReleaseLocks.sha256(bytes))
    }
}
