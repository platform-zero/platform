package net.datamancy.platform

import java.nio.file.Path
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.attribute.PosixFilePermissions
import java.util.UUID
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** The NEW generation's human subjects are allocated once, before sealing its
 * assembly request. No original Keycloak/SQL/Kopia identity is read or adopted.
 * Group grants are explicit policy for the new owner and non-admin outsider.
 */
@Serializable internal data class FreshIdentityBootstrap(val schemaVersion: Int = 1,
    val ownerUuid: String, val outsiderUuid: String, val appNonMemberUuid: String,
    val ownerGroups: Set<String> = setOf("admins", "operators", "users", "developers"),
    val outsiderGroups: Set<String> = emptySet(),
    val appNonMemberGroups: Set<String> = setOf("users")) {
    fun validate() {
        require(schemaVersion == 1 && setOf(ownerUuid, outsiderUuid, appNonMemberUuid).size == 3 &&
            listOf(ownerUuid, outsiderUuid, appNonMemberUuid).all {
                runCatching { UUID.fromString(it).toString() == it }.getOrDefault(false)
            } && ownerGroups == setOf("admins", "operators", "users", "developers") &&
            outsiderGroups.isEmpty() && appNonMemberGroups == setOf("users")) {
            "Gateway-denied outsider must not inherit GROUP; distinct app-test subject requires users only" }
    }
    fun memberships(): Map<String, Set<String>> { validate(); return mapOf(
        ownerUuid to ownerGroups, outsiderUuid to outsiderGroups,
        appNonMemberUuid to appNonMemberGroups) }
    companion object {
        fun createOnce(path: Path): FreshIdentityBootstrap {
            val base = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors")
            val generation = path.fileName.toString().removeSuffix(".json")
            require(path.isAbsolute && path.normalize() == path &&
                generation.matches(Regex("q-[a-f0-9]{12}")) && path.fileName.toString() == "$generation.json" &&
                path == base.resolve("identity/fresh/$generation.json") &&
                Files.isRegularFile(base.resolve("assembly/$generation/inventory.json"), NOFOLLOW_LINKS))
            GenerationPreparationTerminalDisposition.requireClosedForNewSource(generation)
            GenerationAfterNativeImportLineage.beforeSourceIssue(generation)
            GenerationAfterCapacityRefusalLineage.beforeSourceIssue(generation)
            GenerationAfterQ273Lineage.beforeSourceIssue(generation)
            GenerationAfterQ583Lineage.beforeSourceIssue(generation)
            GenerationAfterQ9bLineage.beforeSourceIssue(generation)
            GenerationAfterQ07Lineage.beforeSourceIssue(generation)
            ReleasePrivateFiles.locked(base) {
                for (directory in listOf(base.resolve("identity"), base.resolve("identity/fresh"))) {
                    if (!Files.exists(directory, NOFOLLOW_LINKS)) {
                        Files.createDirectory(directory, PosixFilePermissions.asFileAttribute(
                            PosixFilePermissions.fromString("rwx------")))
                        ReleasePrivateFiles.sync(directory.parent)
                    }
                    ReleasePrivateFiles.directory(directory)
                }
            }
            val grant = FreshIdentityBootstrap(ownerUuid = UUID.randomUUID().toString(),
                outsiderUuid = UUID.randomUUID().toString(),
                appNonMemberUuid = UUID.randomUUID().toString()).also { it.validate() }
            ReleasePrivateFiles.save(path, Json.encodeToString(grant).toByteArray())
            return grant
        }
    }
}
