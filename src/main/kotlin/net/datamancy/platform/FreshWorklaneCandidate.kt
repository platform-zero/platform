package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Fresh-r9 candidate source pin. A repository build is not a native receipt:
 * the immutable copy must still be bound in the new generation's sealed
 * ManagedLanePlan and independently read back before any START.
 */
internal object FreshWorklaneCandidate {
    private const val EXPECTED = "9a5d277c7fb7da3f5e2d61739e11aae5445e9b1723e8188d0f8c4e550be31016"
    fun requireSelected(plan: ManagedLanePlan) {
        val bytes = requireNotNull(javaClass.getResourceAsStream("/fragments/v3/canonical/r9/worklane-candidate.json"))
            .use { it.readBytes() }
        val doc = Json.parseToJsonElement(bytes.decodeToString()).jsonObject
        require(doc.keys == setOf("schemaVersion", "scope", "binary", "toolchain", "chat", "lifecycle") &&
            doc.getValue("schemaVersion").jsonPrimitive.content == "1" &&
            doc.getValue("scope").jsonPrimitive.content == "fresh-r9-unactivated-managed-worklane-candidate")
        // The old selected binary and r9 resource remain immutable. Only the
        // distinct q583 lineage may select a NEW host CLI, after an actual
        // isolated import and no-container missing-broker START refusal.
        if (plan.generation in setOf(GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation)) {
            WorklaneLateBrokerImportProof.verifySelected(plan.native.worklane)
            return
        }
        val pin = doc.getValue("binary").jsonObject
        val path = Path.of(pin.getValue("path").jsonPrimitive.content)
        require(pin.keys == setOf("path", "sha256") && pin.getValue("sha256").jsonPrimitive.content == EXPECTED &&
            plan.native.worklane.path == path.toString() && plan.native.worklane.sha256 == EXPECTED &&
            path.isAbsolute && path.normalize() == path && path.toRealPath() == path &&
            Files.isRegularFile(path, NOFOLLOW_LINKS) && !Files.isSymbolicLink(path) &&
            Files.getPosixFilePermissions(path) == java.nio.file.attribute.PosixFilePermissions.fromString("r-x------") &&
            ReleaseLocks.sha256(Files.readAllBytes(path)) == EXPECTED) {
            "Fresh r9 managed Worklane candidate binary or sealed plan pin changed"
        }
    }
}
