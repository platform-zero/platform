package net.datamancy.platform

import java.time.Instant
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

/** A trusted, locked reference census, NOT caller-supplied authorization on a public CLI.
 * The authority must hold all reference writers excluded throughout the callback (including deletion).
 * Functional IDs must come from retained successful restore evaluations, never snapshot verification alone.
 */
internal fun interface KopiaRetentionAuthority {
    fun withProtection(action: (KopiaRetentionProtection) -> KopiaRetentionResult): KopiaRetentionResult
}

internal data class KopiaRetentionProtection(
    val referenceHeadSha256: String,
    val receipts: List<KopiaSnapshotReceipt>,
    val referencedSnapshotIds: Set<String>,
    val functionallyVerifiedSnapshotIds: Set<String>
)

@Serializable internal data class KopiaRetentionPlan(
    val schemaVersion: Int = 1, val id: String, val generation: String, val referenceHeadSha256: String,
    val beforeSha256: String, val retain: List<String>, val delete: List<String>
)
@Serializable internal data class KopiaRetentionResult(val plan: KopiaRetentionPlan, val afterSha256: String)
@Serializable internal data class KopiaRetentionObservation(val id: String, val planSha256: String,
    val inventorySha256: String, val removed: List<String>, val status: String)

/** Kopia computes calendar retention. Kotlin only adds reference/functional protection and exact identity checks.
 * Never remove pins: Kopia pin updates replace manifest IDs and would invalidate immutable recovery receipts.
 */
internal object KopiaRetention {
    fun inventory(text: String): Map<String, JsonObject> {
        require(text.toByteArray().size in 1..1048576) { "Oversized Kopia retention inventory" }
        val values = Json.parseToJsonElement(text).jsonArray.map { it.jsonObject }
        require(values.size in 2..128) { "Bounded complete retention inventory required" }
        val result = values.associateBy { it.getValue("id").jsonPrimitive.content }
        require(result.size == values.size) { "Duplicate Kopia manifest identity" }
        return result
    }

    fun plan(id: String, generation: String, text: String, protection: KopiaRetentionProtection,
        validateNative: (JsonObject, KopiaSnapshotReceipt) -> Unit): KopiaRetentionPlan {
        require(id.matches(Regex("r-[a-f0-9]{12}")) && generation.matches(Regex("q-[a-f0-9]{12}")) &&
            protection.referenceHeadSha256.matches(Regex("[a-f0-9]{64}")))
        val native = inventory(text)
        val receipts = protection.receipts.associateBy { it.snapshotId }
        require(receipts.size == protection.receipts.size && receipts.keys == native.keys &&
            protection.receipts.map { it.id }.distinct().size == receipts.size) { "Exact retained receipt census required" }
        require(native.keys.containsAll(protection.referencedSnapshotIds) &&
            native.keys.containsAll(protection.functionallyVerifiedSnapshotIds) &&
            protection.functionallyVerifiedSnapshotIds.size >= 2) { "Two functionally verified recovery points and all references required" }
        for ((snapshot, receipt) in receipts) {
            KopiaGenerationStore.validate(receipt)
            require(receipt.generation == generation)
            validateNative(native.getValue(snapshot), receipt)
            // Only the original capture pin is ours to retire. Any additional pin protects the snapshot.
            require(receipt.id in pins(native.getValue(snapshot))) { "Original capture pin missing; uncertain native metadata" }
            Instant.parse(native.getValue(snapshot).getValue("startTime").jsonPrimitive.content)
        }
        val reasons = native.mapValues { (_, value) -> value["retentionReason"]?.jsonArray?.map { it.jsonPrimitive.content }.orEmpty() }
        // Kopia logs policy-evaluation errors but can still exit zero with no reasons. Do not interpret that as permission.
        require((1..2).all { number -> reasons.values.count { "latest-$number" in it } == 1 } &&
            reasons.values.count { "daily-1" in it } == 1 && reasons.values.count { "weekly-1" in it } == 1) {
            "Missing native Kopia retention decision"
        }
        val verified = protection.functionallyVerifiedSnapshotIds.sortedWith(
            compareByDescending<String> { Instant.parse(native.getValue(it).getValue("startTime").jsonPrimitive.content) }.thenBy { it }
        ).take(2).toSet()
        val retain = native.keys.filter { key ->
            key in protection.referencedSnapshotIds || key in verified || reasons.getValue(key).isNotEmpty() ||
                pins(native.getValue(key)).any { it != receipts.getValue(key).id }
        }.sorted()
        return KopiaRetentionPlan(id = id, generation = generation, referenceHeadSha256 = protection.referenceHeadSha256,
            beforeSha256 = ReleaseLocks.sha256(text.toByteArray()), retain = retain, delete = (native.keys - retain.toSet()).sorted())
    }

    private fun pins(value: JsonObject) = value["pins"]?.jsonArray?.map { it.jsonPrimitive.content }.orEmpty()

    fun verifyAfter(before: String, after: String, plan: KopiaRetentionPlan) {
        require(observe(before, after, plan) == plan.delete) { "Uncertain Kopia deletion; retained inventory differs from intent" }
    }

    /** Observation cannot clear a pending claim: an unknown worker may still be running. */
    fun observe(before: String, after: String, plan: KopiaRetentionPlan): List<String> {
        require(ReleaseLocks.sha256(before.toByteArray()) == plan.beforeSha256)
        val old = inventory(before); val current = inventory(after)
        require(plan.retain.toSet().intersect(plan.delete.toSet()).isEmpty() &&
            (plan.retain + plan.delete).toSet() == old.keys && current.keys.all { it in old } &&
            current.keys.containsAll(plan.retain)) { "Protected or unknown Kopia manifest changed" }
        for (key in current.keys) {
            // Retention rank changes after deletion; snapshot identity, contents, pins and times must not.
            require(current.getValue(key).filterKeys { it != "retentionReason" } ==
                old.getValue(key).filterKeys { it != "retentionReason" }) { "Retained Kopia manifest changed" }
        }
        return (old.keys - current.keys).sorted()
    }
}
