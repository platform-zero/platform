package net.datamancy.platform

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** A captured, still-fenced source. Not a resumed backup, functional acceptance, or public authority. */
@Serializable internal data class GenerationHeldCapture(val access: RuntimeBackupAccess,
    val snapshot: KopiaSnapshotReceipt, val fences: Map<String, String>) {
    val sha256: String get() = ReleaseLocks.sha256(Json { encodeDefaults = true }.encodeToString(this).toByteArray())
    fun validate() {
        access.validate(); KopiaGenerationStore.validate(snapshot)
        require(snapshot.id == access.operation && snapshot.generation == access.generation && snapshot.bundleSha256 == access.bundleSha256)
        require(fences.isNotEmpty() && fences.keys.all { it.startsWith(access.generation + "-") } &&
            fences.values.all { it.matches(Regex("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")) })
    }
}

@Serializable internal data class HeldSourceResumeAuthority(val heldSha256: String, val target: String,
    val targetBundleSha256: String, val targetFences: Map<String, String>)
