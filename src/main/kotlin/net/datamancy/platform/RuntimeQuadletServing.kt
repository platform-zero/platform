package net.datamancy.platform

import kotlinx.serialization.Serializable

@Serializable internal data class QuadletServeStopRequest(val schemaVersion: Int = 1,
    val generation: String, val member: String, val bundleSha256: String, val reason: String)
@Serializable internal data class QuadletServeResult(val schemaVersion: Int = 1,
    val bundleSha256: String, val stoppedCids: Map<String, String>, val fenced: Boolean)
