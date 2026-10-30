package net.datamancy.platform

import java.net.URI
import java.net.URISyntaxException
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class HumanLaneSubject(val subject: String, val username: String)

/** Agents have distinct SSO application identities, but no host-account obligation. */
@Serializable
data class LaneAccountRequest(
    val schemaVersion: Int,
    val siteId: String,
    val issuer: String,
    val humans: List<HumanLaneSubject>,
    val agentSubjects: List<String> = emptyList()
) {
    companion object {
        private val json = Json { ignoreUnknownKeys = false }
        fun from(path: Path): LaneAccountRequest {
            require(Files.isRegularFile(path) && Files.size(path) <= 131072) { "Invalid or oversized lane request" }
            return json.decodeFromString<LaneAccountRequest>(Files.readString(path))
        }
    }
}

@Serializable
data class HumanAccountIntent(val issuer: String, val subject: String, val username: String)

/** Data only: never execute useradd, grant app roles, or inspect the host account database. */
@Serializable
data class LaneAccountPlan(val siteId: String, val accounts: List<HumanAccountIntent>)

object LaneAccounts {
    fun occupiedFrom(path: Path): Set<String> {
        require(Files.isRegularFile(path) && Files.size(path) <= 131072) { "Invalid or oversized occupied-username snapshot" }
        val names = Json.decodeFromString<List<String>>(Files.readString(path))
        require(names.isNotEmpty() && names.size <= 4096 && names.all { it.matches(Regex("[a-z_][a-z0-9_-]{0,31}")) } &&
            names.distinct().size == names.size) { "Invalid occupied-username snapshot" }
        return names.toSet()
    }

    private val siteId = Regex("[a-z][a-z0-9-]{0,29}")
    private val subject = Regex("[A-Za-z0-9][A-Za-z0-9._:@|-]{0,127}")
    private val username = Regex("p0v3_[a-z][a-z0-9_]{0,23}")
    private val reserved = setOf("root", "admin", "gerald", "software_lab", "nobody", "system", "agent")

    /** Occupied usernames must come from a separately verified, fresh inventory; this function never reads /etc/passwd. */
    fun plan(request: LaneAccountRequest, trustedIssuer: String, occupiedUsernames: Set<String>): LaneAccountPlan {
        require(request.schemaVersion == 1) { "Unsupported lane request schema" }
        require(siteId.matches(request.siteId)) { "Invalid site ID" }
        require(validIssuer(trustedIssuer) && request.issuer == trustedIssuer) { "Untrusted or invalid issuer" }
        require(request.humans.isNotEmpty() && request.humans.size <= 128 && request.agentSubjects.size <= 128) {
            "Expected 1..128 human subjects and at most 128 agent subjects"
        }
        val humanSubjects = request.humans.map { it.subject }
        val names = request.humans.map { it.username }
        require((humanSubjects + request.agentSubjects).all(subject::matches)) { "Invalid SSO subject" }
        require((humanSubjects + request.agentSubjects).distinct().size == humanSubjects.size + request.agentSubjects.size) {
            "SSO subject reused across humans or agents"
        }
        require(names.distinct().size == names.size) { "Duplicate username" }
        require(names.all { name ->
            username.matches(name) && name.removePrefix("p0v3_") !in reserved && name !in occupiedUsernames
        }) { "Unsafe, reserved or occupied username" }
        return LaneAccountPlan(request.siteId, request.humans.sortedBy { it.username }.map { human ->
            HumanAccountIntent(trustedIssuer, human.subject, human.username)
        })
    }

    private fun validIssuer(value: String): Boolean = try {
        val uri = URI(value)
        uri.scheme == "https" && !uri.host.isNullOrBlank() && uri.rawUserInfo == null &&
            uri.rawQuery == null && uri.rawFragment == null && uri.toASCIIString() == value &&
            !value.endsWith("/") && value.length <= 256
    } catch (_: URISyntaxException) {
        false
    }
}
