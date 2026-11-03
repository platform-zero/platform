package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** A reviewed lock is operator-supplied; the historical container inventory is never executable. */
@Serializable data class ProductSelection(val schemaVersion: Int, val status: String, val products: List<String>) {
    companion object {
        fun bundled(): ProductSelection = Json.decodeFromString(
            requireNotNull(ProductSelection::class.java.getResource("/products.json")).readText())
    }
}
@Serializable enum class ProcessRole { DAEMON, ONE_SHOT, TIMER }
@Serializable enum class NetworkRole { APP, DATA, INGRESS }
@Serializable data class LockedProcess(val id: String, val role: ProcessRole, val image: String,
    val dependencies: List<String>, val readiness: String, val secretKeys: List<String>,
    val userId: Int, val networks: List<NetworkRole>, val stateIds: List<String>, val schedule: String? = null,
    val capabilities: List<String> = emptyList())
@Serializable data class StateSet(val id: String, val owner: String, val containerPath: String,
    val backupHook: String, val restoreHook: String)
@Serializable data class Route(val host: String, val processId: String, val port: Int)
@Serializable data class Journey(val id: String, val outcome: String)
@Serializable data class ProductContract(val id: String, val upstreamVersion: String,
    val processes: List<LockedProcess>, val state: List<StateSet>, val routes: List<Route>, val journeys: List<Journey>)
@Serializable data class ReleaseLock(val schemaVersion: Int, val products: List<ProductContract>)

object ReleaseLocks {
    private val json = Json { ignoreUnknownKeys = false }
    private val slug = Regex("[a-z][a-z0-9-]{0,63}")
    private val digest = Regex("[a-z0-9]+(?:[.-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+@sha256:[a-f0-9]{64}")
    private val host = Regex("[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9]+(?:[a-z0-9-]*[a-z0-9])?)+")
    private val mount = Regex("/(?:[a-zA-Z0-9_-]+/)*[a-zA-Z0-9_-]+")
    private val calendar = Regex("[A-Za-z0-9*,:/ +.-]{1,80}")
    private val hex = "0123456789abcdef".toCharArray()

    /** Strict owner-only file and separately owner-only approved route list. No secrets or approvals in the lock. */
    fun privateBytes(path: Path): ByteArray {
        require(Files.isRegularFile(path, NOFOLLOW_LINKS) && Files.size(path) in 1..1048576) { "Missing or oversized private input" }
        val mode = Files.getPosixFilePermissions(path, NOFOLLOW_LINKS)
        require(PosixFilePermission.OWNER_READ in mode && mode.none {
            it.name.startsWith("GROUP_") || it.name.startsWith("OTHERS_")
        }) { "Input must be owner-only" }
        return Files.readAllBytes(path)
    }
    fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "${hex[(it.toInt() and 255) shr 4]}${hex[it.toInt() and 15]}" }

    fun approvedHosts(approvalPath: Path): Set<String> {
        val approved = json.decodeFromString<List<String>>(privateBytes(approvalPath).toString(Charsets.UTF_8))
        require(approved.distinct().size == approved.size && approved.size <= 64 && approved.all(host::matches)) {
            "Invalid approval list"
        }
        return approved.toSet()
    }

    fun validate(lockPath: Path, checksumPath: Path, signaturePath: Path, trustedKeyPath: Path,
                 approvalPath: Path): Pair<ReleaseLock, String> {
        val bytes = privateBytes(lockPath)
        val expected = privateBytes(checksumPath).toString(Charsets.UTF_8).trim()
        val hash = sha256(bytes)
        require(expected.matches(Regex("[a-f0-9]{64}")) && expected == hash) { "Lock checksum mismatch" }
        val signature = Base64.getDecoder().decode(privateBytes(signaturePath).toString(Charsets.US_ASCII).trim())
        val trustedKey = KeyFactory.getInstance("Ed25519").generatePublic(
            X509EncodedKeySpec(Base64.getDecoder().decode(privateBytes(trustedKeyPath).toString(Charsets.US_ASCII).trim())))
        val verifier = Signature.getInstance("Ed25519")
        verifier.initVerify(trustedKey)
        verifier.update(bytes)
        require(verifier.verify(signature)) { "Untrusted release signature" }
        val approved = approvedHosts(approvalPath)
        val lock = json.decodeFromString<ReleaseLock>(bytes.toString(Charsets.UTF_8))
        check(lock, approved)
        return lock to hash
    }
    fun check(lock: ReleaseLock, approved: Set<String>) {
        val selected = ProductSelection.bundled()
        require(selected.schemaVersion == 1 && selected.products.size == 39 &&
            selected.products.distinct().size == 39 && "portal" !in selected.products) { "Unreviewed product selection" }
        require(lock.schemaVersion == 1 && lock.products.map { it.id }.toSet() == selected.products.toSet() &&
            lock.products.size == selected.products.size) { "Release must cover selected logical products exactly" }
        val processes = lock.products.flatMap { it.processes }
        val ids = processes.map { it.id }
        require(ids.size == ids.toSet().size) { "Duplicate process" }
        for (product in lock.products) {
            require(product.upstreamVersion.isNotBlank() && !product.upstreamVersion.contains("latest", true) &&
                product.processes.isNotEmpty() && product.journeys.isNotEmpty()) { "Unresolved version or journeys: ${product.id}" }
            require(product.journeys.all { slug.matches(it.id) && it.outcome.isNotBlank() } &&
                product.journeys.map { it.id }.distinct().size == product.journeys.size) { "Invalid journeys" }
            require(product.state.map { it.id }.distinct().size == product.state.size && product.state.all {
                slug.matches(it.id) && it.owner == product.id && mount.matches(it.containerPath) &&
                    it.backupHook.isNotBlank() && it.restoreHook.isNotBlank()
            }) { "Unowned or unbacked state" }
            require(product.state.map { it.containerPath }.distinct().size == product.state.size &&
                product.state.all { s -> product.processes.any { s.id in it.stateIds } }) { "Orphan or duplicate state mount" }
            for (p in product.processes) {
                require(slug.matches(p.id) && digest.matches(p.image) && p.readiness.isNotBlank() &&
                    p.dependencies.distinct().size == p.dependencies.size && p.dependencies.all { it in ids && it != p.id } &&
                    p.secretKeys.distinct().size == p.secretKeys.size && p.secretKeys.all { it.matches(Regex("[A-Z][A-Z0-9_]{0,63}")) } &&
                    p.capabilities.distinct().size == p.capabilities.size &&
                    p.capabilities.all { it == "NET_BIND_SERVICE" && p.id == "caddy" } &&
                    p.userId in 1..65534 && p.networks.isNotEmpty() && p.networks.distinct().size == p.networks.size &&
                    (NetworkRole.INGRESS !in p.networks || p.id == "caddy") &&
                    p.stateIds.distinct().size == p.stateIds.size && p.stateIds.all { id -> product.state.any { it.id == id } } &&
                    ((p.role == ProcessRole.TIMER && p.schedule != null && calendar.matches(p.schedule)) ||
                     (p.role != ProcessRole.TIMER && p.schedule == null))) {
                    "Unpinned process, missing dependency or readiness: ${p.id}"
                }
            }
            for (r in product.routes) require(host.matches(r.host) && r.host in approved &&
                r.processId in product.processes.filter { it.role == ProcessRole.DAEMON }.map { it.id } && r.port in 1..65535) {
                "Unapproved route: ${r.host}"
            }
        }
        require(lock.products.flatMap { it.routes }.map { it.host }.distinct().size == lock.products.sumOf { it.routes.size }) {
            "Duplicate hostname"
        }
        val byId = processes.associateBy { it.id }
        val visiting = mutableSetOf<String>()
        val visited = mutableSetOf<String>()
        fun visit(id: String) {
            if (id in visited) return
            require(visiting.add(id)) { "Process dependency cycle" }
            byId.getValue(id).dependencies.forEach(::visit)
            visiting.remove(id)
            visited.add(id)
        }
        ids.forEach(::visit)
    }
}
