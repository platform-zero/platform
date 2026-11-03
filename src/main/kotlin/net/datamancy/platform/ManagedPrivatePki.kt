package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import java.time.Instant
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal enum class PrivatePkiKind { WEB, SEARCH }
@Serializable internal data class PrivatePkiProfile(val kind: PrivatePkiKind, val host: String,
    val dnsNames: List<String> = listOf(host), val nodeSubject: String = host, val clientSubject: String = "p0v3-admin")
@Serializable internal data class PrivatePkiIssue(val operation: String, val profile: PrivatePkiProfile,
    val caSha256: String, val issuedAt: String, val renewAfter: String, val expiresAt: String,
    val previousSha256: String? = null, val material: Map<String, String>)

/** Private controller-only signing custody. Never mount this directory into an application.
 * Renewal issues a new immutable bundle under the same CA; the caller seals it into a replacement
 * generation, rather than changing hashed inputs of running daemons. Legacy discarded CAs cannot
 * be adopted. All outputs exclude the CA key. No host trust installation or implicit rollover.
 */
internal class ManagedPrivatePki(private val root: Path,
    private val run: (Path, List<String>) -> Unit = ::privatePkiOpenSsl,
    private val now: () -> Instant = Instant::now) {
    companion object {
        private val json = Json { encodeDefaults = true }
        private val operationPattern = Regex("pki-[a-f0-9]{16}")
        private val subjectPattern = Regex("[a-z][a-z0-9-]{0,39}")
        fun real(site: String, authority: String, root: Path): ManagedPrivatePki {
            require(subjectPattern.matches(site) && subjectPattern.matches(authority))
            require(root == Path.of("/mnt/media/p0-v3/private-pki").resolve(site).resolve(authority))
            return ManagedPrivatePki(root)
        }
    }
    private fun profile(profile: PrivatePkiProfile) {
        require(listOf(profile.host, profile.nodeSubject, profile.clientSubject).all(subjectPattern::matches))
        require(profile.dnsNames.size in 1..8 && profile.dnsNames.distinct() == profile.dnsNames && profile.host in profile.dnsNames)
        require(profile.dnsNames.all { it.length <= 253 && it.split('.').all(subjectPattern::matches) })
        require(profile.kind != PrivatePkiKind.SEARCH || profile.dnsNames == listOf(profile.host))
    }
    /** First authority creation is explicit. Partial creation stays fenced for operator inspection. */
    fun initialize(operation: String): String = ReleasePrivateFiles.locked(root) {
        require(operationPattern.matches(operation))
        require(!Files.exists(root.resolve("ca.pem"), NOFOLLOW_LINKS) && !Files.exists(root.resolve("ca-key.pem"), NOFOLLOW_LINKS))
        val pending = root.resolve("initialize.pending")
        ReleasePrivateFiles.save(pending, operation.toByteArray())
        temporary { temp ->
            run(temp, listOf("req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "3650",
                "-subj", "/CN=p0v3-private-managed-ca", "-keyout", "ca-key.pem", "-out", "ca.pem",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0", "-addext", "keyUsage=critical,keyCertSign,cRLSign"))
            val ca = output(temp, "ca.pem")
            ReleasePrivateFiles.save(root.resolve("ca-key.pem"), output(temp, "ca-key.pem"))
            ReleasePrivateFiles.save(root.resolve("ca.pem"), ca)
            ReleasePrivateFiles.save(root.resolve("authority.sha256"), ReleaseLocks.sha256(ca).toByteArray())
            ReleasePrivateFiles.removeExact(pending, operation.toByteArray())
            ReleaseLocks.sha256(ca)
        }
    }
    fun issue(operation: String, profile: PrivatePkiProfile): PrivatePkiIssue = ReleasePrivateFiles.locked(root) {
        issueLocked(operation, profile, null)
    }
    /** Requires the original immutable bundle digest; caller time/booleans cannot declare expiry. */
    fun renew(operation: String, previousOperation: String, expectedPreviousSha256: String): PrivatePkiIssue = ReleasePrivateFiles.locked(root) {
        require(operationPattern.matches(operation) && operationPattern.matches(previousOperation) && expectedPreviousSha256.matches(Regex("[a-f0-9]{64}")))
        require(!Files.exists(root.resolve("issue.pending"), NOFOLLOW_LINKS) && !Files.exists(root.resolve("$operation.json"), NOFOLLOW_LINKS))
        val bytes = ReleasePrivateFiles.read(root.resolve("$previousOperation.json"))
        require(ReleaseLocks.sha256(bytes) == expectedPreviousSha256)
        val previous = json.decodeFromString<PrivatePkiIssue>(bytes.decodeToString())
        require(previous.operation == previousOperation && previous.caSha256 == authorityHash())
        require(!now().isBefore(Instant.parse(previous.renewAfter))) { "Private certificate is not due for renewal" }
        // A version may have only one renewal descendant. Interrupted renewal never permits another ID.
        ReleasePrivateFiles.save(root.resolve("$previousOperation.renewal"), operation.toByteArray())
        issueLocked(operation, previous.profile, expectedPreviousSha256)
    }
    fun read(operation: String): PrivatePkiIssue = ReleasePrivateFiles.locked(root) {
        require(operationPattern.matches(operation))
        val record = json.decodeFromString<PrivatePkiIssue>(ReleasePrivateFiles.read(root.resolve("$operation.json")).decodeToString())
        require(record.operation == operation && record.caSha256 == authorityHash())
        record
    }
    private fun authorityHash(): String {
        require(!Files.exists(root.resolve("initialize.pending"), NOFOLLOW_LINKS)) { "Incomplete CA initialization" }
        val hash = ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("ca.pem")))
        require(ReleasePrivateFiles.read(root.resolve("authority.sha256")).decodeToString() == hash)
        return hash
    }
    private fun issueLocked(operation: String, profile: PrivatePkiProfile, previousHash: String?): PrivatePkiIssue {
        require(operationPattern.matches(operation)); profile(profile)
        val caHash = authorityHash()
        require(!Files.exists(root.resolve("$operation.json"), NOFOLLOW_LINKS))
        require(!Files.exists(root.resolve("issue.pending"), NOFOLLOW_LINKS)) { "Interrupted issuance retained; do not replay" }
        val pending = "$operation:$caHash".toByteArray()
        ReleasePrivateFiles.save(root.resolve("issue.pending"), pending)
        return temporary { temp ->
            Files.write(temp.resolve("ca.pem"), ReleasePrivateFiles.read(root.resolve("ca.pem")))
            Files.write(temp.resolve("ca-key.pem"), ReleasePrivateFiles.read(root.resolve("ca-key.pem")))
            // Refuse a near-expired CA: renewal never silently replaces trust anchors.
            run(temp, listOf("x509", "-in", "ca.pem", "-checkend", (91 * 86400).toString(), "-noout"))
            val subjects = if (profile.kind == PrivatePkiKind.WEB) listOf("web" to profile.host)
                else listOf("node" to profile.nodeSubject, "admin" to profile.clientSubject)
            val material = mutableMapOf("ca.pem" to output(temp, "ca.pem").decodeToString())
            val issued = now()
            for ((id, subject) in subjects) {
                val usage = if (id == "admin") "clientAuth" else if (id == "node") "serverAuth,clientAuth" else "serverAuth"
                Files.writeString(temp.resolve("$id.ext"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=$usage\n" +
                    if (id == "admin") "" else "subjectAltName=${profile.dnsNames.joinToString(",") { "DNS:$it" }}\n")
                run(temp, listOf("req", "-new", "-newkey", "rsa:3072", "-nodes", "-sha256", "-subj", "/CN=$subject", "-keyout", "$id-key.pem", "-out", "$id.csr"))
                val serial = ByteArray(20).also { SecureRandom().nextBytes(it); it[0] = (it[0].toInt() and 0x7f).toByte() }
                    .joinToString("") { "%02x".format(it) }
                run(temp, listOf("x509", "-req", "-sha256", "-days", "90", "-in", "$id.csr", "-CA", "ca.pem", "-CAkey", "ca-key.pem",
                    "-set_serial", "0x$serial", "-extfile", "$id.ext", "-out", "$id.pem"))
                run(temp, listOf("verify", "-CAfile", "ca.pem", "-purpose", if (id == "admin") "sslclient" else "sslserver", "$id.pem"))
                material["$id.pem"] = output(temp, "$id.pem").decodeToString()
                material["$id-key.pem"] = output(temp, "$id-key.pem").decodeToString()
            }
            val result = PrivatePkiIssue(operation, profile, caHash, issued.toString(), issued.plusSeconds(60L * 86400).toString(),
                issued.plusSeconds(90L * 86400).toString(), previousHash, material)
            ReleasePrivateFiles.save(root.resolve("$operation.json"), json.encodeToString(result).toByteArray())
            ReleasePrivateFiles.removeExact(root.resolve("issue.pending"), pending)
            result
        }
    }
    private fun output(root: Path, name: String): ByteArray {
        val path = root.resolve(name)
        require(Files.isRegularFile(path, NOFOLLOW_LINKS) && !Files.isSymbolicLink(path))
        return Files.newInputStream(path, NOFOLLOW_LINKS).use { it.readNBytes(65537) }.also { require(it.size in 1..65536) }
    }
    private fun <T> temporary(action: (Path) -> T): T {
        val temp = Files.createTempDirectory("p0v3-managed-pki-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try { return action(temp) }
        finally { Files.walk(temp).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}

/** No shell, inherited stdin or diagnostics containing keys; interruption kills the owned child. */
internal fun privatePkiOpenSsl(root: Path, args: List<String>) {
    val builder = ProcessBuilder(listOf("/usr/bin/openssl") + args).directory(root.toFile())
        .redirectInput(ProcessBuilder.Redirect.from(Path.of("/dev/null").toFile()))
        .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD)
    builder.environment().clear()
    val process = builder.start()
    try {
        if (!process.waitFor(30, TimeUnit.SECONDS)) { process.destroyForcibly(); error("Private PKI operation timed out") }
        check(process.exitValue() == 0) { "Private PKI operation failed" }
    } catch (error: InterruptedException) {
        process.destroyForcibly(); Thread.currentThread().interrupt(); throw error
    }
}
