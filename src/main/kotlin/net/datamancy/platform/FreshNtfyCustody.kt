package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.*

/** Separate fresh ntfy authority, not recovered users, Keycloak password
 * grants, or a token scraped from CLI stdout. No application runs here.
 * Native Basic password custody stays private for later explicitly authorized
 * client enrollment; each generated token belongs to one distinct ACL user.
 */
internal object FreshNtfyCustody {
    private val root = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/identity/ntfy-fresh")
    private const val CLI_SHA256 = "678ade3bfc088749c81a681adc603333ee0bb023b6a6cfe3c0f58bef8ff854e9"
    fun issueOnce(record: Path, binary: Path, password: () -> String = RuntimePreparation::password): FreshNtfyGrants {
        require(record.parent == root && record.fileName.toString().matches(Regex("q-[a-f0-9]{12}\\.json")) &&
            Files.isRegularFile(binary, NOFOLLOW_LINKS) && !Files.isSymbolicLink(binary) &&
            ReleaseLocks.sha256(Files.readAllBytes(binary)) == CLI_SHA256)
        return ReleasePrivateFiles.locked(root) {
            if (Files.exists(record, NOFOLLOW_LINKS)) {
                val doc = Json.parseToJsonElement(ReleasePrivateFiles.read(record).toString(Charsets.UTF_8)).jsonObject
                require(doc.keys == setOf("schemaVersion", "ssoToken", "ssoHash", "ssoPassword",
                    "publisherToken", "publisherHash", "publisherPassword", "ownerToken", "ownerHash", "ownerPassword") &&
                    doc.getValue("schemaVersion").jsonPrimitive.int == 1)
                val raw = listOf("ssoPassword", "publisherPassword", "ownerPassword")
                    .map { doc.getValue(it).jsonPrimitive.content }
                require(raw.distinct().size == raw.size && raw.all { it.matches(Regex("[a-f0-9]{64}")) })
                FreshNtfyGrants(doc.getValue("ssoToken").jsonPrimitive.content,
                    doc.getValue("ssoHash").jsonPrimitive.content,
                    doc.getValue("publisherToken").jsonPrimitive.content,
                    doc.getValue("publisherHash").jsonPrimitive.content,
                    doc.getValue("ownerToken").jsonPrimitive.content,
                    doc.getValue("ownerHash").jsonPrimitive.content)
            } else {
                val raw = List(6) { password() }
                require(raw.distinct().size == raw.size && raw.all { it.matches(Regex("[a-f0-9]{64}")) })
                val tokens = raw.take(3).map { "tk_${it.take(32)}" }
                fun hash(secret: String): String {
                    val cmd = ProcessBuilder(binary.toString(), "hash-password", "--algorithm", "bcrypt",
                        "--bcrypt-cost", "14").start()
                    try {
                        cmd.outputStream.bufferedWriter().use { it.write(secret); it.newLine() }
                        require(cmd.waitFor(30, TimeUnit.SECONDS) && cmd.exitValue() == 0)
                        return cmd.inputStream.use { it.readNBytes(256).toString(Charsets.UTF_8).trim() }
                    } finally { if (cmd.isAlive) cmd.destroyForcibly(); cmd.errorStream.close() }
                }
                val hashes = raw.drop(3).map(::hash)
                val grants = FreshNtfyGrants(tokens[0], hashes[0], tokens[1], hashes[1], tokens[2], hashes[2])
                ReleasePrivateFiles.save(record, buildJsonObject {
                    put("schemaVersion", 1)
                    listOf("sso", "publisher", "owner").forEachIndexed { index, owner ->
                        put("${owner}Token", tokens[index]); put("${owner}Hash", hashes[index])
                        put("${owner}Password", raw[index + 3])
                    }
                }.toString().toByteArray())
                grants
            }
        }
    }
}
