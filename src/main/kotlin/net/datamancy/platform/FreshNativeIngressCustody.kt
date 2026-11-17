package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.*

/** Fresh INSTALL source only; creates no application account, Caddy listener or
 * native effect. Raw qBittorrent native password is held only in the private
 * grant file; the Caddy graph receives its salted bcrypt hash. Never use an
 * OLD model-context password, a fixture hash or argv with a live secret.
 */
internal object FreshNativeIngressCustody {
    private const val CLI_SHA256 = "678ade3bfc088749c81a681adc603333ee0bb023b6a6cfe3c0f58bef8ff854e9"
    private val anchor = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/ingress/fresh")
    /** Read the issued password only for the r9 qBittorrent config producer;
     * never infer it from a bcrypt hash or mint a second application's user. */
    fun qbittorrentPassword(record: Path, grants: FreshNativeIngressGrants): String {
        require(record.parent == anchor && record.fileName.toString().matches(Regex("q-[a-f0-9]{12}\\.json")))
        val doc = Json.parseToJsonElement(ReleasePrivateFiles.read(record).toString(Charsets.UTF_8)).jsonObject
        require(doc.keys == setOf("schemaVersion", "bookstackToken", "bookstackApiId", "bookstackApiSecret",
            "outsiderBookstackApiId", "outsiderBookstackApiSecret", "qbittorrentPassword", "qbittorrentBcrypt") &&
            doc.getValue("schemaVersion").jsonPrimitive.int == 3 &&
            doc.getValue("bookstackApiId").jsonPrimitive.content == grants.bookstackApiId &&
            doc.getValue("bookstackApiSecret").jsonPrimitive.content == grants.bookstackApiSecret &&
            doc.getValue("outsiderBookstackApiId").jsonPrimitive.content == grants.outsiderBookstackApiId &&
            doc.getValue("outsiderBookstackApiSecret").jsonPrimitive.content == grants.outsiderBookstackApiSecret &&
            doc.getValue("bookstackToken").jsonPrimitive.content == grants.bookstackInternalToken &&
            doc.getValue("qbittorrentBcrypt").jsonPrimitive.content == grants.qbittorrentBasicHash)
        return doc.getValue("qbittorrentPassword").jsonPrimitive.content.also {
            require(it.matches(Regex("[a-f0-9]{64}")) && it != grants.bookstackInternalToken)
        }
    }
    fun issueOnce(record: Path, caddyCli: Path, password: () -> String = RuntimePreparation::password): FreshNativeIngressGrants {
        require(record.parent == anchor && record.fileName.toString().matches(Regex("q-[a-f0-9]{12}\\.json")) &&
            Files.isRegularFile(caddyCli, NOFOLLOW_LINKS) && !Files.isSymbolicLink(caddyCli) &&
            ReleaseLocks.sha256(Files.readAllBytes(caddyCli)) == CLI_SHA256)
        return ReleasePrivateFiles.locked(anchor) {
            if (Files.exists(record, NOFOLLOW_LINKS)) {
                // Read-back is not issuance. A corrupt or uncertain record fails closed.
                val doc = Json.parseToJsonElement(ReleasePrivateFiles.read(record).toString(Charsets.UTF_8)).jsonObject
                require(doc.keys == setOf("schemaVersion", "bookstackToken", "bookstackApiId", "bookstackApiSecret",
                    "outsiderBookstackApiId", "outsiderBookstackApiSecret", "qbittorrentPassword", "qbittorrentBcrypt") &&
                    doc.getValue("schemaVersion").jsonPrimitive.int == 3) {
                    "Retained older or uncertain grant intents cannot be silently upgraded"
                }
                val raw = doc.getValue("qbittorrentPassword").jsonPrimitive.content
                val token = doc.getValue("bookstackToken").jsonPrimitive.content
                require(raw.matches(Regex("[a-f0-9]{64}")) && raw != token)
                FreshNativeIngressGrants(token, doc.getValue("qbittorrentBcrypt").jsonPrimitive.content,
                    bookstackApiId = doc.getValue("bookstackApiId").jsonPrimitive.content,
                    bookstackApiSecret = doc.getValue("bookstackApiSecret").jsonPrimitive.content,
                    outsiderBookstackApiId = doc.getValue("outsiderBookstackApiId").jsonPrimitive.content,
                    outsiderBookstackApiSecret = doc.getValue("outsiderBookstackApiSecret").jsonPrimitive.content)
            } else {
                val token = password(); val raw = password(); val apiId = "p0v3-" + password().take(32)
                val apiSecret = password(); val outsiderApiId = "p0v3-" + password().take(32)
                val outsiderApiSecret = password()
                require(listOf(token, raw, apiSecret, outsiderApiSecret).all { it.matches(Regex("[a-f0-9]{64}")) } &&
                    setOf(token, raw, apiSecret, outsiderApiSecret).size == 4 &&
                    apiId != outsiderApiId && listOf(apiId,outsiderApiId).all { it.matches(Regex("p0v3-[a-f0-9]{32}")) })
                val cmd = ProcessBuilder(caddyCli.toString(), "hash-password", "--algorithm", "bcrypt",
                    "--bcrypt-cost", "14").redirectErrorStream(false).start()
                try {
                    cmd.outputStream.bufferedWriter().use { writer -> writer.write(raw); writer.newLine() }
                    require(cmd.waitFor(30, TimeUnit.SECONDS) && cmd.exitValue() == 0)
                    val hash = cmd.inputStream.use { it.readNBytes(256).toString(Charsets.UTF_8) }.trim()
                    val grants = FreshNativeIngressGrants(token, hash, bookstackApiId = apiId,
                        bookstackApiSecret = apiSecret, outsiderBookstackApiId = outsiderApiId,
                        outsiderBookstackApiSecret = outsiderApiSecret)
                    ReleasePrivateFiles.save(record, buildJsonObject {
                        put("schemaVersion", 3); put("bookstackToken", token)
                        put("bookstackApiId", apiId); put("bookstackApiSecret", apiSecret)
                        put("outsiderBookstackApiId", outsiderApiId)
                        put("outsiderBookstackApiSecret", outsiderApiSecret)
                        put("qbittorrentPassword", raw); put("qbittorrentBcrypt", hash)
                    }.toString().toByteArray())
                    grants
                } finally {
                    if (cmd.isAlive) cmd.destroyForcibly()
                    cmd.errorStream.close()
                }
            }
        }
    }
}
