package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Adopt only the 48 credentials minted by the NEW Mastodon one-shot. The
 * original stage result and exact private-store volume are required; no OLD
 * RSS, Redis, SQL, Kopia or token file is consulted. Intent precedes first
 * token copy; uncertain partial custody is never retried as a fresh effect.
 */
@Serializable internal data class FreshRssCustodyResult(val generation: String, val bundleSha256: String,
    val ledgerSha256: String, val tokenHashes: Map<String, String>)
internal object FreshRssFeatureCustody {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    /** Same validation used after the native one-shot, exercised without
     * starting Mastodon or issuing tokens in offline controller tests. */
    internal fun validateLedger(bytes: ByteArray): Map<String, String> {
        require(bytes.size in 1..131072)
        val ledger = Json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(ledger.keys == setOf("schemaVersion", "publicationEnabled", "accounts") &&
            ledger.getValue("schemaVersion").jsonPrimitive.int == 1 &&
            !ledger.getValue("publicationEnabled").jsonPrimitive.boolean)
        val entries = ledger.getValue("accounts").jsonArray.map { it.jsonObject }
        val feeds = RssPacks.load().associateBy { it.feed.account }
        val expected = feeds.keys + "rss_observer"
        require(expected.size == 48 && entries.size == 48 &&
            entries.map { it.getValue("account").jsonPrimitive.content }.toSet() == expected &&
            entries.map { it.getValue("accountId").jsonPrimitive.content }.distinct().size == 48 &&
            entries.all { it.keys == setOf("account", "accountId", "feedId", "pack", "token") &&
                it.getValue("accountId").jsonPrimitive.content.matches(Regex("[1-9][0-9]{0,31}")) &&
                it.getValue("token").jsonPrimitive.content.matches(Regex("[A-Za-z0-9_.-]{20,256}")) } &&
            entries.map { it.getValue("token").jsonPrimitive.content }.distinct().size == 48 &&
            entries.all { entry ->
                val name = entry.getValue("account").jsonPrimitive.content
                if (name == "rss_observer") entry.getValue("feedId").jsonPrimitive.content == "observer" &&
                    entry.getValue("pack").jsonPrimitive.content == "observer"
                else feeds[name]?.let { feed ->
                    entry.getValue("feedId").jsonPrimitive.content == feed.feed.id &&
                        entry.getValue("pack").jsonPrimitive.content == feed.pack
                } == true
            }) { "Fresh 47-bot plus distinct observer ledger differs from sealed feed pack" }
        return entries.associate { entry ->
            "${entry.getValue("account").jsonPrimitive.content}.token" to
                ReleaseLocks.sha256(entry.getValue("token").jsonPrimitive.content.toByteArray())
        }.toSortedMap()
    }
    fun adopt(bundle: GenerationBundle, root: Path) {
        require(bundle.recoverySourceKopia == null && bundle.recoverySourceArchiveSha256 == null &&
            bundle.ownedUpdate == null && bundle.request.rssPlan != null && root.fileName.toString() == bundle.request.id)
        val spec = bundle.members.map { it.spec }.single { pin ->
            pin.processes.any { it.id == "mastodon-rss-feature" }
        }
        require(spec.volumes.any { it.id == "mastodon-bootstrap" } && spec.store == RuntimeStore.CANONICAL_V2)
        val name = "p0v3-live-${spec.name}-volume-mastodon-bootstrap"
        val owner = PrivateRootfulCommands(store = RuntimeStore.CANONICAL_V2)
        val observed = owner.run(listOf("volume", "inspect", name))
        require(observed.exitCode == 0 && observed.output.length in 1..65536)
        val obj = Json.parseToJsonElement(observed.output).jsonArray.single().jsonObject
        require(obj.getValue("Name").jsonPrimitive.content == name)
        val mount = Path.of(obj.getValue("Mountpoint").jsonPrimitive.content)
        require(mount.isAbsolute && mount.normalize() == mount &&
            mount == Path.of(RuntimeStore.CANONICAL_V2.graph).resolve("volumes/$name/_data"))
        val stage = Json.parseToJsonElement(ReleasePrivateFiles.read(root.resolve("${spec.name}.stage.result.json"))
            .decodeToString(throwOnInvalidSequence = true)).jsonArray
        require(stage.any { status -> val s = status.jsonObject
            s["id"]?.jsonPrimitive?.content == "mastodon-rss-feature" &&
                s["exitCode"]?.jsonPrimitive?.int == 0 &&
                s["state"]?.jsonPrimitive?.content in setOf("completed", "exited") })
        val resultPath = root.resolve("rss/fresh-feature.result.json")
        val intentPath = root.resolve("rss/fresh-feature.intent.json")
        require(!Files.exists(intentPath, NOFOLLOW_LINKS) && !Files.exists(resultPath, NOFOLLOW_LINKS))
        // Rootful Podman volume is unreadable by the controller account. The
        // privileged helper only opens the exact inspected source file; it does
        // not create containers, mutate volumes, or print tokens to journal.
        val source = mount.resolve("rss-tokens.json")
        val helper = """import os,sys,stat
p=sys.argv[1]
f=os.open(p, os.O_RDONLY|os.O_NOFOLLOW)
try:
 s=os.fstat(f)
 if not stat.S_ISREG(s.st_mode) or s.st_size<1 or s.st_size>131072 or s.st_nlink!=1 or s.st_mode&0o077: sys.exit(19)
 data=os.read(f,131073)
 if len(data)!=s.st_size: sys.exit(19)
 sys.stdout.buffer.write(data)
finally: os.close(f)
""".trimIndent()
        val child = ProcessBuilder("/usr/bin/sudo", "-n", "/usr/bin/python3", "-c", helper, source.toString())
            .redirectError(ProcessBuilder.Redirect.DISCARD).start()
        val bytes = try {
            val data = child.inputStream.readNBytes(131073)
            require(child.waitFor(30, TimeUnit.SECONDS) && child.exitValue() == 0 && data.size in 1..131072)
            data
        } finally { if (child.isAlive) child.destroyForcibly() }
        val pins = validateLedger(bytes)
        val entries = Json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
            .getValue("accounts").jsonArray.map { it.jsonObject }
        val hash = ReleaseLocks.sha256(bytes)
        val record = FreshRssCustodyResult(bundle.request.id, ReleaseLocks.sha256(
            ReleasePrivateFiles.read(root.resolve("bundle.json"))), hash, pins)
        ReleasePrivateFiles.save(intentPath, json.encodeToString(record).toByteArray())
        val tokens = root.resolve("rss/tokens")
        ReleasePrivateFiles.directory(tokens)
        for (entry in entries.sortedBy { it.getValue("account").jsonPrimitive.content }) {
            val name = entry.getValue("account").jsonPrimitive.content + ".token"
            ReleasePrivateFiles.save(tokens.resolve(name),
                (entry.getValue("token").jsonPrimitive.content + "\n").toByteArray())
        }
        require(pins.all { (name, digest) -> ReleaseLocks.sha256(
            ReleasePrivateFiles.read(tokens.resolve(name)).decodeToString().trimEnd('\n').toByteArray()) == digest })
        ReleasePrivateFiles.save(resultPath, json.encodeToString(record).toByteArray())
        bytes.fill(0)
    }
}
