package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

@Serializable internal data class NotebookEpisodeIntent(val generation: String, val member: String,
    val user: String, val ordinal: Int, val requestId: String, val previousTerminalSha256: String?,
    val specSha256: String, val workingReservationMiB: Int)
@Serializable internal data class NotebookEpisodeStart(val intentSha256: String, val originalStartAckSha256: String,
    val nativeContainerId: String, val nativeSystemdReadbackSha256: String)
@Serializable internal data class NotebookEpisodeTerminal(val startSha256: String, val originalStopAckSha256: String,
    val nativeContainerId: String, val terminalReadbackSha256: String,
    val retainedContainerDispositionSha256: String, val releasedWorkingReservationMiB: Int)

/** Generation-local capacity and lifecycle custody for the two graph-declared
 * JupyterHub notebook container templates. Never invent a terminal record from
 * a running/stopped observation. This ledger has NO systemd/Podman effect;
 * the rootful owner must supply exact original ACKs and native readback after
 * each owned systemd operation. No unknown/partial episode admits a successor.
 */
internal class NotebookLifecycleEpisodes(private val generationRoot: Path, private val member: String,
    private val user: String, private val specSha256: String, private val hardCeilingMiB: Int = 2048) {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val root = generationRoot.resolve("notebooks/episodes/$user")
    private val hex = Regex("[a-f0-9]{64}")
    private val request = Regex("[a-f0-9]{32}")
    init {
        require(generationRoot.isAbsolute && generationRoot.normalize() == generationRoot &&
            generationRoot.fileName.toString().matches(Regex("q-[a-f0-9]{12}")) &&
            member.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,39}")) &&
            member.startsWith("${generationRoot.fileName}-") && user in setOf("alice","bob") &&
            hex.matches(specSha256) && hardCeilingMiB == 2048)
    }
    private fun prepare() {
        ReleasePrivateFiles.directory(generationRoot)
        val notebooks = generationRoot.resolve("notebooks")
        if (!Files.exists(notebooks,NOFOLLOW_LINKS)) Files.createDirectory(notebooks,
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.directory(notebooks)
        val parent = root.parent
        if (!Files.exists(parent,NOFOLLOW_LINKS)) {
            ReleasePrivateFiles.directory(parent.parent)
            Files.createDirectory(parent,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        }
        ReleasePrivateFiles.directory(parent)
        if (!Files.exists(root,NOFOLLOW_LINKS))
            Files.createDirectory(root,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.directory(root)
    }
    private fun path(number: Int, kind: String) = root.resolve("%04d.%s.json".format(number,kind))
    private fun <T> decode(path: Path, deserializer: kotlinx.serialization.DeserializationStrategy<T>): T =
        json.decodeFromString(deserializer, ReleasePrivateFiles.read(path,8192).decodeToString(throwOnInvalidSequence=true))
    fun completed(): List<Pair<NotebookEpisodeIntent,NotebookEpisodeTerminal>> {
        prepare()
        val files = Files.list(root).use { it.toList() }
        require(files.size <= 192 && files.all { it.fileName.toString().matches(
            Regex("[0-9]{4}\\.(intent|start|terminal)\\.json")) })
        val count = files.count { it.fileName.toString().endsWith(".intent.json") }
        require(count <= 64 && files.size == count * 3) { "Uncertain notebook episode: missing original ACK or terminal proof" }
        return (1..count).map { ordinal ->
            val intentBytes = ReleasePrivateFiles.read(path(ordinal,"intent"),8192)
            val intent = json.decodeFromString<NotebookEpisodeIntent>(intentBytes.decodeToString(throwOnInvalidSequence=true))
            val startBytes = ReleasePrivateFiles.read(path(ordinal,"start"),8192)
            val start = json.decodeFromString<NotebookEpisodeStart>(startBytes.decodeToString(throwOnInvalidSequence=true))
            val terminal = decode(path(ordinal,"terminal"), NotebookEpisodeTerminal.serializer())
            require(intent.generation == generationRoot.fileName.toString() && intent.member == member &&
                intent.user == user && intent.ordinal == ordinal && intent.specSha256 == specSha256 &&
                request.matches(intent.requestId) && intent.workingReservationMiB == hardCeilingMiB &&
                intent.previousTerminalSha256 == (if (ordinal == 1) null else
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(path(ordinal-1,"terminal"),8192))) &&
                start.intentSha256 == ReleaseLocks.sha256(intentBytes) && hex.matches(start.originalStartAckSha256) &&
                hex.matches(start.nativeContainerId) && hex.matches(start.nativeSystemdReadbackSha256) &&
                terminal.startSha256 == ReleaseLocks.sha256(startBytes) &&
                terminal.nativeContainerId == start.nativeContainerId &&
                hex.matches(terminal.originalStopAckSha256) && hex.matches(terminal.terminalReadbackSha256) &&
                hex.matches(terminal.retainedContainerDispositionSha256) &&
                terminal.releasedWorkingReservationMiB == hardCeilingMiB) {
                "Foreign or unproved notebook generation episode"
            }
            intent to terminal
        }
    }
    fun active(): Pair<NotebookEpisodeIntent,NotebookEpisodeStart?>? {
        prepare()
        val names = Files.list(root).use { it.toList().map { file -> file.fileName.toString() } }
        require(names.size <= 192 && names.all { it.matches(Regex("[0-9]{4}\\.(intent|start|terminal)\\.json")) })
        val count = names.count { it.endsWith(".intent.json") }
        if (count == 0) { require(names.isEmpty()); return null }
        require(count in 1..64 && (1..count).all { "%04d.intent.json".format(it) in names })
        if ("%04d.terminal.json".format(count) in names) {
            completed() // Verify entire chain before treating the last as terminal.
            return null
        }
        require(names.size == 3 * (count-1) + if ("%04d.start.json".format(count) in names) 2 else 1)
        val intentBytes = ReleasePrivateFiles.read(path(count,"intent"),8192)
        val intent = json.decodeFromString<NotebookEpisodeIntent>(intentBytes.decodeToString(throwOnInvalidSequence=true))
        require(intent.ordinal == count && intent.generation == generationRoot.fileName.toString() &&
            intent.member == member && intent.user == user && intent.specSha256 == specSha256 &&
            intent.workingReservationMiB == hardCeilingMiB && request.matches(intent.requestId) &&
            intent.previousTerminalSha256 == if (count == 1) null else
                ReleaseLocks.sha256(ReleasePrivateFiles.read(path(count-1,"terminal"),8192)))
        val start = if ("%04d.start.json".format(count) in names) {
            json.decodeFromString<NotebookEpisodeStart>(ReleasePrivateFiles.read(path(count,"start"),8192)
                .decodeToString(throwOnInvalidSequence=true)).also {
                require(it.intentSha256 == ReleaseLocks.sha256(intentBytes) && hex.matches(it.originalStartAckSha256) &&
                    hex.matches(it.nativeContainerId) && hex.matches(it.nativeSystemdReadbackSha256))
            }
        } else null
        return intent to start
    }
    fun begin(requestId: String): NotebookEpisodeIntent {
        require(request.matches(requestId))
        val prior = completed()
        require(prior.size < 64 && prior.none { it.first.requestId == requestId })
        val ordinal = prior.size + 1
        val record = NotebookEpisodeIntent(generationRoot.fileName.toString(),member,user,ordinal,requestId,
            if (ordinal == 1) null else ReleaseLocks.sha256(ReleasePrivateFiles.read(path(ordinal-1,"terminal"),8192)),
            specSha256,hardCeilingMiB)
        ReleasePrivateFiles.save(path(ordinal,"intent"),json.encodeToString(record).toByteArray())
        return record
    }
    fun acceptStart(intent: NotebookEpisodeIntent, ackSha256: String, cid: String, readbackSha256: String): NotebookEpisodeStart {
        require(intent.generation == generationRoot.fileName.toString() && intent.member == member && intent.user == user &&
            hex.matches(ackSha256) && hex.matches(cid) && hex.matches(readbackSha256))
        val original = ReleasePrivateFiles.read(path(intent.ordinal,"intent"),8192)
        require(json.decodeFromString<NotebookEpisodeIntent>(original.decodeToString(throwOnInvalidSequence=true)) == intent &&
            !Files.exists(path(intent.ordinal,"start"),NOFOLLOW_LINKS))
        val result = NotebookEpisodeStart(ReleaseLocks.sha256(original),ackSha256,cid,readbackSha256)
        ReleasePrivateFiles.save(path(intent.ordinal,"start"),json.encodeToString(result).toByteArray())
        return result
    }
    fun terminal(intent: NotebookEpisodeIntent, start: NotebookEpisodeStart, stopAck: String,
        terminalReadback: String, retainedDisposition: String): NotebookEpisodeTerminal {
        require(listOf(stopAck,terminalReadback,retainedDisposition).all(hex::matches) &&
            json.decodeFromString<NotebookEpisodeIntent>(ReleasePrivateFiles.read(path(intent.ordinal,"intent"),8192)
                .decodeToString(throwOnInvalidSequence=true)) == intent)
        val startBytes = ReleasePrivateFiles.read(path(intent.ordinal,"start"),8192)
        require(json.decodeFromString<NotebookEpisodeStart>(startBytes.decodeToString(throwOnInvalidSequence=true)) == start &&
            !Files.exists(path(intent.ordinal,"terminal"),NOFOLLOW_LINKS))
        val result = NotebookEpisodeTerminal(ReleaseLocks.sha256(startBytes),stopAck,start.nativeContainerId,
            terminalReadback,retainedDisposition,hardCeilingMiB)
        ReleasePrivateFiles.save(path(intent.ordinal,"terminal"),json.encodeToString(result).toByteArray())
        return result
    }
}
