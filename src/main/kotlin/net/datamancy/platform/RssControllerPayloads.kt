package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** Inert RSS recovery data. Not a schedule, activation permit, timer, lock, or publication authority.
 * Called under the controller RSS operation lock for the whole capture/import transaction. */
internal object RssControllerPayloads {
    private val dirMode = PosixFilePermissions.fromString("rwx------")
    private val fileMode = PosixFilePermissions.fromString("rw-------")
    private val account = Regex("rss_[a-z0-9_]{1,60}\\.token")
    private val custody = Regex("[a-z0-9][a-z0-9.-]{0,95}\\.(json|record)")
    private val fixture = Regex("(?:case-[a-f0-9-]{36}|rssq-[a-f0-9]{12})")
    private const val prefix = "controller/rss/"
    private fun allowed(name: String): Boolean {
        if (!name.startsWith(prefix)) return false
        val relative = name.removePrefix(prefix)
        return relative in setOf("state/rss-state.json", "state/rss-state.previous") ||
            relative.startsWith("tokens/") && account.matches(relative.removePrefix("tokens/")) ||
            relative.startsWith("custody/") && custody.matches(relative.removePrefix("custody/")) ||
            relative.startsWith("qualification-custody/") && relative.endsWith("/bot.token") &&
                fixture.matches(relative.removePrefix("qualification-custody/").removeSuffix("/bot.token"))
    }
    private fun directory(path: Path) {
        require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path &&
            Files.isDirectory(path, NOFOLLOW_LINKS) && Files.getPosixFilePermissions(path, NOFOLLOW_LINKS) == dirMode &&
            (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == UnixSystem().uid) {
            "Unsafe RSS recovery directory"
        }
    }
    private fun selected(root: Path, payloads: MutableMap<String, Path>): List<String> {
        directory(root)
        val rss = root.resolve("rss")
        if (!Files.exists(rss, NOFOLLOW_LINKS)) return emptyList()
        directory(rss)
        val state = rss.resolve("state")
        directory(state)
        RssStateStore(state).read() // Validates checkpoint, pending uncertain outbox and reconciliation checksum.
        val names = linkedMapOf<String, Path>()
        fun add(path: Path, name: String) {
            require(allowed(name) && names.size < 256 && name !in payloads && name !in names)
            RecoveryCapsule.guard(path, 1048576)
            names[name] = path
        }
        add(state.resolve("rss-state.json"), "${prefix}state/rss-state.json")
        if (Files.exists(state.resolve("rss-state.previous"), NOFOLLOW_LINKS))
            add(state.resolve("rss-state.previous"), "${prefix}state/rss-state.previous")
        val tokens = rss.resolve("tokens")
        directory(tokens)
        val pinned = RssPacks.load().map { "${it.feed.account}.token" }.toSet() + "rss_observer.token"
        var tokenCount = 0
        Files.list(tokens).use { stream -> stream.limit(257).forEach { path ->
            require(++tokenCount <= 256 && path.fileName.toString() in pinned && account.matches(path.fileName.toString())) {
                "Unknown RSS token custody entry"
            }
            add(path, "${prefix}tokens/${path.fileName}")
        } }
        val custodyRoot = rss.resolve("custody")
        if (Files.exists(custodyRoot, NOFOLLOW_LINKS)) {
            directory(custodyRoot)
            var custodyCount = 0
            Files.list(custodyRoot).use { stream -> stream.limit(257).forEach { path ->
                require(++custodyCount <= 256)
                add(path, "${prefix}custody/${path.fileName}")
            } }
        }
        val qualifier = rss.resolve("qualification-custody")
        if (Files.exists(qualifier, NOFOLLOW_LINKS)) {
            directory(qualifier)
            var qualifierCount = 0
            Files.list(qualifier).use { stream -> stream.limit(65).forEach { entry ->
                require(++qualifierCount <= 64 && fixture.matches(entry.fileName.toString())) { "Foreign synthetic bot custody" }
                directory(entry)
                val token = entry.resolve("bot.token")
                require(MastodonRssSender.privateToken(token).isNotBlank())
                add(token, "${prefix}qualification-custody/${entry.fileName}/bot.token")
                require(Files.list(entry).use { children -> children.limit(2).count() } == 1L) {
                    "Only one original synthetic bot credential per case"
                }
            } }
        }
        return names.keys.sorted().also { payloads.putAll(names) }
    }
    fun authorized(bundle: GenerationBundle, generation: String, generationRoot: Path): Boolean {
        val request = bundle.request
        val plan = request.rssPlan ?: request.recoveredRssPlan
        if (request.id != generation || plan == null ||
            (request.rssPlan == null) == (request.recoveredRssPlan == null)) return false
        plan.validate()
        return if (request.rssPlan != null) {
            if (bundle.recoverySourceKopia != null || bundle.recoverySourceArchiveSha256 != null) false
            else if (bundle.ownedUpdate == null) true
            else {
                // The owned candidate is genuinely imported/started, never a generic recovered
                // target relabelled runnable. Its source original plan and token/state custody
                // must survive until the independently qualified candidate snapshot.
                OwnedReleaseUpdates.validate(bundle)
                val original = OwnedReleaseUpdates.original(requireNotNull(bundle.ownedUpdate))
                require(original.request.rssPlan == request.rssPlan &&
                    Files.exists(generationRoot.resolve("rss-enrollment.complete.json"), NOFOLLOW_LINKS) &&
                    Files.exists(generationRoot.resolve("rss/schedule/enrolled"), NOFOLLOW_LINKS)) {
                    "Owned RSS capture requires actually enrolled native candidate and original plan"
                }
                val stage = Json.decodeFromString<GenerationOutcome>(ReleasePrivateFiles.read(
                    generationRoot.resolve("stage.result.json"), 1048576).decodeToString(throwOnInvalidSequence = true))
                require(stage.action == "restore-import" && stage.passed && stage.failureType == null &&
                    stage.bundleSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(
                        generationRoot.resolve("bundle.json"))))
                val schedule = generationRoot.resolve("rss/schedule")
                val enrolled = ReleasePrivateFiles.read(schedule.resolve("enrolled"), 64).decodeToString()
                require(enrolled.matches(Regex("[a-f0-9]{64}")))
                // A marker's presence is NOT adoption authority. This verifies the exact
                // bundle-bound enrollment record, native owned-start, original source bytes,
                // migration role retirement and current candidate runtime observation.
                RssSchedule.real().units(schedule, enrolled)
                true
            }
        } else bundle.recoverySourceKopia != null && bundle.ownedUpdate == null &&
            bundle.recoverySourceKopia.generation != generation
    }
    fun capture(generationRoot: Path, payloads: MutableMap<String, Path>): List<String> {
        directory(generationRoot)
        val bytes = ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"), 4194304)
        val bundle = Json.decodeFromString<GenerationBundle>(bytes.decodeToString(throwOnInvalidSequence = true))
        require(bundle.request.id == generationRoot.fileName.toString() &&
            bundle.request.id.matches(Regex("q-[a-f0-9]{12}")))
        val rssRoot = generationRoot.resolve("rss")
        if (bundle.request.rssPlan == null && bundle.request.recoveredRssPlan == null) {
            require(!Files.exists(rssRoot, NOFOLLOW_LINKS)) { "Unplanned RSS custody cannot be omitted from recovery" }
            return emptyList()
        }
        require(Files.isDirectory(rssRoot, NOFOLLOW_LINKS)) { "Planned RSS custody is missing" }
        require(authorized(bundle, generationRoot.fileName.toString(), generationRoot)) {
            "RSS capture requires sealed live or recovery-lineage inert plan"
        }
        return selected(generationRoot, payloads)
    }

    fun validate(manifest: CapsuleManifest) {
        val names = manifest.controllerFiles.filter { it.startsWith(prefix) }
        require(manifest.files.filter { it.name.startsWith(prefix) }.map { it.name }.toSet() == names.toSet() &&
            names.size <= 256 && names.distinct().size == names.size && names.all(::allowed) &&
            (names.isEmpty() || "${prefix}state/rss-state.json" in names) &&
            names.all { name -> manifest.files.count { it.name == name } == 1 &&
                manifest.files.single { it.name == name }.bytes <= 1048576 }) {
            "Invalid RSS recovery payload manifest"
        }
    }

    /** Target's controller root must be fresh; creates only an inert cold projection. Local lock is
     * recreated, never restored. No enrollment or enablement markers are imported or synthesized. */
    fun restore(recovered: RecoveredGeneration, targetRoot: Path) {
        validate(recovered.manifest)
        val names = recovered.manifest.controllerFiles.filter { it.startsWith(prefix) }.sorted()
        if (names.isEmpty()) return
        require(authorized(recovered.bundle, recovered.manifest.generation,
            GenerationRuntime.BASE.resolve(recovered.manifest.generation))) {
            "RSS payload requires original sealed live or authenticated recovery-lineage inert source plan"
        }
        directory(targetRoot)
        val rss = targetRoot.resolve("rss")
        require(!Files.exists(rss, NOFOLLOW_LINKS)) { "Existing RSS target state cannot be overwritten" }
        Files.createDirectory(rss, PosixFilePermissions.asFileAttribute(dirMode))
        val declared = recovered.manifest.files.associateBy { it.name }
        for (name in names) {
            if (Thread.currentThread().isInterrupted) throw InterruptedException("RSS import interrupted")
            val source = recovered.root.resolve(name)
            val descriptor = declared.getValue(name)
            RecoveryCapsule.guard(source, 1048576)
            require(Files.size(source) == descriptor.bytes && RecoveryCapsule.fileHash(source) == descriptor.sha256)
            val relative = name.removePrefix(prefix)
            var parent = rss
            for (component in relative.split('/').dropLast(1)) {
                parent = parent.resolve(component)
                if (!Files.exists(parent, NOFOLLOW_LINKS)) {
                    Files.createDirectory(parent, PosixFilePermissions.asFileAttribute(dirMode))
                    FileChannel.open(parent.parent, READ).use { it.force(true) }
                }
                directory(parent)
            }
            val destination = parent.resolve(relative.substringAfterLast('/'))
            val bytes = Files.readAllBytes(source)
            require(ReleaseLocks.sha256(bytes) == descriptor.sha256)
            FileChannel.open(destination, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(fileMode)).use { channel ->
                val buffer = ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) channel.write(buffer)
                channel.force(true)
            }
            FileChannel.open(parent, READ).use { it.force(true) }
        }
        val state = rss.resolve("state")
        val tokens = rss.resolve("tokens")
        if (!Files.exists(tokens, NOFOLLOW_LINKS)) {
            Files.createDirectory(tokens, PosixFilePermissions.asFileAttribute(dirMode))
            FileChannel.open(rss, READ).use { it.force(true) }
        }
        directory(tokens)
        val lock = state.resolve("rss-state.lock")
        FileChannel.open(lock, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(fileMode)).use { channel ->
            val bytes = ByteBuffer.wrap("rss-state-lock-v1\n".toByteArray())
            while (bytes.hasRemaining()) channel.write(bytes)
            channel.force(true)
        }
        FileChannel.open(state, READ).use { it.force(true) }
        RssStateStore(state).read()
        require(!Files.exists(rss.resolve("schedule"), NOFOLLOW_LINKS)) { "Recovery must remain unpublished" }
        FileChannel.open(rss, READ).use { it.force(true) }
        FileChannel.open(targetRoot, READ).use { it.force(true) }
    }
}
