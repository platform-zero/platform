package net.datamancy.platform

import java.nio.file.Path
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

internal data class VolumeRootMetadata(val uid: Int, val gid: Int, val mode: Int, val modified: VolumeTimestamp,
    val accessAcl: String? = null, val defaultAcl: String? = null, val userXattrs: Map<String, String> = emptyMap()) {
    init { require(uid in 0..65534 && gid in 0..65534 && mode in 0..4095) }
    companion object {
        fun parse(text: String): VolumeRootMetadata {
            val fields = text.split('\n')
            require(fields.size == 6 && fields[5] == "directory") { "Volume root must be an actual directory" }
            require(fields.take(2).all { it.matches(Regex("[0-9]{1,5}")) } && fields[2].matches(Regex("[0-7]{1,4}")))
            require(fields[3].matches(Regex("-?[0-9]{1,10}")) &&
                fields[4].matches(Regex("[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{9} \\+0000"))) { "Precise UTC root timestamp required" }
            val time = Instant.parse(fields[4].substringBefore(" +0000").replace(' ', 'T') + "Z")
            require(time.epochSecond == fields[3].toLong()) { "Inconsistent root timestamps" }
            return VolumeRootMetadata(fields[0].toInt(), fields[1].toInt(), fields[2].toInt(8), VolumeTimestamp(time.epochSecond, time.nano))
        }
    }
}

/** Only observes or restores the exact owned volume root. No shell, dereferencing, recursive chmod or host trust changes. */
internal class ColdVolumeMetadata(private val execute: (List<String>, Path) -> String = ColdMetadataProcess::run,
    private val executeExtended: (List<String>, Path) -> String = ColdMetadataProcess::runLarge) {
    private fun root(spec: PrivateDeploymentSpec, volume: RuntimeVolume): Path {
        PrivateDeployment.validate(spec); require(volume in spec.volumes); spec.store.verifyConfiguration()
        return Path.of("${spec.store.graph}/volumes/p0v3-live-${spec.name}-volume-${volume.id}/_data")
    }
    private val prefix = listOf("/usr/bin/sudo", "-n", "/usr/bin/timeout", "--kill-after=5s", "15s")
    fun observe(spec: PrivateDeploymentSpec, volume: RuntimeVolume, home: Path): VolumeRootMetadata {
        val root = root(spec, volume)
        return VolumeRootMetadata.parse(execute(prefix + listOf("/usr/bin/stat", "--printf=%u\\n%g\\n%a\\n%Y\\n%y\\n%F", "--", root.toString()), home))
    }
    /** Privileged read-only ACL and binary-exact xattr census for the mount root omitted by
     * Podman export. Unsupported namespaces fail before any snapshot writes.
     */
    fun observeFull(spec: PrivateDeploymentSpec, volume: RuntimeVolume, home: Path): VolumeRootMetadata {
        val root = root(spec, volume)
        val stat = observe(spec, volume, home)
        val acl = executeExtended(prefix + listOf("/usr/bin/getfacl", "-c", "-n", "-p", "-E", "--", root.toString()), home)
        val access = mutableListOf<String>(); val defaults = mutableListOf<String>()
        for (line in acl.lines().filter { it.isNotEmpty() }) {
            if (line.startsWith("default:")) defaults += line.removePrefix("default:") else access += line
        }
        fun canonical(lines: List<String>): String {
            require(lines.size in 3..64 && lines.distinct().size == lines.size &&
                listOf("user::", "group::", "other::").all { tag -> lines.count { it.startsWith(tag) } == 1 })
            return lines.joinToString(",")
        }
        val extended = if (access.size == 3) null else canonical(access)
        val defaultAcl = defaults.takeIf { it.isNotEmpty() }?.let(::canonical)
        val attributes = executeExtended(prefix + listOf("/usr/bin/getfattr", "--absolute-names", "-d", "-m", ".", "--encoding=hex", "--", root.toString()), home)
        val xattrs = linkedMapOf<String, String>()
        for (line in attributes.lines().filter { it.isNotEmpty() && !it.startsWith("#") }) {
            val name = line.substringBefore('='); val encoded = line.substringAfter('=', "")
            require(name.matches(Regex("user\\.[a-zA-Z0-9_.-]{1,96}")) && name !in xattrs &&
                encoded.matches(Regex("0x(?:[a-fA-F0-9]{2}){0,4096}"))) { "Unsupported root attribute or security label" }
            xattrs[name] = encoded.lowercase()
        }
        return stat.copy(accessAcl = extended, defaultAcl = defaultAcl, userXattrs = xattrs)
    }
    /** Fixed, volume-local metadata import AFTER native tar import and BEFORE independent
     * re-export. All descriptors and parents are checked before the first privileged write.
     * Child paths never traverse a symlink; a symlink leaf is only changed with -h semantics.
     */
    fun restoreTree(spec: PrivateDeploymentSpec, volume: RuntimeVolume, entries: List<VolumeTarEntry>) {
        val target = root(spec, volume)
        restoreTreeAt(target, entries, volume.userId,
            volume.mappedOwners.map { it.userId to it.groupId }.toSet(),
            restoreRoot = { entry -> restore(spec, volume, entry) })
    }
    /** Read-only native entry preflight on an already failed, still fenced target.
     * Does not retry import or perform the first chown/chmod/touch.
     */
    fun auditTree(spec: PrivateDeploymentSpec, volume: RuntimeVolume, entries: List<VolumeTarEntry>) {
        val target = root(spec, volume)
        restoreTreeAt(target, entries, volume.userId,
            volume.mappedOwners.map { it.userId to it.groupId }.toSet(),
            restoreRoot = { error("Read-only audit must not reach root metadata write") }, readOnlyPreflight = true)
    }
    internal fun restoreTreeAt(target: Path, entries: List<VolumeTarEntry>, owner: Int,
        mappedOwners: Set<Pair<Int, Int>> = emptySet(), readOnlyPreflight: Boolean = false,
        restoreRoot: (VolumeTarEntry) -> Unit) {
        require(target.isAbsolute && target.normalize() == target && owner in 1..65534 &&
            mappedOwners.size <= 64 && entries.size in 1..100000)
        val allowed = mappedOwners + (owner to owner)
        val byPath = entries.associateBy { it.path }
        require(byPath.size == entries.size && byPath["."]?.let {
            it.directory && it.uid == owner && it.gid == owner && it.linkKind == null
        } == true)
        fun checkedPath(entry: VolumeTarEntry): Path {
            require(entry.path == "." || entry.path.length in 1..1024 && !entry.path.startsWith('/') &&
                entry.path.split('/').all { it.isNotEmpty() && it !in setOf(".", "..") &&
                    it.all { char -> char.code >= 32 && char != '\\' } })
            require((entry.uid to entry.gid) in allowed && entry.mode in 0..511 &&
                entry.userXattrs.size <= 64 && entry.userXattrs.all { (name, value) ->
                    name.matches(Regex("user\\.[a-zA-Z0-9_.-]{1,96}")) &&
                        value.matches(Regex("0x(?:[a-f0-9]{2}){0,4096}"))
                })
            val path = if (entry.path == ".") target else target.resolve(entry.path).normalize()
            require(path == target || path.startsWith(target))
            return path
        }
        for (entry in entries) {
            checkedPath(entry)
            VolumeTimestamp(entry.modifiedSeconds, entry.modifiedNanos)
            entry.accessAcl?.let { require(it.length in 1..4096 && it.matches(Regex("[a-zA-Z0-9_:,\\n-]+"))) }
            entry.defaultAcl?.let { require(entry.directory && it.length in 1..4096 && it.matches(Regex("[a-zA-Z0-9_:,\\n-]+"))) }
            if (entry.linkKind == null) require(entry.linkTarget == null)
            if (entry.path == ".") continue
            val parent = entry.path.substringBeforeLast('/', ".")
            require(byPath[parent]?.directory == true) { "Native archive parent is not a directory" }
            when (entry.linkKind) {
                null -> Unit
                "symbolic" -> {
                    val link = requireNotNull(entry.linkTarget)
                    val resolved = Path.of(entry.path).parent?.resolve(link)?.normalize() ?: Path.of(link).normalize()
                    require(!entry.directory && entry.accessAcl == null && entry.defaultAcl == null &&
                        entry.userXattrs.isEmpty() && entry.mode == 511 && link.isNotEmpty() &&
                        !link.startsWith('/') && '\\' !in link && link.none { it.code < 32 } &&
                        link.split('/').none { it.isEmpty() || it == ".." } &&
                        !resolved.isAbsolute && !resolved.startsWith("..") && resolved.toString() != ".") {
                        "Symlink metadata cannot be applied through its target or escape the volume"
                    }
                }
                "hard" -> {
                    val original = byPath[requireNotNull(entry.linkTarget).removePrefix("./")]
                    require(original != null && !original.directory && original.linkKind == null &&
                        original.uid == entry.uid && original.gid == entry.gid && original.mode == entry.mode &&
                        original.modifiedSeconds == entry.modifiedSeconds && original.modifiedNanos == entry.modifiedNanos &&
                        original.accessAcl == entry.accessAcl && original.defaultAcl == entry.defaultAcl &&
                        original.userXattrs == entry.userXattrs) { "Hardlink aliases require identical inode metadata" }
                }
                else -> error("Unsupported imported link descriptor")
            }
            if (!entry.directory) require(entry.defaultAcl == null)
        }
        // Native preflight uses the fixed privileged transport already used for root metadata.
        // A parent that resolves through any link is rejected before modifying ANY member.
        fun call(vararg args: String) = execute(prefix + args, target.parent).trimEnd('\n')
        require(call("/usr/bin/realpath", "-e", "--", target.toString()) == target.toString())
        for ((index, entry) in entries.filter { it.path != "." }.withIndex()) {
            try {
                val path = checkedPath(entry)
                require(call("/usr/bin/realpath", "-e", "--", path.parent.toString()) == path.parent.toString())
                val kind = call("/usr/bin/stat", "--printf=%F", "--", path.toString())
                val expectedKind = when {
                    entry.directory -> "directory"
                    entry.linkKind == "symbolic" -> "symbolic link"
                    else -> "regular file"
                }
                // GNU stat -c %F distinguishes a zero-length regular inode as
                // "regular empty file". It is still S_ISREG, never a symlink.
                require(kind == expectedKind || (expectedKind == "regular file" && kind == "regular empty file")) {
                    "Imported native entry type changed before metadata restore"
                }
                if (entry.linkKind == "symbolic")
                    require(call("/usr/bin/readlink", "--", path.toString()) == entry.linkTarget)
                if (entry.linkKind == "hard") {
                    val other = checkedPath(requireNotNull(byPath[entry.linkTarget!!.removePrefix("./")]))
                    require(call("/usr/bin/stat", "--printf=%d:%i", "--", path.toString()) ==
                        call("/usr/bin/stat", "--printf=%d:%i", "--", other.toString())) {
                        "Imported hardlink is not the original same-volume inode"
                    }
                }
            } catch (failure: Exception) {
                if (!readOnlyPreflight) throw failure
                throw IllegalStateException("Read-only native volume preflight rejected entry index $index (${failure.javaClass.simpleName})", failure)
            }
        }
        if (readOnlyPreflight) return
        for (entry in entries.filter { it.path != "." && it.linkKind != "hard" }
            .sortedWith(compareByDescending<VolumeTarEntry> { it.path.count { char -> char == '/' } }.thenByDescending { it.path })) {
            RecoveryDeadline.remainingSecondsIfBound()
            val path = checkedPath(entry).toString()
            call("/usr/bin/chown", "--no-dereference", "${entry.uid}:${entry.gid}", "--", path)
            if (entry.linkKind != "symbolic") {
                call("/usr/bin/chmod", entry.mode.toString(8), "--", path)
                entry.accessAcl?.let {
                    require(it.length in 1..4096 && it.matches(Regex("[a-zA-Z0-9_:,\\n-]+")))
                    call("/usr/bin/setfacl", "--set=$it", "--", path)
                }
                entry.defaultAcl?.let {
                    require(entry.directory && it.length in 1..4096 && it.matches(Regex("[a-zA-Z0-9_:,\\n-]+")))
                    call("/usr/bin/setfacl", "-d", "--set=$it", "--", path)
                }
                entry.userXattrs.toSortedMap().forEach { (name, value) ->
                    call("/usr/bin/setfattr", "--name=$name", "--value=$value", "--", path)
                }
            }
            call("/usr/bin/touch", "--no-dereference", "--date=@${VolumeTimestamp(entry.modifiedSeconds, entry.modifiedNanos).decimal()}", "--", path)
        }
        restoreRoot(requireNotNull(byPath["."]))
    }
    fun restore(spec: PrivateDeploymentSpec, volume: RuntimeVolume, entry: VolumeTarEntry) {
        require(spec.name.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,23}")) && spec.processes.none { it.oneShot } &&
            entry.directory && entry.path == "." && entry.uid == volume.userId && entry.gid == volume.userId && entry.mode in 0..511)
        val expected = VolumeRootMetadata(entry.uid, entry.gid, entry.mode, VolumeTimestamp(entry.modifiedSeconds, entry.modifiedNanos))
        val root = root(spec, volume)
        observe(spec, volume, root.parent) // A symlink or non-directory root must fail before metadata writes.
        val commands = mutableListOf(
            listOf("/usr/bin/chown", "--no-dereference", "${entry.uid}:${entry.gid}", "--", root.toString()),
            listOf("/usr/bin/chmod", entry.mode.toString(8), "--", root.toString())
        )
        entry.accessAcl?.let { acl ->
            require(acl.length in 1..4096 && acl.matches(Regex("[a-zA-Z0-9_:,\\n-]+")))
            commands += listOf("/usr/bin/setfacl", "--set=$acl", "--", root.toString())
        }
        entry.defaultAcl?.let { acl ->
            require(acl.length in 1..4096 && acl.matches(Regex("[a-zA-Z0-9_:,\\n-]+")))
            commands += listOf("/usr/bin/setfacl", "-d", "--set=$acl", "--", root.toString())
        }
        for ((name, value) in entry.userXattrs.toSortedMap()) {
            require(name.matches(Regex("user\\.[a-zA-Z0-9_.-]{1,96}")) &&
                value.matches(Regex("0x(?:[a-f0-9]{2}){0,4096}")))
            commands += listOf("/usr/bin/setfattr", "--name=$name", "--value=$value", "--", root.toString())
        }
        commands += listOf("/usr/bin/touch", "--no-dereference", "--date=@${expected.modified.decimal()}", "--", root.toString())
        for (args in commands) execute(prefix + args, root.parent)
        require(observe(spec, volume, root.parent) == expected) { "Restored volume-root metadata mismatch" }
    }
}

/** Bounded diagnostics with a clean environment. Tests exercise this using synthetic subprocesses, never sudo/Podman. */
internal object ColdMetadataProcess {
    fun run(argv: List<String>, home: Path): String = execute(argv, home, 25000)
    fun runLarge(argv: List<String>, home: Path): String = execute(argv, home, 25000, 65536)
    internal fun execute(argv: List<String>, home: Path, timeoutMillis: Long, maxBytes: Int = 1024): String {
        require(argv.isNotEmpty() && home.isAbsolute && timeoutMillis in 1..25000 && maxBytes in 1..65536)
        if (Thread.currentThread().isInterrupted) throw InterruptedException("Metadata operation interrupted before effect")
        val process = ProcessBuilder(argv).redirectError(ProcessBuilder.Redirect.DISCARD).apply {
            environment().clear()
            environment().putAll(mapOf("PATH" to "/usr/bin:/bin", "LANG" to "C", "LC_ALL" to "C", "TZ" to "UTC", "HOME" to home.toString()))
        }.start()
        val reader = Executors.newSingleThreadExecutor { task -> Thread(task, "volume-metadata-output").apply { isDaemon = true } }
        try {
            process.outputStream.close()
            val output = reader.submit<ByteArray> { process.inputStream.use { it.readNBytes(maxBytes + 1) } }
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
            check(process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)) { "Volume metadata operation timed out; retain isolation" }
            check(process.exitValue() == 0) { "Volume metadata operation failed; retain isolation" }
            val remaining = deadline - System.nanoTime()
            check(remaining > 0) { "Volume metadata output timed out; retain isolation" }
            val bytes = output.get(remaining, TimeUnit.NANOSECONDS)
            require(bytes.size <= maxBytes) { "Oversized volume metadata output" }
            return bytes.decodeToString(throwOnInvalidSequence = true)
        } catch (failure: InterruptedException) {
            Thread.currentThread().interrupt(); throw failure
        } finally {
            // Only this invocation's process tree; timeout is never authority to resume a source.
            if (process.isAlive) {
                process.descendants().use { children -> children.forEach { it.destroyForcibly() } }
                process.destroyForcibly()
            }
            reader.shutdownNow()
        }
    }
}
