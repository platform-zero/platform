package net.datamancy.platform

import java.nio.file.Files
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption.*
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import com.sun.security.auth.module.UnixSystem
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class QuadletInstallIntent(val schemaVersion: Int = 1, val generation: String,
    val bundleSha256: String, val member: String, val specSha256: String, val filesSha256: Map<String, String>,
    val stagedDestinations: List<String>)
@Serializable internal data class QuadletInstallResult(val schemaVersion: Int = 1, val intentSha256: String,
    val installedAuditSha256: Map<String, String>)

/** Installs the complete *disabled* source/drop-in set. An interrupted install is never retried
 * under another operation ID. In particular daemon-reload, install and audit do not StartUnit.
 * The generation and member locks are held by the caller from preflight through the result.
 */
internal class RuntimeQuadletInstaller(
    private val sourceRoot: Path = Path.of("/etc/containers/systemd/p0-v3"),
    private val systemdRoot: Path = Path.of("/etc/systemd/system"),
    private val effect: (List<String>) -> Unit = ::quadletInstallEffect,
    private val audit: (PrivateDeploymentSpec, RuntimeProcess) -> String = { spec, p ->
        RuntimeQuadletInstalledAudit().audit(spec, p)
    },
    private val controller: (String) -> Unit = { hash ->
        PinnedBackupController.verifyDistribution(
            Path.of("/mnt/media/p0-v3/runtime-supervision/releases/$hash"), hash, "p0-v3-platform")
    },
) {
    private val json = Json { encodeDefaults = true }
    fun install(root: Path, generation: String, bundleSha256: String, spec: PrivateDeploymentSpec): QuadletInstallResult {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
            bundleSha256.matches(Regex("[a-f0-9]{64}")) && spec.name.startsWith("$generation-") &&
            root == GenerationRuntime.BASE.resolve(generation) ||
            // Test-only isolated namespace, never the real installer entry point.
            (sourceRoot != Path.of("/etc/containers/systemd/p0-v3") && root.isAbsolute && root.normalize() == root))
        ReleasePrivateFiles.directory(root)
        require(sourceRoot.isAbsolute && systemdRoot.isAbsolute && sourceRoot.normalize() == sourceRoot &&
            systemdRoot.normalize() == systemdRoot && sourceRoot != systemdRoot)
        val rendered = RuntimeQuadlets.render(spec)
        val hash = requireNotNull(spec.fragmentBinding?.controllerSha256)
        controller(hash)
        val paths = rendered.files.mapKeys { (relative, _) ->
            val name = relative.substringBefore('.')
            require(name.matches(Regex("p0v3-[a-z0-9-]+")))
            val destination = if (relative.endsWith(".container")) sourceRoot.resolve(relative)
                else systemdRoot.resolve(relative)
            require(destination.normalize() == destination && destination.startsWith(if (relative.endsWith(".container")) sourceRoot else systemdRoot))
            destination
        }
        require(paths.size == rendered.files.size && paths.size == spec.processes.size * 2)
        val intentPath = root.resolve("quadlet-install-${spec.name}.intent.json")
        val resultPath = root.resolve("quadlet-install-${spec.name}.result.json")
        require(!Files.exists(intentPath, NOFOLLOW_LINKS) && !Files.exists(resultPath, NOFOLLOW_LINKS)) {
            "Quadlet installation already attempted; reconcile original, never reinstall"
        }
        // All target conflicts are checked before the first effect. Never replace even identical
        // bytes: another installer may own the inode and partial attempts require reconciliation.
        require(paths.keys.none { Files.exists(it, NOFOLLOW_LINKS) }) { "Existing Quadlet source or drop-in" }
        val intent = QuadletInstallIntent(generation = generation, bundleSha256 = bundleSha256,
            member = spec.name, specSha256 = rendered.specSha256,
            filesSha256 = paths.map { (path, value) -> path.toString() to ReleaseLocks.sha256(value.toByteArray()) }.toMap().toSortedMap(),
            stagedDestinations = paths.keys.map(Path::toString))
        val intentBytes = json.encodeToString(intent).toByteArray()
        ReleasePrivateFiles.save(intentPath, intentBytes)
        // Stage exact bytes with CREATE_NEW before privileged copies. Staging files and the intent
        // are retained on failure; neither an absent result nor an installed file permits replay.
        val staging = root.resolve("quadlet-install-${spec.name}")
        Files.createDirectory(staging, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(root)
        for ((index, value) in paths.values.withIndex()) ReleasePrivateFiles.save(staging.resolve("$index.source"), value.toByteArray())
        val pinned = "/mnt/media/p0-v3/runtime-supervision/releases/$hash/bin/p0-v3-platform"
        paths.keys.forEachIndexed { index, path ->
            effect(listOf("/usr/bin/sudo", "-n", pinned, "runtime", "quadlet-copy",
                staging.resolve("$index.source").toString(), path.toString(),
                intent.filesSha256.getValue(path.toString()), hash))
        }
        effect(listOf("/usr/bin/sudo", "-n", "/usr/bin/systemctl", "daemon-reload"))
        val audits = spec.processes.associate { p -> p.id to audit(spec, p) }
        require(audits.values.all { it.matches(Regex("[a-f0-9]{64}")) }) { "Incomplete installed unit audit" }
        controller(hash)
        val result = QuadletInstallResult(intentSha256 = ReleaseLocks.sha256(intentBytes), installedAuditSha256 = audits)
        ReleasePrivateFiles.save(resultPath, json.encodeToString(result).toByteArray())
        return result
    }
}

internal fun quadletInstallEffect(args: List<String>, timeoutSeconds: Long = 40) {
    // Never wait for a pipe read before the deadline: a stalled privileged child can keep
    // stdout open forever. Child output is not authority and is deliberately discarded.
    val process = ProcessBuilder(args).redirectOutput(ProcessBuilder.Redirect.DISCARD)
        .redirectError(ProcessBuilder.Redirect.DISCARD).apply { environment().clear() }.start()
    try {
        require(process.waitFor(timeoutSeconds, TimeUnit.SECONDS) && process.exitValue() == 0) {
            "Quadlet install effect uncertain or failed; retain original intent"
        }
    } finally {
        if (process.isAlive) { process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS) }
    }
}

/** Narrow root-side exclusive copy. The pinned root executable, not `install -T`, owns the
 * destination open. Existing directories are observed, never chmod/chowned or replaced.
 */
internal object RuntimeQuadletRootCopy {
    fun copy(source: Path, destination: Path, expected: String, controller: String) {
        require(UnixSystem().uid == 0L && expected.matches(Regex("[a-f0-9]{64}")))
        PinnedBackupController.verify(controller)
        val stagingPattern = Regex("/mnt/media/p0-v3/release-generations/(q-[a-f0-9]{12})/quadlet-install-(q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,39})/([0-9]+)\\.source")
        val match = requireNotNull(stagingPattern.matchEntire(source.toString())) { "Foreign Quadlet staging path" }
        val (generation, member, indexText) = match.destructured
        require(member.startsWith("$generation-") && source.isAbsolute && source.normalize() == source)
        val name = "p0v3-q-[a-f0-9]{12}-[a-z0-9-]+"
        require(destination.toString().matches(Regex("/etc/containers/systemd/p0-v3/$name\\.container|/etc/systemd/system/$name\\.service\\.d/50-p0-lifecycle\\.conf")) &&
            destination.normalize() == destination)
        val originalRoot = GenerationRuntime.BASE.resolve(generation)
        val owner = (Files.getAttribute(originalRoot, "unix:uid", NOFOLLOW_LINKS) as Number).toLong()
        require(owner in 1..65534)
        fun original(path: Path, limit: Int): ByteArray {
            require(Files.isRegularFile(path, NOFOLLOW_LINKS) &&
                (Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong() == 1L &&
                (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == owner &&
                Files.getPosixFilePermissions(path) == PosixFilePermissions.fromString("rw-------") &&
                Files.isDirectory(path.parent, NOFOLLOW_LINKS) &&
                (Files.getAttribute(path.parent, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == owner &&
                Files.getPosixFilePermissions(path.parent) == PosixFilePermissions.fromString("rwx------")) {
                "Untrusted original Quadlet record"
            }
            return Files.newInputStream(path, NOFOLLOW_LINKS).use { it.readNBytes(limit + 1) }.also {
                require(it.size in 1..limit) { "Invalid original Quadlet record size" }
            }
        }
        val intentBytes = original(originalRoot.resolve("quadlet-install-$member.intent.json"), 65536)
        val json = Json { encodeDefaults = true }
        val intent = json.decodeFromString<QuadletInstallIntent>(intentBytes.decodeToString(throwOnInvalidSequence = true))
        val bundleBytes = original(originalRoot.resolve("bundle.json"), 4 * 1024 * 1024)
        val bundle = json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
        require(ReleaseLocks.sha256(bundleBytes) == intent.bundleSha256 &&
            authorizes(intent, bundle, generation, member, indexText.toIntOrNull() ?: -1,
                destination, expected, controller) &&
            json.encodeToString(intent).toByteArray().contentEquals(intentBytes) &&
            !Files.exists(originalRoot.resolve("quadlet-install-$member.result.json"), NOFOLLOW_LINKS)) {
            "Foreign or completed original Quadlet installation"
        }
        val bytes = original(source, 65536)
        require(ReleaseLocks.sha256(bytes) == expected) { "Staged Quadlet source changed" }
        createExclusive(destination, bytes)
    }

    internal fun authorizes(intent: QuadletInstallIntent, bundle: GenerationBundle,
        generation: String, member: String, index: Int, destination: Path, expected: String,
        controller: String): Boolean {
        if (intent.schemaVersion != 1 || intent.generation != generation || intent.member != member ||
            bundle.request.id != generation || index !in intent.stagedDestinations.indices ||
            intent.stagedDestinations[index] != destination.toString() ||
            intent.filesSha256[destination.toString()] != expected) return false
        val spec = bundle.members.singleOrNull { it.spec.name == member }?.spec ?: return false
        if (spec.fragmentBinding?.controllerSha256 != controller ||
            spec.executionBackend != RuntimeExecutionBackend.QUADLET_V2) return false
        val rendered = RuntimeQuadlets.render(spec)
        return rendered.specSha256 == intent.specSha256 &&
            rendered.files.mapKeys { entry ->
                val relative = entry.key
                (if (relative.endsWith(".container")) Path.of("/etc/containers/systemd/p0-v3")
                 else Path.of("/etc/systemd/system")).resolve(relative).toString()
            }.mapValues { ReleaseLocks.sha256(it.value.toByteArray()) } == intent.filesSha256
    }

    /** Root-owned ancestors cannot be replaced by the unprivileged controller between
     * check and O_EXCL. [anchor] and [owner] permit isolated adversarial unit tests only. */
    internal fun createExclusive(destination: Path, bytes: ByteArray, anchor: Path = Path.of("/"), owner: Long = 0L) {
        require(destination.isAbsolute && destination.normalize() == destination &&
            anchor.isAbsolute && anchor.normalize() == anchor && destination.startsWith(anchor) &&
            destination != anchor && bytes.isNotEmpty() && bytes.size <= 65536)
        fun safeDirectory(path: Path) {
            require(Files.isDirectory(path, NOFOLLOW_LINKS) &&
                (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == owner &&
                Files.getPosixFilePermissions(path).none { it.name == "GROUP_WRITE" || it.name == "OTHERS_WRITE" }) {
                "Untrusted Quadlet destination ancestor"
            }
        }
        var parent = destination.parent
        val missing = mutableListOf<Path>()
        while (!Files.exists(parent, NOFOLLOW_LINKS)) {
            missing.add(parent)
            require(parent != anchor) { "Missing trusted destination root" }
            parent = parent.parent ?: error("Missing trusted destination root")
        }
        var ancestor: Path? = parent
        while (ancestor != null && ancestor.startsWith(anchor)) {
            safeDirectory(ancestor)
            ancestor = if (ancestor == anchor) null else ancestor.parent
        }
        for (dir in missing.asReversed()) {
            safeDirectory(dir.parent)
            Files.createDirectory(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwxr-xr-x")))
            // sudo's inherited umask may be 077. Root owns this NEW inode,
            // so set the exact traversable mode before the non-root installed
            // audit; never chmod a pre-existing directory or another release.
            Files.setPosixFilePermissions(dir,PosixFilePermissions.fromString("rwxr-xr-x"))
            safeDirectory(dir)
            FileChannel.open(dir.parent, READ).use { it.force(true) }
        }
        safeDirectory(destination.parent)
        FileChannel.open(destination, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-r--r--"))).use { channel ->
            val buffer = ByteBuffer.wrap(bytes)
            while (buffer.hasRemaining()) channel.write(buffer)
            // Do not inherit sudo's umask: the non-root audit must read the root-owned
            // sources, while no non-root actor may change them.
            Files.setPosixFilePermissions(destination, PosixFilePermissions.fromString("rw-r--r--"))
            channel.force(true)
        }
        FileChannel.open(destination.parent, READ).use { it.force(true) }
    }
}
