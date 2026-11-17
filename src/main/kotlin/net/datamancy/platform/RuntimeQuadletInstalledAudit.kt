package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.util.concurrent.TimeUnit

/** Read-only, actual installed-unit gate. No call to this class installs or starts a service.
 * The caller must hold the owned runtime lock across this audit AND the later StartUnit.
 */
internal class RuntimeQuadletInstalledAudit(
    private val sourceRoot: Path = Path.of("/etc/containers/systemd/p0-v3"),
    private val systemdRoot: Path = Path.of("/etc/systemd/system"),
    private val show: (String) -> String = ::effectiveUnitShow,
    private val requiredUid: Long = 0L,
    private val trustedAnchor: Path = Path.of("/"),
    private val verifyController: (String) -> Unit = { hash ->
        PinnedBackupController.verifyDistribution(
            Path.of("/mnt/media/p0-v3/runtime-supervision/releases/$hash"), hash, "p0-v3-platform")
    },
    private val generatedRoot: Path = Path.of("/run/systemd/generator"),
    private val translatedStart: (PrivateDeploymentSpec, RuntimeProcess) -> List<String> =
        RuntimeQuadletGeneratedStart::fromPinnedGenerator,
) {
    private data class Observed(val bytes: ByteArray, val key: Any?)
    private fun ownedAncestors(path: Path) {
        require(path.isAbsolute && path.normalize() == path && trustedAnchor.isAbsolute &&
            trustedAnchor.normalize() == trustedAnchor && path.startsWith(trustedAnchor) &&
            (sourceRoot.startsWith(trustedAnchor) && systemdRoot.startsWith(trustedAnchor))) {
            "Installed unit path must be absolute and within trusted root"
        }
        var directory = path.parent
        while (directory != null && directory.startsWith(trustedAnchor)) {
            require(Files.isDirectory(directory, NOFOLLOW_LINKS) &&
                (Files.getAttribute(directory, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == requiredUid &&
                Files.getPosixFilePermissions(directory).none {
                    it.name == "GROUP_WRITE" || it.name == "OTHERS_WRITE"
                }) { "Unowned or writable installed unit directory" }
            directory = directory.parent
        }
    }
    private fun installed(path: Path, limit: Int = 65536): Observed {
        ownedAncestors(path)
        val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        require(attributes.isRegularFile && attributes.fileKey() != null &&
            (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == requiredUid &&
            (Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong() == 1L &&
            Files.getPosixFilePermissions(path).none {
                it.name == "GROUP_WRITE" || it.name == "OTHERS_WRITE"
            }) { "Unsafe installed Quadlet file" }
        val bytes = Files.newInputStream(path, NOFOLLOW_LINKS).use { it.readNBytes(limit + 1) }
        require(bytes.size in 1..limit) { "Oversized or empty installed Quadlet" }
        val after = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        require(after.isRegularFile && after.fileKey() == attributes.fileKey() &&
            after.size() == attributes.size() && after.lastModifiedTime() == attributes.lastModifiedTime()) {
            "Installed Quadlet changed while reading"
        }
        return Observed(bytes, attributes.fileKey())
    }
    /** Podman 5.4.2 emits these three distinct option/value pairs from an unordered map.
     * Only their pre-image placement is immaterial; every other argument, including
     * repeated mounts, environment, labels, image and command, stays in exact order.
     */
    internal fun equivalentStart(installed: List<String>, translated: List<String>, image: String): Boolean {
        val unstable = setOf("--entrypoint", "--pull", "--network-alias")
        fun canonical(argv: List<String>): List<String>? {
            val imageAt = argv.indexOf(image)
            if (imageAt < 2 || argv.lastIndexOf(image) != imageAt || argv.firstOrNull() != "/usr/bin/podman") return null
            val fixed = mutableListOf<String>()
            val moved = sortedMapOf<String, String>()
            var i = 0
            while (i < imageAt) {
                val option = argv[i]
                if (option in unstable) {
                    if (i + 1 >= imageAt || argv[i + 1].isBlank() || option in moved) return null
                    moved[option] = argv[i + 1]
                    i += 2
                } else { fixed += option; i++ }
            }
            return fixed + moved.flatMap { (option, value) -> listOf(option, value) } + argv.drop(imageAt)
        }
        return canonical(installed)?.let { it == canonical(translated) } ?: false
    }
    fun audit(spec: PrivateDeploymentSpec, process: RuntimeProcess): String {
        val bundle = RuntimeQuadlets.render(spec)
        require(process in spec.processes)
        val controller = requireNotNull(spec.fragmentBinding?.controllerSha256)
        verifyController(controller)
        val unit = RuntimeQuadlets.unit(spec, process)
        val sourcePath = sourceRoot.resolve("$unit.container")
        val dropInPath = systemdRoot.resolve("$unit.service.d/50-p0-lifecycle.conf")
        val source = installed(sourcePath)
        val dropIn = installed(dropInPath)
        val generatedPath = generatedRoot.resolve("$unit.service")
        val generated = installed(generatedPath)
        val generatedText = generated.bytes.decodeToString(throwOnInvalidSequence = true)
        val generatedLine = generatedText.lineSequence().single { it.startsWith("ExecStart=/usr/bin/podman ") }
            .substringAfter('=')
        require(generatedText.lineSequence().any {
            it == "SourcePath=${sourcePath}"
        }) { "Generated unit has foreign Quadlet source" }
        val generatedCommand = RuntimeQuadletGeneratedStart.parse(spec, process, generatedLine)
        require(equivalentStart(generatedCommand, translatedStart(spec, process), process.image)) {
            "Installed generated Podman start differs from pinned generator translation"
        }
        val effective = show("$unit.service")
        val digest = RuntimeQuadletEffectiveAudit.audit(spec, bundle, process, source.bytes, dropIn.bytes,
            effective, generatedCommand)
        // Detect changes during systemctl consultation, including a replacement with identical bytes.
        val checkedSource = installed(sourcePath)
        val checkedDropIn = installed(dropInPath)
        val checkedGenerated = installed(generatedPath)
        require(checkedSource.key == source.key && checkedSource.bytes.contentEquals(source.bytes) &&
            checkedDropIn.key == dropIn.key && checkedDropIn.bytes.contentEquals(dropIn.bytes) &&
            checkedGenerated.key == generated.key && checkedGenerated.bytes.contentEquals(generated.bytes)) {
            "Installed Quadlet changed during effective-unit audit"
        }
        verifyController(controller)
        return digest
    }
}

/** Read from the system manager, never `systemd-analyze` or a generated dry-run. */
private fun effectiveUnitShow(unit: String): String {
    require(unit.matches(Regex("p0v3-[a-z0-9-]+\\.service")))
    val keys = listOf("LoadState", "FragmentPath", "SourcePath", "DropInPaths", "Type", "Restart",
        "User", "Delegate", "DelegateSubgroup", "DelegateControllers",
        "ExecStart", "ExecStartPre", "ExecStop", "ExecStopPost")
    val process = ProcessBuilder(listOf("/usr/bin/systemctl", "show", "--no-pager", "--property=${keys.joinToString(",")}", unit))
        .redirectErrorStream(true).apply { environment().clear() }.start()
    try {
        require(process.waitFor(20, TimeUnit.SECONDS) && process.exitValue() == 0) {
            "Cannot inspect installed systemd unit"
        }
        val bytes = process.inputStream.use { it.readNBytes(65537) }
        require(bytes.size in 1..65536) { "Invalid installed systemd inspection" }
        return bytes.decodeToString(throwOnInvalidSequence = true)
    } finally {
        if (process.isAlive) process.destroyForcibly()
    }
}
