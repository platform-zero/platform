package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.SecureDirectoryStream
import java.nio.file.attribute.BasicFileAttributeView
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFileAttributes
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.READ
import kotlinx.serialization.json.*

/** Hash-bound ACTUAL source tree, not the installed bin/lib acceptance controller. */
internal data class QualificationSuitePin(val root: Path, val definition: ActivationInput,
    val runnerHashes: Map<String, String>)

internal object QualificationSuiteClosure {
    internal data class DirectoryIdentity(val owner: Long, val device: Long, val inode: Long, val mode: Int)
    internal interface Reader {
        fun protected(path: Path, limit: Int): ByteArray
        fun directory(path: Path): DirectoryIdentity
        fun source(root: Path, path: Path, owner: Long, limit: Int, executable: Boolean): ByteArray
    }
    private val hex = Regex("[a-f0-9]{64}")
    private val json = Json { ignoreUnknownKeys = false }
    private fun sha(bytes: ByteArray) = ReleaseLocks.sha256(bytes)
    private fun trusted(owner: Long) = owner == 0L || owner == UnixSystem().uid
    private fun safe(identity: DirectoryIdentity) = trusted(identity.owner) &&
        identity.mode.and(18) == 0 && identity.mode.and(64) != 0
    private fun attribute(path: Path, name: String) =
        (Files.getAttribute(path, "unix:$name", NOFOLLOW_LINKS) as Number).toLong()
    private val filesystem = object : Reader {
        override fun protected(path: Path, limit: Int) = ReleasePrivateFiles.read(path, limit)
        override fun directory(path: Path): DirectoryIdentity {
            require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path &&
                Files.isDirectory(path, NOFOLLOW_LINKS))
            val mode = attribute(path, "mode").toInt().and(4095)
            require(mode.and(18) == 0 && mode.and(64) != 0) // no group/world writes; owner can traverse
            return DirectoryIdentity(attribute(path, "uid"), attribute(path, "dev"),
                attribute(path, "ino"), mode)
        }
        override fun source(root: Path, path: Path, owner: Long, limit: Int, executable: Boolean): ByteArray =
            protectedSource(root, path, owner, limit, executable) { }
    }
    /** Test hook fires only after real OS directory handles have been opened. Production uses
     * the SAME reader with an empty hook; no caller-controlled path or hook is serialized. */
    internal fun sourceFileForTest(root: Path, path: Path, limit: Int, executable: Boolean = false,
        onHeld: () -> Unit = {}): ByteArray =
        protectedSource(root, path, UnixSystem().uid, limit, executable, onHeld)

    private fun protectedSource(root: Path, path: Path, owner: Long, limit: Int,
        executable: Boolean, onHeld: () -> Unit): ByteArray {
        require(trusted(owner) && root.isAbsolute && root.normalize() == root && path.isAbsolute &&
            path.normalize() == path && path.startsWith(root) && path != root &&
            root.toRealPath() == root && path.toRealPath() == path &&
            Files.isRegularFile(path, NOFOLLOW_LINKS) && attribute(path, "uid") == owner &&
            attribute(path, "nlink") == 1L && attribute(path, "mode").toInt().and(18) == 0 &&
            (!executable || Files.isExecutable(path)))
        val expectedRoot = filesystem.directory(root)
        require(expectedRoot.owner == owner)
        val held = mutableListOf<Pair<Path, SecureDirectoryStream<Path>>>()
        fun sameDirectory(entry: Pair<Path, SecureDirectoryStream<Path>>) {
            val (name, descriptor) = entry
            val current = filesystem.directory(name)
            val heldBasic = requireNotNull(descriptor.getFileAttributeView(BasicFileAttributeView::class.java))
                .readAttributes()
            val namedBasic = Files.readAttributes(name, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
            val heldPosix = requireNotNull(descriptor.getFileAttributeView(PosixFileAttributeView::class.java))
                .readAttributes()
            val namedPosix = Files.readAttributes(name, PosixFileAttributes::class.java, NOFOLLOW_LINKS)
            require(heldBasic.isDirectory && heldBasic.fileKey() != null &&
                heldBasic.fileKey() == namedBasic.fileKey() &&
                heldPosix.owner() == namedPosix.owner() && heldPosix.permissions() == namedPosix.permissions() &&
                current.owner == owner && safe(current) &&
                (name != root || current == expectedRoot))
        }
        try {
            val opened = Files.newDirectoryStream(root)
            val first = opened as? SecureDirectoryStream<Path>
                ?: run { opened.close(); throw IllegalArgumentException("Descriptor-relative source custody required") }
            held += root to first
            val relative = root.relativize(path)
            var parent = root
            var current = first
            for (index in 0 until relative.nameCount - 1) {
                val segment = relative.getName(index)
                parent = parent.resolve(segment)
                current = current.newDirectoryStream(segment, NOFOLLOW_LINKS)
                held += parent to current
            }
            val initial = held.associate { it.first to filesystem.directory(it.first) }
            require(initial.values.all { it.owner == owner && safe(it) })
            held.forEach(::sameDirectory)
            onHeld()
            held.forEach { entry ->
                require(filesystem.directory(entry.first) == initial.getValue(entry.first))
                sameDirectory(entry)
            }
            val named = Files.readAttributes(path, PosixFileAttributes::class.java, NOFOLLOW_LINKS)
            val file = requireNotNull(current.getFileAttributeView(relative.fileName,
                PosixFileAttributeView::class.java, NOFOLLOW_LINKS))
            val original = file.readAttributes()
            require(original.isRegularFile && original.fileKey() != null && original.fileKey() == named.fileKey() &&
                original.owner() == named.owner() && original.permissions() == named.permissions() &&
                attribute(path, "uid") == owner && attribute(path, "nlink") == 1L &&
                attribute(path, "mode").toInt().and(18) == 0 &&
                (!executable || Files.isExecutable(path)))
            val bytes = current.newByteChannel(relative.fileName,
                setOf<java.nio.file.OpenOption>(READ, NOFOLLOW_LINKS)).use { channel ->
                val length = channel.size()
                require(length in 0..limit.toLong())
                val buffer = ByteBuffer.allocate(length.toInt())
                while (buffer.hasRemaining()) require(channel.read(buffer) > 0)
                require(channel.size() == length)
                buffer.array()
            }
            val after = Files.readAttributes(path, PosixFileAttributes::class.java, NOFOLLOW_LINKS)
            val heldAfter = file.readAttributes()
            require(heldAfter.fileKey() == original.fileKey() && heldAfter.fileKey() == after.fileKey() &&
                heldAfter.permissions() == original.permissions() && heldAfter.owner() == original.owner() &&
                path.toRealPath() == path && attribute(path, "uid") == owner &&
                attribute(path, "nlink") == 1L && attribute(path, "mode").toInt().and(18) == 0)
            held.forEach { entry ->
                require(filesystem.directory(entry.first) == initial.getValue(entry.first))
                sameDirectory(entry)
            }
            return bytes
        } finally { held.asReversed().forEach { it.second.close() } }
    }
    /** Catalog/source pins retain source ownership/modes, never private-control mode assumptions. */
    fun readPinnedDocument(pin: ActivationInput, maximum: Int = 4194304): ByteArray {
        require(maximum in 1..16777216 && hex.matches(pin.sha256))
        val path = Path.of(pin.path)
        require(path.isAbsolute && path.normalize() == path && path.parent != null)
        val parent = filesystem.directory(path.parent)
        require(safe(parent))
        return filesystem.source(path.parent, path, parent.owner, maximum, false).also {
            require(it.size in 1..maximum && sha(it) == pin.sha256 && filesystem.directory(path.parent) == parent)
        }
    }
    fun readPinnedSource(suite: QualificationSuitePin, name: String): ByteArray {
        val relative = Path.of(name)
        require(!relative.isAbsolute && relative.normalize() == relative &&
            relative.none { it.toString() in setOf(".", "..") } && name in suite.runnerHashes)
        val root = filesystem.directory(suite.root)
        require(safe(root))
        return filesystem.source(suite.root, suite.root.resolve(relative), root.owner, 16777216, false).also {
            require(sha(it) == suite.runnerHashes.getValue(name) && filesystem.directory(suite.root) == root)
        }
    }
    fun read(scope: QualificationControlScope): QualificationSuitePin = read(scope, filesystem)
    /** All selections are derived from the requested scope; the seam substitutes bytes/identities,
     * never a different path, manifest closure or requirements policy. */
    internal fun read(scope: QualificationControlScope, reader: Reader): QualificationSuitePin {
        require(scope.schemaVersion == 1 && scope.operation in setOf("execute-staged", "execute-qualified") &&
            scope.journalFile.let { Path.of(it).isAbsolute && Path.of(it).normalize() == Path.of(it) })
        val bindingPath = Path.of(scope.binding.path)
        require(bindingPath.isAbsolute && bindingPath.normalize() == bindingPath && hex.matches(scope.binding.sha256))
        val bindingBytes = reader.protected(bindingPath, 1048576)
        require(bindingBytes.size in 1..1048576 && sha(bindingBytes) == scope.binding.sha256)
        val binding = json.parseToJsonElement(bindingBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val trial = binding.getValue("trialId").jsonPrimitive.content
        val phase = binding.getValue("phase").jsonPrimitive.content
        require(trial.matches(Regex("[a-z][a-z0-9-]{0,63}")) && phase in setOf("INSTALL", "RESTORE") &&
            binding.getValue("generationId").jsonPrimitive.content == scope.generationId)
        val candidate = binding.getValue("candidate").jsonObject.getValue("acceptanceSha256").jsonPrimitive.content
        require(hex.matches(candidate))
        val journal = Path.of(scope.journalFile)
        val stem = "${if (scope.operation == "execute-staged") "staged" else "phase"}-$trial-${phase.lowercase()}"
        val definitionPath = journal.parent.resolve("$stem.definition-v2.json")
        val definitionBytes = reader.protected(definitionPath, 4194304)
        require(definitionBytes.size in 1..4194304 && sha(definitionBytes) == candidate)
        val definitionText = definitionBytes.decodeToString(throwOnInvalidSequence = true)
        val definition = json.parseToJsonElement(definitionText).jsonObject
        require(definitionText == definition.toString() &&
            definition.keys.toList() == listOf("inventorySha256", "manifestSha256", "runnerHashes", "requirementsSha256") &&
            hex.matches(definition.getValue("requirementsSha256").jsonPrimitive.content))
        val manifestPath = Path.of(scope.manifest.path)
        require(manifestPath.isAbsolute && manifestPath.normalize() == manifestPath &&
            manifestPath.nameCount >= 3 && manifestPath.parent != null &&
            hex.matches(scope.manifest.sha256) && hex.matches(scope.products.sha256))
        val root = manifestPath.parent.parent
        val rootIdentity = reader.directory(root)
        require(safe(rootIdentity))
        val directories = linkedMapOf(root to rootIdentity)
        fun guard(path: Path) {
            require(path.isAbsolute && path.normalize() == path && path.startsWith(root) && path != root)
            var parent = path.parent
            while (parent != null && parent.startsWith(root)) {
                val identity = reader.directory(parent)
                require(identity.owner == rootIdentity.owner && safe(identity) &&
                    (directories[parent] ?: identity) == identity)
                directories[parent] = identity
                if (parent == root) break
                parent = parent.parent
            }
        }
        fun source(path: Path, limit: Int, execute: Boolean = false, allowEmpty: Boolean = false): ByteArray {
            guard(path)
            val data = reader.source(root, path, rootIdentity.owner, limit, execute)
            require(data.size in (if (allowEmpty) 0 else 1)..limit)
            guard(path)
            return data
        }
        val productsPath = Path.of(scope.products.path)
        require(productsPath.isAbsolute && productsPath.normalize() == productsPath && productsPath.parent != null)
        // Products are the separately pinned platform inventory, NOT a suite-root mount.
        val inventoryParent = productsPath.parent
        val inventoryIdentity = reader.directory(inventoryParent)
        require(safe(inventoryIdentity))
        val inventory = reader.source(inventoryParent, productsPath, inventoryIdentity.owner, 4194304, false)
        require(inventory.size in 1..4194304 && reader.directory(inventoryParent) == inventoryIdentity)
        val manifest = source(manifestPath, 4194304)
        require(sha(inventory) == scope.products.sha256 && sha(manifest) == scope.manifest.sha256 &&
            definition.getValue("inventorySha256").jsonPrimitive.content == scope.products.sha256 &&
            definition.getValue("manifestSha256").jsonPrimitive.content == scope.manifest.sha256)
        val declared = json.parseToJsonElement(manifest.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(declared.getValue("schemaVersion").jsonPrimitive.int == 2)
        val cases = declared.getValue("cases").jsonArray
        require(cases.size in 1..256)
        val runners = mutableSetOf<String>()
        val executable = mutableSetOf<String>()
        fun name(value: JsonElement): String {
            val file = value.jsonPrimitive.content
            val path = Path.of(file)
            require(file.matches(Regex("(?:cases|runners|scripts)/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")) &&
                !path.isAbsolute && path.normalize() == path && path.none { it.toString() in setOf(".", "..") } &&
                path.nameCount <= 8)
            return file
        }
        cases.forEach { entry ->
            val row = entry.jsonObject
            val runner = name(row.getValue("runner"))
            executable += runner; runners += runner
            row["adapter"]?.takeUnless { it == JsonNull }?.let { runners += name(it) }
            val files = row["runnerFiles"]?.jsonArray?.map(::name).orEmpty()
            require(files.size == files.toSet().size)
            runners += files
        }
        require(runners.size in 1..2048)
        val hashes = definition.getValue("runnerHashes").jsonObject
        require(hashes.keys.toList() == hashes.keys.sorted() && hashes.keys == runners &&
            hashes.values.all { hex.matches(it.jsonPrimitive.content) })
        val exact = hashes.mapValues { (file, expected) ->
            val bytes = source(root.resolve(file), 16777216, file in executable, allowEmpty = true)
            require(sha(bytes) == expected.jsonPrimitive.content) { "Changed source-suite dependency: $file" }
            expected.jsonPrimitive.content
        }
        directories.forEach { (path, identity) -> require(reader.directory(path) == identity) }
        require(reader.directory(inventoryParent) == inventoryIdentity)
        return QualificationSuitePin(root, ActivationInput(definitionPath.toString(), candidate), exact.toMap())
    }
}
