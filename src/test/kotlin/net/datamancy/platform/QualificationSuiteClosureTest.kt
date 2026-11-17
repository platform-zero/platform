package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.json.*
import kotlin.test.*

/** Byte/identity fixture only. No controller, credentials or installed suite are created. */
class QualificationSuiteClosureTest {
    private val json = Json { encodeDefaults = true }
    private val root = Path.of("/synthetic-suite")
    private val manifestPath = root.resolve("cases/manifest.json")
    private val inventoryPath = Path.of("/synthetic-platform/src/main/resources/products.json")
    private val bindingPath = Path.of("/synthetic-control/binding.json")
    private val journal = "/synthetic-control/qualification.jsonl"
    private fun sha(bytes: ByteArray) = ReleaseLocks.sha256(bytes)
    private fun raw(value: JsonElement) = value.toString().encodeToByteArray()
    private class FixtureReader(val files: MutableMap<Path, ByteArray>, val dirs: MutableMap<Path,
        QualificationSuiteClosure.DirectoryIdentity>) : QualificationSuiteClosure.Reader {
        var changeAfter: Path? = null
        override fun protected(path: Path, limit: Int): ByteArray = files.getValue(path).also {
            require(it.size in 1..limit)
        }
        override fun directory(path: Path) = dirs.getValue(path)
        override fun source(root: Path, path: Path, owner: Long, limit: Int, executable: Boolean): ByteArray {
            require(root == Path.of("/synthetic-suite") || root == Path.of("/synthetic-platform/src/main/resources"))
            require(owner in setOf(0L, UnixSystem().uid) && path in files)
            val bytes = files.getValue(path)
            require(bytes.size <= limit)
            if (path == changeAfter) dirs[root] = dirs.getValue(root).copy(inode = 99)
            return bytes
        }
    }
    private data class Fixture(val scope: QualificationControlScope, val reader: FixtureReader,
        val files: Map<String, String>) {
        fun read() = QualificationSuiteClosure.read(scope, reader)
    }
    private fun fixture(extra: Boolean = false, dependency: String = "runners/child.py",
        emptyDependency: Boolean = false): Fixture {
        val sources = sortedMapOf("scripts/qualified-runner.py" to "#!/usr/bin/python3\n",
            "runners/native.py" to "from child import read\n", "runners/child.py" to
                if (emptyDependency) "" else "def read(): return 1\n")
        val inventory = raw(buildJsonObject { put("schemaVersion", 1); put("products", buildJsonArray { add("unit") }) })
        val manifest = raw(buildJsonObject {
            put("schemaVersion", 2)
            put("cases", buildJsonArray { add(buildJsonObject {
                put("runner", "scripts/qualified-runner.py")
                put("adapter", "runners/native.py")
                put("runnerFiles", buildJsonArray { add(dependency) })
            }) })
        })
        val hashes = sources.mapValues { sha(it.value.encodeToByteArray()) }.toSortedMap().toMutableMap()
        if (extra) hashes["runners/foreign.py"] = "a".repeat(64)
        val definition = raw(buildJsonObject {
            put("inventorySha256", sha(inventory)); put("manifestSha256", sha(manifest))
            put("runnerHashes", buildJsonObject { hashes.toSortedMap().forEach { (name, digest) -> put(name, digest) } })
            put("requirementsSha256", "d".repeat(64)) // The raw existing preimage is the candidate pin.
        })
        val candidate = sha(definition)
        val binding = raw(buildJsonObject {
            put("trialId", "trial-one"); put("generationId", "q-111111111111"); put("phase", "RESTORE")
            put("candidate", buildJsonObject { put("acceptanceSha256", candidate) })
        })
        val files = mutableMapOf(inventoryPath to inventory, manifestPath to manifest,
            bindingPath to binding, Path.of("/synthetic-control/phase-trial-one-restore.definition-v2.json") to definition)
        sources.forEach { (name, value) -> files[root.resolve(name)] = value.encodeToByteArray() }
        val identity = QualificationSuiteClosure.DirectoryIdentity(UnixSystem().uid, 3, 4, 493)
        val dirs = mutableMapOf(root to identity,
            inventoryPath.parent to identity.copy(owner = 0L, inode = 8),
            root.resolve("cases") to identity.copy(inode = 5),
            root.resolve("runners") to identity.copy(inode = 6),
            root.resolve("scripts") to identity.copy(inode = 7))
        val scope = QualificationControlScope(suiteId = "b".repeat(24), generationId = "q-111111111111",
            bundleSha256 = "c".repeat(64), operation = "execute-qualified", controllerSha256 = "a".repeat(64),
            products = ActivationInput(inventoryPath.toString(), sha(inventory)),
            manifest = ActivationInput(manifestPath.toString(), sha(manifest)),
            binding = ActivationInput(bindingPath.toString(), sha(binding)), journalFile = journal,
            journalHeadSha256 = "e".repeat(64), artifactRoot = "/synthetic-artifacts", contexts = null)
        return Fixture(scope, FixtureReader(files, dirs), hashes)
    }
    @Test fun `actual candidate pins exact full manifest runner adapter and transitive files`() {
        val f = fixture()
        val before = f.reader.files.toMap()
        val actual = f.read()
        assertEquals(root, actual.root)
        assertEquals(f.files, actual.runnerHashes)
        assertEquals(f.scope.binding.path.substringBeforeLast('/') + "/phase-trial-one-restore.definition-v2.json",
            actual.definition.path)
        assertEquals(before, f.reader.files)
        val empty = fixture(emptyDependency = true)
        assertEquals(ReleaseLocks.sha256(byteArrayOf()), empty.read().runnerHashes.getValue("runners/child.py"))
    }
    @Test fun `missing extra changed or foreign candidate fails without accepting partial closure`() {
        assertFails { fixture(extra = true).read() }
        val f = fixture()
        val child = root.resolve("runners/child.py")
        val old = f.reader.files.remove(child)
        assertFails { f.read() }
        f.reader.files[child] = requireNotNull(old)
        f.reader.files[child] = "changed imported dependency".encodeToByteArray()
        assertFails { f.read() }
        f.reader.files[child] = old
        val originalInventory = f.reader.files.getValue(inventoryPath)
        f.reader.files[inventoryPath] = "other inventory".encodeToByteArray()
        assertFails { f.read() }
        f.reader.files[inventoryPath] = originalInventory
        val untrusted = fixture()
        untrusted.reader.dirs[inventoryPath.parent] = untrusted.reader.dirs.getValue(inventoryPath.parent)
            .copy(owner = 987654L)
        assertFails { untrusted.read() }
        val foreign = f.scope.copy(operation = "execute-staged")
        assertFails { QualificationSuiteClosure.read(foreign, f.reader) }
        val preimage = Path.of("/synthetic-control/phase-trial-one-restore.definition-v2.json")
        val original = f.reader.files.getValue(preimage)
        f.reader.files[preimage] = original + byteArrayOf(32)
        assertFails { f.read() }
        f.reader.files[preimage] = original
        val changedScope = f.scope.copy(binding = f.scope.binding.copy(sha256 = "f".repeat(64)))
        assertFails { QualificationSuiteClosure.read(changedScope, f.reader) }
    }
    @Test fun `real held descriptor rejects byte identical root intermediate or symlink replacement`() {
        fun replacement(kind: String) {
            val temp = Files.createTempDirectory("suite-held-source-")
            val dirMode = PosixFilePermissions.fromString("rwx------")
            try {
                val root = Files.createDirectory(temp.resolve("suite"))
                val twin = Files.createDirectory(temp.resolve("twin"))
                for (directory in listOf(root, twin)) {
                    Files.setPosixFilePermissions(directory, dirMode)
                    val child = Files.createDirectory(directory.resolve("runners"))
                    Files.setPosixFilePermissions(child, dirMode)
                    Files.writeString(child.resolve("native.py"), "identical original bytes\n")
                }
                val file = root.resolve("runners/native.py")
                assertFails {
                    QualificationSuiteClosure.sourceFileForTest(root, file, 65536) {
                        when (kind) {
                            "root" -> {
                                Files.move(root, temp.resolve("moved-root"))
                                Files.move(twin, root)
                            }
                            "intermediate" -> {
                                Files.move(root.resolve("runners"), temp.resolve("moved-runners"))
                                Files.move(twin.resolve("runners"), root.resolve("runners"))
                            }
                            "symlink" -> {
                                Files.move(root, temp.resolve("moved-root"))
                                Files.createSymbolicLink(root, twin)
                            }
                            else -> error("Unknown synthetic replacement")
                        }
                    }
                }
            } finally {
                Files.walk(temp).use { walk -> walk.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
            }
        }
        for (kind in listOf("root", "intermediate", "symlink")) replacement(kind)
    }
    @Test fun `path escapes symlinks or detached directory identity never become the source suite`() {
        val f = fixture()
        f.reader.changeAfter = root.resolve("runners/child.py")
        assertFails { f.read() }
        val other = fixture()
        other.reader.dirs.remove(root.resolve("runners"))
        assertFails { other.read() }
        val thirdParty = fixture()
        thirdParty.reader.dirs[root] = thirdParty.reader.dirs.getValue(root).copy(owner = 987654L)
        assertFails { thirdParty.read() }
        val writable = fixture()
        writable.reader.dirs[root.resolve("runners")] = writable.reader.dirs.getValue(root.resolve("runners"))
            .copy(mode = 511) // world-writable, never source custody
        assertFails { writable.read() }
        // Even a candidate that hashes a malicious relative path is not a path authority.
        assertFails { fixture(dependency = "runners/../other.py").read() }
    }
}
