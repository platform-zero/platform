package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

/** Only declared, nonsecret source files enter the client. Neither the checkout nor
 * the installed controller distribution is a qualification client's mount authority. */
@Serializable internal data class QualificationClientSuite(val definition: ActivationInput,
    val manifestSha256: String, val files: Map<String, String>)

internal object QualificationClientSuites {
    private val hash = Regex("[a-f0-9]{64}")
    private val json = Json { ignoreUnknownKeys = false }
    private fun digest(bytes: ByteArray) = ReleaseLocks.sha256(bytes)
    private fun document(bytes: ByteArray) = json.parseToJsonElement(
        bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
    private fun relative(name: String): Path = Path.of(name).also {
        require(name.matches(Regex("(?:cases|scripts|runners)/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")) &&
            !it.isAbsolute && it.normalize() == it && it.none { part -> part.toString() in setOf(".", "..") })
    }
    internal fun selected(manifest: JsonObject, service: String, surface: String,
        variant: String, journey: String): JsonObject {
        require(manifest.getValue("schemaVersion").jsonPrimitive.int == 2)
        return manifest.getValue("cases").jsonArray.map { it.jsonObject }.single { row ->
            listOf("serviceId" to service, "surface" to surface, "variant" to variant, "journey" to journey)
                .all { (key, value) -> row.getValue(key).jsonPrimitive.content == value }
        }.also { require(it.getValue("runner").jsonPrimitive.content == "scripts/qualified-runner.py") }
    }
    internal fun files(definition: JsonObject): Set<String> = buildSet {
        add(definition.getValue("runner").jsonPrimitive.content)
        definition["adapter"]?.takeUnless { it == JsonNull }?.let { add(it.jsonPrimitive.content) }
        definition["runnerFiles"]?.jsonArray?.forEach { add(it.jsonPrimitive.content) }
    }.also { require(it.size in 1..2048); it.forEach(::relative) }

    fun destination(generation: String, invocation: String): Path {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
            invocation.matches(Regex("case-[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}")))
        return GenerationRuntime.BASE.resolve(generation).resolve("qualification-client-suites/$invocation")
    }
    /** CREATE_NEW whole per-case projection. Failure retains the partial tree, never adopts it. */
    fun stage(scope: QualificationControlScope, invocation: String, suite: QualificationSuitePin,
        definition: JsonObject): Pair<Path, QualificationClientSuite> {
        require(suite == QualificationSuiteClosure.read(scope))
        val manifest = QualificationSuiteClosure.readPinnedDocument(scope.manifest)
        require(digest(manifest) == scope.manifest.sha256)
        require(selected(document(manifest), definition.getValue("serviceId").jsonPrimitive.content,
            definition.getValue("surface").jsonPrimitive.content, definition.getValue("variant").jsonPrimitive.content,
            definition.getValue("journey").jsonPrimitive.content) == definition)
        val chosen = files(definition)
        val root = destination(scope.generationId, invocation)
        privateControlDirectory(root.parent)
        Files.createDirectory(root, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(root.parent)
        val hashes = linkedMapOf<String, String>()
        for (name in (chosen + "cases/manifest.json").sorted()) {
            val bytes = if (name == "cases/manifest.json") manifest else
                QualificationSuiteClosure.readPinnedSource(suite, name)
            val sha = digest(bytes)
            if (name in chosen) require(suite.runnerHashes.getValue(name) == sha)
            val target = root.resolve(relative(name))
            var directory = root
            for (part in root.relativize(target.parent)) {
                if (part.toString().isEmpty()) continue
                val child = directory.resolve(part)
                if (!Files.exists(child, NOFOLLOW_LINKS)) {
                    Files.createDirectory(child, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwxr-xr-x")))
                    ReleasePrivateFiles.sync(directory)
                }
                require(Files.isDirectory(child, NOFOLLOW_LINKS) && child.toRealPath() == child)
                directory = child
            }
            val executable = name == definition.getValue("runner").jsonPrimitive.content ||
                name != "cases/manifest.json" && Files.isExecutable(suite.root.resolve(name))
            val mode = PosixFilePermissions.fromString(if (executable) "rwxr-xr-x" else "rw-r--r--")
            FileChannel.open(target, setOf(CREATE_NEW, WRITE, NOFOLLOW_LINKS),
                PosixFilePermissions.asFileAttribute(mode)).use { file ->
                val buffer = ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) file.write(buffer)
                file.force(true)
            }
            ReleasePrivateFiles.sync(target.parent)
            hashes[name] = sha
        }
        return root to QualificationClientSuite(suite.definition, scope.manifest.sha256, hashes.toMap())
    }
    /** Pure preimage contract, shared with tests. Candidate hash anchors the complete source
     * definition; the client receives only this case's exact transitive subset + manifest. */
    internal fun verifyDefinition(closure: QualificationClientSuite, intent: JsonObject,
        definitionBytes: ByteArray, manifestBytes: ByteArray): JsonObject {
        val candidate = intent.getValue("binding").jsonObject.getValue("candidate").jsonObject
            .getValue("acceptanceSha256").jsonPrimitive.content
        require(hash.matches(candidate) && closure.definition.sha256 == candidate && digest(definitionBytes) == candidate &&
            hash.matches(closure.manifestSha256) && digest(manifestBytes) == closure.manifestSha256)
        val preimage = document(definitionBytes)
        require(preimage.keys.toList() == listOf("inventorySha256", "manifestSha256", "runnerHashes", "requirementsSha256") &&
            preimage.toString().encodeToByteArray().contentEquals(definitionBytes) &&
            preimage.getValue("manifestSha256").jsonPrimitive.content == closure.manifestSha256 &&
            intent.getValue("manifestSha256").jsonPrimitive.content == closure.manifestSha256 &&
            preimage.getValue("inventorySha256") == intent.getValue("inventorySha256") &&
            hash.matches(preimage.getValue("requirementsSha256").jsonPrimitive.content))
        val selected = selected(document(manifestBytes), intent.getValue("serviceId").jsonPrimitive.content,
            intent.getValue("surface").jsonPrimitive.content, intent.getValue("variant").jsonPrimitive.content,
            intent.getValue("journey").jsonPrimitive.content)
        val declared = files(selected)
        val all = preimage.getValue("runnerHashes").jsonObject
        require(closure.files.keys == declared + "cases/manifest.json" &&
            closure.files.values.all(hash::matches) && closure.files.getValue("cases/manifest.json") == closure.manifestSha256 &&
            declared.all { closure.files[it] == all.getValue(it).jsonPrimitive.content } &&
            intent.getValue("runnerSha256").jsonPrimitive.content == closure.files.getValue("scripts/qualified-runner.py"))
        return selected
    }
    fun verify(request: QualificationClientRequest, intent: JsonObject) {
        val closure = requireNotNull(request.suiteClosure)
        val root = destination(request.generationId, request.invocationId)
        require(Path.of(request.suiteDirectory) == root)
        ReleasePrivateFiles.directory(root)
        val uid = UnixSystem().uid
        fun read(name: String, maximum: Int): ByteArray {
            val path = root.resolve(relative(name))
            require(path.toRealPath() == path && Files.isRegularFile(path, NOFOLLOW_LINKS) &&
                (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == uid &&
                (Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong() == 1L &&
                Files.getPosixFilePermissions(path, NOFOLLOW_LINKS) in setOf(
                    PosixFilePermissions.fromString("rw-r--r--"), PosixFilePermissions.fromString("rwxr-xr-x")))
            return QualificationSuiteClosure.readPinnedSource(
                QualificationSuitePin(root, closure.definition, closure.files), name).also {
                require(it.size <= maximum && digest(it) == closure.files.getValue(name))
            }
        }
        val definition = ReleasePrivateFiles.read(Path.of(closure.definition.path), 4194304)
        val row = verifyDefinition(closure, intent, definition, read("cases/manifest.json", 4194304))
        require(request.adapterSha256 == closure.files.getValue(row.getValue("adapter").jsonPrimitive.content))
        val expectedDirectories = closure.files.keys.flatMap { name ->
            val result = mutableListOf<Path>(); var parent = relative(name).parent
            while (parent != null) { result.add(root.resolve(parent)); parent = parent.parent }
            result
        }.toSet() + root
        Files.walk(root).use { stream ->
            val entries = stream.limit(20001).toList()
            require(entries.size <= 20000 && entries.toSet() == expectedDirectories + closure.files.keys.map { root.resolve(relative(it)) })
            expectedDirectories.forEach { directory ->
                require(directory.toRealPath() == directory && Files.isDirectory(directory, NOFOLLOW_LINKS) &&
                    (Files.getAttribute(directory, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == uid &&
                    Files.getPosixFilePermissions(directory, NOFOLLOW_LINKS) == PosixFilePermissions.fromString(
                        if (directory == root) "rwx------" else "rwxr-xr-x"))
            }
        }
        closure.files.keys.forEach { read(it, 16777216) }
        require(Files.isExecutable(root.resolve("scripts/qualified-runner.py")))
    }
}
