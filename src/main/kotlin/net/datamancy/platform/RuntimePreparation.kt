package net.datamancy.platform

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

internal object RuntimePreparation {
    fun password(): String {
        val bytes = ByteArray(32); SecureRandom().nextBytes(bytes)
        return java.util.HexFormat.of().formatHex(bytes)
    }
    fun prepare(spec: PrivateDeploymentSpec, base: Path, generate: () -> Map<String,String>): Path =
        prepare(spec,base,null,generate)
    fun prepare(spec: PrivateDeploymentSpec, base: Path,
        admittedPriorLockOnly: ActivationInput?, generate: () -> Map<String, String>): Path {
        PrivateDeployment.validate(spec)
        if (spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2) {
            val identity = com.sun.security.auth.module.UnixSystem()
            require(spec.fragmentBinding?.controllerSha256 != null &&
                spec.fragmentBinding.controllerUid?.toLong() == identity.uid &&
                spec.fragmentBinding.controllerGid?.toLong() == identity.gid) {
                "Quadlet preparation requires the pinned controller and actual non-root owner identity"
            }
        }
        val mode = PosixFilePermissions.fromString("rwx------")
        fun directory(path: Path) {
            require(path.isAbsolute && path.normalize() == path && path.parent.toRealPath() == path.parent)
            if (!Files.exists(path, NOFOLLOW_LINKS)) Files.createDirectory(path, PosixFilePermissions.asFileAttribute(mode))
            require(Files.isDirectory(path, NOFOLLOW_LINKS) && path.toRealPath() == path && Files.getPosixFilePermissions(path) == mode &&
                Files.getAttribute(path, "unix:uid") == com.sun.security.auth.module.UnixSystem().uid.toInt()) { "Unowned runtime preparation directory" }
        }
        directory(base)
        val path = base.resolve("${spec.name}.json")
        val root = base.resolve(spec.name)
        val encoded = Json.encodeToString(spec)
        val expected = (spec.processes.mapNotNull { it.environmentFile } + spec.processes.flatMap { p -> p.files.map { it.file } }).toSet()
        return PrivateDeployment.withPreparationNamespace(spec.name, base) { freshlyClaimed ->
            if (Files.exists(path, NOFOLLOW_LINKS)) {
                require(!freshlyClaimed && ReleaseLocks.privateBytes(path).decodeToString() == encoded) {
                    "Runtime recipe changed; transactional update required"
                }
                directory(root)
                expected.forEach { ReleaseLocks.privateBytes(root.resolve(it)) }
                path
            } else {
                if (!freshlyClaimed) {
                    val prior = requireNotNull(admittedPriorLockOnly) {
                        "Incomplete runtime preparation; reconcile instead of regenerating credentials"
                    }
                    require(base == PrivateDeployment.BASE && spec.name == "q-5962a9fda75b-v2")
                    val generationRoot = GenerationRuntime.BASE.resolve("q-5962a9fda75b")
                    GenerationCiMemberPreEffectContinuation.verify(generationRoot,prior,base.resolve(spec.name))
                    require(Files.list(base.resolve(spec.name)).use { it.map { entry -> entry.fileName.toString() }.toList() } ==
                        listOf("runtime.lock") &&
                        Files.exists(generationRoot.resolve(GenerationCiMemberPreEffectContinuation.INTENT),NOFOLLOW_LINKS) &&
                        !Files.exists(generationRoot.resolve(GenerationCiMemberPreEffectContinuation.RESULT),NOFOLLOW_LINKS)) {
                        "Only the independently verified original lock-only member may complete"
                    }
                } else require(admittedPriorLockOnly == null) { "Fresh member cannot claim a foreign partial-input disposition" }
                // The parent namespace gate AND exact member runtime.lock are held from
                // before the atomic root claim through entropy generation and manifest fsync.
                // A no-target census cannot mistake this unfinished root for lock-only absence.
                directory(root)
                val inputs = generate()
                require(inputs.keys == expected && inputs.values.all { it.toByteArray().size in 1..1048576 }) {
                    "Runtime input set mismatch"
                }
                fun write(target: Path, text: String) {
                    FileChannel.open(target, setOf(CREATE_NEW, WRITE), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))).use {
                        val data = ByteBuffer.wrap(text.toByteArray()); while (data.hasRemaining()) it.write(data); it.force(true)
                    }
                }
                inputs.forEach { (file, text) -> write(root.resolve(file), text) }
                FileChannel.open(root, READ).use { it.force(true) }
                write(path, encoded)
                FileChannel.open(base, READ).use { it.force(true) }
                path
            }
        }
    }
}
