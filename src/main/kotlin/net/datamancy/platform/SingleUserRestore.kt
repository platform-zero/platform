package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.security.MessageDigest
import java.util.HexFormat

/** Recovery for quiesced, single-daemon UID-1000 applications. Not a database/cluster backup adapter. */
internal object SingleUserRestore {
    fun inputNames(source: PrivateDeploymentSpec): Set<String> =
        (source.processes.mapNotNull { it.environmentFile } + source.processes.flatMap { p -> p.files.map { it.file } }).toSet()

    fun spec(source: PrivateDeploymentSpec, inventory: AcquiredInventory, name: String, sourceHash: String): PrivateDeploymentSpec {
        PrivateDeployment.validate(source)
        require(source.name != name && sourceHash.matches(Regex("[a-f0-9]{64}")))
        require(source.volumes.isNotEmpty() && source.volumes.all { it.userId == 1000 })
        require(source.processes.all { p -> p.userId == 1000 && p.groupId == 1000 && p.capabilities.isEmpty() &&
            inventory.images.any { it.pinnedImage == p.image && it.imageId == p.imageId && it.os == "linux" && it.architecture == "amd64" } })
        val daemon = source.processes.single { !it.oneShot }
        require(daemon.id != "restore-check")
        val check = RuntimeProcess("restore-check", daemon.image, daemon.imageId, 1000, oneShot = true,
            entrypoint = "/bin/sh", apparmorProfile = "p0v3-private-v1",
            volumes = source.volumes.map { RuntimeMount(it.id, "/restored/${it.id}") },
            files = inputNames(source).sorted().map { RuntimeFile(it, "/run/secrets/source-$it") },
            command = listOf("-ec", source.volumes.joinToString("; ") {
                "test ! -e /restored/${it.id}/.restore-in-progress; grep -qx '$sourceHash' /restored/${it.id}/.p0v3-restore-complete"
            }))
        return source.copy(name = name, processes = listOf(check, daemon.copy(dependencies = listOf(check.id))))
            .also { PrivateDeployment.validate(it) }
    }

    fun prepare(inventory: AcquiredInventory, recovered: Path, name: String, base: Path = PrivateDeployment.BASE): Path {
        require(recovered.isAbsolute && recovered.normalize() == recovered && recovered.toRealPath() == recovered)
        val sourcePath = recovered.resolve("source-spec.json")
        val bytes = ReleaseLocks.privateBytes(sourcePath)
        val source = PrivateDeployment.read(sourcePath)
        val hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes))
        val target = spec(source, inventory, name, hash)
        val inputs = inputNames(source).associateWith { ReleaseLocks.privateBytes(recovered.resolve(it)).decodeToString(throwOnInvalidSequence = true) }
        if (Files.exists(base.resolve("$name.json"), NOFOLLOW_LINKS)) {
            inputs.forEach { (file, content) -> require(ReleaseLocks.privateBytes(base.resolve(name).resolve(file)).contentEquals(content.toByteArray())) {
                "Recovered inputs changed; refusing replacement"
            } }
        }
        return RuntimePreparation.prepare(target, base) { inputs }
    }
}
