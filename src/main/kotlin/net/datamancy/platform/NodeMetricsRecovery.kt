package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path

/** Exact stopped metrics/TSDB recovery, not a generic filesystem or production host backup adapter. */
internal object NodeMetricsRecovery {
    fun spec(source: PrivateDeploymentSpec, inventory: AcquiredInventory, name: String, sourceHash: String): PrivateDeploymentSpec {
        require(source == NodeMetricsRuntime.spec(inventory, source.name)) { "Unsupported metrics source recipe" }
        require(source.name != name && sourceHash.matches(Regex("[a-f0-9]{64}")))
        val checks = source.volumes.joinToString("\n") { volume ->
            val root = "/recovered/${volume.id}"
            "test ! -e $root/.restore-in-progress; test ! -L $root/.restore-in-progress; " +
                "test -f $root/.p0v3-restore-complete; test ! -L $root/.p0v3-restore-complete; " +
                "test \"${'$'}(stat -c %s $root/.p0v3-restore-complete)\" = 65; " +
                "grep -qx '$sourceHash' $root/.p0v3-restore-complete"
        }
        return source.copy(name = name, processes = source.processes.map { process ->
            if (process.id != "metrics-init") process else process.copy(
                volumes = source.volumes.map { RuntimeMount(it.id, "/recovered/${it.id}") },
                command = listOf("-ec", checks + "\ntest -f /recovered/metrics/fixture.prom; test ! -L /recovered/metrics/fixture.prom\ntest -d /recovered/prometheus/wal; test ! -L /recovered/prometheus/wal"))
        }).also { PrivateDeployment.validate(it) }
    }
    fun prepare(inventory: AcquiredInventory, recovered: Path, name: String, base: Path = PrivateDeployment.BASE): Path {
        require(recovered.isAbsolute && recovered.normalize() == recovered && recovered.toRealPath() == recovered)
        val sourcePath = recovered.resolve("source-spec.json")
        val sourceBytes = ReleaseLocks.privateBytes(sourcePath)
        val source = PrivateDeployment.read(sourcePath)
        val target = spec(source, inventory, name, ReleaseLocks.sha256(sourceBytes))
        val inputs = SingleUserRestore.inputNames(source).associateWith {
            ReleaseLocks.privateBytes(recovered.resolve(it)).decodeToString(throwOnInvalidSequence = true)
        }
        if (Files.exists(base.resolve("$name.json"), NOFOLLOW_LINKS)) inputs.forEach { (file, contents) ->
            require(ReleaseLocks.privateBytes(base.resolve(name).resolve(file)).contentEquals(contents.toByteArray())) { "Recovered metrics inputs changed; refusing replacement" }
        }
        return RuntimePreparation.prepare(target, base) { inputs }
    }
}
