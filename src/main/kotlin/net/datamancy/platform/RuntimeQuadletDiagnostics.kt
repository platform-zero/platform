package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable

@Serializable internal data class RuntimeQuadletDiagnostic(val generatorVersion: String,
    val services: List<String>, val generatedSha256: String, val lifecycleDropInsRequired: Boolean = true,
    val effectiveInstalledUnitsVerified: Boolean = false, val runtimeAdmitted: Boolean = false)

/** Real generator inspection only. No daemon-reload, image access, installation or startup. */
internal object RuntimeQuadletDiagnostics {
    private val executable = "/usr/lib/systemd/system-generators/podman-system-generator"
    fun verify(spec: PrivateDeploymentSpec, bundle: RuntimeQuadletBundle): RuntimeQuadletDiagnostic = verify(spec, bundle, ::invoke)
    internal fun verify(spec: PrivateDeploymentSpec, bundle: RuntimeQuadletBundle,
        generator: (List<String>, Path?) -> RuntimeCommandResult): RuntimeQuadletDiagnostic {
        require(bundle == RuntimeQuadlets.render(spec)) { "Quadlet bundle differs from its graph" }
        val version = generator(listOf("--version"), null)
        require(version.exitCode == 0 && version.output.trim() == "5.4.2") { "Podman 5.4.2 Quadlet required" }
        val root = Files.createTempDirectory("p0v3-runtime-quadlet-check-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        try {
            bundle.files.filterKeys { it.endsWith(".container") }.forEach { (name, text) -> Files.writeString(root.resolve(name), text) }
            val result = generator(listOf("--dryrun"), root)
            require(result.exitCode == 0 && result.output.toByteArray().size <= 2_000_000)
            audit(spec, result.output)
            return RuntimeQuadletDiagnostic("5.4.2", spec.processes.map { "${RuntimeQuadlets.unit(spec, it)}.service" },
                ReleaseLocks.sha256(result.output.toByteArray()))
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    internal fun audit(spec: PrivateDeploymentSpec, output: String) {
        require(output.toByteArray().size <= 2_000_000 &&
            output.lines().none { it.contains(Regex("(?i)(unsupported key|failed to|error converting|warning:)")) })
        val starts = output.lines().filter { it.startsWith("ExecStart=/usr/bin/podman ") }
        require(starts.size == spec.processes.size) { "Generator omitted or added processes" }
        for (p in spec.processes) {
            val header = "---${RuntimeQuadlets.unit(spec, p)}.service---"
            require(output.split(header).size == 2)
            val section = output.substringAfter(header).substringBefore("\n---")
            val line = section.lines().single { it.startsWith("ExecStart=/usr/bin/podman ") }
            require(line.contains(" ${p.image}") && line.contains("--name p0v3-live-${spec.name}-${p.id} "))
            val options = line.substringBefore(" ${p.image}")
            require(options.contains(" --remote=false ") && options.contains(" --module=${spec.store.module} ") &&
                options.contains(" --root=${spec.store.graph} ") && options.contains(" --runroot=${spec.store.run} ") &&
                options.contains(" --network-config-dir=${spec.store.network} ")) { "Generator selected a foreign store" }
            require(options.indexOf(" --replace=false") > options.indexOf(" --replace ") &&
                options.indexOf(" --rm=false") > options.indexOf(" --rm ") &&
                options.contains(" --pull never ") && !options.contains("--privileged")) { "Unsafe generated lifecycle flags" }
            require(options.contains("--memory=${p.memoryMiB}m") && options.contains("--pids-limit=512") &&
                options.contains("--read-only") && options.contains("--user ${p.userId}:${p.groupId}") &&
                options.contains("--security-opt=no-new-privileges") &&
                (!p.oneShot || options.contains(" --label io.p0v3.initializer-intent=\${P0_INITIALIZER_INTENT} "))) {
                "Generator dropped confinement or original initializer intent label"
            }
            require(section.lines().any { it == "Restart=no" } && section.lines().any { it == "ConditionPathExists=!/" }) {
                "Generator dropped standalone-unit admission guard"
            }
            // The source bundle must always override generated destructive stop defaults at install.
            require(section.lines().any { it.startsWith("ExecStop=") } && section.lines().any { it.startsWith("ExecStopPost=") })
        }
    }

    internal fun invoke(args: List<String>, units: Path?): RuntimeCommandResult {
        val log = Files.createTempFile("p0v3-quadlet-generator-", ".log",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        try {
            val process = ProcessBuilder(listOf(executable) + args).redirectErrorStream(true).redirectOutput(log.toFile()).apply {
                environment().clear(); environment()["PATH"] = "/usr/bin:/bin"; environment()["LANG"] = "C.UTF-8"
                units?.let { environment()["QUADLET_UNIT_DIRS"] = it.toString() }
            }.start()
            try {
                require(process.waitFor(20, TimeUnit.SECONDS)) { "Quadlet generator timed out" }
                require(Files.size(log) <= 2_000_000)
                return RuntimeCommandResult(process.exitValue(), Files.readString(log))
            } catch (interrupted: InterruptedException) {
                Thread.currentThread().interrupt(); throw interrupted
            } finally { if (process.isAlive) { process.destroyForcibly(); process.waitFor() } }
        } finally { Files.deleteIfExists(log) }
    }
}
