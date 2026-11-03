package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit

/** Explicit native diagnostic. Unit tests inject results; ordinary unit tasks never invoke the generator. */
object QuadletDryRun {
    private val generator = Path.of("/usr/lib/systemd/system-generators/podman-system-generator")
    private val mode = PosixFilePermissions.fromString("rwx------")

    fun verify(bundle: QuadletBundle): Int = verify(bundle, ::execute)

    internal fun verify(bundle: QuadletBundle,
        invoke: (List<String>, Path?, Int) -> RuntimeCommandResult): Int {
        val version = invoke(listOf("--version"), null, 5)
        require(version.exitCode == 0 && version.output.trim() == "5.4.2") { "Podman 5.4.2 Quadlet required" }
        val temp = Files.createTempDirectory("p0v3-quadlet-dryrun-", PosixFilePermissions.asFileAttribute(mode))
        try {
            val units = Files.createDirectory(temp.resolve("units"))
            bundle.files.forEach { (name, text) ->
                require(name.matches(Regex("p0v3-[a-z0-9-]+\\.(container|volume|network|timer)"))) { "Unsafe Quadlet name" }
                Files.writeString(units.resolve(name), text)
            }
            val result = invoke(listOf("--dryrun"), units, 20)
            require(result.output.toByteArray().size <= 2_000_000) { "Unbounded generator output" }
            require(result.exitCode == 0) { "Quadlet generator failed" }
            PrivateQuadlets.verifyGeneratorOutput(bundle, result.output)
            return bundle.files.size
        } finally {
            Files.walk(temp).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private fun execute(args: List<String>, units: Path?, timeout: Int): RuntimeCommandResult {
        require(Files.isExecutable(generator)) { "Podman Quadlet generator unavailable" }
        val log = Files.createTempFile("p0v3-quadlet-output-", ".log",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        try {
            val process = ProcessBuilder(listOf(generator.toString()) + args).redirectErrorStream(true)
                .redirectOutput(log.toFile()).apply {
                    environment().clear()
                    environment()["PATH"] = "/usr/bin:/bin"
                    environment()["LANG"] = "C.UTF-8"
                    if (units != null) environment()["QUADLET_UNIT_DIRS"] = units.toString()
                }.start()
            try {
                check(process.waitFor(timeout.toLong(), TimeUnit.SECONDS)) { "Quadlet generator timeout" }
                require(Files.size(log) <= 2_000_000) { "Unbounded generator output" }
                return RuntimeCommandResult(process.exitValue(), Files.readString(log))
            } catch (error: InterruptedException) {
                Thread.currentThread().interrupt()
                throw error
            } finally {
                if (process.isAlive) process.destroyForcibly()
            }
        } finally { Files.deleteIfExists(log) }
    }
}
