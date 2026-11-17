package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** A terminal observation of an interrupted install, NOT its original ACK. No copy,
 * daemon-reload, StartUnit, container effect or invented successful result is permitted.
 * The original intent, installed files and missing result remain intact for custody.
 */
@Serializable internal data class QuadletInstallTerminalObservation(val schemaVersion: Int = 1,
    val generation: String, val member: String, val bundleSha256: String, val originalIntentSha256: String,
    val observedInstalledPolicy: Map<String, String>, val disposition: String = "terminal-incomplete-installed-inactive",
    val originalAcknowledged: Boolean = false, val startAuthorized: Boolean = false)

internal class RuntimeQuadletInstallReconcile(
    private val generationBase: Path = GenerationRuntime.BASE,
    private val sourceRoot: Path = Path.of("/etc/containers/systemd/p0-v3"),
    private val systemdRoot: Path = Path.of("/etc/systemd/system"),
    private val audit: (PrivateDeploymentSpec, RuntimeProcess) -> String = { spec, p ->
        RuntimeQuadletInstalledAudit().audit(spec, p)
    },
    private val inactive: (String) -> Boolean = ::quadletInactiveUnit,
    private val namespaceEmpty: (PrivateDeploymentSpec) -> Boolean = { spec ->
        val census = PrivateRootfulCommands(30, spec.store).run(listOf("container", "ls", "--all", "--format", "{{.Names}}"))
        census.exitCode == 0 && census.output.toByteArray().size <= 2_000_000 &&
            census.output.lineSequence().none { name -> spec.processes.any { p ->
                name.trim() == "p0v3-live-${spec.name}-${p.id}"
            } }
    }) {
    private val json = Json { encodeDefaults = true }
    fun terminal(root: Path, generation: String, expected: String, spec: PrivateDeploymentSpec): QuadletInstallTerminalObservation {
        require(root == generationBase.resolve(generation) && spec.name.startsWith("$generation-") &&
            spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
            expected.matches(Regex("[a-f0-9]{64}")))
        ReleasePrivateFiles.directory(root)
        val original = root.resolve("quadlet-install-${spec.name}.intent.json")
        val outcome = root.resolve("quadlet-install-${spec.name}.result.json")
        val terminal = root.resolve("quadlet-install-${spec.name}.terminal.json")
        require(!Files.exists(outcome, NOFOLLOW_LINKS) && !Files.exists(terminal, NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("stage.intent.json"), NOFOLLOW_LINKS)) {
            "Install has a result, previous terminal observation or start intent"
        }
        val bytes = ReleasePrivateFiles.read(original, 65536)
        val intent = json.decodeFromString<QuadletInstallIntent>(bytes.decodeToString(throwOnInvalidSequence = true))
        val sealed = ReleasePrivateFiles.read(root.resolve("bundle.json"), 1048576)
        val bundle = json.decodeFromString<GenerationBundle>(sealed.decodeToString(throwOnInvalidSequence = true))
        val rendered = RuntimeQuadlets.render(spec)
        val paths = rendered.files.mapKeys { (relative, _) ->
            (if (relative.endsWith(".container")) sourceRoot else systemdRoot).resolve(relative).toString()
        }.mapValues { ReleaseLocks.sha256(it.value.toByteArray()) }
        require(intent.schemaVersion == 1 && intent.generation == generation && intent.member == spec.name &&
            intent.bundleSha256 == expected && intent.specSha256 == rendered.specSha256 &&
            ReleaseLocks.sha256(sealed) == expected && bundle.members.singleOrNull()?.spec == spec &&
            intent.filesSha256 == paths && intent.stagedDestinations == paths.keys.toList() &&
            json.encodeToString(intent).toByteArray().contentEquals(bytes)) {
            "Original installation cannot be bound to sealed installed files"
        }
        val observed = spec.processes.associate { p ->
            val unit = "${RuntimeQuadlets.unit(spec, p)}.service"
            require(inactive(unit)) { "Installed unit is not verified inactive" }
            val digest = audit(spec, p)
            require(digest.matches(Regex("[a-f0-9]{64}")))
            p.id to digest
        }
        require(namespaceEmpty(spec) && !Files.exists(outcome, NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("stage.intent.json"), NOFOLLOW_LINKS)) {
            "Uncertain native process or start/installation result; no terminal disposition"
        }
        val receipt = QuadletInstallTerminalObservation(generation = generation, member = spec.name,
            bundleSha256 = expected, originalIntentSha256 = ReleaseLocks.sha256(bytes),
            observedInstalledPolicy = observed)
        ReleasePrivateFiles.save(terminal, json.encodeToString(receipt).toByteArray())
        return receipt
    }
}

private fun quadletInactiveUnit(unit: String): Boolean {
    require(unit.matches(Regex("p0v3-q-[a-f0-9]{12}-[a-z0-9-]+\\.service")))
    val child = ProcessBuilder("/usr/bin/systemctl", "show", "--no-pager",
        "--property=LoadState,ActiveState,SubState,MainPID", unit)
        .redirectErrorStream(true).apply { environment().clear() }.start()
    try {
        require(child.waitFor(20, TimeUnit.SECONDS) && child.exitValue() == 0)
        val bytes = child.inputStream.use { it.readNBytes(8193) }
        require(bytes.size in 1..8192)
        val fields = bytes.decodeToString(throwOnInvalidSequence = true).lineSequence()
            .filter { it.contains('=') }.associate { it.substringBefore('=') to it.substringAfter('=') }
        return fields["LoadState"] == "loaded" && fields["ActiveState"] == "inactive" &&
            fields["SubState"] == "dead" && fields["MainPID"] == "0"
    } finally { if (child.isAlive) child.destroyForcibly() }
}
