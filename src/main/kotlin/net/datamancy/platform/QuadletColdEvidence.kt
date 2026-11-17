package net.datamancy.platform

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Authenticated ORIGINAL Quadlet initializer and stop evidence, not a synthetic
 * PrivateDeployment.runtime.jobs file and not a startup/qualification grant.
 */
@Serializable internal data class QuadletColdSourceEvidence(val member: String,
    val terminalSha256: String, val originalFiles: List<String>)

internal object QuadletColdEvidence {
    private val hash = Regex("[a-f0-9]{64}")
    private val file = Regex("[a-z0-9.-]{1,192}\\.json")
    private val json = Json { ignoreUnknownKeys = false }
    fun terminal(member: String) = "$member/quadlet/terminal.json"
    fun original(member: String, name: String) = "$member/quadlet/original/$name"
    fun ledgerHash(spec: PrivateDeploymentSpec, receipt: QuadletCapacityTerminalObservation): String {
        require(receipt.member == spec.name && spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2)
        val initializers = spec.processes.filter { it.oneShot }
        require(initializers.isNotEmpty())
        val text = "quadlet-original-initializers-v1\n" + initializers.joinToString("\n") { process ->
            "${process.id}:${receipt.originalEvidenceSha256.getValue("quadlet-member-${spec.name}-${process.id}.result.json")}"
        } + "\n"
        return ReleaseLocks.sha256(text.toByteArray())
    }
    fun validate(manifest: CapsuleManifest) {
        val sources = manifest.quadletSources
        require(sources.size <= manifest.members.size && sources.map { it.member }.distinct().size == sources.size)
        val expected = mutableSetOf<String>()
        for (source in sources) {
            require(source.member.startsWith(manifest.generation + "-") && source.member in manifest.members.map { it.name } &&
                hash.matches(source.terminalSha256) && source.originalFiles.size in 1..128 &&
                source.originalFiles.distinct().size == source.originalFiles.size &&
                source.originalFiles.all { it.matches(file) && !it.startsWith("runtime.") }) {
                "Invalid Quadlet original evidence partition"
            }
            expected += terminal(source.member)
            expected += source.originalFiles.map { original(source.member, it) }
        }
        val actual = manifest.files.map { it.name }.filter { "/quadlet/" in it }.toSet()
        require(actual == expected && manifest.files.filter { it.name in expected }.all {
            it.bytes in 1..65536 && hash.matches(it.sha256)
        }) { "Unknown or incomplete Quadlet original-evidence payload" }
    }
    fun verifyRecovered(source: QuadletColdSourceEvidence, pin: GenerationPin,
        frozen: FrozenRuntimeObservation, manifest: CapsuleManifest, bytes: (String) -> ByteArray): Set<String> {
        require(pin.spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 && pin.spec.name == source.member &&
            manifest.generation == pin.member.name.take(14) &&
            manifest.quadletSources.singleOrNull { it.member == pin.spec.name } == source)
        val terminalPath = terminal(source.member)
        val original = bytes(terminalPath)
        require(ReleaseLocks.sha256(original) == source.terminalSha256)
        val receipt = json.decodeFromString<QuadletCapacityTerminalObservation>(original.decodeToString(throwOnInvalidSequence = true))
        require(receipt.schemaVersion == 1 && receipt.generation == manifest.generation &&
            receipt.bundleSha256 == manifest.bundleSha256 && receipt.member == pin.spec.name &&
            receipt.fingerprint == pin.runtimeFingerprint && receipt.fenceId == frozen.fenceId &&
            !receipt.publicActivation && !receipt.originalIsolationAcknowledged &&
            receipt.originalEvidenceSha256.keys == source.originalFiles.toSet() &&
            receipt.stoppedCids.keys == pin.spec.processes.map { it.id }.toSet() &&
            frozen.jobsSha256 == ledgerHash(pin.spec, receipt) &&
            frozen.completedInitializers == pin.spec.processes.filter { it.oneShot }.map { it.id }.toSet()) {
            "Recovered Quadlet original initializer or terminal proof changed"
        }
        for ((name, expected) in receipt.originalEvidenceSha256) {
            require(hash.matches(expected) && ReleaseLocks.sha256(bytes(original(source.member, name))) == expected) {
                "Recovered Quadlet original evidence changed"
            }
        }
        return source.originalFiles.map { original(source.member, it) }.toSet() + terminalPath
    }
}
