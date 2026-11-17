package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** A read-only interval, not the lost original snapshot/retention/schedule ACK.
 * Direct Podman Kopia helpers have NO systemd unit; their original create ACK
 * must bind the exact CID, intent and name before a terminal disposition is possible.
 */
@Serializable internal data class KopiaOriginalWorkerCreate(val containerId: String,
    val container: String, val intentSha256: String, val unit: String = "none")
internal data class KopiaTerminalExclusion(val generation: String, val bundleSha256: String,
    val originalWorkerCid: String, val originalIntent: ActivationInput,
    val originalCreate: ActivationInput, val pending: ActivationInput,
    val referenceBootstrap: ActivationInput)

internal object GenerationKopiaTerminalExclusion {
    private val json = Json { ignoreUnknownKeys = false }
    private val capture = Regex("cap-[a-f0-9]{12}")
    private val retention = Regex("r-[a-f0-9]{12}")
    private val cid = Regex("[a-f0-9]{64}")
    private val hash = Regex("[a-f0-9]{64}")
    private fun pin(path: Path): ActivationInput = ActivationInput(path.toString(),
        ReleaseLocks.sha256(ReleasePrivateFiles.read(path, 1048576)))

    fun requireOriginalWorkerQuiescent(generation: String, operationId: String, phase: String,
        original: KopiaOriginalWorkerCreate, intent: ActivationInput,
        observed: List<RuntimeCapacityCensus.Container>) {
        val expectedName = "p0v3-kopia-$generation-$operationId-$phase"
        require(original.containerId.matches(cid) && original.container == expectedName &&
            original.unit == "none" && original.intentSha256 == intent.sha256)
        val prefix = "p0v3-kopia-$generation-"
        require(observed.filter { it.name.startsWith(prefix) }
            .all { it.state in setOf("exited", "created", "configured") } &&
            observed.count { it.name == expectedName && it.cid == original.containerId && it.state == "exited" } == 1 &&
            observed.none { it.name == expectedName && it.cid != original.containerId }) {
            "Original Kopia worker CID or concurrent writer is not physically quiescent"
        }
    }

    /** Caller holds original RSS, generation and ALL source native member locks.
     * Ledger lock excludes reference writers for the complete callback; the Kopia
     * repository lock is taken only for original-worker checks, and released before
     * a recovery-owned read-only native census may take it. No effect or fence release.
     */
    fun <T> withExcludedWriters(root: Path, generation: String, bundleSha256: String,
        operationId: String, kind: String, census: () -> List<RuntimeCapacityCensus.Container>,
        action: (KopiaTerminalExclusion) -> T): T {
        require(root == GenerationRuntime.BASE.resolve(generation) && root.toRealPath() == root &&
            generation.matches(Regex("q-[a-f0-9]{12}")) && bundleSha256.matches(hash) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"))) == bundleSha256 &&
            kind in setOf("snapshot", "retention") &&
            (if (kind == "snapshot") operationId.matches(capture) else operationId.matches(retention)))
        val store = root.resolve("kopia-store")
        val reference = root.resolve("recovery-references")
        val operation = if (kind == "snapshot") root.resolve("kopia-captures/$operationId")
            else store.resolve("retention-$operationId")
        val phase = if (kind == "snapshot") "snapshot" else "policy"
        val intentPath = operation.resolve("$phase.intent.json")
        val createPath = operation.resolve("$phase.create.result.json")
        val pendingPath = store.resolve(if (kind == "snapshot") "snapshot.pending.json" else "retention.pending.json")
        ReleasePrivateFiles.directory(operation)
        ReleasePrivateFiles.directory(store)
        ReleasePrivateFiles.directory(reference)
        return ReleasePrivateFiles.locked(reference) {
            val bootstrap = pin(reference.resolve("bootstrap.json"))
            require(ReleasePrivateFiles.read(reference.resolve("ready")).decodeToString() == bootstrap.sha256) {
                "Incomplete reference ledger; writer exclusion cannot authorize a terminal disposition"
            }
            fun read(): KopiaTerminalExclusion = ReleasePrivateFiles.locked(store) {
                val intent = pin(intentPath); val create = pin(createPath); val pending = pin(pendingPath)
                val original = json.decodeFromString<KopiaOriginalWorkerCreate>(ReleasePrivateFiles.read(createPath).decodeToString())
                val expectedName = "p0v3-kopia-$generation-$operationId-$phase"
                val recorded = json.decodeFromString<Map<String, String>>(ReleasePrivateFiles.read(intentPath).decodeToString())
                require(recorded["container"] == expectedName &&
                    (if (kind == "snapshot") json.decodeFromString<Map<String, String>>(
                        ReleasePrivateFiles.read(pendingPath).decodeToString()) ==
                        mapOf("generation" to generation, "capture" to operationId)
                    else json.decodeFromString<Map<String, String>>(
                        ReleasePrivateFiles.read(pendingPath).decodeToString()).let { it["generation"] == generation &&
                            it["id"] == operationId && it["referenceHeadSha256"]?.matches(hash) == true }))
                requireOriginalWorkerQuiescent(generation, operationId, phase, original, intent, census())
                KopiaTerminalExclusion(generation, bundleSha256, original.containerId,
                    intent, create, pending, bootstrap)
            }
            val initial = read()
            val result = action(initial)
            require(read() == initial && pin(reference.resolve("bootstrap.json")) == bootstrap &&
                !Files.isSymbolicLink(reference.resolve("control.lock"))) {
                "Kopia terminal callback changed original custody; retain pending fences"
            }
            result
        }
    }
}
