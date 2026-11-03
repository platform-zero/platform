package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

@Serializable internal data class ActivationInput(val path: String, val sha256: String)
@Serializable internal data class ActivationImagePin(val reference: String, val imageId: String)
/** Digest-bound closure, not an acquisition attestation. Runtime images and both running controllers are reobserved. */
@Serializable internal data class ActivationArtifactClosure(val schemaVersion: Int = 1, val controllers: Map<String, String>,
    val images: Map<String, ActivationImagePin>, val assets: Map<String, String>)
@Serializable internal data class ActivationEvidenceBinding(val inventory: ActivationInput, val manifest: ActivationInput,
    val candidate: ActivationInput, val artifacts: ActivationInput, val qualificationJournal: String, val qualificationHead: String,
    val acceptanceControllerSha256: String)
internal fun interface AcceptanceControllerProcess { fun run(argv: List<String>, directory: Path): RuntimeCommandResult }

/** No shell interpolation, inherited JVM injection, network calls or model requests. Only the pinned local verifier. */
internal class LocalAcceptanceControllerProcess(private val timeoutMillis: Long = 120_000) : AcceptanceControllerProcess {
    override fun run(argv: List<String>, directory: Path): RuntimeCommandResult {
        require(timeoutMillis in 1..120_000 && argv.isNotEmpty() && Path.of(argv.first()).isAbsolute)
        ReleasePrivateFiles.directory(directory)
        val mode = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
        val output = Files.createTempFile(directory, "authority-", ".stdout", mode)
        val error = Files.createTempFile(directory, "authority-", ".stderr", mode)
        val builder = ProcessBuilder(argv).directory(directory.toFile()).redirectOutput(output.toFile()).redirectError(error.toFile())
        builder.environment().apply {
            clear(); put("JAVA_HOME", "/usr/lib/jvm/java-21-openjdk-amd64"); put("PATH", "/usr/bin:/bin")
            put("JAVA_OPTS", "-Xms32m -Xmx512m"); put("LANG", "C.UTF-8"); put("HOME", directory.toString())
        }
        val process = builder.start()
        try {
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
            while (!process.waitFor(50, TimeUnit.MILLISECONDS)) {
                check(System.nanoTime() < deadline && Files.size(output) <= 4 * 1024 * 1024 && Files.size(error) <= 4 * 1024 * 1024) {
                    "Acceptance authorization exceeded time/output bound; retain claim and diagnostics"
                }
            }
            require(Files.size(output) <= 4 * 1024 * 1024 && Files.size(error) <= 4 * 1024 * 1024)
            val bytes = if (Files.size(output) == 0L) byteArrayOf() else ReleasePrivateFiles.read(output)
            return RuntimeCommandResult(process.exitValue(), bytes.decodeToString(throwOnInvalidSequence = true))
        } catch (interrupted: InterruptedException) {
            Thread.currentThread().interrupt(); throw interrupted
        } finally {
            val interrupted = Thread.interrupted()
            try {
                if (process.isAlive) {
                    process.descendants().use { descendants -> descendants.forEach { it.destroyForcibly() } }
                    process.destroyForcibly()
                    process.waitFor(5, TimeUnit.SECONDS)
                }
            } catch (_: InterruptedException) { Thread.currentThread().interrupt() }
            finally { if (interrupted) Thread.currentThread().interrupt() }
            // Retain private diagnostics, including uncertainty; never print them to public/controller logs.
        }
    }
}

/** Concrete production authority. Acceptance revalidates and locks complete history through durable consumption.
 * Live facts are independently reobserved by the Platform adapter before both operations. No permissive fallback.
 */
internal class QualifiedActivationAuthorization(private val evidence: ActivationEvidenceBinding,
    private val transactionJournal: Path, private val consumptionRoot: Path,
    private val controllerRoot: Path, private val verifyController: () -> Unit,
    private val observeLive: (ReleaseDeploymentBinding, JsonObject) -> Unit,
    private val process: AcceptanceControllerProcess) : ReleaseActivationAuthorization {
    companion object {
        private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
        private val hash = Regex("[a-f0-9]{64}")
        private fun closure(pin: ActivationInput): ActivationArtifactClosure {
            val bytes = ReleasePrivateFiles.read(Path.of(pin.path))
            require(ReleaseLocks.sha256(bytes) == pin.sha256)
            return json.decodeFromString<ActivationArtifactClosure>(bytes.decodeToString()).also {
                require(it.schemaVersion == 1 && it.controllers.keys == setOf("platform", "acceptance") &&
                    it.controllers.values.all(hash::matches) && it.images.size in 1..256 && it.assets.size <= 1024 &&
                    (it.images.keys + it.assets.keys).all { name -> name.matches(Regex("[a-z][a-z0-9-]{0,95}")) } &&
                    it.assets.values.all(hash::matches) && it.images.values.all { image ->
                        image.reference.matches(Regex("[a-z0-9][a-z0-9./_:-]*@sha256:[a-f0-9]{64}")) && hash.matches(image.imageId)
                    }) { "Incomplete or malformed activation artifact closure" }
            }
        }
        fun real(evidence: ActivationEvidenceBinding, transactionJournal: Path, consumptionRoot: Path,
            caddy: TransactionalCaddy): QualifiedActivationAuthorization {
            require(hash.matches(evidence.acceptanceControllerSha256) &&
                consumptionRoot == Path.of("/mnt/media/p0-v3/release-activation-consumptions")) { "Canonical activation consumption namespace required" }
            val controller = Path.of("/mnt/media/p0-v3/runtime-supervision/acceptance-releases/${evidence.acceptanceControllerSha256}")
            return QualifiedActivationAuthorization(evidence, transactionJournal, consumptionRoot, controller,
                {
                    PinnedBackupController.verify(closure(evidence.artifacts).controllers.getValue("platform"))
                    PinnedBackupController.verifyDistribution(controller, evidence.acceptanceControllerSha256, "p0-v3-acceptance")
                },
                { deployment, candidate ->
                    val images = closure(evidence.artifacts).images.values.map { it.reference to it.imageId }.toSet()
                    val upstreams = GenerationRuntime.real().checkActivationSource(deployment, candidate, images)
                    require(caddy.observeRestrictedSlotSha256(deployment.generationId, upstreams) == deployment.restrictedConfigurationSha256) { "Restricted Caddy binding changed before activation" }
                }, LocalAcceptanceControllerProcess())
        }
    }
    private fun candidate(): JsonObject {
        for (pin in listOf(evidence.inventory, evidence.manifest, evidence.candidate, evidence.artifacts)) {
            require(hash.matches(pin.sha256) && ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(pin.path))) == pin.sha256) { "Activation definition input changed" }
        }
        require(hash.matches(evidence.qualificationHead) && hash.matches(evidence.acceptanceControllerSha256))
        return json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(evidence.candidate.path)).decodeToString()).jsonObject.also {
            require(it.keys == setOf("implementationSha256", "artifactsSha256", "configurationSha256", "acceptanceSha256", "sitePolicySha256") &&
                it.values.all { value -> value.jsonPrimitive.isString && hash.matches(value.jsonPrimitive.content) }) { "Complete candidate identity required" }
            require(it.getValue("artifactsSha256") == JsonPrimitive(evidence.artifacts.sha256) &&
                closure(evidence.artifacts).controllers.getValue("acceptance") == evidence.acceptanceControllerSha256) { "Verifier or artifact closure is not part of the frozen candidate" }
        }
    }
    private fun bindingJson(binding: ReleaseActivationBinding) = buildJsonObject {
        put("transactionId", binding.transactionId); put("lockDigest", binding.lockDigest); put("acceptedJournalHead", binding.acceptedJournalHead)
        put("deployment", json.encodeToJsonElement(binding.deployment))
    }
    private fun admission(binding: ReleaseActivationBinding, claim: String? = null) {
        binding.deployment.validate(); ReleasePrivateFiles.directory(consumptionRoot)
        require(!Files.exists(consumptionRoot.resolve("${binding.deployment.generationId}.consumed.json"), NOFOLLOW_LINKS)) { "Generation activation already consumed or uncertain" }
        val records = TransactionJournal.verify(transactionJournal)
        val last = records.last()
        require(last.transactionId == binding.transactionId && last.lockDigest == binding.lockDigest && last.deployment == binding.deployment &&
            if (claim == null) last.phase == Phase.ACCEPTED && last.hash == binding.acceptedJournalHead
            else last.phase == Phase.ACTIVATION_STARTED && last.hash == claim && last.prevHash == binding.acceptedJournalHead) { "Activation journal binding changed" }
        verifyController()
        val candidate = candidate()
        require(candidate.getValue("sitePolicySha256").jsonPrimitive.content == binding.deployment.sitePolicySha256)
        observeLive(binding.deployment, candidate)
    }
    private fun call(operation: String, binding: ReleaseActivationBinding, extra: List<String> = emptyList()): JsonObject {
        val args = listOf(controllerRoot.resolve("bin/p0-v3-acceptance").toString(), operation,
            evidence.inventory.path, evidence.manifest.path, evidence.candidate.path, evidence.qualificationJournal,
            evidence.qualificationHead, bindingJson(binding).toString()) + extra
        val result = process.run(args, consumptionRoot)
        check(result.exitCode == 0 && result.output.toByteArray().size in 1..4 * 1024 * 1024) { "Pinned acceptance authorization refused; no activation effects authorized" }
        return json.parseToJsonElement(result.output).jsonObject
    }
    private fun verifyPermit(permit: JsonObject, binding: ReleaseActivationBinding): String {
        require(permit.keys == setOf("schemaVersion", "binding", "candidate", "qualificationHead", "secondTrialId", "snapshotId", "evaluationHashes") &&
            permit.getValue("schemaVersion") == JsonPrimitive(1) && permit.getValue("binding") == bindingJson(binding) &&
            permit.getValue("candidate") == candidate() && permit.getValue("qualificationHead") == JsonPrimitive(evidence.qualificationHead)) { "Foreign activation permit" }
        val snapshot = permit.getValue("snapshotId").jsonPrimitive.content
        val transaction = TransactionJournal.verify(transactionJournal).last()
        require(transaction.update == null || transaction.qualificationSnapshotId != null)
        require(snapshot.matches(Regex("cap-[a-f0-9]{12}")) &&
            (transaction.qualificationSnapshotId ?: transaction.snapshotId) == snapshot) {
            "Transaction snapshot differs from the qualified functional restore"
        }
        val selected = permit.getValue("secondTrialId").jsonPrimitive.content
        val evaluations = permit.getValue("evaluationHashes").jsonObject
        require(selected.matches(Regex("[a-z][a-z0-9-]{0,95}")) && selected in evaluations && evaluations.size in 2..10000 &&
            evaluations.values.all { it.jsonPrimitive.isString && hash.matches(it.jsonPrimitive.content) })
        // Preserve the typed Acceptance serialization order; the protocol response is checked against its digest at consume.
        return ReleaseLocks.sha256(permit.toString().toByteArray())
    }
    override fun verify(binding: ReleaseActivationBinding): String {
        admission(binding)
        return verifyPermit(call("activation-verify", binding), binding)
    }
    override fun consume(binding: ReleaseActivationBinding, permitSha256: String, activationJournalHead: String) {
        require(hash.matches(permitSha256) && hash.matches(activationJournalHead))
        admission(binding, activationJournalHead)
        require(TransactionJournal.verify(transactionJournal).last().activationPermitSha256 == permitSha256)
        // Reverification is not replaced by trusting a prior permit file or signature.
        require(verifyPermit(call("activation-verify", binding), binding) == permitSha256) { "Qualification evidence changed before consumption" }
        val claim = ReleasePrivateFiles.read(transactionJournal, 1048576)
        val receipt = call("activation-consume", binding, listOf(permitSha256, transactionJournal.toString(), ReleaseLocks.sha256(claim), consumptionRoot.toString()))
        val expected = buildJsonObject {
            put("schemaVersion", 1); put("generation", binding.deployment.generationId); put("permitSha256", permitSha256)
            put("activationJournalHead", activationJournalHead); put("qualificationHead", evidence.qualificationHead); put("claimJournalSha256", ReleaseLocks.sha256(claim))
        }
        require(receipt == expected) { "Foreign activation consumption acknowledgement" }
        val retained = json.parseToJsonElement(ReleasePrivateFiles.read(consumptionRoot.resolve("${binding.deployment.generationId}.consumed.json")).decodeToString()).jsonObject
        require(retained.getValue("consumption") == expected && retained.getValue("claimJournal") == JsonPrimitive(claim.decodeToString()) &&
            verifyPermit(retained.getValue("permit").jsonObject, binding) == permitSha256) { "Activation consumption was not durably retained" }
    }
}
