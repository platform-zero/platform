package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import java.time.Instant
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

@Serializable internal data class WeeklyFunctionalCase(val id: String, val serviceId: String, val surface: String,
    val journey: String, val variant: String, val adapter: String, val adapterSha256: String,
    val assertions: Set<String>, val context: JsonObject, val sourceOracle: JsonObject)
@Serializable internal data class WeeklyFunctionalPlan(val schemaVersion: Int = 1, val candidate: JsonObject, val cases: List<WeeklyFunctionalCase>)

/** Executes the same real semantic adapter protocol as Acceptance. The immutable plan contains
 * independently retained original fixture oracles; neither health nor exit code supplies assertions.
 * Adapters and their parent directories must be root-owned and non-writable by the service owner.
 * Request/result/artifact hashes are retained under this weekly invocation, never borrowed as evidence.
 */
internal class WeeklyFunctionalVerifier(private val now: () -> Instant,
    private val execute: (WeeklyFunctionalCase, Path, Path, Instant) -> Unit) {
    companion object {
        private val json = Json { encodeDefaults = true }
        fun candidateHash(plan: WeeklyFunctionalPlan): String {
            val keys = listOf("implementationSha256", "artifactsSha256", "configurationSha256", "acceptanceSha256", "sitePolicySha256")
            require(plan.candidate.keys == keys.toSet() && plan.candidate.values.all { it.jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")) })
            return ReleaseLocks.sha256(JsonObject(keys.associateWith { plan.candidate.getValue(it) }).toString().toByteArray())
        }
        fun validate(plan: WeeklyFunctionalPlan, required: Set<String>) {
            candidateHash(plan)
            require(plan.schemaVersion == 1 && plan.cases.size in 1..128 && plan.cases.map { it.id }.distinct().size == plan.cases.size)
            for (case in plan.cases) {
                require(case.id.matches(Regex("[a-z0-9][a-z0-9-]{0,47}")) && case.surface in setOf("native", "headless") && case.variant == "native" && case.serviceId != "backup-restore" &&
                    listOf(case.serviceId, case.journey, case.variant).all { it.matches(Regex("[a-z0-9][a-z0-9_.:-]{0,127}")) } &&
                    case.adapterSha256.matches(Regex("[a-f0-9]{64}")) && case.assertions.isNotEmpty() && case.sourceOracle.isNotEmpty() &&
                    case.assertions.all { it.matches(Regex("[a-z0-9][a-z0-9_.:-]{0,63}")) })
                val path = Path.of(case.adapter); require(path.isAbsolute && path.normalize() == path && path.fileName.toString().endsWith(".py"))
            }
            require(plan.cases.flatMap { case -> case.assertions.map { "${case.id}:$it" } }.toSet() == required) { "Exact functional assertion closure required" }
        }
        fun validateInstalled(plan: WeeklyFunctionalPlan) { plan.cases.forEach(::validateProgram) }
        private fun validateProgram(case: WeeklyFunctionalCase) {
            val adapter = Path.of(case.adapter)
            var path: Path? = adapter
            while (path != null) {
                require(path.toRealPath() == path && (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == 0L &&
                    Files.getPosixFilePermissions(path).none { it.name in setOf("GROUP_WRITE", "OTHERS_WRITE") }) { "Untrusted functional adapter path" }
                path = path.parent
            }
            require(Files.isRegularFile(adapter, NOFOLLOW_LINKS) && (Files.getAttribute(adapter, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong() == 1L &&
                Files.size(adapter) in 1..1048576 && RecoveryCapsule.fileHash(adapter) == case.adapterSha256)
        }
        fun real() = WeeklyFunctionalVerifier(Instant::now) { case, request, result, deadline ->
            executeProgram(case, request, result, deadline)
        }
        /** Unit seams replace only program validation/process transport; production always uses the guarded defaults. */
        internal fun executeProgram(case: WeeklyFunctionalCase, request: Path, result: Path, deadline: Instant,
            now: () -> Instant = Instant::now, checkProgram: (WeeklyFunctionalCase) -> Unit = ::validateProgram,
            start: (ProcessBuilder) -> Process = { it.start() }) {
            checkProgram(case)
            val adapter = Path.of(case.adapter)
            val out = request.parent.resolve("adapter.stdout"); val err = request.parent.resolve("adapter.stderr")
            for (log in listOf(out, err)) Files.createFile(log, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
            val remaining = minOf(Duration.between(now(), deadline).seconds,
                RecoveryDeadline.remainingSecondsIfBound() ?: Long.MAX_VALUE)
            require(remaining > 0)
            val process = start(ProcessBuilder("/usr/bin/python3", "-I", adapter.toString(), "--request", request.toString(), "--result", result.toString())
                .redirectOutput(out.toFile()).redirectError(err.toFile()).apply {
                    environment().clear(); environment().putAll(mapOf("PATH" to "/usr/bin:/bin", "JAVA_HOME" to "/usr/lib/jvm/java-21-openjdk-amd64", "LANG" to "C.UTF-8"))
                })
            try {
                require(process.waitFor(remaining, java.util.concurrent.TimeUnit.SECONDS)) { "Functional adapter timeout; unknown outcome retained" }
                require(process.exitValue() == 0) { "Functional adapter failed" }
            } catch (e: Exception) {
                // Only this evaluator's process tree. Never restart an uncertain adapter or
                // release a fenced source merely because its process exited/was interrupted.
                process.descendants().use { children -> children.forEach { it.destroyForcibly() } }
                process.destroyForcibly()
                if (e is InterruptedException) Thread.currentThread().interrupt()
                throw e
            }
        }
    }
    fun verify(plan: WeeklyFunctionalPlan, request: WeeklyFunctionalRequest, attempt: Path, deadline: Instant): WeeklyFunctionalResult {
        validate(plan, request.requiredAssertions); KopiaGenerationStore.validate(request.snapshot)
        require(request.target != request.snapshot.generation && request.operation.matches(Regex("cap-[a-f0-9]{12}")) &&
            request.target.matches(Regex("q-[a-f0-9]{12}")) && request.targetBundleSha256.matches(Regex("[a-f0-9]{64}")))
        ReleasePrivateFiles.directory(attempt)
        for (case in plan.cases) {
            require(now() < deadline && !Thread.currentThread().isInterrupted)
            val root = attempt.resolve("functional-${case.id}")
            Files.createDirectory(root, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(attempt)
            val invocation = "${request.operation}-${case.id}"
            val adapterRequest = buildJsonObject {
                put("schemaVersion", 1)
                put("invocation", buildJsonObject {
                    put("invocationId", invocation)
                    put("binding", buildJsonObject {
                        put("trialId", request.operation); put("generationId", request.target); put("phase", "RESTORE")
                        put("candidate", plan.candidate)
                    })
                    put("serviceId", case.serviceId); put("surface", "HEADLESS"); put("journey", case.journey); put("variant", "NATIVE")
                    put("requiredAssertions", JsonArray(case.assertions.sorted().map(::JsonPrimitive)))
                })
                put("url", case.context["url"] ?: JsonNull)
                put("context", JsonObject(case.context + mapOf("generation" to JsonPrimitive(request.target),
                    "bundleSha256" to JsonPrimitive(request.targetBundleSha256), "snapshot" to json.encodeToJsonElement(request.snapshot))))
                put("artifactDirectory", root.toString()); put("sourceOracle", case.sourceOracle)
            }
            val input = root.resolve("request.json"); val output = root.resolve("result.json")
            ReleasePrivateFiles.save(input, json.encodeToString(adapterRequest).toByteArray())
            val inputHash = RecoveryCapsule.fileHash(input)
            execute(case, input, output, deadline)
            require(now() < deadline && !Thread.currentThread().isInterrupted && RecoveryCapsule.fileHash(input) == inputHash)
            val reportBytes = ReleasePrivateFiles.read(output)
            val report = json.parseToJsonElement(reportBytes.decodeToString()).jsonObject
            require(report["schemaVersion"]?.jsonPrimitive?.int == 1 && report["invocationId"]?.jsonPrimitive?.content == invocation)
            val assertions = report.getValue("assertions").jsonObject
            require(assertions.keys == case.assertions && assertions.values.all { it.jsonPrimitive.boolean } && report["oracle"] == case.sourceOracle) {
                "Functional report differs from required assertions or independent original oracle"
            }
            val artifacts = report.getValue("artifacts").jsonObject
            require(artifacts.isNotEmpty() && artifacts.size <= 128)
            for ((name, digest) in artifacts) {
                require(name.matches(Regex("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")) && name !in setOf("request.json", "result.json", "adapter.stdout", "adapter.stderr", "verified.json"))
                require(digest.jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")))
                val bytes = ReleasePrivateFiles.read(root.resolve(name))
                require(ReleaseLocks.sha256(bytes) == digest.jsonPrimitive.content)
            }
            ReleasePrivateFiles.save(root.resolve("verified.json"), json.encodeToString(mapOf("requestSha256" to inputHash,
                "resultSha256" to ReleaseLocks.sha256(reportBytes), "adapterSha256" to case.adapterSha256)).toByteArray())
        }
        return WeeklyFunctionalResult(request.operation, request.target, request.targetBundleSha256, request.snapshot.snapshotId, request.requiredAssertions, true)
    }
}
