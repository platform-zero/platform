package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** ORIGINAL, post-start CI effect. Not required when sealing source or starting
 * the issuer/runner. A lost dispatch ACK is fenced; no second dispatch. */
@Serializable internal data class ForgejoCiJobIntent(val schemaVersion: Int = 1,
    val generation: String, val bundleSha256: String, val nativeStartSha256: String,
    val repository: String, val trustedCommit: String, val dispatchRef: String = "main",
    val workflowPath: String, val workflowSha256: String, val runnerId: Long, val jobImageId: String)
@Serializable internal data class ForgejoCiJobResult(val schemaVersion: Int = 1,
    val intentSha256: String, val generation: String, val repository: String,
    val trustedCommit: String, val workflowPath: String, val workflowSha256: String,
    val runId: Long, val jobId: Long, val runnerId: Long, val jobImageId: String,
    val rootlessJobCid: String, val guardCreateSha256: String, val guardStartSha256: String,
    val guardWaitSha256: String, val nativeRunSha256: String, val nativeJobSha256: String,
    val terminalSuccess: Boolean = true)
internal object ForgejoCiOriginalJob {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val hash = Regex("[a-f0-9]{64}")
    private fun output(process: ProcessBuilder, seconds: Long, max: Int): ByteArray {
        val child = process.redirectError(ProcessBuilder.Redirect.DISCARD).start()
        try {
            val result = child.inputStream.readNBytes(max + 1)
            require(child.waitFor(seconds, TimeUnit.SECONDS) && child.exitValue() == 0 && result.size in 1..max) {
                "Native CI source readback failed" }
            return result
        } finally { if (child.isAlive) child.destroyForcibly() }
    }
    private fun workflowPath(plan: ForgejoCiSourcePlan, root: Path): String {
        val bare = root.resolve("ci/trusted-repository.git")
        require(Files.isDirectory(bare, NOFOLLOW_LINKS))
        val bytes = output(ProcessBuilder("/usr/bin/git", "--git-dir=$bare", "ls-tree", "-r", "--name-only",
            plan.enrollment.trustedCommit, ".forgejo/workflows/"), 15, 1024)
        val path = bytes.decodeToString(throwOnInvalidSequence = true).trim()
        require(path.matches(Regex("\\.forgejo/workflows/[a-z0-9_-]+\\.ya?ml")) && '\n' !in path)
        val source = output(ProcessBuilder("/usr/bin/git", "--git-dir=$bare", "show",
            "${plan.enrollment.trustedCommit}:$path"), 15, 32768)
        require(ReleaseLocks.sha256(source) == plan.workflow.sha256 &&
            source.contentEquals(GenerationRuntime.privateInput(Path.of(plan.workflow.path))))
        ForgejoWorkflowSource.inspect(plan.enrollment, plan.enrollment.trustedCommit, source)
        return path
    }
    private fun list(body: ByteArray, key: String): List<JsonObject> {
        require(body.size in 2..65536)
        val parsed = json.parseToJsonElement(body.decodeToString(throwOnInvalidSequence = true))
        val items = parsed.jsonObject.getValue(key).jsonArray
        require(items.size <= 100)
        return items.map { it.jsonObject }
    }
    private fun number(value: JsonObject, key: String): Long =
        requireNotNull(value[key]?.jsonPrimitive?.longOrNull?.takeIf { it > 0 }) { "Missing native CI $key" }
    private fun string(value: JsonObject, key: String): String =
        requireNotNull(value[key]?.jsonPrimitive?.contentOrNull) { "Missing native CI $key" }
    private fun guard(plan: ForgejoCiSourcePlan): JsonObject {
        val directory = "/home/webservices-lab-ci-runner/.local/share/p0v3-ci/${plan.generation}/guard-state"
        // Only fixed file names, O_NOFOLLOW, dedicated UID, bounded stdout. No
        // engine socket, direct-Podman or foreign job is admitted by this reader.
        val script = """import hashlib,json,os,stat,sys
p=sys.argv[1]
if os.geteuid()!=784 or os.getegid()!=784: sys.exit(11)
if os.stat(p,follow_symlinks=False).st_mode&0o077: sys.exit(12)
r={}
for name in ('create.intent.json','create.result.json','start.intent.json','start.result.json','wait.intent.json','wait.result.json'):
 f=os.open(p+'/'+name,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  s=os.fstat(f)
  if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_size<2 or s.st_size>8192: sys.exit(13)
  b=os.read(f,8193)
  if len(b)!=s.st_size: sys.exit(14)
  r[name]={'sha256':hashlib.sha256(b).hexdigest(),'value':json.loads(b)}
 finally: os.close(f)
print(json.dumps(r,separators=(',',':')))
""".trimIndent()
        val observed = output(ProcessBuilder("/usr/bin/sudo", "-n", "-u", plan.dedicatedAccount,
            "--", "/usr/bin/python3", "-c", script, directory), 15, 8192)
        return json.parseToJsonElement(observed.decodeToString(throwOnInvalidSequence = true)).jsonObject
    }
    /** Cold-capture admission: the already-issued result must still match
     * the original sealed plan and the independent rootless terminal custody. */
    fun verifyForCapture(bundle: GenerationBundle, root: Path, custody: ForgejoCiOriginalCustody): ForgejoCiJobResult {
        val plan = requireNotNull(bundle.request.forgejoCi)
        require(bundle.recoverySourceKopia == null && root == GenerationRuntime.BASE.resolve(plan.generation))
        val ci = root.resolve("ci")
        val intentBytes = ReleasePrivateFiles.read(ci.resolve("original-job.intent.json"), 8192)
        val intent = json.decodeFromString<ForgejoCiJobIntent>(intentBytes.decodeToString(throwOnInvalidSequence = true))
        val result = json.decodeFromString<ForgejoCiJobResult>(ReleasePrivateFiles.read(
            ci.resolve("original-job.result.json"), 8192).decodeToString(throwOnInvalidSequence = true))
        val originalHash = ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304))
        val runBytes = ReleasePrivateFiles.read(ci.resolve("original-job-run.json"), 8192)
        val jobBytes = ReleasePrivateFiles.read(ci.resolve("original-job-job.json"), 8192)
        val run = json.parseToJsonElement(runBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        val job = json.parseToJsonElement(jobBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(number(run, "id") == result.runId && string(run, "head_sha") == plan.enrollment.trustedCommit &&
            string(run, "event") == "workflow_dispatch" && string(run, "status") == "completed" &&
            string(run, "conclusion") == "success" && number(job, "id") == result.jobId &&
            number(job, "runner_id") == result.runnerId && string(job, "status") == "completed" &&
            string(job, "conclusion") == "success")
        require(intent.schemaVersion == 1 && result.schemaVersion == 1 && intent.bundleSha256 == originalHash &&
            custody.sourceBundleSha256 == originalHash && custody.sourceGeneration == plan.generation &&
            intent.generation == plan.generation && result.generation == plan.generation &&
            result.intentSha256 == ReleaseLocks.sha256(intentBytes) &&
            intent.nativeStartSha256 == custody.nativeStartSha256 &&
            intent.repository == plan.enrollment.repository && result.repository == intent.repository &&
            intent.trustedCommit == plan.enrollment.trustedCommit && intent.dispatchRef == "main" &&
            result.trustedCommit == intent.trustedCommit &&
            intent.workflowSha256 == plan.workflow.sha256 && result.workflowSha256 == intent.workflowSha256 &&
            intent.workflowPath == result.workflowPath &&
            intent.workflowPath.matches(Regex("\\.forgejo/workflows/[a-z0-9_-]+\\.ya?ml")) &&
            intent.jobImageId == plan.jobArchive.expectedImageId && result.jobImageId == intent.jobImageId &&
            result.runnerId == intent.runnerId && result.runId > 0 && result.jobId > 0 &&
            result.rootlessJobCid.matches(hash) && result.terminalSuccess &&
            custody.jobStateSha256["create.result.json"] == result.guardCreateSha256 &&
            custody.jobStateSha256["start.result.json"] == result.guardStartSha256 &&
            custody.jobStateSha256["wait.result.json"] == result.guardWaitSha256 &&
            result.nativeRunSha256 == ReleaseLocks.sha256(runBytes) &&
            result.nativeJobSha256 == ReleaseLocks.sha256(jobBytes)) {
            "Original trusted job lacks a protected native result bound to terminal rootless custody" }
        return result
    }
    fun produce(bundle: GenerationBundle, root: Path, bundleSha256: String): ForgejoCiJobResult {
        val plan = requireNotNull(bundle.request.forgejoCi)
        require(bundle.recoverySourceKopia == null && bundle.request.recoveredForgejoCiTarget == null &&
            root == GenerationRuntime.BASE.resolve(plan.generation) && plan.generation == bundle.request.id &&
            bundleSha256.matches(hash) && ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)) == bundleSha256)
        plan.validate(plan.generation)
        SiteOwnerships.checkSealed(bundle)
        val ci = root.resolve("ci")
        val startBytes = ReleasePrivateFiles.read(ci.resolve("native-start.result.json"), 16384)
        val start = json.decodeFromString<ForgejoCiNativeStartResult>(startBytes.decodeToString(throwOnInvalidSequence = true))
        val registration = json.decodeFromString<ForgejoCiRegistrationResult>(ReleasePrivateFiles.read(
            ci.resolve("registration.result.json"), 8192).decodeToString(throwOnInvalidSequence = true))
        require(start.generation == plan.generation && start.bundleSha256 == bundleSha256 &&
            start.stages.keys.containsAll(setOf("runner", "guard", "transport")) &&
            start.stages.values.all { it.activeState == "active" } && registration.runnerId > 0 &&
            start.registrationSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(ci.resolve("registration.result.json"), 8192)) &&
            ReleasePrivateFiles.read(ci.resolve("fresh-push.result.json"), 128).decodeToString() == plan.enrollment.trustedCommit)
        val workflow = workflowPath(plan, root)
        val intent = ForgejoCiJobIntent(generation = plan.generation, bundleSha256 = bundleSha256,
            nativeStartSha256 = ReleaseLocks.sha256(startBytes), repository = plan.enrollment.repository,
            trustedCommit = plan.enrollment.trustedCommit, workflowPath = workflow,
            workflowSha256 = plan.workflow.sha256, runnerId = registration.runnerId,
            jobImageId = plan.jobArchive.expectedImageId)
        val intentPath = ci.resolve("original-job.intent.json")
        val resultPath = ci.resolve("original-job.result.json")
        require(!Files.exists(intentPath, NOFOLLOW_LINKS) && !Files.exists(resultPath, NOFOLLOW_LINKS)) {
            "Previous CI dispatch may have taken effect; never redispatch" }
        val owner = ForgejoCiFreshIssuer.credential(bundle, root)
        try {
            val prefix = "/api/v1/repos/${plan.enrollment.repository}/actions"
            val branch = ForgejoCiPrivateApi.freshRepository(plan, owner,
                "/api/v1/repos/${plan.enrollment.repository}/branches/main")
            require(branch.status == 200 && branch.body.size in 2..8192 &&
                json.parseToJsonElement(branch.body.decodeToString(throwOnInvalidSequence = true))
                    .jsonObject.getValue("commit").jsonObject.getValue("id").jsonPrimitive.content ==
                    plan.enrollment.trustedCommit) { "Trusted main branch changed before original workflow dispatch" }
            val before = ForgejoCiPrivateApi.originalJob(plan, owner, "GET", "$prefix/runs")
            require(before.status == 200 && list(before.body, "workflow_runs").isEmpty()) {
                "Original trusted repository is not a fresh, readable CI run source" }
            val intentBytes = json.encodeToString(intent).toByteArray()
            ReleasePrivateFiles.save(intentPath, intentBytes)
            val reply = ForgejoCiPrivateApi.originalJob(plan, owner, "POST",
                "$prefix/workflows/${workflow.substringAfterLast('/')}/dispatches",
                buildJsonObject { put("ref", "main") }.toString().toByteArray())
            require(reply.status == 204) { "Original dispatch result uncertain; preserve intent and do not retry" }
            // Poll is observation only, not a second effect. A timeout leaves the
            // intent and genuine job for read-only reconciliation, never replay.
            val deadline = System.nanoTime() + TimeUnit.MINUTES.toNanos(30)
            var run: JsonObject? = null
            while (System.nanoTime() < deadline) {
                val observed = ForgejoCiPrivateApi.originalJob(plan, owner, "GET", "$prefix/runs")
                require(observed.status == 200)
                val matches = list(observed.body, "workflow_runs").filter {
                    it["head_sha"]?.jsonPrimitive?.content == plan.enrollment.trustedCommit &&
                        it["event"]?.jsonPrimitive?.content == "workflow_dispatch" }
                require(matches.size <= 1) { "Ambiguous original job; no inferred result" }
                if (matches.singleOrNull()?.get("status")?.jsonPrimitive?.content == "completed") {
                    run = matches.single(); break
                }
                Thread.sleep(3000)
            }
            val complete = requireNotNull(run) { "Original job not terminal; preserve dispatch intent" }
            require(string(complete, "conclusion") == "success")
            val runId = number(complete, "id")
            val jobsReply = ForgejoCiPrivateApi.originalJob(plan, owner, "GET", "$prefix/runs/$runId/jobs")
            require(jobsReply.status == 200)
            val jobs = list(jobsReply.body, "jobs")
            require(jobs.size == 1)
            val job = jobs.single()
            require(string(job, "status") == "completed" && string(job, "conclusion") == "success" &&
                number(job, "runner_id") == registration.runnerId &&
                job["run_id"]?.jsonPrimitive?.longOrNull?.let { it == runId } != false)
            val guard = guard(plan)
            fun record(name: String) = guard.getValue(name).jsonObject
            val cid = record("create.result.json").getValue("value").jsonObject.getValue("id").jsonPrimitive.content
            require(cid.matches(hash) && listOf("start.result.json", "wait.result.json").all {
                record(it).getValue("value").jsonObject.getValue("id").jsonPrimitive.content == cid } &&
                record("wait.result.json").getValue("value").jsonObject.getValue("exitCode").jsonPrimitive.int == 0 &&
                record("create.intent.json").getValue("value").jsonObject.getValue("requestSha256").jsonPrimitive.content.matches(hash))
            val runBytes = complete.toString().toByteArray()
            val jobBytes = job.toString().toByteArray()
            require(runBytes.size in 2..8192 && jobBytes.size in 2..8192)
            ReleasePrivateFiles.save(ci.resolve("original-job-run.json"), runBytes)
            ReleasePrivateFiles.save(ci.resolve("original-job-job.json"), jobBytes)
            val receipt = ForgejoCiJobResult(intentSha256 = ReleaseLocks.sha256(intentBytes), generation = plan.generation,
                repository = plan.enrollment.repository, trustedCommit = plan.enrollment.trustedCommit,
                workflowPath = workflow, workflowSha256 = plan.workflow.sha256,
                runId = runId, jobId = number(job, "id"), runnerId = registration.runnerId,
                jobImageId = plan.jobArchive.expectedImageId, rootlessJobCid = cid,
                guardCreateSha256 = record("create.result.json").getValue("sha256").jsonPrimitive.content,
                guardStartSha256 = record("start.result.json").getValue("sha256").jsonPrimitive.content,
                guardWaitSha256 = record("wait.result.json").getValue("sha256").jsonPrimitive.content,
                nativeRunSha256 = ReleaseLocks.sha256(runBytes),
                nativeJobSha256 = ReleaseLocks.sha256(jobBytes))
            ReleasePrivateFiles.save(resultPath, json.encodeToString(receipt).toByteArray())
            return receipt
        } finally { owner.fill(0) }
    }
}
