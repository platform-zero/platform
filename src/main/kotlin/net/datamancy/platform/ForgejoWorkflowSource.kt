package net.datamancy.platform

import kotlinx.serialization.json.*

/** Parse the actual enrolled workflow bytes, never a caller-provided account of
 * what jobs.<id>.container says. This is a source policy, NOT a native job ACK:
 * the rootless worker must independently reobserve the effective create.
 */
internal object ForgejoWorkflowSource {
    fun inspect(enrollment: TrustedForgejoWorkflowEnrollment, trustedCommit: String,
        bytes: ByteArray): ForgejoWorkflowReview {
        require(ReleaseLocks.sha256(bytes) == enrollment.workflowSha256 &&
            trustedCommit == enrollment.trustedCommit)
        val source = FragmentYaml.parse(bytes)
        require(source.keys.all { it in setOf("name", "on", "jobs", "permissions") } &&
            source.getValue("on") == JsonPrimitive("workflow_dispatch") &&
            source["permissions"]?.jsonObject?.all { (permission, value) ->
                permission in setOf("contents", "actions") && value.jsonPrimitive.content in setOf("none", "read")
            } != false)
        val jobs = source.getValue("jobs").jsonObject
        require(jobs.size == 1)
        val (jobId, jobValue) = jobs.entries.single()
        require(jobId.matches(Regex("[a-z][a-z0-9_-]{0,48}")))
        val job = jobValue.jsonObject
        require(job.keys.all { it in setOf("runs-on", "container", "steps", "timeout-minutes") } &&
            job.getValue("runs-on").jsonPrimitive.content == "p0v3-rootless-oci" &&
            job["timeout-minutes"]?.jsonPrimitive?.intOrNull?.let { it in 1..30 } != false)
        val container = job.getValue("container")
        val image = if (container is JsonPrimitive) container.content else {
            val options = container.jsonObject
            require(options.keys == setOf("image"))
            options.getValue("image").jsonPrimitive.content
        }
        require(image == enrollment.jobImage)
        val steps = job.getValue("steps").jsonArray.map { it.jsonObject }
        // Forgejo runner v3.5.1 itself exercises full-URL checkout and
        // upload-artifact actions. These two mirrors must be private Forgejo
        // repositories at reviewed Git commit IDs, never a moving tag.
        val checkout = "https://forgejo.datamancy.net/actions/checkout@${enrollment.checkoutActionCommit}"
        val upload = "https://forgejo.datamancy.net/actions/upload-artifact@${enrollment.uploadActionCommit}"
        val localOnly = enrollment.checkoutActionCommit == null && enrollment.uploadActionCommit == null
        if (localOnly) {
            // An approved fixture can execute the pinned job image's own
            // tools, with no external action repositories or checkout. The
            // workflow and its Git commit are independently sealed below.
            require(steps.size in 1..32 && steps.all { fields ->
                fields.keys.all { it in setOf("name", "run", "shell") } &&
                    fields.containsKey("run") &&
                    fields.getValue("run").jsonPrimitive.content.length in 1..32768 &&
                    fields["shell"]?.jsonPrimitive?.content?.let { it == "bash" } != false
            }) { "Local CI fixture cannot reference action mirrors or an unreviewed step" }
        } else require(steps.size in 3..32 &&
            steps.first().keys == setOf("uses", "with") &&
            steps.first().getValue("uses").jsonPrimitive.content == checkout &&
            steps.first().getValue("with").jsonObject == buildJsonObject {
                put("ref", enrollment.trustedCommit)
                put("persist-credentials", "false")
                put("fetch-depth", "1")
            } &&
            steps.last().keys == setOf("uses", "with") &&
            steps.last().getValue("uses").jsonPrimitive.content == upload &&
            steps.last().getValue("with").jsonObject == buildJsonObject {
                put("name", "p0v3-reviewed-job")
                put("path", "artifacts/")
                put("if-no-files-found", "error")
                put("retention-days", "7")
            } &&
            steps.drop(1).dropLast(1).all { fields ->
                fields.keys.all { it in setOf("name", "run", "shell") } &&
                    fields.containsKey("run") && fields.getValue("run").jsonPrimitive.content.length in 1..32768 &&
                    fields["shell"]?.jsonPrimitive?.content?.let { it == "bash" } != false
            }) { "Only pinned private Forgejo checkout, reviewed shell and artifact transport allowed" }
        return ForgejoRunnerWorkflowPreview.review(enrollment, ForgejoWorkflowJobShape(
            repository = enrollment.repository, workflowSha256 = enrollment.workflowSha256,
            commit = trustedCommit, runsOn = "p0v3-rootless-oci", effectiveJobImage = image,
            jobsContainerOverride = image))
    }
}
