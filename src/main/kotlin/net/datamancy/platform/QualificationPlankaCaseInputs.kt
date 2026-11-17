package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.*

/** Only the selected r2 original one-shot may supply Planka's two real principals.
 * Bootstrap never enters a case/QClient and a stopped RESTORE never enrolls again. */
internal object QualificationPlankaCaseInputs {
    private val json = Json { ignoreUnknownKeys = false }
    private val hash = Regex("[a-f0-9]{64}")
    fun issue(caseDir: Path, target: GenerationPin, source: GenerationPin,
        originalGeneration: String, phase: String, original: JsonObject,
        sourceReceipt: Path? = null): Map<String,JsonElement> {
        require(phase in setOf("INSTALL","RESTORE") && target.spec.store == RuntimeStore.CANONICAL_V2 &&
            target.spec.name.endsWith("-v2") && source.spec.name == "$originalGeneration-v2" &&
            source.spec.fragmentBinding?.resources?.containsKey(
                "fragments/v3/planka/r2/fragment.yaml") == true &&
            source.spec.processes.any { it.id == "planka-enroll" && it.oneShot } &&
            (phase != "RESTORE" || target.spec.processes.none { it.id == "planka-enroll" }))
        val origin = PrivateDeployment.BASE.resolve(source.spec.name).resolve("planka-enrollment.env")
        val raw = ReleasePrivateFiles.read(origin,8192)
        require(ReleaseLocks.sha256(raw) == source.inputHashes.getValue("planka-enrollment.env"))
        val fields = raw.decodeToString(throwOnInvalidSequence = true).trimEnd('\n').lines()
            .map { it.split('=',limit = 2).also { parts -> require(parts.size == 2) } }
        val values = fields.associate { it[0] to it[1] }
        require(values.size == 5 && values.keys == setOf("PLANKA_ENROLL_GENERATION",
            "PLANKA_TERMS_SHA256","PLANKA_BOOTSTRAP_PASSWORD","PLANKA_OWNER_PASSWORD",
            "PLANKA_OUTSIDER_PASSWORD") && values.getValue("PLANKA_ENROLL_GENERATION") == originalGeneration &&
            listOf("PLANKA_TERMS_SHA256","PLANKA_BOOTSTRAP_PASSWORD","PLANKA_OWNER_PASSWORD",
                "PLANKA_OUTSIDER_PASSWORD").all { hash.matches(values.getValue(it)) } &&
            values.values.filter(hash::matches).size == 4 &&
            listOf("PLANKA_BOOTSTRAP_PASSWORD","PLANKA_OWNER_PASSWORD","PLANKA_OUTSIDER_PASSWORD")
                .map(values::getValue).toSet().size == 3 &&
            values.getValue("PLANKA_TERMS_SHA256") == ReleaseLocks.sha256(
                PlankaRuntime.FIXTURE_TERMS.encodeToByteArray()))
        val current = QualificationMatrixActor.selectedProcess(target.spec,target.runtimeFingerprint,"planka")
        val name = "p0v3-live-${target.spec.name}-planka"
        val reply = PrivateRootfulCommands(30,target.spec.store).run(listOf("exec","--user","1000",
            name,"cat","/app/data/actor-enrollment/completed.json"))
        require(reply.exitCode == 0 && reply.output.length in 1..8192 &&
            current.getValue("containerId").jsonPrimitive.content.matches(hash))
        val completed = json.parseToJsonElement(reply.output).jsonObject
        require(completed.keys == setOf("schemaVersion","generation","bootstrapId","ownerId",
            "outsiderId","bootstrapSha256","ownerSha256","outsiderSha256","ownerRole",
            "outsiderRole","outsiderUsersStatus") && completed.getValue("schemaVersion").jsonPrimitive.int == 1 &&
            completed.getValue("generation").jsonPrimitive.content == originalGeneration &&
            completed.getValue("bootstrapSha256").jsonPrimitive.content == ReleaseLocks.sha256(
                values.getValue("PLANKA_BOOTSTRAP_PASSWORD").encodeToByteArray()) &&
            completed.getValue("ownerSha256").jsonPrimitive.content == ReleaseLocks.sha256(
                values.getValue("PLANKA_OWNER_PASSWORD").encodeToByteArray()) &&
            completed.getValue("outsiderSha256").jsonPrimitive.content == ReleaseLocks.sha256(
                values.getValue("PLANKA_OUTSIDER_PASSWORD").encodeToByteArray()) &&
            completed.getValue("ownerRole").jsonPrimitive.content == "admin" &&
            completed.getValue("outsiderRole").jsonPrimitive.content == "boardUser" &&
            completed.getValue("outsiderUsersStatus").jsonPrimitive.int == 403 &&
            listOf("bootstrapId","ownerId","outsiderId").map {
                completed.getValue(it).jsonPrimitive.content.also { id -> require(id.matches(Regex("[0-9]{1,20}"))) }
            }.toSet().size == 3)
        if (phase == "RESTORE") {
            requireNotNull(sourceReceipt)
            require(ReleasePrivateFiles.read(sourceReceipt,8192).decodeToString(
                throwOnInvalidSequence = true) == reply.output) {
                "Imported Planka enrollment must be the same original durable source receipt"
            }
        } else require(sourceReceipt == null)
        val proof = caseDir.resolve("owner-proofs/planka-original-enrollment.json")
        ReleasePrivateFiles.save(proof,reply.output.encodeToByteArray())
        val credentials = caseDir.resolve("owner-proofs/planka-original-credentials.json")
        ReleasePrivateFiles.save(credentials,buildJsonObject {
            putJsonObject("owner") {
                put("username","p0v3_owner"); put("password",values.getValue("PLANKA_OWNER_PASSWORD"))
            }
            putJsonObject("outsider") {
                put("username","p0v3_outsider"); put("password",values.getValue("PLANKA_OUTSIDER_PASSWORD"))
            }
        }.toString().encodeToByteArray())
        require(original["credentials"] == null && original["originalPlankaEnrollmentFile"] == null)
        return mapOf("credentials" to JsonPrimitive(if (caseDir.fileName.toString().endsWith("--web--browser"))
            "/case/owner-proofs/planka-original-credentials.json" else credentials.toString()),
            "originalPlankaEnrollmentFile" to JsonPrimitive(if (caseDir.fileName.toString().endsWith("--web--browser"))
                "/case/owner-proofs/planka-original-enrollment.json" else proof.toString()),
            "originalPlankaEnrollmentSha256" to JsonPrimitive(ReleaseLocks.sha256(reply.output.encodeToByteArray())))
    }
}
