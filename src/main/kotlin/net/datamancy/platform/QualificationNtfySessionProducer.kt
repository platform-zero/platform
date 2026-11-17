package net.datamancy.platform

import java.nio.file.Path
import java.time.Instant
import java.util.UUID
import kotlinx.serialization.json.*

/** Post-exit verification of ONE already-run, confined ntfy WEB login and UI journey.
 * The browser obtains the cookie and observes the Keycloak and auth-gateway
 * responses. This producer never authenticates, invents a session, or retries
 * an uncertain login. CASE_PREPARE must not require these future files. */
internal object QualificationNtfySessionProducer {
    private val json = Json { ignoreUnknownKeys = false }
    private val hex = Regex("[a-f0-9]{64}")
    private val generation = Regex("q-[a-f0-9]{12}")
    private const val web = "ntfy.datamancy.net"
    private const val issuer = "https://auth.datamancy.net/realms/p0v3"
    private const val gateway = "keycloak-auth.datamancy.net"

    private fun pinned(input: ActivationInput, path: Path, limit: Int = 65536): ByteArray {
        require(Path.of(input.path) == path && input.sha256.matches(hex))
        return ReleasePrivateFiles.read(path, limit).also {
            require(ReleaseLocks.sha256(it) == input.sha256) { "Changed ntfy owner file" }
        }
    }

    /** Same-owner evidence, not a caller's claim that a cookie implies GROUP. */
    internal fun validateObserved(intent: JsonObject, issuerResult: JsonObject,
        observation: JsonObject, session: JsonObject, sourceSubject: String,
        generationId: String, bundleSha256: String, invocationId: String,
        intentSha: String, issuerSha: String, sessionSha: String,
        issuerLeaf: String, gatewayLeaf: String) {
        require(intent.keys == setOf("schemaVersion", "invocationId", "generationId", "bundleSha256",
            "caseIntentSha256", "phase", "ownerSubject", "ownerCustodySha256",
            "completedPasswordSha256", "completedTotpSha256", "host", "issuerHost", "gatewayHost",
            "operation") && intent.getValue("schemaVersion").jsonPrimitive.int == 1 &&
            intent.getValue("invocationId").jsonPrimitive.content == invocationId &&
            intent.getValue("generationId").jsonPrimitive.content == generationId &&
            intent.getValue("bundleSha256").jsonPrimitive.content == bundleSha256 &&
            intent.getValue("ownerSubject").jsonPrimitive.content == sourceSubject &&
            intent.getValue("host").jsonPrimitive.content == web &&
            intent.getValue("issuerHost").jsonPrimitive.content == "auth.datamancy.net" &&
            intent.getValue("gatewayHost").jsonPrimitive.content == gateway &&
            intent.getValue("operation").jsonPrimitive.content == "ORIGINAL_OWNER_OIDC_GROUP_LOGIN_ONCE" &&
            intent.getValue("caseIntentSha256").jsonPrimitive.content.matches(hex))
        require(issuerResult.keys == setOf("schemaVersion", "invocationId", "generationId",
            "bundleSha256", "issuer", "expectedSubject", "username", "loginIntentSha256",
            "callbackUrlSha256", "accountPageSha256", "accountStatus", "issuerLeafSha256") &&
            issuerResult.getValue("schemaVersion").jsonPrimitive.int == 1 &&
            issuerResult.getValue("invocationId").jsonPrimitive.content == invocationId &&
            issuerResult.getValue("generationId").jsonPrimitive.content == generationId &&
            issuerResult.getValue("bundleSha256").jsonPrimitive.content == bundleSha256 &&
            issuerResult.getValue("issuer").jsonPrimitive.content == issuer &&
            issuerResult.getValue("expectedSubject").jsonPrimitive.content == sourceSubject &&
            issuerResult.getValue("username").jsonPrimitive.content == "owner" &&
            issuerResult.getValue("loginIntentSha256").jsonPrimitive.content == intentSha &&
            issuerResult.getValue("accountStatus").jsonPrimitive.int == 200 &&
            issuerResult.getValue("issuerLeafSha256").jsonPrimitive.content == issuerLeaf &&
            listOf("callbackUrlSha256", "accountPageSha256").all {
                issuerResult.getValue(it).jsonPrimitive.content.matches(hex)
            }) { "Original selected Keycloak OIDC result absent" }
        require(observation.keys == setOf("schemaVersion", "invocationId", "generationId",
            "bundleSha256", "host", "gatewayHost", "gatewayPath", "issuer", "httpStatus",
            "subject", "username", "groups", "gatewayLeafSha256", "issuerResultSha256",
            "sessionSha256", "loginIntentSha256") &&
            observation.getValue("schemaVersion").jsonPrimitive.int == 1 &&
            observation.getValue("invocationId").jsonPrimitive.content == invocationId &&
            observation.getValue("generationId").jsonPrimitive.content == generationId &&
            observation.getValue("bundleSha256").jsonPrimitive.content == bundleSha256 &&
            observation.getValue("host").jsonPrimitive.content == web &&
            observation.getValue("gatewayHost").jsonPrimitive.content == gateway &&
            observation.getValue("gatewayPath").jsonPrimitive.content == "/oauth2/auth" &&
            observation.getValue("issuer").jsonPrimitive.content == issuer &&
            observation.getValue("httpStatus").jsonPrimitive.int == 202 &&
            observation.getValue("subject").jsonPrimitive.content == sourceSubject &&
            observation.getValue("username").jsonPrimitive.content == "owner" &&
            observation.getValue("gatewayLeafSha256").jsonPrimitive.content == gatewayLeaf &&
            observation.getValue("issuerResultSha256").jsonPrimitive.content == issuerSha &&
            observation.getValue("sessionSha256").jsonPrimitive.content == sessionSha &&
            observation.getValue("loginIntentSha256").jsonPrimitive.content == intentSha &&
            observation.getValue("groups").jsonArray.map { it.jsonPrimitive.content }.let {
                it.isNotEmpty() && it.distinct().size == it.size &&
                    it.any { group -> group in setOf("admins", "operators") }
            }) { "Real selected gateway did not admit original subject and group" }
        val cookies = session.getValue("cookies").jsonArray.map { it.jsonObject }
        require(session.keys == setOf("cookies", "origins") && session.getValue("origins").jsonArray.isEmpty() &&
            cookies.isNotEmpty() && cookies.all { cookie ->
                cookie.getValue("name").jsonPrimitive.content == "_p0v3_edge" &&
                    cookie.getValue("domain").jsonPrimitive.content in setOf("datamancy.net", ".datamancy.net") &&
                    cookie.getValue("path").jsonPrimitive.content == "/" &&
                    cookie.getValue("secure").jsonPrimitive.boolean &&
                    cookie.getValue("httpOnly").jsonPrimitive.boolean &&
                    cookie.getValue("sameSite").jsonPrimitive.content == "Lax" &&
                    cookie.getValue("value").jsonPrimitive.content.isNotBlank() &&
                    cookie.getValue("expires").jsonPrimitive.double > Instant.now().epochSecond
            } && cookies.map { it.getValue("name").jsonPrimitive.content }.distinct().size == cookies.size) {
            "No real selected original-host-applicable secure HttpOnly GROUP cookie"
        }
    }

    fun capture(caseDir: Path, target: GenerationBundle, selected: GenerationPin,
        bundleSha256: String, phase: String, invocationId: String, caseIntentSha256: String,
        originalOwner: QualificationIdentityOriginalOwner, completedPassword: ActivationInput,
        completedTotp: ActivationInput, qclientRunReceipt: ActivationInput,
        loginIntent: ActivationInput, issuerResult: ActivationInput,
        gatewayObservation: ActivationInput, browserSession: ActivationInput): NtfyGroupOwnerReadback {
        ReleasePrivateFiles.directory(caseDir)
        val id = target.request.id
        require(id.matches(generation) && bundleSha256.matches(hex) && caseIntentSha256.matches(hex) &&
            invocationId.matches(Regex("[A-Za-z0-9_-]{1,128}")) && phase in setOf("INSTALL", "RESTORE") &&
            caseDir.fileName.toString() == "ntfy--workflow--web--browser" &&
            target.members.single() == selected && selected.spec.name == "$id-v2" &&
            selected.spec.store == RuntimeStore.CANONICAL_V2 &&
            selected.spec.fragmentBinding?.phase == phase &&
            selected.spec.fragmentBinding?.resources?.containsKey("fragments/v3/canonical/r10/manifest.yaml") == true &&
            setOf("ntfy", "keycloak", "auth-gateway", "caddy").all { service ->
                selected.spec.processes.any { it.id == service }
            } && ReleaseLocks.sha256(ReleasePrivateFiles.read(
                GenerationRuntime.BASE.resolve(id).resolve("bundle.json"),4194304)) == bundleSha256)
        val caseIntent = ReleasePrivateFiles.read(caseDir.resolve("intent.json"),65536)
        require(ReleaseLocks.sha256(caseIntent) == caseIntentSha256)
        val bound = json.parseToJsonElement(caseIntent.decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(bound.getValue("invocationId").jsonPrimitive.content == invocationId &&
            bound.getValue("serviceId").jsonPrimitive.content == "ntfy" &&
            bound.getValue("surface").jsonPrimitive.content == "WEB" &&
            bound.getValue("variant").jsonPrimitive.content == "BROWSER" &&
            bound.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content == phase &&
            bound.getValue("binding").jsonObject.getValue("generationId").jsonPrimitive.content == id)
        val context = json.parseToJsonElement(ReleasePrivateFiles.read(caseDir.resolve("context.json"),4194304)
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(ReleaseLocks.sha256(ReleasePrivateFiles.read(caseDir.resolve("context.json"),4194304)) ==
            bound.getValue("contextSha256").jsonPrimitive.content &&
            context.getValue("ntfySelectedHost").jsonPrimitive.content == web &&
            context.getValue("ntfyIssuerLeafSha256").jsonPrimitive.content.matches(hex) &&
            context.getValue("ntfyGatewayLeafSha256").jsonPrimitive.content.matches(hex))
        require(!originalOwner.ownerFirstUse && UUID.fromString(originalOwner.subject).toString() ==
            originalOwner.subject && originalOwner.operatorPasswordOutput == completedPassword.path &&
            originalOwner.operatorTotpOutput == completedTotp.path)
        val proofs = caseDir.resolve("owner-proofs")
        val custody = pinned(originalOwner.originalCustody,proofs.resolve("identity-original-owner.json"))
        val original = json.parseToJsonElement(custody.decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(original.keys == setOf("subject", "username") &&
            original.getValue("subject").jsonPrimitive.content == originalOwner.subject &&
            original.getValue("username").jsonPrimitive.content == "owner")
        require(pinned(completedPassword,proofs.resolve("identity-operator-password.txt"),8192)
            .decodeToString(throwOnInvalidSequence=true).matches(Regex("[a-f0-9]{64}")))
        val totp = json.parseToJsonElement(pinned(completedTotp,proofs.resolve("identity-browser-totp.json"),8192)
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(totp.keys == setOf("seed","algorithm") && totp.getValue("algorithm").jsonPrimitive.content == "sha256" &&
            totp.getValue("seed").jsonPrimitive.content.matches(Regex("[A-Z2-7]{16,128}")))
        val completion = json.parseToJsonElement(pinned(qclientRunReceipt,GenerationRuntime.BASE.resolve(id)
            .resolve("qualification-client/$invocationId/completion.json"))
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(completion.keys == setOf("invocationId", "containerId", "imageId", "finishedAt", "exitCode") &&
            completion.getValue("invocationId").jsonPrimitive.content == invocationId &&
            completion.getValue("exitCode").jsonPrimitive.int == 0 &&
            completion.getValue("containerId").jsonPrimitive.content.matches(hex) &&
            completion.getValue("imageId").jsonPrimitive.content.matches(hex) &&
            completion.getValue("finishedAt").jsonPrimitive.content.isNotBlank())
        val gate = json.parseToJsonElement(ReleasePrivateFiles.read(caseDir.resolve("qualification-client-gate.json"),65536)
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(gate.getValue("invocationId").jsonPrimitive.content == invocationId &&
            gate.getValue("nativeContainerId").jsonPrimitive.content ==
                completion.getValue("containerId").jsonPrimitive.content)
        val attempt = json.parseToJsonElement(pinned(loginIntent,caseDir.resolve("ntfy-web-login.intent.json"))
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(attempt.getValue("caseIntentSha256").jsonPrimitive.content == caseIntentSha256 &&
            attempt.getValue("phase").jsonPrimitive.content == phase &&
            attempt.getValue("ownerCustodySha256").jsonPrimitive.content == originalOwner.originalCustody.sha256 &&
            attempt.getValue("completedPasswordSha256").jsonPrimitive.content == completedPassword.sha256 &&
            attempt.getValue("completedTotpSha256").jsonPrimitive.content == completedTotp.sha256)
        val issued = json.parseToJsonElement(pinned(issuerResult,caseDir.resolve("ntfy-issuer-result.json"))
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
        val observed = json.parseToJsonElement(pinned(gatewayObservation,
            caseDir.resolve("ntfy-gateway-observation.json")).decodeToString(throwOnInvalidSequence=true)).jsonObject
        val session = json.parseToJsonElement(pinned(browserSession,caseDir.resolve("ntfy-browser-session.json"))
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
        validateObserved(attempt,issued,observed,session,originalOwner.subject,id,bundleSha256,
            invocationId,loginIntent.sha256,issuerResult.sha256,browserSession.sha256,
            context.getValue("ntfyIssuerLeafSha256").jsonPrimitive.content,
            context.getValue("ntfyGatewayLeafSha256").jsonPrimitive.content)
        val groups = observed.getValue("groups").jsonArray.map { it.jsonPrimitive.content }
        val admissionBytes = buildJsonObject {
            put("schemaVersion",1); put("generationId",id); put("bundleSha256",bundleSha256)
            put("host",web); put("serviceId","ntfy"); put("subject",originalOwner.subject)
            put("groups",groups.first { it in setOf("admins","operators") })
            put("invocationId",invocationId); put("caseIntentSha256",caseIntentSha256)
            put("gatewayObservationSha256",gatewayObservation.sha256)
            put("sessionSha256",browserSession.sha256); put("issuerResultSha256",issuerResult.sha256)
            put("qclientCompletionSha256",qclientRunReceipt.sha256)
        }.toString().encodeToByteArray()
        val admissionPath = caseDir.resolve("ntfy-group-admission.json")
        ReleasePrivateFiles.save(admissionPath,admissionBytes) // create-new; uncertain completion is never adopted
        val readback = NtfyGroupOwnerReadback(id,bundleSha256,web,browserSession,
            ActivationInput(admissionPath.toString(),ReleaseLocks.sha256(admissionBytes)),issuerResult)
        QualificationNtfyGroupReadback.verify(readback,id,bundleSha256)
        return readback
    }
}
