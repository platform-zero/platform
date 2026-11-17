package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.*

/** Original Keycloak issuer input for the *actual* first browser required-action flow.
 * This source does not assert first-use completion, issue an admin bearer, or mint a
 * PKCE receipt. C1 must invoke the real owner browser + one-use code redemption and
 * native issuer readback before supplying any native/Keykeeper case bearer. */
internal data class QualificationIdentityOriginalOwner(val subject: String,
    val originalCustody: ActivationInput, val operatorPasswordOutput: String,
    val operatorTotpOutput: String, val ownerFirstUse: Boolean)

internal object QualificationIdentityCaseInputs {
    private val generationPattern = Regex("q-[a-f0-9]{12}")
    private val passwordPattern = Regex("[a-f0-9]{64}")
    private val json = Json { ignoreUnknownKeys = false }

    /** Exact generation-scoped, non-admin client name. Its actual client UUID,
     * secret, service-account UUID and token are created/read by the selected
     * Keycloak issuer under the owner-verified native action, never here. */
    fun retirementClientName(generation: String): String {
        require(generation.matches(generationPattern))
        return "p0v3-qual-retire-${generation.removePrefix("q-")}"
    }

    /** Reads only the original immutable selected Keycloak import, never proposed
     * context, fresh target bootstrap or a caller-authored completed-owner receipt. */
    fun stageOriginalOwner(source: GenerationPin, generation: String, caseDir: Path): QualificationIdentityOriginalOwner =
        stage(source,generation,caseDir,true)

    /** Onboarding WEB after completed Keycloak WEB and all RESTORE browsers never see
     * the original temporary seed password. C1 separately supplies the completed
     * owner password/TOTP from its authenticated Keycloak WEB result/capture. */
    fun stageInheritedOwner(source: GenerationPin, generation: String, caseDir: Path): QualificationIdentityOriginalOwner =
        stage(source,generation,caseDir,false)

    private fun stage(source: GenerationPin, generation: String, caseDir: Path,
        firstUse: Boolean): QualificationIdentityOriginalOwner {
        require(generation.matches(generationPattern) && source.spec.name == "$generation-v2" &&
            source.spec.store == RuntimeStore.CANONICAL_V2 &&
            source.spec.processes.any { it.id == "keycloak" } &&
            source.spec.fragmentBinding?.resources?.containsKey("fragments/v3/keycloak/r3/fragment.yaml") == true &&
            caseDir.isAbsolute && caseDir.normalize() == caseDir)
        val bytes = ReleasePrivateFiles.read(PrivateDeployment.BASE.resolve(source.spec.name)
            .resolve("identity-realm.json"),1048576)
        require(ReleaseLocks.sha256(bytes) == source.inputHashes.getValue("identity-realm.json"))
        val owner = extractOriginalOwner(bytes.decodeToString(throwOnInvalidSequence = true),generation)
        val custody = caseDir.resolve("owner-proofs/identity-original-owner.json")
        val original = buildJsonObject {
            put("subject",owner.first); put("username","owner")
            if (firstUse) put("temporaryPassword",owner.second)
        }.toString().encodeToByteArray()
        ReleasePrivateFiles.save(custody,original)
        val root = custody.parent
        return QualificationIdentityOriginalOwner(owner.first,ActivationInput(custody.toString(),
            ReleaseLocks.sha256(original)),root.resolve("identity-operator-password.txt").toString(),
            root.resolve("identity-browser-totp.json").toString(),firstUse)
    }

    /** Pure check of the exact original account and fixed registered human S256 client.
     * This is authority to attempt first use, NOT evidence that first use succeeded. */
    internal fun extractOriginalOwner(realmJson: String, generation: String): Pair<String,String> {
        require(generation.matches(generationPattern))
        val realm = json.parseToJsonElement(realmJson).jsonObject
        require(realm.getValue("realm").jsonPrimitive.content == "p0v3" &&
            realm.getValue("registrationAllowed").jsonPrimitive.boolean == false &&
            realm.getValue("sslRequired").jsonPrimitive.content == "all")
        val owner = realm.getValue("users").jsonArray.map { it.jsonObject }.single {
            it.getValue("username").jsonPrimitive.content == "owner" }
        val id = owner.getValue("id").jsonPrimitive.content
        val password = owner.getValue("credentials").jsonArray.single().jsonObject
        val client = realm.getValue("clients").jsonArray.map { it.jsonObject }.single {
            it.getValue("clientId").jsonPrimitive.content == "identity-controller" }
        require(java.util.UUID.fromString(id).toString() == id &&
            owner.getValue("enabled").jsonPrimitive.boolean &&
            owner.getValue("requiredActions").jsonArray.map { it.jsonPrimitive.content }.toSet() ==
                setOf("UPDATE_PASSWORD", "CONFIGURE_TOTP") &&
            password.getValue("type").jsonPrimitive.content == "password" &&
            password.getValue("temporary").jsonPrimitive.boolean &&
            password.getValue("value").jsonPrimitive.content.matches(passwordPattern) &&
            client == IdentityRuntime.canonicalOperatorClient(generation)) {
            "Original Keycloak owner first-use/S256 source is not selected"
        }
        return id to password.getValue("value").jsonPrimitive.content
    }
}
