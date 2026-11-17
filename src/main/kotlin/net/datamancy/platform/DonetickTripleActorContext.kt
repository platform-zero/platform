package net.datamancy.platform

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

/** r9 original-case interface. Native grants and issuer sign-in grants are different secrets.
 * GROUP-authorized app non-member never aliases the separately gateway-denied outsider. */
internal object DonetickTripleActorContext {
    const val ownerNative = "ownerCredentialFile"
    const val appNative = "appNonMemberCredentialFile"
    const val gatewayNative = "outsiderCredentialFile"
    const val ownerSso = "ownerSsoCredentialFile"
    const val appSso = "appNonMemberSsoCredentialFile"
    const val gatewaySso = "gatewayOutsiderSsoCredentialFile"
    const val appSubject = "appNonMemberSubject"
    const val gatewaySubject = "gatewayOutsiderSubject"
    const val ownerIssuerUuid = "ownerIssuerSubjectUuid"
    const val appIssuerUuid = "appNonMemberIssuerSubjectUuid"
    const val gatewayIssuerUuid = "gatewayOutsiderIssuerSubjectUuid"
    val issuerUuidFields = setOf(ownerIssuerUuid, appIssuerUuid, gatewayIssuerUuid)
    val credentialFields = setOf(ownerNative, appNative, gatewayNative, ownerSso, appSso, gatewaySso)
    fun requireContext(original: JsonObject) {
        require(original.keys.containsAll(credentialFields + issuerUuidFields + setOf(appSubject, gatewaySubject))) {
            "Original Donetick triple-actor context lacks distinct native/issuer grants"
        }
        require(credentialFields.map { original.getValue(it).jsonPrimitive.content }.toSet().size == 6 &&
            original.getValue(appSubject).jsonPrimitive.content == "app-nonmember" &&
            original.getValue(gatewaySubject).jsonPrimitive.content == "outsider" &&
            issuerUuidFields.map { field ->
                val raw = original.getValue(field).jsonPrimitive.content
                java.util.UUID.fromString(raw).toString().also { require(it == raw) }
            }.toSet().size == 3) {
            "Donetick GROUP app non-member cannot alias gateway outsider or another grant"
        }
    }
}
