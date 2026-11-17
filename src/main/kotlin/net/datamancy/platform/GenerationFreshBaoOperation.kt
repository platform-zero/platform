package net.datamancy.platform

import kotlinx.serialization.Serializable

/** Separately sealed post-native result, NOT a field in the sealed request.
 * Written only by the same-generation stage owner after the original native
 * CID, transport issuer/leaf, initialized/unsealed readback and derived-token
 * result all agree. An intent or source declaration cannot substitute for it.
 */
@Serializable internal data class GenerationFreshBaoNativeResult(val generation: String,
    val bundleSha256: String, val operationSha256: String, val selectedMember: String,
    val selectedProcess: String, val originalCid: String, val originalNativeStageResultSha256: String,
    val issuerCaSha256: String, val servedLeafDerSha256: String,
    val originalInit: ActivationInput, val derivedKeykeeperToken: ActivationInput,
    val initializedAndUnsealedReadback: Boolean, val scope: String = "original-install") {
    fun validate(generationId: String, bundle: GenerationBundle) {
        require(generation==generationId && bundle.request.id==generation &&
            bundle.request.baoBootstrapOperation?.also { it.validate(generation) } != null &&
            bundleSha256==ReleaseLocks.sha256(kotlinx.serialization.json.Json.encodeToString(
                GenerationBundle.serializer(),bundle).toByteArray()) &&
            operationSha256==ReleaseLocks.sha256(kotlinx.serialization.json.Json.encodeToString(
                GenerationFreshBaoOperation.serializer(),bundle.request.baoBootstrapOperation!!).toByteArray()) &&
            selectedMember==bundle.members.single().member.name && selectedProcess=="bao" &&
            originalCid.matches(Regex("[a-f0-9]{64}")) &&
            listOf(originalNativeStageResultSha256,issuerCaSha256,servedLeafDerSha256,
                originalInit.sha256,derivedKeykeeperToken.sha256).all { it.matches(Regex("[a-f0-9]{64}")) } &&
            initializedAndUnsealedReadback && scope=="original-install")
    }
}

/** Pre-start declaration only. It does not assert an already-issued root or
 * scoped token, init ACK, operator share custody or an active Bao instance.
 * The original native issuer's eventual result must bind this exact authority
 * separately before any Keykeeper consumer is allowed to start.
 */
@Serializable internal data class GenerationFreshBaoOperation(val generation: String,
    val selectedProcess: String = "bao", val endpoint: String = "https://bao:8200",
    val issuer: String = "FreshOpenBaoBootstrap.issueOriginal",
    val derivedPolicy: String = "p0v3-keykeeper",
    val phase: String = "INSTALL") {
    fun validate(id: String) {
        require(generation == id && id.matches(Regex("q-[a-f0-9]{12}")) &&
            selectedProcess == "bao" && endpoint == "https://bao:8200" &&
            issuer == "FreshOpenBaoBootstrap.issueOriginal" &&
            derivedPolicy == "p0v3-keykeeper" && phase == "INSTALL") {
            "Fresh original OpenBao is a typed late issuer, not a preissued token"
        }
    }
}
