package net.datamancy.platform

import kotlinx.serialization.Serializable

/** A pre-start declaration of WHO produces the post-start original result.
 * No expected status receipt, digest, credential or issuer CA is forged here.
 * Issuance separately consumes the result-hashed artifact after native cases.
 */
@Serializable internal data class OriginalGatewayDenialProducer(
    val caseKey: String = "donetick--workflow--headless--native",
    val artifact: String = "donetick-gateway-denial-proof.json",
    val phase: String = "INSTALL",
    val host: String = "donetick.datamancy.net",
    val subject: String = "outsider",
    val expectedStatus: Int = 403) {
    fun validate() {
        require(this == OriginalGatewayDenialProducer()) {
            "Original GROUP denial must be produced by the selected native Donetick case after startup"
        }
    }
}
