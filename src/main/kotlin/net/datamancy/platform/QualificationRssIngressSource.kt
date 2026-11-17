package net.datamancy.platform

import java.net.URI

/** Preserve the native issuer's real ingress-control address, never the QClient network
 * or a caller-proposed private IP. C1 obtains all arguments from independent owner readbacks. */
internal object QualificationRssIngressSource {
    fun address(endpoint: String, observedIngressAddress: String, servedNetwork: String,
        servedCaSha256: String, selectedCaSha256: String,
        servedLeafSha256: String, selectedLeafSha256: String): String {
        val origin = URI(endpoint)
        require(origin.scheme == "https" && origin.port == 443 &&
            origin.host == observedIngressAddress && origin.userInfo == null &&
            origin.rawPath.isNullOrEmpty() && origin.rawQuery == null && origin.rawFragment == null &&
            servedNetwork == "ingress-control" &&
            servedCaSha256.matches(Regex("[a-f0-9]{64}")) && servedCaSha256 == selectedCaSha256 &&
            servedLeafSha256.matches(Regex("[a-f0-9]{64}")) && servedLeafSha256 == selectedLeafSha256 &&
            observedIngressAddress.matches(Regex("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) &&
            observedIngressAddress.split('.').all { it.toInt() in 0..255 } &&
            java.net.InetAddress.getByName(observedIngressAddress).isSiteLocalAddress) {
            "RSS native transport differs from verified selected Caddy ingress-control leaf/CA"
        }
        return observedIngressAddress
    }
}
