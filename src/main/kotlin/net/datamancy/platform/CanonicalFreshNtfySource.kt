package net.datamancy.platform

/** Pinned ntfy v2.35's declarative auth provisioner: no OLD database, passwords or
 * Keycloak password grant. Browsers use a separately scoped, read-only server
 * token after OIDC group admission. Native Basic/Bearer use ntfy's own new
 * users, token custody and topic ACLs, never a spoofable remote-user header.
 */
internal data class FreshNtfyGrants(val ssoToken: String, val ssoPasswordHash: String,
    val publisherToken: String, val publisherPasswordHash: String,
    val ownerToken: String, val ownerPasswordHash: String) {
    init {
        val tokens = listOf(ssoToken, publisherToken, ownerToken)
        val hashes = listOf(ssoPasswordHash, publisherPasswordHash, ownerPasswordHash)
        require(tokens.distinct().size == tokens.size && tokens.all { it.matches(Regex("tk_[A-Za-z0-9]{32}")) } &&
            hashes.distinct().size == hashes.size && hashes.all {
                it.matches(Regex("\\$2[aby]\\$1[234]\\$[./A-Za-z0-9]{53}")) })
    }
}
internal object CanonicalFreshNtfySource {
    fun inputs(grants: FreshNtfyGrants): Map<String, String> = mapOf(
        "ntfy-config.yml" to """
            listen-http: ":8080"
            base-url: "https://ntfy.datamancy.net"
            cache-file: /var/cache/ntfy/cache.db
            attachment-cache-dir: /var/cache/ntfy/attachments
            auth-file: /var/cache/ntfy/auth.db
            auth-default-access: deny-all
            enable-signup: false
            enable-login: false
            auth-users:
              - "ntfy-sso:${grants.ssoPasswordHash}:user"
              - "ntfy-publisher:${grants.publisherPasswordHash}:user"
              - "ntfy-owner:${grants.ownerPasswordHash}:user"
            auth-access:
              - "ntfy-sso:p0-owner-*:deny"
              - "ntfy-sso:*:read-only"
              - "ntfy-publisher:webservices-alerts:write-only"
              - "ntfy-publisher:webservices-critical:write-only"
              - "ntfy-publisher:webservices-warnings:write-only"
              - "ntfy-owner:p0-owner-*:read-write"
            auth-tokens:
              - "ntfy-sso:${grants.ssoToken}:Browser OIDC read-only"
              - "ntfy-publisher:${grants.publisherToken}:Alert publisher"
              - "ntfy-owner:${grants.ownerToken}:Native owner topic"
        """.trimIndent() + "\n")
}
