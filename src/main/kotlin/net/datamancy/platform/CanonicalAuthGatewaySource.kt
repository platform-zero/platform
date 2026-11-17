package net.datamancy.platform

import java.util.Base64
import java.util.HexFormat
import kotlinx.serialization.json.*

/** Historical auth-gateway support, not an additional selected product. The
 * private proxy authenticates via the exact original realm; Caddy must still
 * enforce its own per-request revocation/subject authorization before a route
 * can be called protected. A proxy login cookie alone is NOT that evidence.
 */
internal object CanonicalAuthGatewaySource {
    fun client(secret: String): JsonObject {
        require(secret.matches(Regex("[a-f0-9]{64}")))
        return buildJsonObject {
            put("clientId", "p0v3-edge"); put("enabled", true); put("protocol", "openid-connect")
            put("publicClient", false); put("secret", secret)
            put("standardFlowEnabled", true); put("directAccessGrantsEnabled", false)
            put("serviceAccountsEnabled", false); put("fullScopeAllowed", false)
            // OLD configure-runtime.sh attaches its owned groups scope to the
            // edge client; do not derive app RBAC from preferred_username.
            put("optionalClientScopes", buildJsonArray { add("groups") })
            put("redirectUris", buildJsonArray { add("https://keycloak-auth.datamancy.net/oauth2/callback") })
            put("webOrigins", buildJsonArray { add("https://keycloak-auth.datamancy.net") })
        }
    }

    fun inputs(clientSecret: String, cookieKeyHex: String, sessionPassword: String): Map<String, String> {
        client(clientSecret)
        require(cookieKeyHex.matches(Regex("[a-f0-9]{64}")) &&
            sessionPassword.matches(Regex("[a-f0-9]{64}")) &&
            setOf(clientSecret, cookieKeyHex, sessionPassword).size == 3)
        val cookie = Base64.getEncoder().encodeToString(HexFormat.of().parseHex(cookieKeyHex))
        return mapOf("auth-gateway.env" to """
            OAUTH2_PROXY_PROVIDER=keycloak-oidc
            OAUTH2_PROXY_OIDC_ISSUER_URL=https://auth.datamancy.net/realms/p0v3
            OAUTH2_PROXY_PROVIDER_CA_FILE=/run/secrets/identity-ca.pem
            OAUTH2_PROXY_CLIENT_ID=p0v3-edge
            OAUTH2_PROXY_CLIENT_SECRET=$clientSecret
            OAUTH2_PROXY_USER_ID_CLAIM=sub
            OAUTH2_PROXY_REDIRECT_URL=https://keycloak-auth.datamancy.net/oauth2/callback
            OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:4180
            OAUTH2_PROXY_UPSTREAMS=static://202
            OAUTH2_PROXY_EMAIL_DOMAINS=*
            OAUTH2_PROXY_COOKIE_SECRET=$cookie
            OAUTH2_PROXY_COOKIE_NAME=_p0v3_edge
            OAUTH2_PROXY_COOKIE_DOMAINS=datamancy.net,.datamancy.net
            OAUTH2_PROXY_WHITELIST_DOMAINS=datamancy.net,.datamancy.net
            OAUTH2_PROXY_SESSION_STORE_TYPE=redis
            OAUTH2_PROXY_REDIS_CONNECTION_URL=redis://auth-gateway:$sessionPassword@valkey:6379/2
            OAUTH2_PROXY_COOKIE_SECURE=true
            OAUTH2_PROXY_COOKIE_HTTPONLY=true
            OAUTH2_PROXY_COOKIE_SAMESITE=lax
            OAUTH2_PROXY_COOKIE_EXPIRE=15m
            OAUTH2_PROXY_COOKIE_REFRESH=1m
            OAUTH2_PROXY_REVERSE_PROXY=true
            OAUTH2_PROXY_SET_XAUTHREQUEST=true
            OAUTH2_PROXY_PASS_ACCESS_TOKEN=false
            OAUTH2_PROXY_PASS_AUTHORIZATION_HEADER=false
            OAUTH2_PROXY_CODE_CHALLENGE_METHOD=S256
            OAUTH2_PROXY_SKIP_PROVIDER_BUTTON=true
            OAUTH2_PROXY_SCOPE=openid profile email groups
        """.trimIndent() + "\n")
    }
}
