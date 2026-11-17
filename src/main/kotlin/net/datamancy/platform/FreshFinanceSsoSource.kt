package net.datamancy.platform

import java.util.Base64
import java.util.HexFormat
import kotlinx.serialization.json.*

/** Fresh confidential PKCE browser clients, separate from Keycloak's edge
 * gateway and from Firefly's native Passport bearer transport. Never reuse OLD
 * client secrets, sessions or finance account email as a subject identity.
 */
internal object FreshFinanceSsoSource {
    fun client(id: String, origin: String, secret: String): JsonObject {
        require(id in setOf("firefly-sso", "firefly-importer-sso") &&
            origin == if (id == "firefly-sso") "https://firefly.datamancy.net" else
                "https://firefly-importer.datamancy.net")
        require(secret.matches(Regex("[a-f0-9]{64}")))
        return buildJsonObject {
            put("clientId", id); put("enabled", true); put("protocol", "openid-connect")
            put("publicClient", false); put("secret", secret)
            put("standardFlowEnabled", true); put("directAccessGrantsEnabled", false)
            put("serviceAccountsEnabled", false); put("fullScopeAllowed", false)
            put("redirectUris", buildJsonArray { add("$origin/oauth2/callback") })
            put("webOrigins", buildJsonArray { add(origin) })
            put("optionalClientScopes", buildJsonArray { add("groups") })
            put("attributes", buildJsonObject { put("pkce.code.challenge.method", "S256") })
        }
    }

    fun inputs(id: String, origin: String, clientSecret: String, cookieKey: String, upstream: String): String {
        client(id, origin, clientSecret)
        require(cookieKey.matches(Regex("[a-f0-9]{64}")) && cookieKey != clientSecret &&
            upstream == if (id == "firefly-sso") "http://firefly:8080/" else "http://firefly-importer:8080/")
        val cookie = Base64.getEncoder().encodeToString(HexFormat.of().parseHex(cookieKey))
        return """
            OAUTH2_PROXY_PROVIDER=keycloak-oidc
            OAUTH2_PROXY_OIDC_ISSUER_URL=https://auth.datamancy.net/realms/p0v3
            OAUTH2_PROXY_PROVIDER_CA_FILE=/run/secrets/identity-ca.pem
            OAUTH2_PROXY_CLIENT_ID=$id
            OAUTH2_PROXY_CLIENT_SECRET=$clientSecret
            OAUTH2_PROXY_USER_ID_CLAIM=sub
            OAUTH2_PROXY_OIDC_GROUPS_CLAIM=groups
            OAUTH2_PROXY_ALLOWED_GROUPS=admins,operators,users
            OAUTH2_PROXY_REDIRECT_URL=$origin/oauth2/callback
            OAUTH2_PROXY_HTTP_ADDRESS=0.0.0.0:4180
            OAUTH2_PROXY_UPSTREAMS=$upstream
            OAUTH2_PROXY_EMAIL_DOMAINS=*
            OAUTH2_PROXY_COOKIE_SECRET=$cookie
            OAUTH2_PROXY_COOKIE_NAME=__Host-${id.replace('-', '_')}
            OAUTH2_PROXY_COOKIE_SECURE=true
            OAUTH2_PROXY_COOKIE_HTTPONLY=true
            OAUTH2_PROXY_COOKIE_SAMESITE=lax
            OAUTH2_PROXY_COOKIE_PATH=/
            OAUTH2_PROXY_COOKIE_EXPIRE=15m
            OAUTH2_PROXY_COOKIE_REFRESH=1m
            OAUTH2_PROXY_REVERSE_PROXY=true
            OAUTH2_PROXY_PASS_USER_HEADERS=true
            OAUTH2_PROXY_PASS_BASIC_AUTH=false
            OAUTH2_PROXY_PASS_AUTHORIZATION_HEADER=false
            OAUTH2_PROXY_PASS_ACCESS_TOKEN=false
            OAUTH2_PROXY_SKIP_AUTH_STRIP_HEADERS=false
            OAUTH2_PROXY_SKIP_PROVIDER_BUTTON=true
            OAUTH2_PROXY_CODE_CHALLENGE_METHOD=S256
            OAUTH2_PROXY_SCOPE=openid profile email groups
            OAUTH2_PROXY_REQUEST_LOGGING=false
            OAUTH2_PROXY_AUTH_LOGGING=false
        """.trimIndent() + "\n"
    }
}
