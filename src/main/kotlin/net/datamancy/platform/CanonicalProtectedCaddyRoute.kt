package net.datamancy.platform

import kotlinx.serialization.json.*

/** Adapted from the pinned OLD Caddyfile's keycloak_auth/keycloak_group_allow
 * snippets (Caddyfile sha256:cd5297dd239b573ea677539a61415a21cd0ed9d32917b064120ea640862775e6).
 * This controls only OLD group-protected hosts; native-authenticated
 * protocols keep their own route policy. An absent, empty or malformed group
 * (or absent authenticated subject) NEVER falls through to the app proxy.
 * The private OIDC gateway checks its SESSION on each request; that is NOT
 * an immediate Keycloak group-revocation guarantee. Its cached session may
 * retain older claims until refresh/re-authentication. A live group removal
 * needs separately evidenced session invalidation before immediate denial can
 * be asserted.
 */
internal object CanonicalProtectedCaddyRoute {
    private val groups = mapOf(
        "kopia" to "admins|operators", "prometheus" to "admins|operators",
        "alerts" to "admins|operators", "grafana" to "admins|operators",
        "vaultwarden" to "admins|operators|users", "huly" to "admins|operators|developers",
        "donetick" to "users|operators|admins", "erpnext" to "admins|operators",
        "seafile" to "admins|operators|users", "portal" to "admins|operators|users",
        "jupyterhub" to "admins|operators|developers", "homeassistant" to "admins|operators|users",
        "ntfy" to "admins|operators", "models" to "admins|operators|agents",
        "websearch" to "admins|operators|agents", "search" to "admins|operators|agents",
        "pipeline" to "admins|operators", "control" to "admins|operators|users")
    private val denied = buildJsonObject { put("handler", "static_response"); put("status_code", 403) }
    // The OLD Caddyfile delegates these precise paths to the application's
    // own token/JWT/session authentication, never to a browser SSO group.
    private val nativePaths = mapOf(
        "seafile" to listOf("/seafhttp/*", "/onlyoffice/editor-callback", "/onlyoffice/editor-callback/*"),
        "homeassistant" to listOf("/api/webhook/*"),
        "jupyterhub" to listOf("/hub/api/*", "/user/*"))
    private val stripped = listOf("Remote-User", "Remote-Groups", "X-Remote-User", "X-Remote-Groups",
        "X-Webservices-SSO-Subject", "X-Webservices-SSO-Issuer", "X-Auth-Request-User",
        "X-Auth-Request-Groups", "Remote_User", "Remote_Groups", "X_Remote_User",
        "X_Remote_Groups", "X_Webservices_SSO_Subject", "X_Webservices_SSO_Issuer",
        "X_Auth_Request_User", "X_Auth_Request_Groups")
    fun groupPolicy(host: String): String? = groups[host.substringBefore(".datamancy.net")]
        ?.takeIf { host == "${host.substringBefore(".datamancy.net")}.datamancy.net" }

    fun guarded(host: String, generation: String, upstream: JsonObject): JsonObject {
        val policy = requireNotNull(groupPolicy(host)) { "Host lacks OLD shared group policy" }
        require(generation.matches(Regex("q-[a-f0-9]{12}")) && upstream["handler"] == JsonPrimitive("reverse_proxy"))
        val auth = buildJsonObject {
            put("handler", "reverse_proxy")
            put("upstreams", buildJsonArray { add(buildJsonObject {
                put("dial", "p0v3-live-$generation-auth-gateway:4180")
            }) })
            put("rewrite", buildJsonObject { put("method", "GET"); put("uri", "/oauth2/auth") })
            put("headers", buildJsonObject { put("request", buildJsonObject {
                put("delete", buildJsonArray { add("Authorization") })
                put("set", buildJsonObject {
                    put("X-Forwarded-Method", buildJsonArray { add("{http.request.method}") })
                    put("X-Forwarded-Uri", buildJsonArray { add("{http.request.uri}") })
                })
            }) })
            put("handle_response", buildJsonArray { add(buildJsonObject {
                put("match", buildJsonObject { put("status_code", buildJsonArray { add(2) }) })
                put("routes", buildJsonArray {
                    add(buildJsonObject { put("handle", buildJsonArray { add(buildJsonObject { put("handler", "vars") }) }) })
                    add(buildJsonObject { put("handle", buildJsonArray { add(buildJsonObject {
                        put("handler", "headers"); put("request", buildJsonObject { put("set", buildJsonObject {
                            put("Remote-Groups", buildJsonArray { add("{http.reverse_proxy.header.X-Auth-Request-Groups}") })
                            put("X-Webservices-SSO-Subject", buildJsonArray { add("{http.reverse_proxy.header.X-Auth-Request-User}") })
                        }) })
                    }) }) })
                })
            }) })
        }
        return buildJsonObject {
            put("handler", "subroute")
            put("routes", buildJsonArray {
                add(buildJsonObject { put("handle", buildJsonArray {
                    add(buildJsonObject { put("handler", "headers"); put("request", buildJsonObject {
                        put("delete", buildJsonArray { stripped.forEach { add(it) } })
                    }) })
                }) })
                nativePaths[host.substringBefore(".datamancy.net")]?.let { paths ->
                    add(buildJsonObject {
                        put("match", buildJsonArray { add(buildJsonObject {
                            put("path", buildJsonArray { paths.forEach { add(it) } })
                        }) })
                        put("handle", buildJsonArray { add(upstream) }); put("terminal", true)
                    })
                }
                add(buildJsonObject { put("handle", buildJsonArray { add(auth) }) })
                if (host == "control.datamancy.net") add(buildJsonObject {
                    put("match", buildJsonArray { add(buildJsonObject {
                        put("path", buildJsonArray { add("/ops"); add("/ops/*") })
                        put("header_regexp", buildJsonObject {
                            put("Remote-Groups", buildJsonObject {
                                put("pattern", "(^|.*[,\\s])(admins|operators)([,\\s].*|${'$'})")
                            })
                            put("X-Webservices-SSO-Subject", buildJsonObject {
                                put("pattern", "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}${'$'}")
                            })
                        })
                    }) })
                    put("handle", buildJsonArray { add(upstream) }); put("terminal", true)
                })
                add(buildJsonObject {
                    put("match", buildJsonArray { add(buildJsonObject {
                        if (host == "control.datamancy.net") put("not", buildJsonArray {
                            add(buildJsonObject { put("path", buildJsonArray { add("/ops"); add("/ops/*") }) })
                        })
                        put("header_regexp", buildJsonObject {
                            put("Remote-Groups", buildJsonObject {
                                put("pattern", "(^|.*[,\\s])($policy)([,\\s].*|${'$'})")
                            })
                            put("X-Webservices-SSO-Subject", buildJsonObject {
                                put("pattern", "^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}${'$'}")
                            })
                        })
                    }) })
                    put("handle", buildJsonArray { add(upstream) }); put("terminal", true)
                })
                add(buildJsonObject { put("handle", buildJsonArray { add(denied) }); put("terminal", true) })
            })
        }
    }
}
