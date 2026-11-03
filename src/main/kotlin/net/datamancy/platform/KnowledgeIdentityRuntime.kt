package net.datamancy.platform

import java.nio.file.Path
import java.util.UUID
import kotlinx.serialization.json.*

/** Separate composite fixture: native BookStack OIDC, Keycloak onboarding, and private TLS. */
internal object KnowledgeIdentityRuntime {
    fun spec(inventory: AcquiredInventory, name: String = "knowledge-identity"): PrivateDeploymentSpec {
        val identity = IdentityRuntime.spec(inventory, name)
        val wiki = BookStackRuntime.spec(inventory, name)
        val processes = identity.processes.map { p ->
            if (p.environmentFile == "database-init.env") p.copy(environmentFile = "identity-database.env") else p
        } + wiki.processes.map { p ->
            when (p.id) {
                "bookstack-files-init" -> p.copy(command = p.command.dropLast(1) + (p.command.last() + "\nmkdir -p /config/www/themes/p0v3-closed"))
                "bookstack-migrate", "php" -> p.copy(files = p.files + listOf(
                    RuntimeFile("closed-registration.php", "/config/www/themes/p0v3-closed/functions.php"),
                    RuntimeFile("ca.pem", "/run/secrets/ca.pem")))
                "bookstack" -> p.copy(id = "knowledge", dependencies = p.dependencies + "keycloak",
                    readinessHttpPath = "/healthz", files = p.files + listOf(
                        RuntimeFile("web.pem", "/run/secrets/web.pem"), RuntimeFile("web-key.pem", "/run/secrets/web-key.pem")))
                else -> p
            }
        }
        return PrivateDeploymentSpec(name = name, volumes = identity.volumes + wiki.volumes, processes = processes)
            .also { PrivateDeployment.validate(it) }
    }
    fun inputs(pki: () -> Map<String, String> = { PrivateWebPki.generate("knowledge") }): Map<String, String> {
        val identity = IdentityRuntime.inputs().toMutableMap()
        identity["identity-database.env"] = identity.remove("database-init.env")!!
        identity["keycloak.env"] = identity.getValue("keycloak.env")
            .replace("KC_HOSTNAME=http://keycloak:8080", "KC_HOSTNAME=https://knowledge:8443/identity") +
            "KC_PROXY_HEADERS=xforwarded\n"
        val realm = Json.parseToJsonElement(identity.getValue("realm.json")).jsonObject.toMutableMap()
        val ownerId = UUID.randomUUID().toString()
        val clientSecret = RuntimePreparation.password()
        val owner = realm.getValue("users").jsonArray.single().jsonObject.toMutableMap().apply {
            put("id", JsonPrimitive(ownerId)); put("email", JsonPrimitive("fixture@localhost.invalid"))
            put("emailVerified", JsonPrimitive(true)); put("firstName", JsonPrimitive("Fixture")); put("lastName", JsonPrimitive("Owner"))
        }
        realm["users"] = buildJsonArray {
            add(JsonObject(owner))
            add(buildJsonObject {
                put("username", "outsider"); put("enabled", true); put("email", "outsider@localhost.invalid")
                put("emailVerified", true); put("firstName", "Unprovisioned"); put("lastName", "Fixture")
                put("credentials", buildJsonArray { add(buildJsonObject {
                    put("type", "password"); put("value", RuntimePreparation.password()); put("temporary", false)
                }) })
            })
        }
        realm["clients"] = buildJsonArray { add(buildJsonObject {
            put("clientId", "bookstack"); put("enabled", true); put("protocol", "openid-connect")
            put("publicClient", false); put("secret", clientSecret); put("standardFlowEnabled", true)
            put("directAccessGrantsEnabled", false); put("serviceAccountsEnabled", false); put("fullScopeAllowed", false)
            put("redirectUris", buildJsonArray { add("https://knowledge:8443/oidc/callback") })
            put("webOrigins", buildJsonArray { add("https://knowledge:8443") })
            put("defaultClientScopes", buildJsonArray { add("profile"); add("email") })
            put("attributes", buildJsonObject { put("pkce.code.challenge.method", "S256") })
        }) }
        identity["realm.json"] = JsonObject(realm).toString()
        val wiki = BookStackRuntime.inputs().toMutableMap()
        val oidc = "APP_THEME=p0v3-closed\nOIDC_NAME=Platform Zero\nOIDC_CLIENT_ID=bookstack\nOIDC_CLIENT_SECRET=$clientSecret\nOIDC_ISSUER=https://knowledge:8443/identity/realms/p0v3\nOIDC_ISSUER_DISCOVER=true\nOIDC_FETCH_AVATAR=false\nOIDC_DUMP_USER_DETAILS=false\nOIDC_USER_TO_GROUPS=false\n"
        for (file in listOf("bookstack.env", "admin.env")) {
            wiki[file] = wiki.getValue(file).replace("APP_URL=http://bookstack:8080", "APP_URL=https://knowledge:8443")
                .replace("AUTH_METHOD=standard", "AUTH_METHOD=oidc").replace("SESSION_SECURE_COOKIE=false", "SESSION_SECURE_COOKIE=true") + oidc
        }
        wiki["admin.env"] = wiki.getValue("admin.env") + "P0V3_OWNER_SUB=$ownerId\n"
        wiki["admin.php"] = wiki.getValue("admin.php").replace("'--password' =>", "'--external-auth-id' => getenv('P0V3_OWNER_SUB'), '--password' =>")
        wiki["closed-registration.php"] = """
            <?php
            use BookStack\Facades\Theme;
            use BookStack\Theming\ThemeEvents;
            // Native OIDC auto-registration is independent of the standard registration setting.
            // Only explicitly pre-provisioned subjects may use this deployment.
            Theme::listen(ThemeEvents::AUTH_PRE_REGISTER, function () { return false; });
        """.trimIndent() + "\n"
        wiki["fpm.conf"] = wiki.getValue("fpm.conf") +
            "php_admin_value[curl.cainfo] = /run/secrets/ca.pem\nphp_admin_value[openssl.cafile] = /run/secrets/ca.pem\n"
        wiki["nginx.conf"] = wiki.getValue("nginx.conf")
            .replace("listen 8080;", "listen 8443 ssl;\nssl_certificate /run/secrets/web.pem;\nssl_certificate_key /run/secrets/web-key.pem;\nssl_protocols TLSv1.2 TLSv1.3;")
            .replace("server_name bookstack;", "server_name knowledge;\nlocation ^~ /identity/ { proxy_pass http://keycloak:8080/; proxy_set_header Host ${'$'}http_host; proxy_set_header X-Forwarded-Proto https; proxy_set_header X-Forwarded-Port 8443; proxy_set_header X-Forwarded-For ${'$'}remote_addr; }")
            .replace("fastcgi_param HTTP_AUTHORIZATION", "fastcgi_param HTTPS on;\nfastcgi_param HTTP_AUTHORIZATION")
            .replace("server {", """
                server {
                    listen 8080;
                    location = /healthz {
                        include /etc/nginx/fastcgi_params;
                        fastcgi_param SCRIPT_FILENAME /run/secrets/health.php;
                        fastcgi_param HTTP_PROXY "";
                        fastcgi_pass php:9000;
                    }
                    location / { return 404; }
                }
                server {
            """.trimIndent())
        return identity + wiki + pki()
    }
    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "knowledge-identity", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) { inputs() }
}
