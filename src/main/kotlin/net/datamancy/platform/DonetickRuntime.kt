package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.*

internal data class FreshDonetickActorGrant(val generation: String,
    val ownerPassword: String, val outsiderPassword: String, val appNonMemberPassword: String) {
    init {
        val passwords = listOf(ownerPassword, outsiderPassword, appNonMemberPassword)
        require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
            passwords.all { it.matches(Regex("[a-f0-9]{64}")) } && passwords.toSet().size == 3)
    }
}

/** Private chore-management fixture. Signup is local to this isolated network, not public onboarding. */
internal object DonetickRuntime {
    /** Pin the caller's graph-selected APP route before sending either password;
     * reject legacy chores alias, redirects, alternate ports and injected paths. */
    internal fun requireActorOrigin(selectedOrigin: java.net.URI): String {
        require(selectedOrigin.toASCIIString() == "https://donetick.datamancy.net") {
            "Fresh Donetick native actor origin differs from selected APP route"
        }
        return selectedOrigin.toASCIIString()
    }

    /** Explicit original native roles. Only APP_NON_MEMBER may supply the chore-denial session;
     * GATEWAY_OUTSIDER is reserved for the independent site/gateway-denial journey and
     * must never be given a GROUP SSO session just to reach this native endpoint. */
    internal val actorUsernames: Map<String, String> = mapOf(
        "OWNER" to "owner", "APP_NON_MEMBER" to "app-nonmember", "GATEWAY_OUTSIDER" to "outsider")

    /** After real INSTALL completion: authenticate owner and APP_NON_MEMBER native accounts
     * against the live private-CA service and read the exact original private chore.
     * Login tokens stay in local memory and never enter output or typed custody.
     */
    fun nativeIssuanceReadback(ownerClient: java.net.http.HttpClient,
        appNonMemberClient: java.net.http.HttpClient, selectedOrigin: java.net.URI,
        owner: String, ownerPassword: String, appNonMember: String, appNonMemberPassword: String,
        originalChoreId: Long, originalChoreName: String): Map<String, String> {
        val origin = requireActorOrigin(selectedOrigin)
        require(owner == actorUsernames.getValue("OWNER") &&
            appNonMember == actorUsernames.getValue("APP_NON_MEMBER") &&
            listOf(ownerPassword, appNonMemberPassword).all { it.matches(Regex("[a-f0-9]{64}")) } &&
            ownerPassword != appNonMemberPassword && originalChoreId > 0 &&
            originalChoreName.isNotBlank() && originalChoreName.length <= 256 &&
            ownerClient !== appNonMemberClient &&
            listOf(ownerClient, appNonMemberClient).all { it.followRedirects() == java.net.http.HttpClient.Redirect.NEVER })
        fun send(client: java.net.http.HttpClient, method: String, path: String, body: String?,
            bearer: String?): java.net.http.HttpResponse<String> {
            val builder = java.net.http.HttpRequest.newBuilder(java.net.URI.create(origin + path))
                .timeout(java.time.Duration.ofSeconds(10)).header("Accept", "application/json")
            if (bearer != null) builder.header("Authorization", "Bearer $bearer")
            if (body != null) builder.header("Content-Type", "application/json")
            val request = builder.method(method, if (body == null) java.net.http.HttpRequest.BodyPublishers.noBody()
                else java.net.http.HttpRequest.BodyPublishers.ofString(body)).build()
            val response = client.send(request, java.net.http.HttpResponse.BodyHandlers.ofString())
            require(response.body().length <= 65536) { "Unbounded native Donetick response" }
            return response
        }
        fun login(client: java.net.http.HttpClient, username: String, password: String): String {
            val payload = buildJsonObject { put("username", username); put("password", password) }.toString()
            val response = send(client, "POST", "/api/v1/auth/login", payload, null)
            require(response.statusCode() == 200) { "Original Donetick actor login denied" }
            val obj = Json.parseToJsonElement(response.body()).jsonObject
            val token = (obj["token"] ?: obj["access_token"])?.jsonPrimitive?.content
            require(token != null && token.matches(Regex("[A-Za-z0-9_.-]{24,8192}"))) {
                "Native Donetick actor token absent"
            }
            return token
        }
        val ownerToken = login(ownerClient, owner, ownerPassword)
        val appNonMemberToken = login(appNonMemberClient, appNonMember, appNonMemberPassword)
        require(ownerToken != appNonMemberToken) { "Donetick native accounts share one session" }
        val path = "/api/v1/chores/$originalChoreId"
        val visible = send(ownerClient, "GET", path, null, ownerToken)
        require(visible.statusCode() == 200 &&
            Json.parseToJsonElement(visible.body()).jsonObject.getValue("res").jsonObject
                .getValue("name").jsonPrimitive.content == originalChoreName) {
            "Owner cannot read original native Donetick chore"
        }
        // A negative owner-chore response alone could be an expired/invalid bearer.
        // First require a successful native authenticated read with this same token
        // through its own GROUP-gated client, then check the protected owner chore.
        val ownCircle = send(appNonMemberClient, "GET", "/api/v1/chores/", null, appNonMemberToken)
        require(ownCircle.statusCode() == 200 &&
            Json.parseToJsonElement(ownCircle.body()).jsonObject["res"] != null) {
            "APP non-member native session was not independently authenticated"
        }
        val denied = send(appNonMemberClient, "GET", path, null, appNonMemberToken)
        require(denied.statusCode() in setOf(401, 403, 404) &&
            runCatching { Json.parseToJsonElement(denied.body()).jsonObject["res"]?.jsonObject }.getOrNull() == null) {
            "APP non-member reached original Donetick chore"
        }
        return mapOf("owner" to owner, "appNonMember" to appNonMember,
            "nativeResourceId" to originalChoreId.toString())
    }

    fun spec(inventory: AcquiredInventory, name: String = "donetick"): PrivateDeploymentSpec {
        val image = inventory.images.single { it.product == "donetick" }
        require(image.os == "linux" && image.architecture == "amd64")
        return PrivateDeploymentSpec(name = name, volumes = listOf(RuntimeVolume("data", 1000)), processes = listOf(
            RuntimeProcess("donetick", image.pinnedImage, image.imageId, 1000, entrypoint = "/donetick",
                environmentFile = "donetick.env", files = listOf(RuntimeFile("selfhosted.yaml", "/config/selfhosted.yaml")),
                volumes = listOf(RuntimeMount("data", "/donetick-data")), apparmorProfile = "p0v3-private-v1",
                readinessHttpPort = 2021, memoryMiB = 512)
        )).also { PrivateDeployment.validate(it) }
    }
    /** New release-only single original SQLite state; no network/provider cloned from legacy fixture. */
    fun canonicalFragment(inventory: AcquiredInventory, member: String): CanonicalProviderFragment {
        val legacy = spec(inventory, member)
        val daemon = legacy.processes.single().copy(networks = listOf("donetick-web"),
            // Account enrollment is a native one-time INSTALL action before ingress; no fixture password in daemon.
            environmentFile = "donetick-runtime.env")
        return CanonicalProviderFragment("donetick", legacy.copy(store = RuntimeStore.CANONICAL_V2,
            networks = listOf("donetick-web"), processes = listOf(daemon)), webNetworks = setOf("donetick-web"))
    }

    fun canonicalColdFragment(fresh: CanonicalProviderFragment): CanonicalProviderFragment {
        require(fresh.product == "donetick" && fresh.spec.store == RuntimeStore.CANONICAL_V2 &&
            fresh.spec.processes.single().id == "donetick" && !fresh.spec.processes.single().oneShot)
        return fresh // Original SQLite database and JWT signing key MUST be imported, never generated again.
    }

    /** Only the isolated one-use initializer has signup enabled; serving config always
     * disables public account creation. Three native registrations create independent
     * circles: owner, APP non-member, and site/gateway-denied outsider. Only the first
     * two are eligible for separate GROUP sessions and the native chore-denial journey.
     * Never retry after the attempted marker, even if either signup ACK was lost.
     */
    fun freshActorEnrollmentInputs(grant: FreshDonetickActorGrant, servingConfig: String): Map<String, String> {
        val anchor = "is_user_creation_disabled: true\n"
        require(servingConfig.split(anchor).size == 2 &&
            servingConfig.contains("secret: ") && !servingConfig.contains("is_user_creation_disabled: false") &&
            !servingConfig.contains("single_circle_instance: true"))
        fun signup(username: String, password: String) = buildJsonObject {
            put("username", username); put("password", password)
            put("email", "$username@localhost.invalid"); put("displayName", "Fresh $username")
        }.toString() + "\n"
        return mapOf("donetick-actor-enroll.env" to "DT_ENV=selfhosted\nDT_SQLITE_PATH=/donetick-data/donetick.db\nP0V3_GENERATION=${grant.generation}\n",
            "donetick-actor-enroll.yaml" to servingConfig.replace(anchor, "is_user_creation_disabled: false\n"),
            "donetick-owner-signup.json" to signup(actorUsernames.getValue("OWNER"), grant.ownerPassword),
            "donetick-outsider-signup.json" to signup(actorUsernames.getValue("GATEWAY_OUTSIDER"), grant.outsiderPassword),
            "donetick-app-nonmember-signup.json" to signup(actorUsernames.getValue("APP_NON_MEMBER"), grant.appNonMemberPassword),
            "donetick-actor-enroll.sh" to nativeActorEnrollmentSource())
    }

    fun nativeActorEnrollmentSource(): String = """
        #!/bin/sh
        set -euC
        umask 077
        case "${'$'}{P0V3_GENERATION:-}" in
            q-????????????) case "${'$'}{P0V3_GENERATION#q-}" in *[!a-f0-9]*|'') exit 1;; esac ;;
            *) exit 1;;
        esac
        root=/donetick-data
        test -d "${'$'}root" && test ! -L "${'$'}root" || exit 1
        test ! -e "${'$'}root/donetick.db" && test ! -L "${'$'}root/donetick.db" || exit 1
        intent="${'$'}root/p0v3-actor-enrollment-${'$'}P0V3_GENERATION.attempted"
        receipt="${'$'}root/p0v3-actor-enrollment-${'$'}P0V3_GENERATION.completed"
        test ! -e "${'$'}intent" && test ! -L "${'$'}intent" &&
            test ! -e "${'$'}receipt" && test ! -L "${'$'}receipt" || exit 1
        # Exclusive attempted-effect fence BEFORE starting the signup-enabled binary.
        (printf '%s\n' "${'$'}P0V3_GENERATION";
         busybox sha256sum /run/secrets/donetick-owner-signup.json /run/secrets/donetick-outsider-signup.json /run/secrets/donetick-app-nonmember-signup.json) > "${'$'}intent" || exit 1
        sync
        /donetick >/dev/null 2>&1 & server=${'$'}!
        trap 'kill "${'$'}server" 2>/dev/null || :; wait "${'$'}server" 2>/dev/null || :' EXIT HUP INT TERM
        ready=0
        n=0
        while [ "${'$'}n" -lt 60 ]; do
            kill -0 "${'$'}server" 2>/dev/null || exit 1
            if busybox wget -q -T 2 -O /dev/null http://127.0.0.1:2021/api/v1/health; then ready=1; break; fi
            n=${'$'}((n+1)); sleep 1
        done
        test "${'$'}ready" -eq 1 || exit 1
        # Selected Donetick v0.1.85: POST /api/v1/auth/ -> signUp (201), separate circles.
        # --post-file keeps both passwords out of argv, environment and stdout.
        busybox wget -q -T 15 -O /dev/null --header='Content-Type: application/json' \
            --post-file=/run/secrets/donetick-owner-signup.json http://127.0.0.1:2021/api/v1/auth/
        busybox wget -q -T 15 -O /dev/null --header='Content-Type: application/json' \
            --post-file=/run/secrets/donetick-outsider-signup.json http://127.0.0.1:2021/api/v1/auth/
        busybox wget -q -T 15 -O /dev/null --header='Content-Type: application/json' \
            --post-file=/run/secrets/donetick-app-nonmember-signup.json http://127.0.0.1:2021/api/v1/auth/
        kill "${'$'}server"; wait "${'$'}server"
        trap - EXIT HUP INT TERM
        (printf '%s\n' "${'$'}P0V3_GENERATION";
         busybox sha256sum /run/secrets/donetick-owner-signup.json /run/secrets/donetick-outsider-signup.json /run/secrets/donetick-app-nonmember-signup.json) > "${'$'}receipt" || exit 1
        sync
    """.trimIndent() + "\n"

    fun canonicalInputs(secret: () -> String = RuntimePreparation::password): Map<String, String> {
        val signingKey = secret()
        require(signingKey.matches(Regex("[a-f0-9]{64}")))
        return mapOf("donetick-runtime.env" to "DT_ENV=selfhosted\nDT_SQLITE_PATH=/donetick-data/donetick.db\n",
            "selfhosted.yaml" to """
                name: selfhosted
                is_done_tick_dot_com: false
                is_user_creation_disabled: true
                database:
                  type: sqlite
                  migration: true
                jwt:
                  secret: $signingKey
                  session_time: 24h
                  max_refresh: 168h
                server:
                  port: 2021
                  read_timeout: 10s
                  write_timeout: 10s
                  rate_period: 60s
                  rate_limit: 300
                  cors_allow_origins: ['https://donetick.datamancy.net']
                  serve_frontend: true
                  serve_swagger: false
                  public_host: https://donetick.datamancy.net
                logging:
                  level: info
                  encoding: json
                  development: false
                email:
                  log_raw_url: false
                storage:
                  storage_type: local
                  base_path: /donetick-data/uploads
                bridge:
                  enabled: false
                realtime:
                  enabled: true
                  sse_enabled: true
                  allowed_origins: ['https://donetick.datamancy.net']
            """.trimIndent() + "\n")
    }

    fun prepare(inventory: AcquiredInventory, base: Path = PrivateDeployment.BASE, name: String = "donetick", store: RuntimeStore = RuntimeStore.LEGACY): Path =
        RuntimePreparation.prepare(spec(inventory, name).copy(store = store), base) {
            mapOf("donetick.env" to "DT_ENV=selfhosted\nDT_SQLITE_PATH=/donetick-data/donetick.db\nP0V3_FIXTURE_PASSWORD=${RuntimePreparation.password()}\n",
                "selfhosted.yaml" to """
                    name: selfhosted
                    is_done_tick_dot_com: false
                    is_user_creation_disabled: false
                    database:
                      type: sqlite
                      migration: true
                    jwt:
                      secret: ${RuntimePreparation.password()}
                      session_time: 24h
                      max_refresh: 168h
                    server:
                      port: 2021
                      read_timeout: 10s
                      write_timeout: 10s
                      rate_period: 60s
                      rate_limit: 300
                      cors_allow_origins: ['http://donetick:2021']
                      serve_frontend: true
                      serve_swagger: true
                      public_host: http://donetick:2021
                    logging:
                      level: info
                      encoding: json
                      development: false
                    email:
                      log_raw_url: false
                    storage:
                      storage_type: local
                      base_path: /donetick-data/uploads
                    bridge:
                      enabled: false
                    realtime:
                      enabled: true
                      sse_enabled: true
                      allowed_origins: ['http://donetick:2021']
                """.trimIndent() + "\n")
        }
}
