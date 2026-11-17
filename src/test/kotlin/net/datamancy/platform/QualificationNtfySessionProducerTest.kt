package net.datamancy.platform

import java.time.Instant
import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertFails

class QualificationNtfySessionProducerTest {
    private val generation = "q-abcdef123456"
    private val invocation = "original-web-one"
    private val hash = "a".repeat(64)
    private val issuerHash = "b".repeat(64)
    private val sessionHash = "c".repeat(64)
    private val subject = "11111111-1111-4111-8111-111111111111"
    private val issuerLeaf = "d".repeat(64)
    private val gatewayLeaf = "e".repeat(64)
    private fun intent() = buildJsonObject {
        put("schemaVersion",1); put("invocationId",invocation); put("generationId",generation)
        put("bundleSha256",hash); put("caseIntentSha256",hash); put("phase","INSTALL")
        put("ownerSubject",subject); put("ownerCustodySha256",hash)
        put("completedPasswordSha256",hash); put("completedTotpSha256",hash)
        put("host","ntfy.datamancy.net"); put("issuerHost","auth.datamancy.net")
        put("gatewayHost","keycloak-auth.datamancy.net")
        put("operation","ORIGINAL_OWNER_OIDC_GROUP_LOGIN_ONCE")
    }
    private fun issued() = buildJsonObject {
        put("schemaVersion",1); put("invocationId",invocation); put("generationId",generation)
        put("bundleSha256",hash); put("issuer","https://auth.datamancy.net/realms/p0v3")
        put("expectedSubject",subject); put("username","owner"); put("loginIntentSha256",hash)
        put("callbackUrlSha256",hash); put("accountPageSha256",hash)
        put("accountStatus",200); put("issuerLeafSha256",issuerLeaf)
    }
    private fun gateway() = buildJsonObject {
        put("schemaVersion",1); put("invocationId",invocation); put("generationId",generation)
        put("bundleSha256",hash); put("host","ntfy.datamancy.net")
        put("gatewayHost","keycloak-auth.datamancy.net"); put("gatewayPath","/oauth2/auth")
        put("issuer","https://auth.datamancy.net/realms/p0v3"); put("httpStatus",202)
        put("subject",subject); put("username","owner")
        put("groups",buildJsonArray { add("admins"); add("users") })
        put("gatewayLeafSha256",gatewayLeaf); put("issuerResultSha256",issuerHash)
        put("sessionSha256",sessionHash); put("loginIntentSha256",hash)
    }
    private fun session() = buildJsonObject {
        put("cookies",buildJsonArray { add(buildJsonObject {
            put("name","_p0v3_edge"); put("value","real-selected-cookie")
            put("domain",".datamancy.net"); put("path","/")
            put("secure",true); put("httpOnly",true); put("sameSite","Lax")
            put("expires",Instant.now().epochSecond+600)
        }) }); put("origins",buildJsonArray {})
    }
    private fun checked(intent: JsonObject = intent(), issuer: JsonObject = issued(),
        gateway: JsonObject = gateway(), session: JsonObject = session()) =
        QualificationNtfySessionProducer.validateObserved(intent,issuer,gateway,session,
            subject,generation,hash,invocation,hash,issuerHash,sessionHash,issuerLeaf,gatewayLeaf)

    @Test fun realParentDomainCookieAndSelectedGroupAreAllowedWithoutRewritingHost() {
        checked()
        checked(session=JsonObject(session() + ("cookies" to buildJsonArray { add(
            JsonObject(session().getValue("cookies").jsonArray.single().jsonObject +
                ("domain" to JsonPrimitive("datamancy.net")))) })))
    }

    @Test fun outsiderOrAnonymousDenialIsNotGroupAdmission() {
        assertFails { checked(gateway=JsonObject(gateway() +
            ("groups" to buildJsonArray { add("users") }))) }
        assertFails { checked(gateway=JsonObject(gateway() +
            ("httpStatus" to JsonPrimitive(403)))) }
        assertFails { checked(gateway=JsonObject(gateway() +
            ("subject" to JsonPrimitive("22222222-2222-4222-8222-222222222222")))) }
        assertFails { checked(gateway=JsonObject(gateway() +
            ("issuerResultSha256" to JsonPrimitive("f".repeat(64))))) }
    }

    @Test fun noForeignCookieOrSynthesizedIssuer() {
        val cookie = session().getValue("cookies").jsonArray.single().jsonObject
        fun withCookie(name: String, value: JsonElement) = JsonObject(session() +
            ("cookies" to buildJsonArray { add(JsonObject(cookie + (name to value))) }))
        assertFails { checked(session=withCookie("domain",JsonPrimitive("ntfy.datamancy.net"))) }
        assertFails { checked(session=withCookie("domain",JsonPrimitive("foreign.example"))) }
        assertFails { checked(session=withCookie("secure",JsonPrimitive(false))) }
        assertFails { checked(session=withCookie("httpOnly",JsonPrimitive(false))) }
        assertFails { checked(session=withCookie("name",JsonPrimitive("not-a-gateway-session"))) }
        assertFails { checked(issuer=JsonObject(issued() + ("accountStatus" to JsonPrimitive(302)))) }
        assertFails { checked(intent=JsonObject(intent() + ("operation" to JsonPrimitive("RETRY")))) }
    }
}
