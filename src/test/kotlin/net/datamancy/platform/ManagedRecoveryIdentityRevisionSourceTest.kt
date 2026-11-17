package net.datamancy.platform

import java.util.Base64
import kotlinx.serialization.json.*
import kotlin.test.*
import org.junit.jupiter.api.Test

/** Fake transport below checks only source-code preflight shape. Native PKIX, real
 * Keycloak 26 admin semantics, logout-all and old-token denial are NOT qualified. */
class ManagedRecoveryIdentityRevisionSourceTest {
    private fun token(subject:String,generation:String,id:String):String {
        val encode={ text:String -> Base64.getUrlEncoder().withoutPadding().encodeToString(text.toByteArray()) }
        val payload=buildJsonObject {
            put("sub",subject);put("azp",id);put("iss","https://auth.datamancy.net/realms/p0v3")
            put("p0v3_generation",generation);put("exp",java.time.Instant.now().epochSecond+200)
        }
        return "${encode("{\"alg\":\"RS256\"}")}.${encode(payload.toString())}.${"a".repeat(80)}"
    }
    @Test fun `target grant readback refuses wrong subject and generation before enrollment`() {
        val id="managed-lane-agent";val subject="11111111-1111-4111-8111-111111111111"
        val generation="q-123456789abc"
        val transport=object:ManagedRevisionHttp {
            override fun request(method:String,path:String,bearer:String?,body:ByteArray?):Pair<Int,ByteArray> {
                assertEquals("POST",method)
                assertEquals("/realms/p0v3/protocol/openid-connect/token",path)
                assertNull(bearer)
                assertTrue(String(requireNotNull(body)).contains("client_id=managed-lane-agent"))
                return 200 to buildJsonObject { put("access_token",token(subject,generation,id)) }.toString().toByteArray()
            }
        }
        assertNotNull(ManagedRecoveryIdentityReadback.token(transport,id,"b".repeat(64),generation,subject))
        assertFailsWith<IllegalArgumentException> {
            ManagedRecoveryIdentityReadback.token(transport,id,"b".repeat(64),"q-000000000000",subject)
        }
        assertFailsWith<IllegalArgumentException> {
            ManagedRecoveryIdentityReadback.token(transport,id,"b".repeat(64),generation,
                "22222222-2222-4222-8222-222222222222")
        }
    }
    @Test fun `private admin transport cannot target public or foreign hosts`() {
        assertFailsWith<IllegalArgumentException> {
            PrivatePinnedSocketFactory(javax.net.ssl.SSLContext.getDefault().socketFactory,
                "api.openai.com","10.20.30.40")
        }
        assertFailsWith<IllegalArgumentException> {
            PrivatePinnedSocketFactory(javax.net.ssl.SSLContext.getDefault().socketFactory,
                "keycloak","127.0.0.1")
        }
    }
}
