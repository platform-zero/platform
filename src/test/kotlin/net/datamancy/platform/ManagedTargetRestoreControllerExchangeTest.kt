package net.datamancy.platform

import java.time.Instant
import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class ManagedTargetRestoreControllerExchangeTest {
    private val subject = "18ea7f8a-714f-4ea3-ab01-0a08cbb3d244"
    private val generation = "q-123456789abc"
    private val token = "a".repeat(80)
    private fun native(active: Boolean = true, roles: List<String> = listOf("view-users", "view-clients",
        "manage-clients", "manage-realm"), issuer: String = "https://auth.datamancy.net/realms/p0v3") = buildJsonObject {
        put("active",active); put("iss",issuer); put("azp","managed-restore-controller")
        put("sub",subject); put("p0v3_generation",generation)
        put("exp",Instant.now().epochSecond+180)
        put("aud",buildJsonArray { add("realm-management") })
        put("resource_access",buildJsonObject {
            put("realm-management",buildJsonObject {
                put("roles",buildJsonArray { roles.forEach { add(it) } })
            })
        })
    }
    @Test fun `target-native introspection requires exact original generation scoped roles subject and issuer`() {
        val expiration=ManagedTargetRestoreControllerExchange.validateIntrospection(native(),generation,subject,token)
        assertEquals(true,expiration > Instant.now().epochSecond)
        assertFailsWith<IllegalArgumentException> { ManagedTargetRestoreControllerExchange.validateIntrospection(
            native(active=false),generation,subject,token) }
        assertFailsWith<IllegalArgumentException> { ManagedTargetRestoreControllerExchange.validateIntrospection(
            native(roles=listOf("view-users","manage-clients")),generation,subject,token) }
        assertFailsWith<IllegalArgumentException> { ManagedTargetRestoreControllerExchange.validateIntrospection(
            native(issuer="https://foreign.example/realms/p0v3"),generation,subject,token) }
        assertFailsWith<IllegalArgumentException> { ManagedTargetRestoreControllerExchange.validateIntrospection(
            native(),"q-000000000000",subject,token) }
    }
}
