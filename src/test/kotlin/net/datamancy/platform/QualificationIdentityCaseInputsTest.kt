package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlinx.serialization.json.*

class QualificationIdentityCaseInputsTest {
    private val generation = "q-abcdef012345"
    private val ownerId = "11111111-1111-4111-8111-111111111111"
    private fun source(actions: List<String> = listOf("UPDATE_PASSWORD", "CONFIGURE_TOTP"),
        temporary: Boolean = true, client: JsonObject = IdentityRuntime.canonicalOperatorClient(generation)) =
        buildJsonObject {
            put("realm","p0v3"); put("registrationAllowed",false); put("sslRequired","all")
            put("users",buildJsonArray { add(buildJsonObject {
                put("username","owner"); put("id",ownerId); put("enabled",true)
                put("requiredActions",buildJsonArray { actions.forEach { add(it) } })
                put("credentials",buildJsonArray { add(buildJsonObject {
                    put("type","password"); put("temporary",temporary); put("value","a".repeat(64))
                }) })
            }) })
            put("clients",buildJsonArray { add(client) })
        }.toString()

    @Test fun dedicatedRetirementClientNameIsBoundToOneOriginalGeneration() {
        assertEquals("p0v3-qual-retire-abcdef012345", QualificationIdentityCaseInputs.retirementClientName(generation))
        assertFailsWith<IllegalArgumentException> { QualificationIdentityCaseInputs.retirementClientName("q-not-hex") }
    }

    @Test fun onlySealedOriginalFirstUseSourceCanAuthorizeBrowserAttempt() {
        assertEquals(ownerId to "a".repeat(64),
            QualificationIdentityCaseInputs.extractOriginalOwner(source(),generation))
        assertFailsWith<IllegalArgumentException> {
            QualificationIdentityCaseInputs.extractOriginalOwner(source(temporary=false),generation)
        }
        assertFailsWith<IllegalArgumentException> {
            QualificationIdentityCaseInputs.extractOriginalOwner(source(actions=emptyList()),generation)
        }
        assertFailsWith<IllegalArgumentException> {
            QualificationIdentityCaseInputs.extractOriginalOwner(source(client=buildJsonObject {
                put("clientId","identity-controller"); put("directAccessGrantsEnabled",true)
            }),generation)
        }
        assertFailsWith<IllegalArgumentException> {
            QualificationIdentityCaseInputs.extractOriginalOwner(source(),"q-bbbbbbbbbbbb")
        }
    }
}
