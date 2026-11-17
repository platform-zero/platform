package net.datamancy.platform

import kotlin.test.*

class FreshRequiredActionJourneyTest {
    private val fresh = FreshIdentityBootstrap(ownerUuid = "00000000-0000-4000-8000-000000000001",
        outsiderUuid = "00000000-0000-4000-8000-000000000002",
        appNonMemberUuid = "00000000-0000-4000-8000-000000000003")
    private val user = """{"id":"${fresh.ownerUuid}","enabled":true,"requiredActions":[]}"""
    private val creds = """[{"type":"password","temporary":false},{"type":"otp"}]"""

    @Test fun `fresh realm requires private first login password and TOTP not an account redirect`() {
        val pem = "-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----\n"
        var next = 1
        val realm = IdentityRuntime.canonicalInputs("a".repeat(64),
            pki = { mapOf("ca.pem" to pem, "web.pem" to pem, "web-key.pem" to pem) },
            password = { (next++).toString(16).repeat(64) }, originalOwnerId = fresh.ownerUuid,
            originalOutsiderId = fresh.outsiderUuid, originalMemberships = fresh.memberships(),
            originalAppNonMemberId = fresh.appNonMemberUuid)
            .getValue("identity-realm.json")
        FreshRequiredActionJourney.requireImportedSource(realm, fresh)
        val route = PackagedGraphFragment.pendingV3R9().first.integratedReference!!.modules
            .flatMap { it.privateRoutes }.single { it.label == "onboarding" }
        assertEquals("CONTROL", route.policy)
        assertEquals("onboarding", route.special)
        assertNull(route.process) // Native OIDC flow, not an OLD account-page server.
        FreshRequiredActionJourney.requireCompleted(fresh.ownerUuid, user, creds, fresh)
        assertFailsWith<IllegalArgumentException> {
            FreshRequiredActionJourney.requireCompleted(fresh.ownerUuid,
                user.replace("\"requiredActions\":[]", "\"requiredActions\":[\"CONFIGURE_TOTP\"]"), creds, fresh)
        }
        assertFailsWith<IllegalArgumentException> {
            FreshRequiredActionJourney.requireCompleted(fresh.ownerUuid, user, """[{"type":"password"}]""", fresh)
        }
        assertFailsWith<IllegalArgumentException> {
            FreshRequiredActionJourney.requireImportedSource(
                realm.replace("\"registrationAllowed\":false", "\"registrationAllowed\":true"), fresh)
        }
    }
}
