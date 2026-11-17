package net.datamancy.platform

import kotlin.test.*
import org.junit.jupiter.api.Test

/** User chose Pi-managed OpenAI OAuth, not a project-key brokerage. */
class ManagedPiSubscriptionDecisionTest {
    @Test fun `subscription issuer rejects unpinned controller before touching custody`() {
        assertFails { GenerationR9ManagedPlan.issue("q-5962a9fda75b","invalid") }
    }
    @Test fun `target issuer rejects invalid generation before target credentials`() {
        assertFails { GenerationR9ManagedRecoveryAuthority.issue("q-5962a9fda75b","invalid") }
    }
}
