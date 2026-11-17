package net.datamancy.platform

import kotlin.test.*

class CanonicalFreshNtfySourceTest {
    @Test fun `fresh declarative users separate browser read publisher write and native owner`() {
        val grants = FreshNtfyGrants("tk_" + "a".repeat(32),
            "\$2a\$12\$0un/uJ8ntkji/FFOdcPUgeK4Zo/x0qsj.n6yfmRLORMk8mTKBCPu2",
            "tk_" + "b".repeat(32),
            "\$2a\$12\$xCgDJoYpBHHl2rsALcb/VOW8zuP/BwHHj1jFQLNdMOOVlg8EMP7t.",
            "tk_" + "c".repeat(32),
            "\$2a\$12\$Vm1xWeGnz3ws/cmDpvRWb.X/Z3uBmDYswlYYNaIT6Pypgx3VhIKEK")
        val source = CanonicalFreshNtfySource.inputs(grants).getValue("ntfy-config.yml")
        assertContains(source, "auth-default-access: deny-all")
        assertContains(source, "ntfy-sso:p0-owner-*:deny")
        assertContains(source, "ntfy-sso:*:read-only")
        assertContains(source, "ntfy-publisher:webservices-critical:write-only")
        assertContains(source, "ntfy-owner:p0-owner-*:read-write")
        assertFalse(source.contains("admin"))
        assertEquals(3, source.lines().count { it.trim().startsWith("- \"ntfy-") && it.contains("tk_") })
        assertFails { grants.copy(ownerToken = grants.ssoToken) }
        assertFails { grants.copy(ssoPasswordHash = grants.ownerPasswordHash) }
    }
}
