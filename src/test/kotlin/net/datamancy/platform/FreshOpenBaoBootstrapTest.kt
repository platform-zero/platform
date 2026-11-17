package net.datamancy.platform

import kotlin.test.*

class FreshOpenBaoBootstrapTest {
    @Test fun `fresh issuer has only the selected non-dev Keykeeper KV policy`() {
        val policy = FreshOpenBaoBootstrap.policySource()
        assertContains(policy, "keykeeper/data/*")
        assertContains(policy, "keykeeper/metadata/")
        assertFalse("delete" in policy)
        assertFalse("sys/" in policy)
        assertFalse("sudo" in policy)
        assertFalse("root" in policy)
        assertFalse("path \"*\"" in policy)
        val source = OpenBaoRuntime.inputs { mapOf("ca.pem" to "ca", "web.pem" to "cert", "web-key.pem" to "key") }
        assertContains(source.getValue("bao.hcl"), "storage \"raft\"")
        assertContains(source.getValue("bao.hcl"), "tls_cert_file")
        assertFalse("-dev" in source.getValue("bao.hcl"))
    }
}
