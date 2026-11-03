package net.datamancy.platform

import kotlin.test.*
import kotlinx.serialization.json.*

class SogoMailRuntimeTest {
    private val inventory = AcquiredInventory(1, "candidate", listOf("postgres", "sogo", "memcached").map {
        val pin = "example.org/$it@sha256:" + "a".repeat(64)
        AcquiredImage(it, "upstream", "example.org/$it:1", pin, "b".repeat(64), emptyList(), pin.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `fresh composite binds shared fixture identities without credential or trust shadowing`() {
        val spec = SogoMailRuntime.spec(inventory)
        val inputs = SogoMailRuntime.inputs { host -> mapOf("ca.pem" to "$host-ca", "web.pem" to "$host-cert", "web-key.pem" to "$host-key") }
        assertEquals(SingleUserRestore.inputNames(spec), inputs.keys)
        assertEquals(5, spec.processes.count { !it.oneShot })
        assertEquals(3, spec.processes.count { it.oneShot })
        assertEquals(3, spec.volumes.size)
        val app = spec.processes.single { it.id == "sogod" }
        assertContains(app.dependencies, "mail")
        assertContains(app.files, RuntimeFile("mail-ca.pem", "/etc/ssl/certs/ca-certificates.crt"))
        assertEquals("mail-ca", inputs.getValue("mail-ca.pem"))
        assertEquals("groupware-ca", inputs.getValue("ca.pem"))
        assertEquals("database-ca", inputs.getValue("db-ca.pem"))
        assertEquals("mail-bootstrap.env", spec.processes.single { it.id == "mail-init" }.environmentFile)
        assertFalse(inputs.getValue("bootstrap.env").contains("RECOVERY"))
        assertFalse(inputs.getValue("mail-bootstrap.env").contains("PGPASSWORD"))
        for ((user, password) in Json.parseToJsonElement(inputs.getValue("users.json")).jsonObject) {
            assertContains(inputs.getValue("bootstrap.env"), "${user.uppercase()}_PASSWORD=${password.jsonPrimitive.content}\n")
            assertContains(inputs.getValue("setup.sql"), "$user@p0v3.example.org")
        }
        assertContains(inputs.getValue("sogo.conf"), "imaps://mail:2993/?tlsVerifyMode=default")
        assertContains(inputs.getValue("sogo.conf"), "smtps://mail:2465/?tlsVerifyMode=default")
        assertContains(inputs.getValue("sogo.conf"), "SOGoForceExternalLoginWithEmail = YES")
        assertContains(inputs.getValue("sogo.conf"), "SOGoMailSpoolPath = \"/home/sogo/spool\"")
        assertFalse(inputs.getValue("apache.conf").contains("[R=503,L]"))
        assertContains(inputs.getValue("apache.conf"), "HTTP:Origin")
        assertFalse(spec.processes.filterNot { it.oneShot }.any { it.environmentFile in setOf("bootstrap.env", "mail-bootstrap.env") })
        assertFails { SogoMailRuntime.spec(inventory, "../escape") }
        assertFails { SogoRuntime.inputs(users = mapOf("alice" to "invalid")) }
        var pkiCalled = false
        assertFails { SogoRuntime.inputs(users = listOf("alice", "bob", "outsider").associateWith { "a".repeat(64) }) { pkiCalled = true; error("must not generate keys") } }
        assertFalse(pkiCalled)
    }
}
