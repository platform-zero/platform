package net.datamancy.platform

import kotlin.test.*
import kotlinx.serialization.json.*

class MailRuntimeTest {
    @Test fun `native mail has isolated one shot recovery and restricted serving permissions`() {
        val spec = MailRuntime.spec()
        val inputs = MailRuntime.inputs { mapOf("ca.pem" to "ca", "web.pem" to "certificate", "web-key.pem" to "key") }
        assertEquals(SingleUserRestore.inputNames(spec), inputs.keys)
        assertEquals(1, spec.processes.count { it.oneShot })
        assertTrue(spec.processes.all { it.userId == 2000 && it.capabilities.isEmpty() && it.apparmorProfile == "p0v3-private-v1" })
        val daemon = spec.processes.single { !it.oneShot }
        assertFalse(daemon.files.any { it.file in setOf("users.json", "mail-seed.json") })
        assertFalse(inputs.getValue("mail.env").contains("RECOVERY"))
        assertContains(daemon.command.last(), "cmp /data/ready /run/secrets/generation")
        assertContains(daemon.command.last(), "test -s /data/store/CURRENT")
        val seed = Json.parseToJsonElement(inputs.getValue("mail-seed.json")).jsonArray
        fun update(type: String) = seed.single { it.jsonObject["method"]!!.jsonPrimitive.content == "x:$type/set" }.jsonObject["arguments"]!!.jsonObject["update"]!!.jsonObject["singleton"]!!.jsonObject
        assertEquals("false", update("MtaStageRcpt")["allowRelaying"]!!.jsonObject["else"]!!.jsonPrimitive.content)
        assertEquals("true", update("MtaStageAuth")["require"]!!.jsonObject["else"]!!.jsonPrimitive.content)
        assertEquals(JsonNull, update("SpamSettings")["spamFilterRulesUrl"])
        assertFalse(update("SystemSettings")["includeSecrets"]!!.jsonPrimitive.boolean)
        assertEquals("Disabled", seed.single { it.jsonObject["method"]!!.jsonPrimitive.content == "x:Asn/set" }.jsonObject["arguments"]!!.jsonObject["create"]!!.jsonObject["asn"]!!.jsonObject["@type"]!!.jsonPrimitive.content)
        assertContains(inputs.getValue("mail.env"), "HTTPS_PROXY=http://127.0.0.1:9")
        assertContains(inputs.getValue("bootstrap.env"), "HTTPS_PROXY=http://127.0.0.1:9")
        assertEquals("'local'", update("MtaOutboundStrategy")["route"]!!.jsonObject["else"]!!.jsonPrimitive.content)
        assertTrue(seed.any { it.jsonObject["bindBuiltinApplication"]?.jsonPrimitive?.content == "builtin-ui" })
        val accounts = seed.single { it.jsonObject["method"]!!.jsonPrimitive.content == "x:Account/set" }.jsonObject["arguments"]!!.jsonObject["create"]!!.jsonObject
        assertEquals(setOf("alice", "bob", "outsider"), accounts.keys)
        for (account in accounts.values) {
            val permissions = account.jsonObject["permissions"]!!.jsonObject
            assertEquals("Replace", permissions["@type"]!!.jsonPrimitive.content)
            assertTrue(permissions["enabledPermissions"]!!.jsonObject.keys.none { it.startsWith("sys") || it.startsWith("jmap") || it.startsWith("sieve") || it.startsWith("calendar") })
        }
        assertEquals(3, Json.parseToJsonElement(inputs.getValue("users.json")).jsonObject.values.toSet().size)
        assertFails { MailRuntime.spec("../escape") }
    }
}
