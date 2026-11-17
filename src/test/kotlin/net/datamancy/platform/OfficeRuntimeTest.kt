package net.datamancy.platform

import kotlin.test.*

class OfficeRuntimeTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("seafile", "mariadb", "valkey").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `canonical Office shares exactly one Seafile identity and retains callback uncertainty`(): Unit {
        val storage = SeafileRuntime.canonicalFragment(inventory, "canonical-files", officeEnabled = true)
        val editor = OfficeRuntime.canonicalFragment(inventory, "canonical-files")
        assertEquals(setOf("office-data"), storage.spec.networks.toSet() - setOf("seafile-data", "seafile-web"))
        assertEquals(setOf("office-data", "onlyoffice-web"), editor.spec.networks.toSet())
        assertTrue(editor.providerNetworks.isEmpty() && editor.spec.databaseAccess.isEmpty())
        assertEquals(setOf("onlyoffice-office"), editor.spec.volumes.map { it.id }.toSet())
        assertFalse(editor.spec.processes.any { it.id in storage.spec.processes.map(RuntimeProcess::id) })
        val pki: (String) -> Map<String, String> = { host -> mapOf("ca.pem" to "CA-$host\n",
            "web.pem" to "leaf-$host", "web-key.pem" to "key-$host") }
        val generated = OfficeRuntime.canonicalInputs("1".repeat(64), "2".repeat(64), "3".repeat(64),
            "-----BEGIN CERTIFICATE-----\nunit\n-----END CERTIFICATE-----\n", pki)
        assertEquals(PrivateDeployment.inputNames(storage.spec).toSet(), generated.seafile.keys)
        assertEquals(PrivateDeployment.inputNames(editor.spec).toSet(), generated.onlyoffice.keys)
        assertContains(generated.seafile.getValue("seafile-seahub-settings.py"), "https://office.datamancy.net/")
        assertContains(generated.seafile.getValue("seafile-office-callback-guard.py"), "office.datamancy.net")
        assertContains(generated.onlyoffice.getValue("onlyoffice-office-nginx.conf"), "onlyoffice-docservice:8000")
        val cold = OfficeRuntime.coldRestoreFragment(editor)
        assertTrue(cold.spec.processes.none { it.oneShot })
        assertEquals(editor.spec.volumes, cold.spec.volumes)
    }
    @Test fun `native Office callback ledger collection is bound to exact running Seafile CID image fingerprint and state volume`(): Unit {
        val spec = SeafileRuntime.canonicalFragment(inventory, "canonical-files", officeEnabled = true).spec
        val key = "office-callback-v2:${"a".repeat(64)}"
        val fingerprint = "c".repeat(64)
        class Native(private val swap: Boolean) : OfficeCallbackNativeTransport {
            var inspections = 0
            override fun inspect(exactContainer: String): String {
                assertEquals("p0v3-live-canonical-files-seafile-backend", exactContainer)
                val cid = if (swap && ++inspections == 2) "d".repeat(64) else "f".repeat(64)
                return """[{"Id":"$cid","Image":"sha256:${"b".repeat(64)}","State":{"Running":true},"Config":{"Labels":{"io.p0v3.private-deployment":"canonical-files","io.p0v3.runtime-fingerprint":"$fingerprint"}},"Mounts":[{"Destination":"/state","Name":"p0v3-live-canonical-files-volume-seafile-state"}]}]"""
            }
            override fun readonly(exactContainer: String, key: String): String =
                """{"schemaVersion":1,"completedCount":2,"operationKey":"$key","state":"pending","replayAdmission":"deny"}"""
        }
        val observed = OfficeCallbackNativeCollector.collect(spec, "q-012345abcdef", fingerprint, key, Native(false))
        assertEquals("pending", observed.callbackState)
        assertEquals("deny", observed.replayAdmission)
        assertEquals("f".repeat(64), observed.backendContainerId)
        assertFails { OfficeCallbackNativeCollector.collect(spec, "q-012345abcdef", fingerprint, key, Native(true)) }
        assertFails { OfficeCallbackNativeCollector.collect(spec, "q-012345abcdef", fingerprint, "foreign", Native(false)) }
    }
    @Test fun `office is isolated authenticated and uses immutable generated assets`(): Unit {
        val spec = OfficeRuntime.spec(inventory)
        assertEquals(7, spec.processes.count { !it.oneShot })
        assertEquals(11, PrivateDeployment.validate(spec).size)
        assertTrue(spec.processes.all { it.capabilities.isEmpty() && it.apparmorProfile == "p0v3-private-v1" })
        val files = OfficeRuntime.inputs { host -> mapOf("ca.pem" to "CA-$host", "web.pem" to "leaf-$host", "web-key.pem" to "key-$host") }
        assertEquals(SingleUserRestore.inputNames(spec), files.keys)
        assertContains(files.getValue("office.json"), "\"rejectUnauthorized\":true")
        assertContains(files.getValue("office.json"), "\"allowMetaIPAddress\":false")
        assertContains(files.getValue("office.json"), "\"address\":\"*\",\"allowed\":false")
        assertContains(files.getValue("office.json"), "\"retries\":0")
        assertContains(files.getValue("seahub-settings.py"), "OfficeCallbackGuard")
        assertContains(files.getValue("seahub-settings.py"), "VERIFY_ONLYOFFICE_CERTIFICATE=True")
        assertContains(files.getValue("office-nginx.conf"), "secure_link_md5")
        assertContains(files.getValue("office-nginx.conf"), "ssl_protocols TLSv1.2 TLSv1.3")
        assertFalse("verysecretstring" in files.getValue("office.json"))
        assertFalse(spec.processes.single { it.id == "docservice" }.files.any { it.file in setOf("office-db.env", "users.json") })
        assertContains(spec.processes.single { it.id == "office-state-init" }.command.last(), "test -z")
        assertFalse(spec.processes.any { it.id in setOf("broker", "postgres", "converter") })
        assertFails { OfficeRuntime.spec(inventory.copy(images = inventory.images.dropLast(1))) }
        assertFails { OfficeRuntime.spec(inventory.copy(images = inventory.images.map { it.copy(os = "other") })) }
        assertFails { OfficeRuntime.spec(inventory, "../bad") }
        assertFails { SeafileRecovery.spec(spec, inventory, "other", "a".repeat(64)) }
    }
}
