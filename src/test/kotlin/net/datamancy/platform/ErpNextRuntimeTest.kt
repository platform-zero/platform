package net.datamancy.platform

import kotlin.test.*
import kotlinx.serialization.json.*

class ErpNextRuntimeTest {
    @Test fun `fixed authenticated Redis bridge keeps provider password out of ERP daemons and denies global scans`(): Unit {
        val bridge = ErpNextRuntime.releaseRedisBridge(inventory, "canonical-release-v2")
        assertEquals("erp-redis-bridge", bridge.id)
        assertEquals(setOf("erp-cache", "cache-data"), bridge.networks.toSet())
        assertEquals("erp-bridge.env", bridge.environmentFile)
        assertEquals(listOf("valkey"), bridge.dependencies)
        assertTrue(bridge.files.any { it.file == "erp-redis-bridge.py" })
        assertTrue(bridge.files.any { it.file == "erp-source-attestation.json" })
        val source = ErpNextRuntime.releaseRedisBridgeSource()
        assertTrue(source.startsWith("#!/usr/bin/env python3\n"))
        assertContains(source, "if not __debug__:")
        assertTrue(source.indexOf("if not __debug__:") < source.indexOf("import asyncio"))
        assertContains(source, "SITE_PREFIX = b'p0_erp|'")
        assertContains(source, "QUEUE_PREFIX = b'rq:queue:p0v3-erp:'")
        assertContains(source, "KEY_PATTERN.fullmatch(parts[1])")
        assertContains(source, "b'SCAN'")
        assertContains(source, "b'FLUSHALL'")
        assertContains(source, "b'EVAL'")
        assertContains(source, "AUTH_USER = b'erp-app'")
        assertContains(source, "PROVIDER_USER = b'erpnext'")
        assertContains(source, "client_password == provider_password")
        assertFalse(source.contains("~*"))
        assertFalse(source.contains("&*"))
        val sealed = ErpNextRuntime.releaseRedisBridgeInputs("b".repeat(64), "c".repeat(64))
        assertEquals(source, sealed.getValue("erp-redis-bridge.py"))
        assertContains(sealed.getValue("erp-bridge.env"), "ERP_PROVIDER_PASSWORD=${"c".repeat(64)}")
        assertFalse(sealed.getValue("erp-bridge.env").contains("ERP_MIGRATION_PASSWORD"))
        assertFails { ErpNextRuntime.releaseRedisBridgeInputs("b".repeat(64), "b".repeat(64)) }
    }

    @Test fun `native Frappe no-root installation retains uncertain intent and securely switches site config`(): Unit {
        val site = ErpNextRuntime.releaseNativeSiteInstall(inventory, "canonical-release-v2")
        assertTrue(site.oneShot)
        assertEquals("erp-native-site-install", site.id)
        assertEquals(setOf("mariadb", "erp-redis-bridge"), site.dependencies.toSet())
        assertEquals(setOf("erp-data", "erp-cache"), site.networks.toSet())
        assertTrue(site.files.map { it.file }.toSet().containsAll(setOf("erp-native-site-install.py",
            "erp-common-site.json", "erp-maria-client.cnf", "mariadb-ca.pem", "erp-source-attestation.json")))
        val pair = CanonicalMariaCredentialPair("a".repeat(64), "b".repeat(64))
        val actors = FreshErpActorGrant("e".repeat(64), "f".repeat(64))
        val inputs = ErpNextRuntime.releaseNativeSiteInputs(pair, "c".repeat(64), "d".repeat(64), "q-111111111111", actors)
        val script = inputs.getValue("erp-native-site-install.py")
        assertTrue(script.startsWith("#!/usr/bin/env python3\nif not __debug__:"))
        assertContains(script, "not any(SITES.iterdir())")
        assertContains(script, "CURRENT_USER(), DATABASE()")
        assertContains(script, "information_schema.tables")
        assertContains(script, "'attempted': True")
        assertContains(script, "os.O_EXCL | os.O_NOFOLLOW")
        assertContains(script, "setup_db=False")
        assertContains(script, "force=True")
        assertContains(script, "'db_ssl_check_hostname': True")
        assertContains(script, "'--defaults-extra-file=' + MYSQL_CNF")
        assertContains(script, "argv if arg != '--password=' + migration")
        assertContains(script, "get_encryption_key()")
        assertContains(script, "owner_email = 'p0v3-erp-owner@localhost.invalid'")
        assertContains(script, "outsider_email = 'p0v3-erp-outsider@localhost.invalid'")
        assertContains(script, "'Journal Entry': ('read', 'create', 'write', 'submit')")
        assertContains(script, "'Scheduled Job Log': ('read',)")
        assertContains(script, "update_password(email, password)")
        assertContains(script, "allow_login_using_user_name', 1)")
        assertContains(script, "enable_scheduler', 1)")
        assertContains(script, "native_jobs = frappe.get_all('Scheduled Job Type'")
        assertContains(script, "role not in frappe.get_roles(outsider_email)")
        assertContains(script, "frappe.db.commit()")
        assertTrue(script.indexOf("frappe.db.commit()") < script.indexOf("exclusive(RECEIPT"))
        assertFalse(script.contains("user.append('roles', {'role': 'System Manager'})"))
        assertContains(inputs.getValue("erp-site-bootstrap.env"), "ERP_OWNER_PASSWORD=${actors.ownerPassword}")
        assertContains(inputs.getValue("erp-site-bootstrap.env"), "ERP_OUTSIDER_PASSWORD=${actors.outsiderPassword}")
        assertContains(script, "generated = json.loads((site_dir / 'site_config.json').read_text())")
        assertContains(script, "target = dict(generated, db_password=runtime)")
        assertContains(script, "os.replace(temp, site_dir / 'site_config.json')")
        assertContains(script, "'cutoverPending': True")
        assertContains(script, "'CREATE USER ON *.*' in grant")
        assertFalse(script.contains("cursor.execute('CREATE USER"))
        assertFalse(script.contains("--db-root-password"))
        val config = Json.parseToJsonElement(inputs.getValue("erp-common-site.json")).jsonObject
        assertEquals("p0v3-erp", config.getValue("bench_id").jsonPrimitive.content)
        assertEquals("https://erp.datamancy.net", config.getValue("host_name").jsonPrimitive.content)
        assertEquals(0, config.getValue("pause_scheduler").jsonPrimitive.int)
        assertContains(inputs.getValue("erp-maria-client.cnf"), "ssl-verify-server-cert")
        val attestation = Json.parseToJsonElement(inputs.getValue("erp-source-attestation.json")).jsonObject
        assertEquals("15.125.0", attestation.getValue("frappeVersion").jsonPrimitive.content)
        assertEquals("1.15.1", attestation.getValue("rqVersion").jsonPrimitive.content)
        assertEquals(18, attestation.getValue("hashes").jsonObject.size)
        assertContains(attestation.getValue("hashes").jsonObject.keys, "frappe/permissions.py")
        assertFalse(inputs.getValue("erp-maria-client.cnf").contains("b".repeat(64)))
        assertFails { ErpNextRuntime.releaseNativeSiteInputs(pair, "c".repeat(64), "d".repeat(64), "q-111111111111") }
        assertFails { ErpNextRuntime.releaseNativeSiteInputs(pair, "a".repeat(64), "d".repeat(64), "q-111111111111", actors) }
        assertFails { ErpNextRuntime.releaseNativeSiteInputs(pair, "c".repeat(64), "c".repeat(64), "q-111111111111", actors) }
        assertFails { ErpNextRuntime.releaseNativeSiteInputs(pair, "c".repeat(64), "d".repeat(64), "q-111111111111",
            FreshErpActorGrant("c".repeat(64), "f".repeat(64))) }
        assertFails { FreshErpActorGrant("e".repeat(64), "e".repeat(64)) }
    }

    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("erpnext", "mariadb", "valkey").map {
        AcquiredImage(it, "upstream", "example.org/app:1", image, "b".repeat(64), emptyList(), image.substringAfter('@'), "amd64", "linux")
    })
    @Test fun `native site installation retires its database privilege and isolates credentials`() {
        val spec = ErpNextRuntime.spec(inventory)
        assertEquals(12, PrivateDeployment.validate(spec).size)
        assertEquals(8, spec.processes.count { !it.oneShot })
        assertTrue(spec.processes.all { it.userId != 0 && it.capabilities.isEmpty() && it.apparmorProfile == "p0v3-private-v1" })
        val files = ErpNextRuntime.inputs { mapOf("ca.pem" to "ca", "web.pem" to "cert", "web-key.pem" to "key") }
        assertEquals(SingleUserRestore.inputNames(spec), files.keys)
        assertTrue(spec.processes.filterNot { it.oneShot }.none { it.environmentFile in setOf("bootstrap.env", "installer.env") })
        assertContains(spec.processes.single { it.id == "installer-retire" }.command.last(), "DROP USER")
        assertContains(files.getValue("site-init.py"), "force=False")
        assertContains(files.getValue("site-init.py"), "Existing or interrupted site retained")
        assertContains(files.getValue("site-init.py"), "if not __debug__:")
        assertContains(files.getValue("queue.conf"), "appendonly yes")
        assertContains(files.getValue("cache.conf"), "appendonly no")
        val common = Json.parseToJsonElement(files.getValue("common-site.json")).jsonObject
        assertEquals(false, common.getValue("server_script_enabled").jsonPrimitive.boolean)
        assertEquals(1, common.getValue("pause_scheduler").jsonPrimitive.int)
        assertEquals("backend", common.getValue("webserver_host").jsonPrimitive.content)
        assertEquals(8000, common.getValue("webserver_port").jsonPrimitive.int)
        assertContains(files.getValue("nginx.conf"), "default ${'$'}http_origin;")
        assertContains(files.getValue("nginx.conf"), "proxy_set_header Origin ${'$'}erp_origin;")
        assertFalse("proxy_set_header Origin https:" in files.getValue("nginx.conf"))
        assertTrue(spec.processes.filter { it.id in setOf("worker", "scheduler", "websocket") }.all { it.command.first() == "/run/secrets/process-init.py" })
        assertTrue(common.getValue("redis_queue").jsonPrimitive.content.startsWith("redis://:"))
        assertFails { ErpNextRuntime.spec(inventory.copy(images = inventory.images.drop(1))) }
        assertFails { ErpNextRuntime.spec(inventory.copy(images = inventory.images.map { it.copy(os = "other") })) }
        assertFails { ErpNextRuntime.spec(inventory, "../bad") }
    }
}
