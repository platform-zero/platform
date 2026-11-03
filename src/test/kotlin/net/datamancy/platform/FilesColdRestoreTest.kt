package net.datamancy.platform

import kotlin.test.*

class FilesColdRestoreTest {
    private val image = "example.org/app@sha256:" + "a".repeat(64)
    private val inventory = AcquiredInventory(1, "candidate", listOf("seafile", "mariadb", "valkey", "jupyterhub", "jupyter-notebook", "caddy").map {
        val pinned = if (it == "caddy") HulyRuntime.CADDY_BASE else image
        AcquiredImage(it, "upstream", "example.org/app:1", pinned, "b".repeat(64), emptyList(), pinned.substringAfter('@'), "amd64", "linux")
    })
    private fun tls() = mapOf("ca.pem" to "ca", "web.pem" to "cert", "web-key.pem" to "key")

    @Test fun `provider-less files recipe has no database root authority or duplicate provider`() {
        val spec = SeafileRuntime.applicationSpec(inventory)
        assertEquals(setOf("state", "rpc"), spec.volumes.map { it.id }.toSet())
        assertEquals(setOf("schema-init", "server", "users-init", "backend", "files"), spec.processes.map { it.id }.toSet())
        val files = SeafileRuntime.applicationInputs("1".repeat(64), "2".repeat(64), ::tls)
        assertEquals(SingleUserRestore.inputNames(spec), files.keys)
        assertFalse("mariadb.env" in files)
        assertFalse("cache.conf" in files)
        assertContains(files.getValue("app.env"), "SEAFILE_MYSQL_DB_PASSWORD=" + "1".repeat(64))
        assertContains(files.getValue("app.env"), "REDIS_PASSWORD=" + "2".repeat(64))
        assertFails { SeafileRuntime.applicationInputs("bad", "2".repeat(64), ::tls) }
        assertFails { SeafileRuntime.applicationInputs("1".repeat(64), "1".repeat(64), ::tls) }
        val office = OfficeRuntime.applicationSpec(inventory)
        val officeInputs = OfficeRuntime.applicationInputs("1".repeat(64), "2".repeat(64)) { tls() }
        assertEquals(SingleUserRestore.inputNames(office), officeInputs.keys)
        assertFalse("mariadb.env" in officeInputs)
        assertContains(officeInputs.getValue("app.env"), "REDIS_PASSWORD=" + "2".repeat(64))
        assertContains(officeInputs.getValue("app.env"), "REQUESTS_CA_BUNDLE=")
        assertContains(officeInputs.getValue("seahub-settings.py"), "ENABLE_ONLYOFFICE=True")
        assertTrue(OfficeRuntime.coldRestoreSpec(office).processes.none { it.oneShot })
        assertFails { OfficeRuntime.applicationInputs("bad", "2".repeat(64)) { tls() } }
    }

    @Test fun `cold files retire bootstrap credentials and preserve serving dependency order`() {
        for (source in listOf(SeafileRuntime.spec(inventory), SeafileRuntime.applicationSpec(inventory))) {
            val restored = SeafileRuntime.coldRestoreSpec(source)
            assertTrue(restored.processes.none { it.oneShot })
            assertEquals(source.volumes, restored.volumes)
            assertEquals(listOf("server"), restored.processes.single { it.id == "backend" }.dependencies)
            assertFalse("users.json" in SingleUserRestore.inputNames(restored))
            assertFalse("schema.py" in SingleUserRestore.inputNames(restored))
            assertFalse("mariadb.env" in SingleUserRestore.inputNames(restored))
            val server = restored.processes.single { it.id == "server" }
            assertContains(server.command.joinToString(" "), "test ! -L /state/seafile-data")
            assertContains(server.command.joinToString(" "), "process-init.py")
            PrivateDeployment.validate(restored)
        }
        val source = SeafileRuntime.spec(inventory)
        assertFails { SeafileRuntime.coldRestoreSpec(source.copy(processes = source.processes.filterNot { it.id == "users-init" })) }
        assertFails { SeafileRuntime.coldRestoreSpec(source.copy(processes = source.processes.map { if (it.id == "server") it.copy(entrypoint = "/unknown") else it })) }
    }

    @Test fun `cold office retains document cache and callback ledger volume without replaying state initialization`() {
        val source = OfficeRuntime.spec(inventory)
        val restored = OfficeRuntime.coldRestoreSpec(source)
        assertEquals(source.volumes, restored.volumes)
        assertTrue(restored.processes.none { it.oneShot })
        assertContains(restored.processes.single { it.id == "docservice" }.command.joinToString(" "), "test -d /state/cache/files")
        assertEquals(source.processes.single { it.id == "backend" }.files, restored.processes.single { it.id == "backend" }.files)
        assertFails { OfficeRuntime.coldRestoreSpec(source.copy(processes = source.processes.filterNot { it.id == "office-state-init" })) }
    }

    @Test fun `cold notebook and hub refuse silent home database and cookie regeneration`() {
        val notebook = NotebookRuntime.coldRestoreSpec(NotebookRuntime.spec(inventory))
        assertEquals(listOf("notebook"), notebook.processes.map { it.id })
        assertContains(notebook.processes.single().command.joinToString(" "), "test ! -L /home/jovyan/work")
        assertTrue(notebook.processes.single().dependencies.isEmpty())
        val source = JupyterHubRuntime.spec(inventory)
        val hub = JupyterHubRuntime.coldRestoreSpec(source)
        assertEquals(source.volumes, hub.volumes)
        val controller = hub.processes.single { it.id == "controller" }.command.joinToString(" ")
        assertContains(controller, "test -s /state/hub.sqlite")
        assertContains(controller, "test -s /state/cookie-secret")
        assertContains(controller, "/srv/venv/bin/jupyterhub")
        for (user in listOf("alice", "bob")) {
            val command = hub.processes.single { it.id == user }.command.joinToString(" ")
            assertContains(command, "grep -qx stopped /home/jovyan/.p0-hub-state")
            assertContains(command, "test ! -L /home/jovyan/.p0-hub-state.pending")
        }
        assertFails { JupyterHubRuntime.coldRestoreSpec(source.copy(processes = source.processes.drop(1))) }
        assertFails { NotebookRuntime.coldRestoreSpec(notebook) }
    }
}
