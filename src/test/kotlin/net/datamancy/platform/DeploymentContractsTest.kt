package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DeploymentContractsTest {
    private val image = "docker.io/library/busybox@sha256:${"a".repeat(64)}"
    private val db = ModuleContract("postgres", emptyList(), listOf(ComponentContract("postgres", ComponentMode.DAEMON, image, listOf("DB_KEY"))),
        listOf(PersistenceContract("postgres", "database", "/var/lib/postgresql")))
    private val app = ModuleContract("portal", listOf("postgres"), listOf(ComponentContract("portal", ComponentMode.DAEMON, image, emptyList())), emptyList())
    private val route = ApprovedRoute("portal.example.test", "portal", 8080)
    private val boundary = DeploymentBoundary(Path.of("/tmp/p0v3-contract-data"), Path.of("/tmp/p0v3-contract-backup"), setOf(route.host))
    private fun site(vararg modules: ModuleContract) = DeploymentSite(1, "scratch", modules.toList(), listOf(route))
    private fun plan(site: DeploymentSite) = DeploymentContracts.plan(site, boundary)

    @Test fun `explicit contracts produce sorted steps without making inventory installable`() {
        val first = plan(site(app, db))
        val second = plan(site(db, app))
        assertEquals(first, second)
        assertEquals(listOf("postgres", "portal"), first.install.map { it.moduleId })
        assertEquals(listOf(WorkflowKind.REQUIRE_VERIFIED_BACKUP, WorkflowKind.REQUIRE_FUNCTIONAL_TEST,
            WorkflowKind.REMOVE, WorkflowKind.REMOVE), first.teardown.map { it.kind })
        assertEquals(listOf("portal", "postgres"), first.teardown.takeLast(2).map { it.moduleId })
        assertEquals(listOf("portal", "postgres"), first.backup.take(2).map { it.moduleId })
        assertEquals(listOf("database"), first.backup.filter { it.kind == WorkflowKind.SNAPSHOT }.map { it.volume })
        assertEquals(listOf("portal", "postgres"), first.backup.filter { it.kind == WorkflowKind.STOP }.map { it.componentId })
        assertEquals(listOf(WorkflowKind.RESTORE_ISOLATED, WorkflowKind.REQUIRE_FUNCTIONAL_TEST), first.restore.map { it.kind })
        assertEquals("/tmp/p0v3-contract-data/scratch", first.dataPath)
        assertEquals("/tmp/p0v3-contract-backup/scratch", first.backupPath)
        assertEquals(listOf(route), first.routes)
        assertEquals(2, first.modules.size)
        assertFalse(first.toString().contains("useradd"))
    }

    @Test fun `routes require independent approval and explicit targets`() {
        assertFailsWith<IllegalArgumentException> { DeploymentContracts.plan(site(db, app), boundary.copy(approvedHosts = emptySet())) }
        assertFailsWith<IllegalArgumentException> { plan(site(db, app).copy(routes = listOf(route.copy(componentId = "keycloak")))) }
        assertFailsWith<IllegalArgumentException> { plan(site(db, app).copy(routes = listOf(route.copy(containerPort = 0)))) }
        assertFailsWith<IllegalArgumentException> { plan(site(db, app).copy(routes = listOf(route.copy(host = "bad\nHost")))) }
        assertFailsWith<IllegalArgumentException> { plan(site(db, app).copy(routes = listOf(route, route))) }
        assertTrue(plan(site(db, app).copy(routes = emptyList())).routes.isEmpty())
        assertFailsWith<IllegalArgumentException> {
            plan(site(db, app.copy(components = listOf(app.components[0].copy(mode = ComponentMode.ONE_SHOT)))))
        }
    }

    @Test fun `modules must have real explicit components dependencies and persistence`() {
        assertFailsWith<IllegalArgumentException> { plan(site(app)) } // missing dependency, not inferred from inventory
        assertFailsWith<IllegalArgumentException> { plan(site(db, app, app)) }
        assertFailsWith<IllegalArgumentException> { plan(site(db.copy(id = "invented"), app)) }
        assertFailsWith<IllegalArgumentException> { plan(site(db.copy(components = emptyList()), app)) }
        assertFailsWith<IllegalArgumentException> { plan(site(db.copy(components = listOf(ComponentContract("portal", ComponentMode.DAEMON, image, emptyList()))), app)) }
        assertFailsWith<IllegalArgumentException> { plan(site(db.copy(components = listOf(db.components[0].copy(image = "docker.io/library/busybox:latest"))), app)) }
        assertFailsWith<IllegalArgumentException> { plan(site(db.copy(components = listOf(db.components[0].copy(secretKeys = listOf("plaintext=value")))), app)) }
        assertFailsWith<IllegalArgumentException> { plan(site(db.copy(persistence = listOf(PersistenceContract("postgres", "database", "/../host"))), app)) }
        assertFailsWith<IllegalArgumentException> { plan(site(db.copy(persistence = listOf(PersistenceContract("portal", "database", "/data"))), app)) }
        assertFailsWith<IllegalArgumentException> { plan(site(db.copy(persistence = db.persistence + db.persistence[0]), app)) }
        assertFailsWith<IllegalArgumentException> { plan(site(db.copy(dependsOn = listOf("postgres")), app)) }
        val incompleteKeycloak = ModuleContract("keycloak", emptyList(),
            listOf(ComponentContract("keycloak", ComponentMode.DAEMON, image, emptyList())), emptyList())
        assertFailsWith<IllegalArgumentException> { plan(site(db, app, incompleteKeycloak)) }
        val explicit = incompleteKeycloak.copy(components = incompleteKeycloak.components +
            ComponentContract("keycloak-bootstrap", ComponentMode.ONE_SHOT, image, emptyList()))
        val noRoutes = DeploymentSite(1, "scratch", listOf(explicit), emptyList())
        assertEquals(ComponentMode.ONE_SHOT, plan(noRoutes).modules.single().components.last().mode)
        assertEquals(listOf("keycloak"), plan(noRoutes).backup.filter { it.kind == WorkflowKind.STOP }.map { it.componentId })
        assertFailsWith<IllegalArgumentException> {
            plan(noRoutes.copy(routes = listOf(route.copy(componentId = "keycloak-bootstrap"))))
        }
        val cycle = db.copy(dependsOn = listOf("portal"))
        assertFailsWith<IllegalArgumentException> { plan(site(cycle, app)) }
    }

    @Test fun `roots and site IDs must not select host or unrelated media`() {
        assertFailsWith<IllegalArgumentException> { plan(site(db, app).copy(siteId = "../software_lab")) }
        assertFailsWith<IllegalArgumentException> { plan(site(db, app).copy(schemaVersion = 2)) }
        assertFailsWith<IllegalArgumentException> { plan(site()) }
        assertFailsWith<IllegalArgumentException> { DeploymentContracts.plan(site(db, app), boundary.copy(dataRoot = Path.of("/"))) }
        assertFailsWith<IllegalArgumentException> { DeploymentContracts.plan(site(db, app), boundary.copy(backupRoot = Path.of("/tmp/p0v3-contract-data/backup"))) }
        assertFailsWith<IllegalArgumentException> { DeploymentContracts.plan(site(db, app), boundary.copy(dataRoot = Path.of("relative"))) }
    }

    @Test fun `host-local site rejects broad permissions symlinks and plaintext secret fields`() {
        val file = Files.createTempFile("p0v3-contract-", ".json")
        val link = file.resolveSibling(file.fileName.toString() + "-link")
        val approvals = Files.createTempFile("p0v3-approved-", ".json")
        try {
            val json = """{"schemaVersion":1,"siteId":"scratch","modules":[{"id":"postgres","dependsOn":[],"components":[{"id":"postgres","mode":"DAEMON","image":"$image","secretKeys":[]}],"persistence":[]}],"routes":[]}"""
            Files.writeString(file, json)
            Files.setPosixFilePermissions(file, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE))
            assertEquals("scratch", DeploymentSite.hostLocal(file).siteId)
            Files.writeString(approvals, """["portal.example.test"]""")
            Files.setPosixFilePermissions(approvals, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE))
            val result = mutableListOf<String>()
            val errors = mutableListOf<String>()
            assertEquals(0, runCommand(arrayOf("contract", "plan", file.toString(), approvals.toString(),
                boundary.dataRoot.toString(), boundary.backupRoot.toString()), result::add, errors::add))
            assertTrue(result.single().contains("RESTORE_ISOLATED"))
            assertTrue(errors.isEmpty())
            Files.writeString(approvals, """["portal.example.test","portal.example.test"]""")
            assertFailsWith<IllegalArgumentException> { DeploymentSite.approvedHosts(approvals) }
            Files.setPosixFilePermissions(approvals, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.GROUP_READ))
            assertFailsWith<IllegalArgumentException> { DeploymentSite.approvedHosts(approvals) }
            Files.createSymbolicLink(link, file)
            assertFailsWith<IllegalArgumentException> { DeploymentSite.hostLocal(link) }
            Files.setPosixFilePermissions(file, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.GROUP_READ))
            assertFailsWith<IllegalArgumentException> { DeploymentSite.hostLocal(file) }
            Files.setPosixFilePermissions(file, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE))
            Files.writeString(file, json.replace("\"secretKeys\":[]", "\"secretValue\":\"do-not-store-secrets\",\"secretKeys\":[]"))
            assertFailsWith<Exception> { DeploymentSite.hostLocal(file) }
        } finally {
            Files.deleteIfExists(link)
            Files.delete(file)
            Files.delete(approvals)
        }
    }
}
