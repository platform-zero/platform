package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*

class FreshFinanceSelectedBackendsTest {
    @Test fun `finance ingress HTTPS leaf and importer trust are bound to one generation`() {
        val fragment = PackagedGraphFragment.loadPendingV3("private-firefly-iii", 5, 9)
        val graph = fragment.definition
        val importer = graph.processes.single { it.id == "firefly-importer" }
        val front = graph.processes.single { it.id == "firefly" }
        assertTrue(importer.files.any { it.file == "finance-ingress-ca.pem" &&
            it.target == "/run/secrets/finance-ingress-ca.pem" })
        assertTrue(importer.files.any { it.file == "finance-ingress-php.ini" &&
            it.target == "/usr/local/etc/php/conf.d/99-p0v3-finance-ingress.ini" })
        assertTrue(front.files.any { it.file == "finance-ingress-web.pem" })
        assertTrue(front.files.any { it.file == "finance-ingress-web-key.pem" })
        val ini = FragmentTemplates.render(fragment, "finance-ingress-php.ini", emptyMap())
        assertContains(ini, "curl.cainfo=/run/secrets/finance-ingress-ca.pem")
        assertContains(ini, "openssl.cafile=/run/secrets/finance-ingress-ca.pem")
        val policy = FragmentTemplates.render(fragment, "finance-initialize-policy.php", emptyMap())
        assertContains(policy, "config('importer.connection.verify') !== true")
        assertContains(policy, "config('importer.url') !== 'https://firefly.datamancy.net'")
        assertContains(FreshFinanceImporterSource.inputs("00000000-0000-4000-8000-000000000001",
            "a".repeat(64), "q-000000000001"), "SSL_CERT_FILE=/run/secrets/finance-ingress-ca.pem")
    }
    @Test fun `r9 selected finance backends and sealed patches retain pinned provenance`() {
        val fragment = PackagedGraphFragment.loadPendingV3("private-firefly-iii", 5, 9)
        val graph = fragment.definition
        val peers = graph.processes.associateBy { it.id }
        for (id in listOf("firefly-importer", "firefly-sso", "firefly-importer-sso")) {
            assertTrue(id in graph.install.processes && id in graph.restore.processes)
            assertFalse(peers.getValue(id).oneShot)
        }
        assertEquals("firefly-importer", peers.getValue("firefly-importer").artifact)
        assertEquals("firefly-sso", peers.getValue("firefly-sso").artifact)
        assertEquals("firefly-sso", peers.getValue("firefly-importer-sso").artifact)
        assertTrue("finance-api" in peers.getValue("firefly-native-api").networks &&
            "finance-api" in peers.getValue("firefly-importer").networks)
        assertFalse("finance-api" in graph.webNetworks)
        assertTrue("keycloak" in graph.install.dependencies.getValue("firefly-users-init"))
        assertTrue(graph.volumes.any { it.id == "firefly-importer-storage" && it.userId == 33 })
        assertTrue(peers.getValue("firefly-importer").files.any {
            it.file == "finance-restore-access-reset.php" &&
                it.target == "/opt/firefly-importer/RestoreAccessReset.php" })
        assertContains(FragmentTemplates.render(fragment, "finance-restore-access-reset.php", emptyMap()),
            "restore-session-reset.")
        val manifest = PackagedGraphFragment.pendingV3R9().first
        val declarations = manifest.integratedReference!!.modules.single { it.id == "firefly-iii" }.privateRoutes
        assertEquals("firefly-sso", declarations.single { it.label == "firefly" }.process)
        assertEquals("firefly-importer-sso", declarations.single { it.label == "firefly-importer" }.process)
        val source = Path.of("/tmp/p0-old-full-36b6b7/modules/firefly-iii/legacy/stack.config/firefly-importer")
        if (Files.isRegularFile(source.resolve("ImporterSubjects.php"))) {
            for ((file, output) in listOf("ImportJobRepository.php" to "finance-importjobrepository.php",
                "ManualFilePolicy.php" to "finance-manualfilepolicy.php",
                "bootstrap-app.php" to "finance-bootstrap-app.php")) {
                assertEquals(Files.readString(source.resolve(file)), FragmentTemplates.render(fragment, output, emptyMap()))
            }
        }
        val subjects = FragmentTemplates.render(fragment, "finance-importersubjects.php", emptyMap())
        assertContains(subjects, "realms/p0v3")
        assertContains(subjects, "p0-subject-owners")
        assertContains(subjects, "fsync(")
        val boundary = FragmentTemplates.render(fragment, "finance-subjectboundary.php", emptyMap())
        assertContains(boundary, "http://firefly-native-api:8081/api/v1/about/user")
        assertContains(boundary, "hash_equals(")
        assertFalse(boundary.contains("file_get_contents((string) config('importer.url').'/api/v1/about/user'"))
        val php = peers.getValue("firefly-php")
        assertTrue(php.files.any { it.target == "/var/www/html/app/Providers/AuthServiceProvider.php" })
        assertTrue(php.files.any { it.target == "/var/www/html/config/session.php" })
    }
}
