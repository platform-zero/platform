package net.datamancy.platform

import java.nio.file.Files
import kotlin.test.*

class FreshSearchReaderSourceTest {
    @Test fun `fresh mTLS reader is independently issued and only granted read actions`() {
        val source = OpenSearchRuntime.canonicalFreshInputs()
        val ca = source.getValue("opensearch-ca.pem")
        val reader = source.getValue("opensearch-reader.pem")
        assertTrue(ca.contains("BEGIN CERTIFICATE") && reader.contains("BEGIN CERTIFICATE"))
        assertNotEquals(reader, source.getValue("opensearch-node.pem"))
        assertNotEquals(reader, source.getValue("opensearch-admin.pem"))
        val roles = source.getValue("opensearch-roles.yml")
        val mapping = source.getValue("opensearch-roles-mapping.yml")
        assertContains(roles, "caddy_reader:")
        assertContains(roles, "allowed_actions: ['read']")
        assertContains(mapping, "users: ['p0v3-caddy-reader']")
        assertFalse(mapping.contains("admin_dn: ['CN=p0v3-caddy-reader']"))
        val root = Files.createTempDirectory("p0-r9-search-reader-test-")
        try {
            val caFile = root.resolve("ca.pem"); val readerFile = root.resolve("reader.pem")
            Files.writeString(caFile, ca); Files.writeString(readerFile, reader)
            val verify = ProcessBuilder("openssl", "verify", "-CAfile", caFile.toString(), readerFile.toString())
                .redirectErrorStream(true).start()
            assertEquals(0, verify.waitFor())
            val text = ProcessBuilder("openssl", "x509", "-in", readerFile.toString(), "-noout", "-subject")
                .redirectErrorStream(true).start().inputStream.bufferedReader().readText()
            assertContains(text, "p0v3-caddy-reader")
            assertFalse(text.contains("p0v3-admin"))
        } finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
