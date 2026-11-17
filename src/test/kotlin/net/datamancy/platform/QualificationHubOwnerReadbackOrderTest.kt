package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QualificationHubOwnerReadbackOrderTest {
    @Test fun `owner creates exactly once before C1 and refuses an existing or symlinked proof dir`() {
        val base=Files.createTempDirectory("hub-owner-order-")
        Files.setPosixFilePermissions(base,PosixFilePermissions.fromString("rwx------"))
        try {
            val caseDir=Files.createDirectory(base.resolve("jupyterhub--workflow--web--browser"),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            assertFalse(Files.exists(caseDir.resolve("owner-proofs"),NOFOLLOW_LINKS))
            val proof=QualificationHubOwnerReadback.createOwnerProofDirectory(caseDir)
            assertEquals(caseDir.resolve("owner-proofs"),proof)
            assertEquals(PosixFilePermissions.fromString("rwx------"),Files.getPosixFilePermissions(proof))
            assertFalse(Files.exists(proof.resolve("hub-db-snapshot.intent.json"),NOFOLLOW_LINKS))
            assertFailsWith<IllegalArgumentException> {
                QualificationHubOwnerReadback.createOwnerProofDirectory(caseDir)
            }
            Files.delete(proof)
            Files.createSymbolicLink(proof,base)
            assertFailsWith<IllegalArgumentException> {
                QualificationHubOwnerReadback.createOwnerProofDirectory(caseDir)
            }
            Files.delete(proof)
            Files.setPosixFilePermissions(caseDir,PosixFilePermissions.fromString("rwxrwx---"))
            assertFailsWith<IllegalArgumentException> {
                QualificationHubOwnerReadback.createOwnerProofDirectory(caseDir)
            }
            assertFalse(Files.exists(proof,NOFOLLOW_LINKS))
        } finally {
            Files.walk(base).sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }
}
