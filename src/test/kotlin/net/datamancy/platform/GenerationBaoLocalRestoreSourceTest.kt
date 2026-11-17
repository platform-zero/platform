package net.datamancy.platform

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Schema and fail-closed source proof, never a replacement for original Bao
 * export, actual local decryption, target unseal or qualified RESTORE. */
class GenerationBaoLocalRestoreSourceTest {
    @Test fun `local-only result requires original hash and no invented offline custody`() {
        val value = BaoLocalAgeDecryptResult(sourceGeneration = "q-111111111111",
            targetGeneration = "q-222222222222", snapshotSha256 = "a".repeat(64),
            encryptedArchiveSha256 = "b".repeat(64), originalInitSha256 = "c".repeat(64),
            decryptedOriginalInitSha256 = "c".repeat(64), localAgeIdentitySha256 = "d".repeat(64),
            recipientSha256 = "e".repeat(64), originalIssuerResultSha256 = "f".repeat(64))
        val source = Json { encodeDefaults = true }.encodeToString(value)
        assertEquals(setOf("schemaVersion", "qualificationScope", "sourceGeneration",
            "targetGeneration", "snapshotSha256", "encryptedArchiveSha256", "originalInitSha256",
            "decryptedOriginalInitSha256", "localAgeIdentitySha256", "recipientSha256",
            "originalIssuerResultSha256", "nativeDecryptionVerified", "independentOffsiteCustodyVerified"),
            Json.parseToJsonElement(source).jsonObject.keys)
        assertTrue(value.nativeDecryptionVerified)
        assertFalse(value.independentOffsiteCustodyVerified)
        assertEquals("LOCAL_ENCRYPTED_BACKUP_ISOLATED_RESTORE", value.qualificationScope)
    }
}
