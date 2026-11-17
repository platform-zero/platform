package net.datamancy.platform

import kotlin.test.Test
import java.nio.file.Files
import kotlinx.serialization.json.*
import kotlin.test.assertFails

class QualificationNtfyGroupReadbackTest {
    @Test fun `selected parent-domain gateway cookie keeps its real scope and flags`() {
        // Pure protected-file fixture: no issuer login or gateway effect is claimed.
        val dir = Files.createTempDirectory("ntfy-cookie-fault-")
        try {
            val generation = "q-123456abcdef"
            val bundle = "a".repeat(64)
            fun pin(name: String, bytes: ByteArray): ActivationInput {
                val path = dir.resolve(name)
                ReleasePrivateFiles.save(path,bytes)
                return ActivationInput(path.toString(),ReleaseLocks.sha256(bytes))
            }
            val issuer = pin("issuer.json", "test-only-issuer".encodeToByteArray())
            fun inspect(domain: String, name: String = "_p0v3_edge", secure: Boolean = true,
                httpOnly: Boolean = true) {
                val session = pin("session-${name.replace(Regex("[^a-zA-Z0-9]"),"")}-${domain.replace(".","dot")}-${secure}-${httpOnly}.json",
                    buildJsonObject {
                        put("cookies",buildJsonArray { add(buildJsonObject {
                            put("name",name); put("domain",domain); put("path","/")
                            put("value","unit-only"); put("secure",secure)
                            put("httpOnly",httpOnly); put("sameSite","Lax")
                        }) }); put("origins",buildJsonArray {})
                    }.toString().encodeToByteArray())
                val admission = pin("admission-${session.sha256}.json",buildJsonObject {
                    put("generationId",generation); put("host","ntfy.datamancy.net")
                    put("serviceId","ntfy"); put("groups","operators")
                    put("sessionSha256",session.sha256); put("issuerResultSha256",issuer.sha256)
                }.toString().encodeToByteArray())
                val readback = NtfyGroupOwnerReadback(generation,bundle,"ntfy.datamancy.net",
                    session,admission,issuer)
                if (name == "_p0v3_edge" && domain in setOf("datamancy.net",".datamancy.net") &&
                    secure && httpOnly)
                    kotlin.test.assertEquals(admission to session,
                        QualificationNtfyGroupReadback.verify(readback,generation,bundle))
                else assertFails { QualificationNtfyGroupReadback.verify(readback,generation,bundle) }
            }
            inspect("datamancy.net")
            inspect(".datamancy.net")
            inspect("evil.example")
            inspect("ntfy.datamancy.net")
            inspect(".datamancy.net",name="other_cookie")
            inspect(".datamancy.net",secure=false)
            inspect(".datamancy.net",httpOnly=false)
        } finally {
            Files.list(dir).use { paths -> paths.forEach { Files.delete(it) } }
            Files.delete(dir)
        }
    }

    @Test fun `GROUP cookie cannot come from another generation or unselected host`() {
        val hash = "a".repeat(64)
        val pin = ActivationInput("/unavailable/owner-result",hash)
        val valid = NtfyGroupOwnerReadback("q-123456abcdef",hash,"ntfy.datamancy.net",
            pin,pin,pin)
        assertFails { QualificationNtfyGroupReadback.verify(valid.copy(
            generationId="q-abcdef123456"),"q-123456abcdef",hash) }
        assertFails { QualificationNtfyGroupReadback.verify(valid.copy(
            host="ntfy-native.datamancy.net"),"q-123456abcdef",hash) }
        assertFails { QualificationNtfyGroupReadback.verify(valid.copy(
            bundleSha256="b".repeat(64)),"q-123456abcdef",hash) }
        // Three independent protected bytes are mandatory, not the same token
        // renamed as a browser cookie and issuer result.
        assertFails { QualificationNtfyGroupReadback.verify(valid,"q-123456abcdef",hash) }
    }
}
