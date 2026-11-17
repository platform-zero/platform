package net.datamancy.platform

import kotlinx.serialization.json.*
import java.nio.file.Path

/** Core's actual selected GROUP/OIDC post-login session; never caller context or
 * a native ntfy bearer substituted for a browser cookie. Producer must attest
 * Keycloak issuer/group and Caddy gateway admission before constructing this. */
internal data class NtfyGroupOwnerReadback(val generationId: String, val bundleSha256: String,
    val host: String, val session: ActivationInput, val admission: ActivationInput,
    val issuerResult: ActivationInput)

internal object QualificationNtfyGroupReadback {
    fun verify(readback: NtfyGroupOwnerReadback, generationId: String, bundleSha256: String): Pair<ActivationInput,ActivationInput> {
        val hex = Regex("[a-f0-9]{64}")
        require(readback.generationId == generationId && readback.bundleSha256 == bundleSha256 &&
            readback.host == "ntfy.datamancy.net" && hex.matches(bundleSha256))
        val originals = listOf(readback.session,readback.admission,readback.issuerResult)
        require(originals.map { it.path }.toSet().size == 3 && originals.all { pin ->
            hex.matches(pin.sha256) && Path.of(pin.path).isAbsolute &&
                ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(pin.path),65536)) == pin.sha256
        })
        val admission = Json.parseToJsonElement(ReleasePrivateFiles.read(
            Path.of(readback.admission.path),65536).decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(admission.getValue("generationId").jsonPrimitive.content == generationId &&
            admission.getValue("host").jsonPrimitive.content == readback.host &&
            admission.getValue("serviceId").jsonPrimitive.content == "ntfy" &&
            admission.getValue("groups").jsonPrimitive.content in setOf("admins","operators") &&
            admission.getValue("sessionSha256").jsonPrimitive.content == readback.session.sha256 &&
            admission.getValue("issuerResultSha256").jsonPrimitive.content == readback.issuerResult.sha256)
        val session = Json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(readback.session.path),65536)
            .decodeToString(throwOnInvalidSequence=true)).jsonObject
        // The selected auth-gateway issues a parent-domain cookie for its real
        // OIDC callback. Never rewrite it to ntfy's host or accept another name,
        // domain, security flag or foreign browser storage state.
        require(session.keys == setOf("cookies","origins") && session.getValue("cookies").jsonArray.isNotEmpty() &&
            session.getValue("origins").jsonArray.isEmpty() &&
            session.getValue("cookies").jsonArray.all { raw ->
                val cookie = raw.jsonObject
                cookie.getValue("name").jsonPrimitive.content == "_p0v3_edge" &&
                    cookie.getValue("domain").jsonPrimitive.content in setOf("datamancy.net",".datamancy.net") &&
                    cookie.getValue("path").jsonPrimitive.content == "/" &&
                    cookie.getValue("value").jsonPrimitive.content.isNotBlank() &&
                    cookie.getValue("secure").jsonPrimitive.boolean &&
                    cookie.getValue("httpOnly").jsonPrimitive.boolean &&
                    cookie.getValue("sameSite").jsonPrimitive.content.equals("lax",ignoreCase=true)
            })
        // The core producer validates the actual issuer result and active native
        // GROUP session; these raw bytes remain a separate pin, not a fabricated ACK.
        return readback.admission to readback.session
    }
}
