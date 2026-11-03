package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Exact sealed runtime endpoint; no ambient host-loopback fallback for release effects. */
@Serializable internal data class ReleaseCaddyEndpoint(val manifest: ActivationInput, val runtimeFingerprint: String)

internal object ReleaseCaddyEndpoints {
    fun spec(ingress: ReleaseIngress, runtimeBase: Path = PrivateDeployment.BASE): PrivateDeploymentSpec {
        val endpoint = requireNotNull(ingress.runtime) { "Release ingress requires a pinned canonical Caddy runtime" }
        require(endpoint.runtimeFingerprint.matches(Regex("[a-f0-9]{64}")) &&
            endpoint.manifest.sha256.matches(Regex("[a-f0-9]{64}")))
        val path = Path.of(endpoint.manifest.path)
        require(path.isAbsolute && path.normalize() == path && path.parent == runtimeBase) {
            "Caddy manifest must belong to the canonical runtime registry"
        }
        val bytes = ReleasePrivateFiles.read(path)
        require(ReleaseLocks.sha256(bytes) == endpoint.manifest.sha256) { "Caddy manifest changed" }
        val spec = Json.decodeFromString<PrivateDeploymentSpec>(bytes.decodeToString(throwOnInvalidSequence = true))
        PrivateDeployment.validate(spec)
        require(path.fileName.toString() == "${spec.name}.json" &&
            spec.name.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,23}")) &&
            spec.store == RuntimeStore.CANONICAL_V2 && spec.ingress != null) {
            "Release ingress requires an explicitly published canonical generation"
        }
        NamespaceCaddyTransport.checkBinding(ingress.site, spec)
        return spec
    }

    fun real(ingress: ReleaseIngress): TransactionalCaddy = TransactionalCaddy.inRuntime(
        Path.of(ingress.root), ingress.site, spec(ingress), requireNotNull(ingress.runtime).runtimeFingerprint)
}
