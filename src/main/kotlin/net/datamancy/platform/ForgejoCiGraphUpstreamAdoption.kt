package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** One-use source handoff AFTER the original graph Caddy issuer is actually
 * serving. The request declares this authority, never a future successful
 * native CA readback or guessed private IP. No rootless CI effect precedes it.
 */
@Serializable internal data class ForgejoCiGraphUpstreamIntent(val generation: String,
    val bundleSha256: String, val hostname: String, val network: String,
    val servedLeafObservation: ActivationInput, val ca: ActivationInput,
    val privateUpstream: String)
internal object ForgejoCiGraphUpstreamAdoption {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private const val host = "forgejo.datamancy.net"
    /** Revalidate the original result and live current issuer before every host
     * API or Git operation. A declaration alone never authorizes transport. */
    fun current(plan: ForgejoCiSourcePlan): Pair<String, ActivationInput> {
        require(plan.graphOwnedLateUpstream)
        val root = GenerationRuntime.BASE.resolve(plan.generation)
        val ci = root.resolve("ci")
        val bytes = ReleasePrivateFiles.read(ci.resolve("transport-upstream-adoption.intent.json"),8192)
        val intent = json.decodeFromString<ForgejoCiGraphUpstreamIntent>(
            bytes.decodeToString(throwOnInvalidSequence = true))
        require(ReleasePrivateFiles.read(ci.resolve("transport-upstream-adoption.result.json"),128)
            .decodeToString(throwOnInvalidSequence = true) == ReleaseLocks.sha256(bytes) &&
            intent.generation == plan.generation && intent.hostname == host &&
            intent.network == "ingress-control" && ForgejoCiTransportSource.validUpstream(intent.privateUpstream) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(ci.resolve("transport-upstream-ca.pem"),65536)) == intent.ca.sha256)
        val bundleBytes = ReleasePrivateFiles.read(root.resolve("bundle.json"),4194304)
        require(ReleaseLocks.sha256(bundleBytes) == intent.bundleSha256)
        val bundle = json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
        require(bundle.request.forgejoCi == plan || bundle.request.recoveredForgejoCiTarget == plan)
        val manifest = PackagedGraphFragment.pendingV3R9().first
        val verified = CanonicalCaddyServedLeafReadback(root,bundle,intent.bundleSha256,manifest)
        require(verified.verify(host) == intent.servedLeafObservation &&
            verified.verifiedPrivateEndpoint(host) == intent.privateUpstream &&
            CanonicalCaddyInternalCaCustody(root,bundle,intent.bundleSha256,manifest).activationInput() == intent.ca)
        return intent.privateUpstream to intent.ca
    }
    fun adopt(plan: ForgejoCiSourcePlan, bundle: GenerationBundle, root: Path,
        expected: String, recovered: Boolean = false) {
        require(plan.graphOwnedLateUpstream &&
            (if (recovered) bundle.request.recoveredForgejoCiTarget == plan &&
                bundle.recoverySourceKopia != null && bundle.request.forgejoCi == null
            else plan.freshIssuerBootstrap && bundle.request.forgejoCi == plan &&
                bundle.recoverySourceKopia == null) &&
            root == GenerationRuntime.BASE.resolve(plan.generation) &&
            expected == ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)))
        val ci = root.resolve("ci")
        ReleasePrivateFiles.directory(ci)
        val pending = json.decodeFromString<ForgejoCiGraphUpstreamPending>(ReleasePrivateFiles.read(
            ci.resolve("transport-upstream.pending.json"), 8192).decodeToString(throwOnInvalidSequence = true))
        require(pending == ForgejoCiGraphUpstreamPending(plan.generation, host, "ingress-control") &&
            listOf("transport-upstream-adoption.intent.json", "transport-upstream-adoption.result.json",
                "transport-upstream-ca.pem", "transport-Caddyfile").none {
                Files.exists(ci.resolve(it), NOFOLLOW_LINKS)
            }) { "Graph CI upstream already attempted; never replay an uncertain original handoff" }
        val manifest = PackagedGraphFragment.pendingV3R9().first
        val spec = bundle.members.single().spec
        require(spec.fragmentBinding?.phase == if (recovered) FragmentPhase.RESTORE.name
            else FragmentPhase.INSTALL.name)
        val route = CanonicalPrivateIngressTrust.requireRoute(manifest,spec,"forgejo","APP",host)
        require(route.mode == PrivateIngressTrustMode.POST_START_CADDY_CA &&
            route.hostname == host)
        val verified = CanonicalCaddyServedLeafReadback(root,bundle,expected,manifest)
        val leaf = verified.verify(host)
        val upstream = verified.verifiedPrivateEndpoint(host)
        require(ForgejoCiTransportSource.validUpstream(upstream))
        val ca = CanonicalCaddyInternalCaCustody(root,bundle,expected,manifest).activationInput()
        val bytes = ReleasePrivateFiles.read(Path.of(ca.path),65536)
        require(ReleaseLocks.sha256(bytes) == ca.sha256 && bytes.decodeToString().contains("BEGIN CERTIFICATE"))
        val intent = ForgejoCiGraphUpstreamIntent(plan.generation,expected,host,"ingress-control",
            leaf,ca,upstream)
        val intentBytes = json.encodeToString(intent).toByteArray()
        ReleasePrivateFiles.save(ci.resolve("transport-upstream-adoption.intent.json"),intentBytes)
        // Original native issuer CA bytes are copied into this generation's
        // protected rootful source, not projected from OLD or issued by CI.
        ReleasePrivateFiles.save(ci.resolve("transport-upstream-ca.pem"),bytes)
        ReleasePrivateFiles.save(ci.resolve("transport-Caddyfile"),ForgejoCiTransportSource.config(
            plan.generation,"/etc/ci/forgejo-ca.pem",upstream).toByteArray())
        ReleasePrivateFiles.save(ci.resolve("transport-upstream-adoption.result.json"),
            ReleaseLocks.sha256(intentBytes).toByteArray())
    }
}
