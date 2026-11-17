package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.json.Json

/** A qualification client receives only current original-serving Caddy receipts.
 * Core alone seals/observes issuer and SNI; this reader never chooses an issuer,
 * contacts an alternate listener, probes a source container or adopts WebPKI.
 */
internal data class QualificationPrivateTlsProof(val roots: ByteArray, val leaves: Map<String,String>)

internal object QualificationPrivateTls {
    private val json = Json { ignoreUnknownKeys = false }

    /** Select the packaged source graph only when the generation sealed its EXACT
     * baseline, full r9 index, manifest, Caddy JSON and every selected fragment.
     * Neither the globally active r7 index nor a bare pending-r9 lookup can
     * authorize private ingress trust for an unrelated sealed generation. */
    internal fun selectedManifest(binding: RuntimeFragmentBinding): CanonicalSharedManifest {
        val selected = listOf(PackagedGraphFragment.pendingV3R9(),
            PackagedGraphFragment.pendingV3R10()).single { candidate ->
            val resources = candidate.second.mapKeys { (path, _) ->
                if (path.startsWith("v2/")) "fragments/$path" else "fragments/v3/$path"
            }
            binding.resources == resources
        }
        val manifest = selected.first
        val expected = selected.second.mapKeys { (path, _) ->
            if (path.startsWith("v2/")) "fragments/$path" else "fragments/v3/$path"
        }
        require(manifest.revision in setOf(9,10) && manifest.scope == "full-private" &&
            binding.recipe == CanonicalSharedYamlGraph.RECIPE &&
            binding.phase in setOf(FragmentPhase.INSTALL.name, FragmentPhase.RESTORE.name) &&
            expected.size == selected.second.size && binding.resources == expected) {
            "Qualification ingress requires an exact sealed full r9/r10 graph closure"
        }
        return manifest
    }

    fun observe(bundle: GenerationBundle, hosts: Set<String>, expectedBundleSha256: String): QualificationPrivateTlsProof {
        require(hosts.isNotEmpty() && hosts.size <= 8 && bundle.members.size == 1 &&
            bundle.request.store == RuntimeStore.CANONICAL_V2)
        val root = GenerationRuntime.BASE.resolve(bundle.request.id)
        val sealedBytes = ReleasePrivateFiles.read(root.resolve("bundle.json"),1048576)
        require(ReleaseLocks.sha256(sealedBytes) == expectedBundleSha256 &&
            json.decodeFromString<GenerationBundle>(sealedBytes.decodeToString(throwOnInvalidSequence=true)) == bundle)
        SiteOwnerships.checkSealed(bundle)
        val spec = bundle.members.single().spec
        require(PrivateDeployment.expectedFingerprint(spec, bundle.members.single().inputHashes) ==
            bundle.members.single().runtimeFingerprint &&
            (if (bundle.recoverySourceKopia != null) spec.fragmentBinding?.phase == FragmentPhase.RESTORE.name
             else spec.fragmentBinding?.phase == FragmentPhase.INSTALL.name)) {
            "Qualification issuer must belong to this sealed generation phase and runtime"
        }
        val manifest = selectedManifest(requireNotNull(spec.fragmentBinding))
        val graph = CanonicalPrivateIngressTrust.project(manifest,spec)
        require(hosts.all { it in graph } && (hosts.size == 1 || hosts in setOf(
            setOf("bookstack.datamancy.net","auth.datamancy.net"),
            setOf("office.datamancy.net","files.datamancy.net"),
            setOf("ntfy.datamancy.net","ntfy-native.datamancy.net"),
            setOf("ntfy.datamancy.net","ntfy-native.datamancy.net",
                "auth.datamancy.net","keycloak-auth.datamancy.net"),
            setOf("office.datamancy.net","files.datamancy.net","files-native.datamancy.net"),
            setOf("files.datamancy.net","files-native.datamancy.net"),
            setOf("firefly.datamancy.net","auth.datamancy.net"),
            setOf("firefly.datamancy.net","firefly-importer.datamancy.net","auth.datamancy.net"),
            setOf("erp.datamancy.net","auth.datamancy.net","keycloak-auth.datamancy.net"),
            setOf("donetick.datamancy.net","auth.datamancy.net","keycloak-auth.datamancy.net"),
            setOf("forgejo.datamancy.net","auth.datamancy.net"),
            setOf("chat.datamancy.net","matrix.datamancy.net",
                "matrix-auth.datamancy.net","matrix-rtc.datamancy.net",
                "auth.datamancy.net")))) {
            "Qualification host set is not an approved selected ingress journey"
        }
        val native = CanonicalCaddyServedLeafReadback(root,bundle,expectedBundleSha256,manifest)
        val cases = CanonicalCaddyCaseTlsBundle(root,bundle,expectedBundleSha256,manifest)
        // The core producer seals the BookStack and importer pairs. Other SSO
        // hosts are separately core-sealed singletons; combining only their
        // verified PEM bytes does not invent an issuer or weaken leaf checks.
        val groups = mutableListOf<Set<String>>()
        val pending = hosts.toMutableSet()
        for (pair in listOf(setOf("bookstack.datamancy.net","auth.datamancy.net"),
            setOf("firefly.datamancy.net","firefly-importer.datamancy.net"),
            setOf("office.datamancy.net","files.datamancy.net","files-native.datamancy.net"),
            setOf("office.datamancy.net","files.datamancy.net"),
            setOf("files.datamancy.net","files-native.datamancy.net"),
            setOf("ntfy.datamancy.net","ntfy-native.datamancy.net"))) {
            if (pending.containsAll(pair)) { groups += pair; pending.removeAll(pair) }
        }
        groups += pending.sorted().map { setOf(it) }
        val roots = groups.flatMap { selected ->
            val input = cases.verify(selected)
            val bytes = ReleasePrivateFiles.read(Path.of(input.path),65536)
            require(ReleaseLocks.sha256(bytes) == input.sha256 &&
                bytes.decodeToString(throwOnInvalidSequence=true).contains("-----BEGIN CERTIFICATE-----"))
            listOf(bytes.decodeToString(throwOnInvalidSequence=true).trimEnd())
        }.distinct().joinToString("\n",postfix="\n").toByteArray()
        require(roots.size in 512..1048576)
        val leaves = hosts.sorted().associateWith { host ->
            val input = native.verify(host)
            val bytes = ReleasePrivateFiles.read(Path.of(input.path),8192)
            require(ReleaseLocks.sha256(bytes) == input.sha256)
            val value = json.decodeFromString<CaddyServedLeafReadback>(bytes.decodeToString(throwOnInvalidSequence=true))
            val selected = graph.getValue(host)
            require(value.generation == bundle.request.id && value.bundleSha256 == expectedBundleSha256 &&
                value.hostname == host && value.product == selected.product &&
                value.routePolicies == selected.routePolicies && value.mode == selected.mode &&
                host in value.exactDnsSans && value.servedLeafDerSha256.matches(Regex("[a-f0-9]{64}")))
            value.servedLeafDerSha256
        }
        return QualificationPrivateTlsProof(roots,leaves)
    }
}
