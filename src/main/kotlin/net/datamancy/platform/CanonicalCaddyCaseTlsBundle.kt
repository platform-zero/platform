package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class CaddyCaseTlsBundleReceipt(val generation: String, val bundleSha256: String,
    val phase: String, val hosts: List<String>, val originalCaddyCid: String,
    val currentCaSha256: Map<String,String>, val servedLeafObservationSha256: Map<String,String>,
    val trustPemSha256: String)

/** Exact per-case public issuer PEM projection from the original private Caddy
 * stage. Authentication still pins each native served DER leaf separately;
 * this public CA bundle is NOT an ACME revision or a synthetic native ACK.
 */
internal class CanonicalCaddyCaseTlsBundle(private val root: Path, private val bundle: GenerationBundle,
    private val expected: String, private val manifest: CanonicalSharedManifest,
    private val runtimeBase: Path = PrivateDeployment.BASE) {
    private val json=Json { encodeDefaults=true; ignoreUnknownKeys=false }
    private val pin=bundle.members.single()
    private val spec=pin.spec
    private val directory=root.resolve("ingress/trust/cases")
    private val leaves=CanonicalCaddyServedLeafReadback(root,bundle,expected,manifest,runtimeBase)
    private val graph=CanonicalPrivateIngressTrust.project(manifest,spec)
    private val phase=if (bundle.recoverySourceKopia == null) "INSTALL" else "RESTORE"
    private fun hosts(selected: Set<String>): List<String> {
        require(selected.isNotEmpty() && selected.size <= 3 && selected.all { it in graph })
        val allowed=selected.size == 1 || selected == setOf("bookstack.datamancy.net","auth.datamancy.net") ||
            selected == setOf("firefly.datamancy.net","firefly-importer.datamancy.net") ||
            selected == setOf("office.datamancy.net","files.datamancy.net") ||
            selected == setOf("ntfy.datamancy.net","ntfy-native.datamancy.net") ||
            selected == setOf("office.datamancy.net","files.datamancy.net","files-native.datamancy.net") ||
            selected == setOf("files.datamancy.net","files-native.datamancy.net")
        require(allowed) { "TLS case requires one graph host or an approved cross-issuer browser pair" }
        return selected.sorted()
    }
    private fun files(selected: List<String>): Pair<Path,Path> {
        val name=ReleaseLocks.sha256(selected.joinToString("\n",postfix="\n").toByteArray())
        return directory.resolve("$name.pem") to directory.resolve("$name.json")
    }
    private fun material(selected: List<String>, internal: ActivationInput,
        recheckNativeLeaf: Boolean): Triple<ByteArray,Map<String,String>,Map<String,String>> {
        val ca=linkedMapOf<String,ByteArray>()
        val leafHashes=linkedMapOf<String,String>()
        val hostHashes=linkedMapOf<String,String>()
        for (host in selected) {
            val binding=graph.getValue(host)
            val issuer=if (binding.mode==PrivateIngressTrustMode.POST_START_CADDY_CA)
                ReleasePrivateFiles.read(Path.of(internal.path),65536)
            else {
                val file=requireNotNull(binding.caInput)
                val bytes=ReleasePrivateFiles.read(runtimeBase.resolve(spec.name).resolve(file),65536)
                require(ReleaseLocks.sha256(bytes)==pin.inputHashes.getValue(file))
                bytes
            }
            val hash=ReleaseLocks.sha256(issuer)
            ca.putIfAbsent(hash,issuer)
            hostHashes[host]=hash
            leafHashes[host]=if (recheckNativeLeaf) leaves.verify(host).sha256 else {
                val leaf=ReleasePrivateFiles.read(root.resolve("ingress/trust/leaves/$host.json"),8192)
                val witness=json.decodeFromString<CaddyServedLeafReadback>(leaf.decodeToString())
                require(witness.generation==bundle.request.id && witness.bundleSha256==expected &&
                    witness.hostname==host && witness.product==binding.product &&
                    witness.caSha256==hash && witness.servedLeafDerSha256.matches(Regex("[a-f0-9]{64}")))
                ReleaseLocks.sha256(leaf)
            }
        }
        val pem=ca.values.joinToString("\n") { it.decodeToString(throwOnInvalidSequence=true).trimEnd() }
            .plus("\n").toByteArray()
        require(pem.size in 512..65536 && ca.size <= selected.size)
        return Triple(pem,hostHashes,leafHashes)
    }
    fun sealAll(): List<ActivationInput> {
        require(root == GenerationRuntime.BASE.resolve(bundle.request.id) &&
            !Files.exists(directory,NOFOLLOW_LINKS))
        Files.createDirectory(directory,PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------")))
        val internal=CanonicalCaddyInternalCaCustody(root,bundle,expected,manifest).activationInput()
        val groups=graph.keys.map { setOf(it) } + listOf(
            setOf("bookstack.datamancy.net","auth.datamancy.net"),
            setOf("firefly.datamancy.net","firefly-importer.datamancy.net"),
            setOf("office.datamancy.net","files.datamancy.net"),
            setOf("ntfy.datamancy.net","ntfy-native.datamancy.net"),
            setOf("office.datamancy.net","files.datamancy.net","files-native.datamancy.net"),
            setOf("files.datamancy.net","files-native.datamancy.net"))
        return groups.map { group ->
            val selected=hosts(group)
            val (pem,ca,proof)=material(selected,internal,recheckNativeLeaf=false)
            val cid=json.decodeFromString<CaddyServedLeafReadback>(ReleasePrivateFiles.read(
                root.resolve("ingress/trust/leaves/${selected.first()}.json"),8192).decodeToString()).caddyCid
            val (path,receiptPath)=files(selected)
            val receipt=CaddyCaseTlsBundleReceipt(bundle.request.id,expected,phase,selected,cid,ca,proof,
                ReleaseLocks.sha256(pem))
            ReleasePrivateFiles.save(path,pem)
            ReleasePrivateFiles.save(receiptPath,json.encodeToString(receipt).toByteArray())
            ActivationInput(path.toString(),receipt.trustPemSha256)
        }
    }
    /** Read-only recovery boundary. No path or CA provided by the caller is
     * trusted: the native current leaf/owner/issuer is re-observed first.
     */
    fun verify(selectedHosts: Set<String>): ActivationInput {
        val selected=hosts(selectedHosts)
        val (path,receiptPath)=files(selected)
        val receipt=json.decodeFromString<CaddyCaseTlsBundleReceipt>(ReleasePrivateFiles.read(receiptPath,8192)
            .decodeToString(throwOnInvalidSequence=true))
        val internal=CanonicalCaddyInternalCaCustody(root,bundle,expected,manifest).activationInput()
        val (pem,ca,proof)=material(selected,internal,recheckNativeLeaf=true)
        val cid=json.decodeFromString<CaddyServedLeafReadback>(ReleasePrivateFiles.read(
            root.resolve("ingress/trust/leaves/${selected.first()}.json"),8192).decodeToString()).caddyCid
        require(receipt == CaddyCaseTlsBundleReceipt(bundle.request.id,expected,phase,selected,cid,ca,proof,
            ReleaseLocks.sha256(pem)) && ReleasePrivateFiles.read(path,65536).contentEquals(pem)) {
            "Case issuer bundle does not match current graph and native served leaves"
        }
        return ActivationInput(path.toString(),receipt.trustPemSha256)
    }
}
