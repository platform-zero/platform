package net.datamancy.platform

import java.io.ByteArrayInputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Serializable internal data class CaddyServedLeafReadback(val generation: String, val bundleSha256: String,
    val member: String, val fingerprint: String, val caddyCid: String, val hostname: String,
    val product: String, val routePolicies: Set<String>, val mode: PrivateIngressTrustMode,
    val caSha256: String, val servedLeafDerSha256: String, val exactDnsSans: List<String>,
    val internalCaReadbackSha256: String? = null, val privateNetwork: String)

/** Live, private-only SNI+PKIX handshake to the *original running* Caddy CID.
 * No public host publication, global trust, ignore_https_errors or certificate
 * probe with a trust-all manager. One sealed readback per graph-authorized host;
 * any absent route or mismatched issuer/leaf stops source acceptance.
 */
internal class CanonicalCaddyServedLeafReadback(private val root: Path, private val bundle: GenerationBundle,
    private val expected: String, private val manifest: CanonicalSharedManifest,
    private val runtimeBase: Path = PrivateDeployment.BASE,
    private val commands: RuntimeCommands = PrivateRootfulCommands(45,RuntimeStore.CANONICAL_V2),
    private val handshake: (String,String,ByteArray) -> X509Certificate = ::verifiedHandshake) {
    private val json=Json { encodeDefaults=true; ignoreUnknownKeys=false }
    private val pin=bundle.members.single()
    private val spec=pin.spec
    private val directory=root.resolve("ingress/trust/leaves")
    private val certFactory=CertificateFactory.getInstance("X.509")
    private fun certificate(bytes: ByteArray): X509Certificate =
        certFactory.generateCertificate(ByteArrayInputStream(bytes)) as X509Certificate
    private fun input(file: String): ByteArray {
        val hash=pin.inputHashes.getValue(file)
        val path=runtimeBase.resolve(spec.name).resolve(file)
        val bytes=ReleasePrivateFiles.read(path,65536)
        require(ReleaseLocks.sha256(bytes)==hash) { "Graph-issued ingress CA or leaf input changed" }
        return bytes
    }
    private fun caddy(requireOriginalOwner: Boolean): Pair<String,String> {
        require(root == GenerationRuntime.BASE.resolve(bundle.request.id) &&
            expected == ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"),1048576)) &&
            bundle.request.store == RuntimeStore.CANONICAL_V2 &&
            spec.fragmentBinding?.recipe == CanonicalSharedYamlGraph.RECIPE &&
            spec.processes.any { it.id == "caddy" && "ingress-control" in it.networks })
        val launch=ReleasePrivateFiles.read(root.resolve("quadlet-launch-${spec.name}-caddy.result.json"),8192)
        val result=json.decodeFromString<QuadletLaunchResult>(launch.decodeToString(throwOnInvalidSequence=true))
        val launchIntent=ReleasePrivateFiles.read(root.resolve("quadlet-launch-${spec.name}-caddy.intent.json"),8192)
        val delegate=json.decodeFromString<QuadletDelegationIntent>(ReleasePrivateFiles.read(root.resolve(
            "quadlet-delegate-${spec.name}-caddy-start.intent.json"),8192).decodeToString(throwOnInvalidSequence=true))
        require(result.nativeAcknowledged && result.containerId.matches(Regex("[a-f0-9]{64}")) &&
            result.imageId == spec.processes.single { it.id == "caddy" }.imageId &&
            result.intentSha256 == ReleaseLocks.sha256(launchIntent) &&
            (!requireOriginalOwner || delegate.ownerPid == ProcessHandle.current().pid()) &&
            delegate.bundleSha256 == expected && delegate.member == spec.name &&
            QuadletNativeLockProof.classifyStableEvidence(delegate.ownerPid,delegate.ownerStartTicks,
                root.parent.resolve("generation.lock"),runtimeBase.resolve(spec.name).resolve("runtime.lock")).proof ==
                QuadletOwnerProof.VERIFIED) {
            "Served-leaf proof requires original owner-held Caddy CID and both locks"
        }
        RuntimeQuadletSystemd.requireServing("${RuntimeQuadlets.unit(spec,spec.processes.single { it.id == "caddy" })}.service",
            result.containerId,spec.store)
        val name="p0v3-live-${spec.name}-caddy"
        val inspect=commands.run(listOf("container","inspect",name))
        require(inspect.exitCode==0 && inspect.output.toByteArray().size in 100..262144)
        val objectValue=json.parseToJsonElement(inspect.output).jsonArray.single().jsonObject
        val labels=objectValue.getValue("Config").jsonObject.getValue("Labels").jsonObject
        val nativeNetwork="p0v3-live-${spec.name}-ingress-control"
        val network=objectValue.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject
            .getValue(nativeNetwork).jsonObject
        val address=network.getValue("IPAddress").jsonPrimitive.content
        require(objectValue.getValue("Id").jsonPrimitive.content.removePrefix("sha256:")==result.containerId &&
            objectValue.getValue("State").jsonObject.getValue("Running").jsonPrimitive.boolean &&
            labels.getValue("io.p0v3.private-deployment").jsonPrimitive.content==spec.name &&
            labels.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content==pin.runtimeFingerprint &&
            address.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            InetAddress.getByName(address).isSiteLocalAddress) {
            "Selected original Caddy CID has no owned private ingress-control address"
        }
        return result.containerId to address
    }
    fun record(hosts: Set<String>): List<CaddyServedLeafReadback> {
        val graph=CanonicalPrivateIngressTrust.project(manifest,spec)
        require(hosts.isNotEmpty() && hosts.size <= 70 && hosts == graph.keys) {
            "Serve original selected ingress host set, never a caller-supplied partial subset"
        }
        val caCustody=CanonicalCaddyInternalCaCustody(root,bundle,expected,manifest)
        val internal=caCustody.activationInput()
        val nativeCa=ReleasePrivateFiles.read(Path.of(internal.path),65536)
        val internalReceipt=ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve(
            "ingress/trust/caddy-internal-ca.readback.json"),8192))
        val (cid,address)=caddy(requireOriginalOwner=true)
        require(!Files.exists(directory,NOFOLLOW_LINKS)) { "Original served-leaf observation already attempted" }
        Files.createDirectory(directory,PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------")))
        return hosts.sorted().map { host ->
            val binding=graph.getValue(host)
            val ca=if (binding.mode==PrivateIngressTrustMode.POST_START_CADDY_CA) nativeCa
                else input(requireNotNull(binding.caInput))
            val served=handshake(address,host,ca)
            val sans=served.subjectAlternativeNames.orEmpty().filter { it[0]==2 }
                .map { it[1].toString() }.distinct().sorted()
            require(host in sans && served.basicConstraints < 0)
            val digest=ReleaseLocks.sha256(served.encoded)
            if (binding.mode==PrivateIngressTrustMode.GRAPH_ISSUED_LEAF) {
                val selected=certificate(input(requireNotNull(binding.leafInput)))
                require(digest==ReleaseLocks.sha256(selected.encoded) &&
                    selected.issuerX500Principal == certificate(ca).subjectX500Principal) {
                    "Native Caddy served a different graph-issued leaf"
                }
            }
            val receipt=CaddyServedLeafReadback(bundle.request.id,expected,spec.name,
                pin.runtimeFingerprint,cid,host,binding.product,binding.routePolicies,binding.mode,
                ReleaseLocks.sha256(ca),digest,sans,
                if (binding.mode==PrivateIngressTrustMode.POST_START_CADDY_CA) internalReceipt else null,
                "ingress-control")
            ReleasePrivateFiles.save(directory.resolve("$host.json"),json.encodeToString(receipt).toByteArray())
            receipt
        }.also {
            caCustody.verify()
            RuntimeQuadletSystemd.requireServing("${RuntimeQuadlets.unit(spec,spec.processes.single { p -> p.id == "caddy" })}.service",
                cid,spec.store)
        }
    }
    /** Read-only qualification consumer: recheck the original owner locks,
     * original native CID and exact PKIX/SNI leaf now, then return its pinned
     * sealed observation. Never renew or silently rewrite a rotated leaf.
     */
    fun verify(host: String): ActivationInput {
        val binding=CanonicalPrivateIngressTrust.project(manifest,spec).getValue(host)
        val currentCa=CanonicalCaddyInternalCaCustody(root,bundle,expected,manifest).activationInput()
        val ca=if (binding.mode==PrivateIngressTrustMode.POST_START_CADDY_CA)
            ReleasePrivateFiles.read(Path.of(currentCa.path),65536) else input(requireNotNull(binding.caInput))
        val path=directory.resolve("$host.json")
        val bytes=ReleasePrivateFiles.read(path,8192)
        val saved=json.decodeFromString<CaddyServedLeafReadback>(bytes.decodeToString(throwOnInvalidSequence=true))
        val (cid,address)=caddy(requireOriginalOwner=false)
        val leaf=handshake(address,host,ca)
        require(saved.generation==bundle.request.id && saved.bundleSha256==expected &&
            saved.member==spec.name && saved.fingerprint==pin.runtimeFingerprint &&
            saved.caddyCid==cid && saved.hostname==host && saved.product==binding.product &&
            saved.routePolicies==binding.routePolicies && saved.mode==binding.mode &&
            saved.caSha256==ReleaseLocks.sha256(ca) &&
            saved.servedLeafDerSha256==ReleaseLocks.sha256(leaf.encoded) &&
            saved.exactDnsSans==leaf.subjectAlternativeNames.orEmpty().filter { it[0]==2 }
                .map { it[1].toString() }.distinct().sorted() &&
            saved.internalCaReadbackSha256==(if (binding.mode==PrivateIngressTrustMode.POST_START_CADDY_CA)
                ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("ingress/trust/caddy-internal-ca.readback.json"),8192))
                else null) && host in saved.exactDnsSans && saved.privateNetwork=="ingress-control") {
            "Serving Caddy leaf or graph-bound private issuer changed after original observation"
        }
        return ActivationInput(path.toString(),ReleaseLocks.sha256(bytes))
    }
    /** Native original CID address on the sealed ingress-control network.
     * A CI transport may adopt it only AFTER verified current SNI/PKIX readback;
     * this is not an address guessed or frozen into the assembly request. */
    fun verifiedPrivateEndpoint(host: String): String {
        val receipt = verify(host)
        val observed = json.decodeFromString<CaddyServedLeafReadback>(ReleasePrivateFiles.read(
            Path.of(receipt.path), 8192).decodeToString(throwOnInvalidSequence = true))
        val (cid, address) = caddy(requireOriginalOwner = false)
        require(observed.caddyCid == cid && observed.hostname == host)
        return "https://$address:443"
    }
    private companion object {
        fun verifiedHandshake(address: String,host: String,caPem: ByteArray): X509Certificate {
            val ca=CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(caPem)) as X509Certificate
            ca.checkValidity()
            val store=KeyStore.getInstance("PKCS12").apply {
                load(null,null); setCertificateEntry("selected-ingress-ca",ca)
            }
            val manager=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                .apply { init(store) }
            val tls=SSLContext.getInstance("TLS").apply { init(null,manager.trustManagers,null) }
            val socket=tls.socketFactory.createSocket() as SSLSocket
            socket.use {
                it.soTimeout=7_000
                it.connect(InetSocketAddress(address,443),7_000)
                it.sslParameters=SSLParameters().apply {
                    serverNames=listOf(SNIHostName(host)); endpointIdentificationAlgorithm="HTTPS"
                }
                it.startHandshake()
                return it.session.peerCertificates.first() as X509Certificate
            }
        }
    }
}
