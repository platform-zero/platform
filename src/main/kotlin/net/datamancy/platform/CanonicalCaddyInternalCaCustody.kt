package net.datamancy.platform

import java.io.ByteArrayInputStream
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Serializable internal data class CaddyIngressCaReadback(val generation: String, val bundleSha256: String,
    val member: String, val fingerprint: String, val caddyCid: String, val originalLaunchResultSha256: String,
    val volumeName: String, val volumeMountSha256: String, val graphHostSetSha256: String,
    val caSha256: String, val currentNativeCa: Boolean)

/** Distinct post-start Caddy internal CA export for the graph's `tls internal`
 * routes. Never substitutes an offline CA or writes host/system trust. Callers
 * must receive this exact generation-bound public certificate as a sealed
 * private input AFTER native Caddy start; the CA private key stays in its
 * graph-owned named volume. Selected app-issued leaves use their own CA instead.
 */
internal class CanonicalCaddyInternalCaCustody(private val root: Path, private val bundle: GenerationBundle,
    private val expected: String, private val manifest: CanonicalSharedManifest,
    private val commands: RuntimeCommands = PrivateRootfulCommands(45,RuntimeStore.CANONICAL_V2),
    private val volumeBase: Path = Path.of(PrivateRootfulCommands.ROOT)) {
    private val json=Json { encodeDefaults=true; ignoreUnknownKeys=false }
    private val spec=bundle.members.single().spec
    private val pin=bundle.members.single()
    private val caddy=spec.processes.single { it.id == "caddy" }
    private val directory=root.resolve("ingress/trust")
    private val caFile=directory.resolve("caddy-internal-ca.pem")
    private val receiptFile=directory.resolve("caddy-internal-ca.readback.json")
    private val hex=Regex("[a-f0-9]{64}")
    private fun preflight() {
        require(root == GenerationRuntime.BASE.resolve(bundle.request.id) &&
            bundle.request.store == RuntimeStore.CANONICAL_V2 &&
            expected.matches(hex) && ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"),1048576)) == expected &&
            spec.name.startsWith("${bundle.request.id}-") &&
            spec.fragmentBinding?.recipe == CanonicalSharedYamlGraph.RECIPE &&
            caddy.volumes.any { it.volume == "caddy-data" && it.target == "/data" })
    }
    private fun graphHosts(): String {
        val bindings=CanonicalPrivateIngressTrust.project(manifest,spec)
        val internal=bindings.values.filter { it.mode == PrivateIngressTrustMode.POST_START_CADDY_CA }
            .map { it.hostname }.sorted()
        require(internal.size in 25..70 && "bookstack.datamancy.net" in internal)
        return ReleaseLocks.sha256(internal.joinToString("\n",postfix="\n").toByteArray())
    }
    private fun volume(): Pair<Path,String> {
        val volume="p0v3-live-${spec.name}-volume-caddy-data"
        val reply=commands.run(listOf("volume","inspect",volume))
        require(reply.exitCode==0 && reply.output.toByteArray().size in 1..65536)
        val item=json.parseToJsonElement(reply.output).jsonArray.single().jsonObject
        val labels=item.getValue("Labels").jsonObject
        val mount=Path.of(item.getValue("Mountpoint").jsonPrimitive.content)
        require(item.getValue("Name").jsonPrimitive.content == volume &&
            labels.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
            labels.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == pin.runtimeFingerprint &&
            mount.isAbsolute && mount.normalize()==mount && mount.startsWith(volumeBase.resolve("volumes")) &&
            mount.fileName.toString()=="_data" && mount.parent.fileName.toString()==volume &&
            Files.isDirectory(mount,NOFOLLOW_LINKS) && mount.toRealPath()==mount) {
            "Private Caddy issuer volume is not the selected owned data volume"
        }
        return mount to volume
    }
    private fun nativeCa(mount: Path): ByteArray {
        val parent=mount.resolve("caddy/pki/authorities/local")
        require(parent.toRealPath()==parent && Files.isDirectory(parent,NOFOLLOW_LINKS))
        val file=parent.resolve("root.crt")
        require(Files.isRegularFile(file,NOFOLLOW_LINKS) && file.toRealPath()==file &&
            Files.size(file) in 512..65536)
        val bytes=Files.newInputStream(file,NOFOLLOW_LINKS).use { it.readNBytes(65537) }
        require(bytes.size in 512..65536)
        val cert=CertificateFactory.getInstance("X.509")
            .generateCertificate(ByteArrayInputStream(bytes)) as X509Certificate
        cert.checkValidity(); cert.verify(cert.publicKey)
        require(cert.basicConstraints >= 0 && cert.keyUsage?.getOrNull(5)==true &&
            cert.subjectX500Principal == cert.issuerX500Principal) {
            "Caddy private issuer is not a current self-signed root CA"
        }
        return bytes
    }
    private fun nativeCid(): Pair<String,String> {
        val launch=ReleasePrivateFiles.read(root.resolve("quadlet-launch-${spec.name}-caddy.result.json"),8192)
        val value=json.decodeFromString<QuadletLaunchResult>(launch.decodeToString(throwOnInvalidSequence=true))
        require(value.nativeAcknowledged && value.imageId == caddy.imageId && value.containerId.matches(hex))
        RuntimeQuadletSystemd.requireServing("${RuntimeQuadlets.unit(spec,caddy)}.service",value.containerId,spec.store)
        return value.containerId to ReleaseLocks.sha256(launch)
    }
    fun record(): CaddyIngressCaReadback {
        preflight()
        require(!Files.exists(receiptFile,NOFOLLOW_LINKS) && !Files.exists(caFile,NOFOLLOW_LINKS))
        val (mount,volume)=volume()
        val ca=nativeCa(mount)
        val (cid,launchSha)=nativeCid()
        val receipt=CaddyIngressCaReadback(bundle.request.id,expected,spec.name,pin.runtimeFingerprint,
            cid,launchSha,volume,ReleaseLocks.sha256(mount.toString().toByteArray()),graphHosts(),
            ReleaseLocks.sha256(ca),true)
        val parent=directory.parent
        if (!Files.exists(parent,NOFOLLOW_LINKS)) Files.createDirectory(parent,
            java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.directory(parent)
        if (!Files.exists(directory,NOFOLLOW_LINKS)) Files.createDirectory(directory,
            java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.directory(directory)
        ReleasePrivateFiles.save(caFile,ca)
        ReleasePrivateFiles.save(receiptFile,json.encodeToString(receipt).toByteArray())
        return receipt
    }
    /** Recovery receives an exact read-only, owner-verified public CA input;
     * no Mozilla fixture or private signing material crosses this boundary. */
    fun activationInput(): ActivationInput = verify().let { current ->
        ActivationInput(caFile.toString(),current.caSha256)
    }
    fun verify(): CaddyIngressCaReadback {
        preflight()
        val saved=json.decodeFromString<CaddyIngressCaReadback>(ReleasePrivateFiles.read(receiptFile,8192)
            .decodeToString(throwOnInvalidSequence=true))
        val (mount,volume)=volume()
        val bytes=nativeCa(mount)
        val (cid,launchSha)=nativeCid()
        require(saved == CaddyIngressCaReadback(bundle.request.id,expected,spec.name,pin.runtimeFingerprint,
            cid,launchSha,volume,ReleaseLocks.sha256(mount.toString().toByteArray()),graphHosts(),
            ReleaseLocks.sha256(bytes),true) &&
            ReleasePrivateFiles.read(caFile,65536).contentEquals(bytes)) {
            "Current native Caddy CA changed; private callers cannot adopt old trust"
        }
        return saved
    }
}
