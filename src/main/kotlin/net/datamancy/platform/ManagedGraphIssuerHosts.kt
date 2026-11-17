package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.net.InetAddress
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

@Serializable internal data class ManagedGraphIssuerHostResult(val generation:String,val bundleSha256:String,
    val caddyLeafReceiptSha256:String,val keycloakStartSha256:String,
    val caddyCid:String,val keycloakCid:String,val hostsSha256:String,
    val graphTrustOnly:Boolean=true)
/** Native current-generation host mapping scoped to the managed-broker JVM,
 * not /etc/hosts, public DNS or an arbitrary imported issuer. */
internal object ManagedGraphIssuerHosts {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    private fun current(bundle:GenerationBundle,root:Path,expected:String): Pair<ManagedGraphIssuerHostResult,ByteArray> {
        require(bundle.request.managedLanes?.native?.brokerHost?.graphOwnedLatePublicTrust==true &&
            root==GenerationRuntime.BASE.resolve(bundle.request.id) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"),4194304))==expected)
        val pin=bundle.members.single();val spec=pin.spec
        val binding=requireNotNull(spec.fragmentBinding)
        val r9=binding.resources.containsKey("fragments/v3/canonical/r9/index.yaml")
        val r10=binding.resources.containsKey("fragments/v3/canonical/r10/index.yaml")
        require(r9 != r10 && binding.recipe==CanonicalSharedYamlGraph.RECIPE) {
            "Managed issuer host admission requires the exact selected full graph revision" }
        val manifest=QualificationPrivateTls.selectedManifest(binding)
        require(manifest.revision==(if(r10) 10 else 9)) {
            "Managed issuer selected graph source changed since sealing" }
        CanonicalPrivateIngressTrust.requireRoute(manifest,spec,"keycloak","OPEN","auth.datamancy.net")
        val served=CanonicalCaddyServedLeafReadback(root,bundle,expected,manifest)
        val leaf=served.verify("auth.datamancy.net")
        val endpoint=served.verifiedPrivateEndpoint("auth.datamancy.net")
        val caddyIp=java.net.URI(endpoint).host
        require(java.net.URI(endpoint).scheme=="https" && java.net.URI(endpoint).port==443)
        val keycloakPath=root.resolve("quadlet-member-${spec.name}-keycloak.result.json")
        val startBytes=ReleasePrivateFiles.read(keycloakPath,8192)
        val start=json.decodeFromString<QuadletMemberStart>(startBytes.decodeToString(throwOnInvalidSequence=true))
        require(start.bundleSha256==expected && start.process=="keycloak" && start.status.state=="running")
        val observed=PrivateRootfulCommands(30,spec.store).run(listOf("container","inspect",start.containerId))
        require(observed.exitCode==0 && observed.output.length in 128..65536)
        val native=json.parseToJsonElement(observed.output).jsonArray.single().jsonObject
        val network=native.getValue("NetworkSettings").jsonObject.getValue("Networks").jsonObject
        val id="p0v3-live-${spec.name}-identity-web"
        require(native.getValue("Id").jsonPrimitive.content==start.containerId &&
            native.getValue("State").jsonObject.getValue("Running").jsonPrimitive.boolean && id in network &&
            network.keys==spec.processes.single { it.id=="keycloak" }.networks.map {
                "p0v3-live-${spec.name}-$it" }.toSet())
        val keycloakIp=network.getValue(id).jsonObject.getValue("IPAddress").jsonPrimitive.content
        require(listOf(caddyIp,keycloakIp).distinct().size==2 && listOf(caddyIp,keycloakIp).all { address ->
            address.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
                InetAddress.getByName(address).let { it.hostAddress==address && it.isSiteLocalAddress } })
        val hosts="$caddyIp auth.datamancy.net\n$keycloakIp keycloak\n".toByteArray()
        val caddyStart=json.decodeFromString<CaddyServedLeafReadback>(ReleasePrivateFiles.read(
            Path.of(leaf.path),8192).decodeToString(throwOnInvalidSequence=true))
        val result=ManagedGraphIssuerHostResult(bundle.request.id,expected,leaf.sha256,
            ReleaseLocks.sha256(startBytes),caddyStart.caddyCid,start.containerId,ReleaseLocks.sha256(hosts))
        return result to hosts
    }
    fun adopt(bundle:GenerationBundle,root:Path,expected:String) {
        val (result,bytes)=current(bundle,root,expected)
        val dir=root.resolve("managed/control")
        ReleasePrivateFiles.directory(dir)
        val hosts=dir.resolve("issuer.hosts")
        val intent=dir.resolve("issuer-hosts.intent.json")
        val complete=dir.resolve("issuer-hosts.result.json")
        require(listOf(hosts,intent,complete).none { Files.exists(it,NOFOLLOW_LINKS) }) {
            "Managed graph issuer address adoption already attempted; do not replay"
        }
        ReleasePrivateFiles.save(intent,json.encodeToString(result).toByteArray())
        ReleasePrivateFiles.save(hosts,bytes)
        ReleasePrivateFiles.save(complete,json.encodeToString(result).toByteArray())
    }
    fun addresses(bundle:GenerationBundle,root:Path,expected:String):Map<String,String> {
        verify(bundle,root,expected)
        val lines=ReleasePrivateFiles.read(root.resolve("managed/control/issuer.hosts"),8192)
            .decodeToString(throwOnInvalidSequence=true).trimEnd('\n').lines()
        require(lines.size==2)
        val entries=lines.map { it.split(' ').also { cells -> require(cells.size==2) } }
        require(entries.map { it[1] }==listOf("auth.datamancy.net","keycloak"))
        return entries.associate { it[1] to it[0] }
    }
    fun verify(bundle:GenerationBundle,root:Path,expected:String) {
        val (current,hosts)=current(bundle,root,expected)
        val dir=root.resolve("managed/control")
        val original=ReleasePrivateFiles.read(dir.resolve("issuer-hosts.intent.json"),8192)
        val result=ReleasePrivateFiles.read(dir.resolve("issuer-hosts.result.json"),8192)
        require(original.contentEquals(result) &&
            json.decodeFromString<ManagedGraphIssuerHostResult>(result.decodeToString(throwOnInvalidSequence=true))==current &&
            ReleasePrivateFiles.read(dir.resolve("issuer.hosts"),8192).contentEquals(hosts))
    }
}
