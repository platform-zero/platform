package net.datamancy.platform

import java.nio.file.Path
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.util.concurrent.TimeUnit
import java.security.cert.CertificateFactory
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** One original Keycloak service/reader grant under the foreground owner. No
 * user/password is copied from Pi auth; only generation-local managed seed
 * credentials identical to the selected imported realm are consumed. */
internal object ManagedOriginalIdentityEnrollment {
    fun provision(bundle:GenerationBundle,root:Path,expected:String,controller:Path) {
        val plan=requireNotNull(bundle.request.managedLanes)
        val host=requireNotNull(plan.native.brokerHost)
        require(host.graphOwnedLatePublicTrust && root==GenerationRuntime.BASE.resolve(plan.generation) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"),4194304))==expected)
        ManagedGraphIssuerHosts.adopt(bundle,root,expected)
        val descriptor=requireNotNull(bundle.members.single().spec.fragmentBinding?.controllerSha256)
        require(controller==Path.of("/mnt/media/p0-v3/runtime-supervision/releases/$descriptor/bin/p0-v3-platform"))
        PinnedBackupController.verifyDistribution(controller.parent.parent,descriptor,"p0-v3-platform")
        if(bundle.recoverySourceKopia!=null)
            ManagedRecoveryIdentityRevision.beforeEnrollment(bundle,root,expected,controller)
        val path=root.resolve("managed/identity/provision.intent.json")
        require(!Files.exists(path,NOFOLLOW_LINKS))
        val child=ProcessBuilder(controller.toString(),"release","generation-original-managed-identity",
            plan.generation,expected).also {
                it.environment()["JAVA_TOOL_OPTIONS"]="-Djdk.net.hosts.file=${root.resolve("managed/control/issuer.hosts")}" 
                it.redirectOutput(ProcessBuilder.Redirect.DISCARD)
                it.redirectError(ProcessBuilder.Redirect.DISCARD)
            }.start()
        try { require(child.waitFor(100,TimeUnit.SECONDS) && child.exitValue()==0) {
            "Original managed issuer has no native result; preserve intent, never replay"
        } } finally { if(child.isAlive) child.destroyForcibly() }
        NativeManagedIdentityLedger(root.resolve("managed/identity")).requireBound(plan,expected)
    }
    fun issueInChild(generation:String,expected:String) {
        val root=GenerationRuntime.BASE.resolve(generation)
        val bundle=Json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(root.resolve("bundle.json"),4194304)
            .decodeToString(throwOnInvalidSequence=true))
        val plan=requireNotNull(bundle.request.managedLanes)
        val host=requireNotNull(plan.native.brokerHost)
        require(bundle.request.id==generation && host.graphOwnedLatePublicTrust &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"),4194304))==expected &&
            System.getProperty("jdk.net.hosts.file")==root.resolve("managed/control/issuer.hosts").toString())
        ManagedGraphIssuerHosts.verify(bundle,root,expected)
        val member=bundle.members.single()
        val selected=QualificationPrivateTls.selectedManifest(requireNotNull(member.spec.fragmentBinding))
        val ca=CanonicalCaddyCaseTlsBundle(root,bundle,expected,selected)
            .verify(setOf("auth.datamancy.net"))
        val leaf=CanonicalCaddyServedLeafReadback(root,bundle,expected,selected)
            .verify("auth.datamancy.net")
        val receipt=Json.decodeFromString<CaddyServedLeafReadback>(ReleasePrivateFiles.read(
            Path.of(leaf.path),8192).decodeToString(throwOnInvalidSequence=true))
        val inputs=PrivateDeployment.BASE.resolve(member.spec.name).resolve("inputs")
        val privateCa=inputs.resolve("identity-ca.pem")
        val privateLeaf=inputs.resolve("identity-web.pem")
        if(bundle.recoverySourceKopia!=null) ManagedRecoveryIdentityRevision.verify(bundle,root,expected)
        else {
            val realm=ReleasePrivateFiles.read(inputs.resolve("identity-realm.json"),4194304)
            require(ReleaseLocks.sha256(realm)==member.inputHashes.getValue("identity-realm.json"))
            val clients=Json.parseToJsonElement(realm.decodeToString(throwOnInvalidSequence=true))
                .jsonObject.getValue("clients").jsonArray.map { it.jsonObject }
            require(clients.single { it.getValue("clientId").jsonPrimitive.content=="managed-lane-agent" }
                .getValue("secret").jsonPrimitive.content==host.secret(host.agentSecret,generation) &&
                clients.single { it.getValue("clientId").jsonPrimitive.content=="managed-lane-reader" }
                    .getValue("secret").jsonPrimitive.content==host.secret(host.readerSecret,generation))
        }
        require(ReleaseLocks.sha256(ReleasePrivateFiles.read(privateCa,65536))==
            member.inputHashes.getValue("identity-ca.pem") &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(privateLeaf,65536))==
                member.inputHashes.getValue("identity-web.pem"))
        val certificate=CertificateFactory.getInstance("X.509")
            .generateCertificate(ReleasePrivateFiles.read(privateLeaf,65536).inputStream())
        val transport=PinnedLaneIdentityTransport(Path.of(ca.path),receipt.servedLeafDerSha256,
            privateCa,ReleaseLocks.sha256(certificate.encoded),"managed-lane-agent",
            { host.secret(host.agentSecret,generation) })
        if(bundle.recoverySourceKopia==null) {
            val http=PinnedManagedRevisionHttp(privateCa,privateLeaf,
                ManagedGraphIssuerHosts.addresses(bundle,root,expected).getValue("keycloak"))
            ManagedTargetRestoreControllerExchange.issueOriginal(bundle,root,expected,http)
        }
        val reader=requireNotNull(plan.readerSubject)
        val issuer=NativeManagedAgentTokenIssuer { id,subject ->
            require(id==generation && subject==plan.lanes.first().subject)
            transport.agentBearer(id,subject,host.secret(host.agentSecret,generation))
        }
        val admin={ transport.readerBearer(generation,reader,host.secret(host.readerSecret,generation)) }
        ManagedIdentityProvision.initial(bundle,root.resolve("managed/identity"),reader,issuer,transport,admin)
    }
}
