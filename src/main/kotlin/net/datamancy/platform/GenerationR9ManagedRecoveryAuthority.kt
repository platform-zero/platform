package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** Source-only isolated RESTORE authority; supplies NEW target-native client
 * secrets and an owner-approved target provider key. Nothing comes from Pi auth,
 * captured source home, or the source realm's confidential client secrets. */
internal object GenerationR9ManagedRecoveryAuthority {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    fun verify(source:ManagedLanePlan,targetGeneration:String,host:ManagedBrokerHostBinding) {
        val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$targetGeneration")
        host.validate(targetGeneration)
        val sealed=ReleasePrivateFiles.read(root.resolve("recovery-broker-host.json"),16384)
        if (host.authenticationMode=="pi-openai-oauth-v2") {
            require(source.native.brokerHost?.authenticationMode=="pi-openai-oauth-v2" &&
                host.upstreamKey.sha256==ManagedPiSubscriptionCustody.verify() &&
                host.upstreamKey.path=="/home/gerald/.local/share/p0-v3-subscription/openai-only/script-v3.result.json" &&
                host.agentSecret.path==root.resolve("recovery-agent-secret").toString() &&
                host.readerSecret.path==root.resolve("recovery-reader-secret").toString() &&
                host.agentSecret.sha256!=source.native.brokerHost?.agentSecret?.sha256 &&
                host.readerSecret.sha256!=source.native.brokerHost?.readerSecret?.sha256 &&
                listOf(host.agentSecret,host.readerSecret).all {
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(it.path),8192))==it.sha256
                } && json.decodeFromString<ManagedBrokerHostBinding>(sealed.decodeToString(throwOnInvalidSequence=true))==host)
            val decision=ReleasePrivateFiles.read(root.resolve("target-subscription-authority.json"),8192)
                .decodeToString(throwOnInvalidSequence=true)
            require(decision=="pi-openai-oauth-v2|$targetGeneration|owner-authorized-isolated-restore|${host.upstreamKey.sha256}\n")
            return
        }
        require(json.decodeFromString<ManagedBrokerHostBinding>(sealed.decodeToString(throwOnInvalidSequence=true))==host &&
            host.agentSecret.path==root.resolve("recovery-agent-secret").toString() &&
            host.readerSecret.path==root.resolve("recovery-reader-secret").toString() &&
            host.upstreamKey.path==root.resolve("upstream-openai-key").toString() &&
            host.agentSecret.sha256!=source.native.brokerHost?.agentSecret?.sha256 &&
            host.readerSecret.sha256!=source.native.brokerHost?.readerSecret?.sha256 &&
            listOf(host.agentSecret,host.readerSecret,host.upstreamKey).all {
                ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(it.path),8192))==it.sha256
            })
        val authority=json.decodeFromString<R9ModelAuthority>(ReleasePrivateFiles.read(
            root.resolve("upstream-openai-authority.json"),8192).decodeToString(throwOnInvalidSequence=true))
        require(authority==R9ModelAuthority(1,targetGeneration,"openai","gpt-6-sol",
            "owner-approved-isolated-restore-managed-broker-only","operator-provisioned-new-project-key",
            host.upstreamKey.sha256))
    }
    fun issue(sourceGeneration:String,targetGeneration:String):ActivationInput {
        require(sourceGeneration.matches(Regex("q-[a-f0-9]{12}")) &&
            sourceGeneration!="q-5962a9fda75b" && targetGeneration.matches(Regex("q-[a-f0-9]{12}")) &&
            sourceGeneration!=targetGeneration)
        val sourceRoot=GenerationRuntime.BASE.resolve(sourceGeneration)
        val source=json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(sourceRoot.resolve("bundle.json"),4194304)
            .decodeToString(throwOnInvalidSequence=true))
        require(source.request.id==sourceGeneration && source.members.size==1 && source.recoverySourceKopia==null &&
            source.request.managedLanes?.native?.brokerHost?.authenticationMode=="pi-openai-oauth-v2")
        val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$targetGeneration")
        ReleasePrivateFiles.directory(root)
        require(!Files.exists(GenerationRuntime.BASE.resolve(targetGeneration),NOFOLLOW_LINKS))
        val names=listOf("recovery-agent-secret","recovery-reader-secret","recovery-broker-host.json","target-subscription-authority.json")
        require(names.none { Files.exists(root.resolve(it),NOFOLLOW_LINKS) })
        val selected=ManagedPiSubscriptionCustody.verify()
        val agent=RuntimePreparation.password();val reader=RuntimePreparation.password()
        require(agent!=reader && agent.matches(Regex("[a-f0-9]{64}")) && reader.matches(Regex("[a-f0-9]{64}")))
        val agentPath=root.resolve(names[0]);val readerPath=root.resolve(names[1])
        ReleasePrivateFiles.save(root.resolve(names[3]),
            "pi-openai-oauth-v2|$targetGeneration|owner-authorized-isolated-restore|$selected\n".toByteArray())
        ReleasePrivateFiles.save(agentPath,agent.toByteArray())
        ReleasePrivateFiles.save(readerPath,reader.toByteArray())
        val host=ManagedBrokerHostBinding(ActivationInput(agentPath.toString(),ReleaseLocks.sha256(agent.toByteArray())),
            ActivationInput(readerPath.toString(),ReleaseLocks.sha256(reader.toByteArray())),
            ActivationInput("/home/gerald/.local/share/p0-v3-subscription/openai-only/script-v3.result.json",selected),
            graphOwnedLatePublicTrust=true,authenticationMode="pi-openai-oauth-v2")
        host.validate(targetGeneration)
        val bytes=json.encodeToString(host).toByteArray()
        val file=root.resolve(names[2]);ReleasePrivateFiles.save(file,bytes)
        verify(requireNotNull(source.request.managedLanes),targetGeneration,host)
        return ActivationInput(file.toString(),ReleaseLocks.sha256(bytes))
    }

    /** Historical issuer retained for audit, not selected by any current caller. */
    private fun historicalProjectKeyIssue(sourceGeneration:String,targetGeneration:String):ActivationInput {
        require(sourceGeneration.matches(Regex("q-[a-f0-9]{12}")) &&
            targetGeneration.matches(Regex("q-[a-f0-9]{12}")) && sourceGeneration!=targetGeneration)
        val sourceRoot=GenerationRuntime.BASE.resolve(sourceGeneration)
        val source=json.decodeFromString<GenerationBundle>(ReleasePrivateFiles.read(
            sourceRoot.resolve("bundle.json"),4194304).decodeToString(throwOnInvalidSequence=true))
        require(source.request.id==sourceGeneration && source.members.size==1 &&
            source.request.managedLanes?.native?.brokerHost?.graphOwnedLatePublicTrust==true &&
            source.recoverySourceKopia==null)
        val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$targetGeneration")
        ReleasePrivateFiles.directory(root)
        require(!Files.exists(GenerationRuntime.BASE.resolve(targetGeneration),NOFOLLOW_LINKS))
        val authority=json.decodeFromString<R9ModelAuthority>(ReleasePrivateFiles.read(
            root.resolve("upstream-openai-authority.json"),8192).decodeToString(throwOnInvalidSequence=true))
        val key=ReleasePrivateFiles.read(root.resolve("upstream-openai-key"),8192)
        require(authority==R9ModelAuthority(1,targetGeneration,"openai","gpt-6-sol",
            "owner-approved-isolated-restore-managed-broker-only","operator-provisioned-new-project-key",
            ReleaseLocks.sha256(key)) && key.size in 40..4096 &&
            key.decodeToString(throwOnInvalidSequence=true).trimEnd('\n')
                .matches(Regex("sk-proj-[A-Za-z0-9_-]{20,4096}"))) {
            "RESTORE requires explicit project-owner authority; no automatic source or Pi credential copying"
        }
        key.fill(0)
        val names=listOf("recovery-agent-secret","recovery-reader-secret","recovery-broker-host.json")
        require(names.none { Files.exists(root.resolve(it),NOFOLLOW_LINKS) }) {
            "Target source authority already attempted; preserve original state"
        }
        val agent=RuntimePreparation.password();val reader=RuntimePreparation.password()
        require(agent!=reader && agent.matches(Regex("[a-f0-9]{64}")) && reader.matches(Regex("[a-f0-9]{64}")))
        val agentPath=root.resolve(names[0]);val readerPath=root.resolve(names[1])
        ReleasePrivateFiles.save(agentPath,agent.toByteArray())
        ReleasePrivateFiles.save(readerPath,reader.toByteArray())
        val host=ManagedBrokerHostBinding(ActivationInput(agentPath.toString(),ReleaseLocks.sha256(agent.toByteArray())),
            ActivationInput(readerPath.toString(),ReleaseLocks.sha256(reader.toByteArray())),
            ActivationInput(root.resolve("upstream-openai-key").toString(),authority.keySha256),
            graphOwnedLatePublicTrust=true)
        host.validate(targetGeneration)
        val bytes=json.encodeToString(host).toByteArray()
        val file=root.resolve(names[2]);ReleasePrivateFiles.save(file,bytes)
        return ActivationInput(file.toString(),ReleaseLocks.sha256(bytes))
    }
}
