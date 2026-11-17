package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.security.MessageDigest
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Host-only rootless broker inputs. The agent and reader secrets are the SAME
 * pinned bytes used for the generation's Keycloak client definitions, never a
 * second invented issuer. Neither credentials nor an OpenAI key enter a lane,
 * CLI argument, systemd unit, bundle, journal or recovery capsule. */
@Serializable internal data class ManagedBrokerHostBinding(
    val agentSecret: ActivationInput, val readerSecret: ActivationInput,
    val upstreamKey: ActivationInput, val publicCa: ActivationInput? = null,
    val publicLeafSha256: String? = null,
    val graphOwnedLatePublicTrust: Boolean = false,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val authenticationMode: String = "legacy-project-key-v1") {
    fun validate(generation: String) {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
            authenticationMode in setOf("legacy-project-key-v1", "pi-openai-oauth-v2") &&
            (generation != "q-5962a9fda75b" || authenticationMode == "pi-openai-oauth-v2"))
        if (graphOwnedLatePublicTrust) require(publicCa==null && publicLeafSha256==null)
        else require(publicCa!=null && publicLeafSha256?.matches(Regex("[a-f0-9]{64}"))==true)
        val root = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$generation")
        for (binding in listOfNotNull(agentSecret, readerSecret, publicCa)) {
            val path = Path.of(binding.path)
            require(path.isAbsolute && path.normalize() == path && path.parent == root &&
                binding.sha256.matches(Regex("[a-f0-9]{64}")))
        }
        val upstream=Path.of(upstreamKey.path)
        require(upstream.isAbsolute && upstream.normalize()==upstream &&
            upstreamKey.sha256.matches(Regex("[a-f0-9]{64}")) &&
            (if (authenticationMode=="pi-openai-oauth-v2")
                upstream.toString()=="/home/gerald/.local/share/p0-v3-subscription/openai-only/script-v3.result.json"
             else upstream.parent==root))
        require(listOfNotNull(agentSecret.path, readerSecret.path, upstreamKey.path, publicCa?.path)
            .distinct().size == if (graphOwnedLatePublicTrust) 3 else 4)
    }
    fun privateBytes(pin: ActivationInput, generation: String): ByteArray {
        validate(generation)
        require(pin in listOfNotNull(agentSecret, readerSecret, publicCa) ||
            authenticationMode=="legacy-project-key-v1" && pin==upstreamKey)
        val bytes = GenerationRuntime.privateInput(Path.of(pin.path))
        require(bytes.size in 1..65536 && MessageDigest.isEqual(
            ReleaseLocks.sha256(bytes).chunked(2).map { it.toInt(16).toByte() }.toByteArray(),
            pin.sha256.chunked(2).map { it.toInt(16).toByte() }.toByteArray()))
        return bytes
    }
    fun secret(pin: ActivationInput, generation: String): String = privateBytes(pin, generation)
        .decodeToString(throwOnInvalidSequence = true).trimEnd('\n').also { value ->
            require(value.length in 16..4096 && !value.contains('\n') && !value.contains('\r'))
        }
}

/** Entrypoint of the pinned managed-broker-serve unit. Fail before opening a
 * socket if source inputs, identity lineage, or authentic client secrets differ. */
internal object ManagedBrokerHostSource {
    fun serve(generation: String, configurationSha256: String) {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) &&
            configurationSha256.matches(Regex("[a-f0-9]{64}")))
        val root = GenerationRuntime.BASE.resolve(generation)
        ReleasePrivateFiles.directory(root)
        val bytes = ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)
        val bundle = Json.decodeFromString<GenerationBundle>(bytes.decodeToString(throwOnInvalidSequence = true))
        val plan = requireNotNull(bundle.request.managedLanes)
        require(bundle.request.id == generation && plan.generation == generation &&
            plan.native.broker?.configuration?.sha256 == configurationSha256)
        SiteOwnerships.checkSealed(bundle)
        val host = requireNotNull(plan.native.brokerHost)
        host.validate(generation)
        if (host.authenticationMode == "pi-openai-oauth-v2") {
            require(generation == "q-5962a9fda75b" &&
                ManagedPiSubscriptionCustody.verify() == host.upstreamKey.sha256 &&
                host.upstreamKey.path == "/home/gerald/.local/share/p0-v3-subscription/openai-only/script-v3.result.json")
        }
        val agent = host.secret(host.agentSecret, generation)
        val reader = host.secret(host.readerSecret, generation)
        require(agent.matches(Regex("[a-f0-9]{64}")) && reader.matches(Regex("[a-f0-9]{64}")) && agent != reader)
        val member = bundle.members.single { member -> member.spec.processes.any { it.id == "keycloak" } }
        val inputRoot = PrivateDeployment.BASE.resolve(member.member.name).resolve("inputs")
        ReleasePrivateFiles.directory(inputRoot)
        if (bundle.recoverySourceKopia!=null)
            ManagedRecoveryIdentityRevision.verify(bundle,root,ReleaseLocks.sha256(bytes))
        else {
            val realmBytes = ReleasePrivateFiles.read(inputRoot.resolve("identity-realm.json"), 4194304)
            require(ReleaseLocks.sha256(realmBytes) == member.inputHashes.getValue("identity-realm.json"))
            val clients = Json.parseToJsonElement(realmBytes.decodeToString(throwOnInvalidSequence = true))
                .jsonObject.getValue("clients").jsonArray.map { it.jsonObject }
            require(clients.single { it.getValue("clientId").jsonPrimitive.content == "managed-lane-agent" }
                .getValue("secret").jsonPrimitive.content == agent &&
                clients.single { it.getValue("clientId").jsonPrimitive.content == "managed-lane-reader" }
                    .getValue("secret").jsonPrimitive.content == reader)
        }
        val ca = inputRoot.resolve("identity-ca.pem")
        val leaf = inputRoot.resolve("identity-web.pem")
        require(ReleaseLocks.sha256(ReleasePrivateFiles.read(ca, 65536)) == member.inputHashes.getValue("identity-ca.pem") &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(leaf, 65536)) == member.inputHashes.getValue("identity-web.pem"))
        val certificate = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(Files.newInputStream(leaf, NOFOLLOW_LINKS))
        val privatePin = ReleaseLocks.sha256(certificate.encoded)
        val (publicCa, publicLeafSha256) = if (host.graphOwnedLatePublicTrust) {
            val expected=ReleaseLocks.sha256(bytes)
            ManagedGraphIssuerHosts.verify(bundle,root,expected)
            val selected=PackagedGraphFragment.pendingV3R9().first
            CanonicalPrivateIngressTrust.requireRoute(selected,member.spec,"keycloak","OPEN",
                "auth.datamancy.net")
            val caPin=CanonicalCaddyCaseTlsBundle(root,bundle,expected,selected)
                .verify(setOf("auth.datamancy.net"))
            val leafPin=CanonicalCaddyServedLeafReadback(root,bundle,expected,selected)
                .verify("auth.datamancy.net")
            val leafReceipt=Json.decodeFromString<CaddyServedLeafReadback>(ReleasePrivateFiles.read(
                Path.of(leafPin.path),8192).decodeToString(throwOnInvalidSequence=true))
            require(leafReceipt.hostname=="auth.datamancy.net" &&
                leafReceipt.bundleSha256==expected && leafReceipt.generation==generation)
            Path.of(caPin.path) to leafReceipt.servedLeafDerSha256
        } else {
            val pin=requireNotNull(host.publicCa)
            host.privateBytes(pin,generation)
            Path.of(pin.path) to requireNotNull(host.publicLeafSha256)
        }
        val transport = PinnedLaneIdentityTransport(publicCa, publicLeafSha256,
            ca, privatePin, "managed-lane-agent", { host.secret(host.agentSecret, generation) },
            if (host.graphOwnedLatePublicTrust)
                ManagedGraphIssuerHosts.addresses(bundle,root,ReleaseLocks.sha256(bytes)) else emptyMap())
        val readerSubject = requireNotNull(plan.readerSubject)
        val readerIssuer = ManagedLaneNativeReader(transport, generation, readerSubject,
            { host.secret(host.readerSecret, generation) })
        val ledger = NativeManagedIdentityLedger(root.resolve("managed/identity"))
        val authority = ManagedLaneIdentityAuthority(transport, ledger, readerIssuer::bearer,
            setOf(plan.lanes.single { it.kind == ManagedLaneKind.PI }.subject),
            mapOf("managed-lane-agent" to "AGENT"))
        val issuer = NativeManagedAgentTokenIssuer { id, subject ->
            require(id == generation && subject == plan.lanes.first().subject)
            transport.agentBearer(id, subject, host.secret(host.agentSecret, generation))
        }
        ManagedLaneBrokerService.serve(plan, root, authority, issuer,
            { require(host.authenticationMode == "legacy-project-key-v1");
                host.secret(host.upstreamKey, generation).toCharArray() },
            ManagedLaneInitialDelivery { bound, token, operation ->
                ManagedLaneRuntime.real(root, bound).deliverBroker(
                    bound.lanes.single { it.kind == ManagedLaneKind.PI }, token, operation)
            })
    }
}
