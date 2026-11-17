package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class HttpsLifecycleRequest(val schemaVersion: Int = 1, val action: String,
    val operation: String, val runtimeManifest: String, val runtimeFingerprint: String, val binding: CaddySiteBinding,
    val expectedConfiguration: String? = null, val nonces: Map<String, String> = emptyMap(),
    val environment: String? = null, val expectedIntent: String? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val previousCertificates: Map<String, PublicCertificateIdentity>? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val renewalBudgetSeconds: Int? = null)
@Serializable internal data class ListenerSuccessionRequest(val binding: ListenerSuccessionBinding,
    val sourceManifest: ActivationInput, val targetManifest: ActivationInput,
    val action: String, val expectedIntentSha256: String? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val heldCapture: ActivationInput? = null)
@Serializable internal data class RestoredBridgeRequest(val binding: RestoredBridgeBinding,
    val sourceManifest: ActivationInput, val targetManifest: ActivationInput, val sourceFingerprint: String,
    val action: String, val expectedConfigurationSha256: String? = null, val expectedIntentSha256: String? = null,
    val removalOperation: String? = null, val isolationSha256: String? = null)
@Serializable internal data class PrivatePkiLifecycleRequest(val schemaVersion: Int = 1, val action: String,
    val site: String, val authority: String, val operation: String, val profile: PrivatePkiProfile? = null,
    val previousOperation: String? = null, val previousSha256: String? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val consumerManifest: ActivationInput? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val consumerFingerprint: String? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val consumerFiles: List<String> = emptyList())
@Serializable internal data class PrivatePkiLifecycleResult(val operation: String, val caSha256: String,
    val issueSha256: String? = null, val renewAfter: String? = null)

/** Typed runtime entrypoints. Never grants release activation or prints private key material. */
internal class CaddyLifecycle(private val control: (HttpsLifecycleRequest) -> CaddyHttpsProvisioner,
    private val observation: (HttpsLifecycleRequest) -> AcmeObservation,
    private val renewal: ((HttpsLifecycleRequest) -> CaddyPublicRenewal)? = null) {
    companion object {
        private val json = Json { encodeDefaults = true }
        private inline fun <reified T> readRequest(path: Path): T = try {
            json.decodeFromString(ReleaseLocks.privateBytes(path).decodeToString(throwOnInvalidSequence = true))
        } catch (_: kotlinx.serialization.SerializationException) {
            throw IllegalArgumentException("Invalid private lifecycle request; contents withheld")
        }
        fun readHttps(path: Path): HttpsLifecycleRequest = readRequest(path)
        fun readListener(path: Path): ListenerSuccessionRequest = readRequest(path)
        fun readRestoredBridge(path: Path): RestoredBridgeRequest = readRequest(path)
        fun readPrivatePki(path: Path): PrivatePkiLifecycleRequest = readRequest(path)
        private fun deployment(pin: ActivationInput): PrivateDeploymentSpec {
            require(pin.sha256.matches(Regex("[a-f0-9]{64}")))
            val path = Path.of(pin.path)
            require(path.isAbsolute && path.normalize() == path && path.parent == PrivateDeployment.BASE)
            val bytes = ReleasePrivateFiles.read(path)
            require(ReleaseLocks.sha256(bytes) == pin.sha256)
            return json.decodeFromString<PrivateDeploymentSpec>(bytes.decodeToString(throwOnInvalidSequence = true)).also {
                PrivateDeployment.validate(it); require(path.fileName.toString() == "${it.name}.json")
            }
        }
        fun listenerSuccession(request: ListenerSuccessionRequest): ListenerSuccessionOutcome {
            require(request.action in setOf("succeed", "reconcile") &&
                (if (request.action == "reconcile") request.expectedIntentSha256?.matches(Regex("[a-f0-9]{64}")) == true
                 else request.expectedIntentSha256 == null))
            val actor = IngressListenerSuccession.real(Path.of("/mnt/media/p0-v3/ingress-succession").resolve(request.binding.site),
                request.binding, deployment(request.sourceManifest), deployment(request.targetManifest))
            return if (request.action == "succeed") actor.succeed(request.binding)
                else actor.reconcile(request.binding, requireNotNull(request.expectedIntentSha256))
        }
        fun quiesceListenerForBridge(request: ListenerSuccessionRequest): ListenerBridgeQuiesceResult {
            require(request.action in setOf("quiesce-bridge", "read-quiesce", "held-quiesce-bridge", "read-held-quiesce") &&
                (if (request.action in setOf("read-quiesce", "read-held-quiesce"))
                    request.expectedIntentSha256?.matches(Regex("[a-f0-9]{64}")) == true
                 else request.expectedIntentSha256 == null) &&
                ((request.action in setOf("held-quiesce-bridge", "read-held-quiesce")) == (request.heldCapture != null)))
            val source = deployment(request.sourceManifest)
            val actor = IngressListenerSuccession.real(Path.of("/mnt/media/p0-v3/ingress-succession").resolve(request.binding.site),
                request.binding, source, deployment(request.targetManifest), forBridge = true)
            return when (request.action) {
                "quiesce-bridge" -> actor.quiesceForBridge(request.binding)
                "read-quiesce" -> actor.readQuiesce(request.binding, requireNotNull(request.expectedIntentSha256))
                "held-quiesce-bridge" -> actor.heldQuiesceForBridge(request.binding,
                    requireNotNull(request.heldCapture), source)
                else -> actor.readHeldQuiesce(request.binding, requireNotNull(request.heldCapture), source,
                    requireNotNull(request.expectedIntentSha256))
            }
        }
        fun restoredBridge(request: RestoredBridgeRequest): String {
            require(request.action in setOf("install", "remove", "reconcile", "resume-proof"))
            val actor = RestrictedRestoreBridge.real(Path.of("/mnt/media/p0-v3/restored-bridges").resolve(request.binding.site)
                .resolve(request.binding.targetGeneration), request.binding, deployment(request.targetManifest),
                deployment(request.sourceManifest), request.sourceFingerprint)
            return when (request.action) {
                "install" -> json.encodeToString(actor.install(requireNotNull(request.expectedConfigurationSha256)))
                "remove" -> json.encodeToString(actor.remove(requireNotNull(request.removalOperation),
                    requireNotNull(request.expectedConfigurationSha256)))
                "reconcile" -> json.encodeToString(actor.reconcile(requireNotNull(request.removalOperation),
                    requireNotNull(request.expectedIntentSha256)))
                else -> {
                    val operation = requireNotNull(request.removalOperation)
                    val path = Path.of("/mnt/media/p0-v3/restored-bridges").resolve(request.binding.site)
                        .resolve(request.binding.targetGeneration).resolve("$operation.result.json")
                    val result = json.decodeFromString<RestoredBridgeResult>(ReleasePrivateFiles.read(path).decodeToString())
                    actor.sourceResumeProof(result, requireNotNull(request.isolationSha256))
                }
            }
        }
        private fun spec(request: HttpsLifecycleRequest): PrivateDeploymentSpec {
            val spec = PrivateDeployment.read(Path.of(request.runtimeManifest))
            PrivateDeployment.validate(spec)
            require(spec.store == RuntimeStore.CANONICAL_V2 && spec.ingress != null)
            NamespaceCaddyTransport.checkBinding(request.binding, spec)
            return spec
        }
        fun real(): CaddyLifecycle = CaddyLifecycle({ request ->
            val spec = spec(request)
            require(request.binding.site.matches(Regex("[a-z][a-z0-9-]{0,39}")))
            val base = privateControlDirectory(Path.of("/mnt/media/p0-v3/caddy-https"))
            val root = privateControlDirectory(base.resolve(request.binding.site))
            CaddyHttpsProvisioner.inRuntime(root, request.binding, spec, request.runtimeFingerprint)
        }, { request ->
            val spec = spec(request)
            val runtime = PrivateDeployment.real(mapOf(spec.name to request.runtimeFingerprint))
            PublicHttp01Observation(request.binding.approvedHosts) { port -> runtime.ingressPortOwner(spec, request.runtimeFingerprint, port) }
        }, { request ->
            val spec = spec(request)
            val base = privateControlDirectory(Path.of("/mnt/media/p0-v3/caddy-public-renewal"))
            val root = privateControlDirectory(base.resolve(request.binding.site))
            val httpsBase = privateControlDirectory(Path.of("/mnt/media/p0-v3/caddy-https"))
            val caddy = CaddyHttpsProvisioner.inRuntime(privateControlDirectory(httpsBase.resolve(request.binding.site)),
                request.binding, spec, request.runtimeFingerprint)
            val runtime = PrivateDeployment.real(mapOf(spec.name to request.runtimeFingerprint))
            CaddyPublicRenewal(root, request.binding.approvedHosts, caddy::observeConfigurationSha256,
                nativePolicy = {
                    val audit = runtime.audit(spec)
                    require(audit.maintenanceId == null && audit.statuses.single { it.id == "caddy" }.state == "running" &&
                        listOf(80, 443).all { runtime.ingressPortOwner(spec, request.runtimeFingerprint, it) == PortOwner.OWNED_V3 }) {
                        "Caddy native scheduler must own both live HTTPS renewal listeners"
                    }
                    caddy.ownedAutomaticRenewalPolicy(caddy.observeConfigurationSha256())
                })
        })
        fun privatePki(request: PrivatePkiLifecycleRequest,
            authority: (String, String) -> ManagedPrivatePki = { site, name ->
                val base = privateControlDirectory(Path.of("/mnt/media/p0-v3/private-pki"))
                val siteRoot = privateControlDirectory(base.resolve(site))
                ManagedPrivatePki.real(site, name, privateControlDirectory(siteRoot.resolve(name)))
            }): PrivatePkiLifecycleResult {
            require(request.schemaVersion == 1 && request.action in setOf("initialize", "issue", "renew", "adopt") &&
                listOf(request.site, request.authority).all { it.matches(Regex("[a-z][a-z0-9-]{0,39}")) } &&
                request.operation.matches(Regex("pki-[a-f0-9]{16}")))
            when (request.action) {
                "initialize" -> require(request.profile == null && request.previousOperation == null && request.previousSha256 == null &&
                    request.consumerManifest == null && request.consumerFiles.isEmpty() && request.consumerFingerprint == null)
                "issue" -> require(request.profile != null && request.previousOperation == null && request.previousSha256 == null &&
                    request.consumerManifest == null && request.consumerFiles.isEmpty() && request.consumerFingerprint == null)
                "renew" -> require(request.profile == null && request.previousOperation?.matches(Regex("pki-[a-f0-9]{16}")) == true &&
                    request.previousSha256?.matches(Regex("[a-f0-9]{64}")) == true && request.consumerManifest == null)
                "adopt" -> require(request.profile == null && request.previousOperation?.matches(Regex("pki-[a-f0-9]{16}")) == true &&
                    request.previousSha256?.matches(Regex("[a-f0-9]{64}")) == true &&
                    request.consumerManifest != null && request.consumerFingerprint?.matches(Regex("[a-f0-9]{64}")) == true &&
                    request.consumerFiles.size == 3)
            }
            val signer = authority(request.site, request.authority)
            if (request.action == "initialize") return PrivatePkiLifecycleResult(request.operation, signer.initialize(request.operation))
            if (request.action == "adopt") {
                val manifest = requireNotNull(request.consumerManifest)
                val adoption = signer.adopt(request.operation, requireNotNull(request.previousOperation),
                    requireNotNull(request.previousSha256), Path.of(manifest.path), manifest.sha256,
                    requireNotNull(request.consumerFingerprint), request.consumerFiles[0], request.consumerFiles[1], request.consumerFiles[2])
                return PrivatePkiLifecycleResult(request.operation, adoption.caSha256,
                    ReleaseLocks.sha256(json.encodeToString(adoption).toByteArray()))
            }
            val issue = if (request.action == "issue") signer.issue(request.operation, requireNotNull(request.profile))
                else signer.renew(request.operation, requireNotNull(request.previousOperation), requireNotNull(request.previousSha256))
            return PrivatePkiLifecycleResult(issue.operation, issue.caSha256,
                ReleaseLocks.sha256(json.encodeToString(issue).toByteArray()), issue.renewAfter)
        }
    }
    fun execute(request: HttpsLifecycleRequest): HttpsProvisionResult {
        require(request.schemaVersion == 1 && request.action in setOf("stage-http01", "provision", "reconcile", "observe-renewal") &&
            request.operation.matches(Regex("r-[a-f0-9]{12}")) && request.runtimeFingerprint.matches(Regex("[a-f0-9]{64}")))
        if (request.action == "observe-renewal") {
            require(request.expectedConfiguration?.matches(Regex("[a-f0-9]{64}")) == true && request.expectedIntent == null &&
                request.nonces.isEmpty() && request.environment == null)
            val result = requireNotNull(renewal) { "Explicit renewal observer required" }(request).observe(request.operation,
                requireNotNull(request.expectedConfiguration), requireNotNull(request.previousCertificates),
                requireNotNull(request.renewalBudgetSeconds))
            return HttpsProvisionResult(result.operation, result.intentSha256, "observed-changed-later-expiry",
                requireNotNull(request.expectedConfiguration))
        }
        require(request.previousCertificates == null && request.renewalBudgetSeconds == null)
        if (request.action == "reconcile") require(request.expectedIntent?.matches(Regex("[a-f0-9]{64}")) == true &&
            request.expectedConfiguration == null && request.nonces.isEmpty() && request.environment == null)
        else require(request.expectedConfiguration?.matches(Regex("[a-f0-9]{64}")) == true && request.expectedIntent == null &&
            request.nonces.keys == request.binding.approvedHosts &&
            (if (request.action == "provision") request.environment in AcmeEnvironment.entries.map { it.name } else request.environment == null))
        val controller = control(request)
        return when (request.action) {
            "stage-http01" -> controller.stageHttp01(request.operation, requireNotNull(request.expectedConfiguration), request.nonces,
                observation(request)::portOwner)
            "provision" -> controller.provision(request.operation, requireNotNull(request.expectedConfiguration), request.nonces,
                AcmeEnvironment.valueOf(requireNotNull(request.environment)), observation(request))
            else -> controller.reconcile(request.operation, requireNotNull(request.expectedIntent))
        }
    }
}

@Serializable internal data class ListenerSuccessionBinding(val operation: String, val site: String,
    val source: String, val sourceFingerprint: String, val target: String, val targetFingerprint: String,
    val approvedHosts: Set<String>)
@Serializable internal data class ListenerSuccessionOutcome(val operation: String, val intentSha256: String,
    val sourceStopped: Boolean, val targetStarted: Boolean, val sourceProofSha256: String, val targetProofSha256: String)
@Serializable internal data class ListenerBridgeQuiesceResult(val operation: String, val intentSha256: String,
    val sourceGeneration: String, val targetGeneration: String, val sourceStoppedProofSha256: String,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val heldCaptureSha256: String? = null,
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val captureId: String? = null)

/** Never infer ownership from a listening socket; observations must audit the exact generation. */
internal interface ListenerGenerationControl {
    fun owned(generation: String, fingerprint: String, port: Int): PortOwner
    fun hostPort(port: Int): PortOwner
    fun stop(generation: String, fingerprint: String)
    fun start(generation: String, fingerprint: String)
    /** SHA-256 of independently audited, retained generation/runtime status, not a caller boolean. */
    fun stateSha256(generation: String, fingerprint: String, running: Boolean): String
}

/** The source stays down through target isolation; another operation cannot replay an uncertain start.
 * The release transaction, not this listener actor, may subsequently resume an isolated source. */
internal fun sealedRestoredBridgeSource(source: PrivateDeploymentSpec, generation: String,
    fingerprint: String, site: String, hosts: Set<String>): Boolean {
    if (source.ingress != null) return source.ingress.site == site &&
        source.ingress.approvedHosts == hosts
    require(source.nativeIngress == null && source.store == RuntimeStore.CANONICAL_V2)
    val raw = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(generation).resolve("bundle.json"))
    val bundle = Json.decodeFromString<GenerationBundle>(raw.decodeToString(throwOnInvalidSequence = true))
    require(bundle.request.id == generation && bundle.ownedUpdate != null)
    SiteOwnerships.checkSealed(bundle)
    OwnedReleaseUpdates.validate(bundle)
    return bundle.ownership?.let { it.contract.site == site && it.approvedHosts == hosts } == true &&
        bundle.members.singleOrNull()?.let { it.spec == source && it.runtimeFingerprint == fingerprint } == true
}

internal class IngressListenerSuccession(private val root: Path, private val control: ListenerGenerationControl) {
    companion object {
        fun real(root: Path, binding: ListenerSuccessionBinding, source: PrivateDeploymentSpec,
            target: PrivateDeploymentSpec, forBridge: Boolean = false): IngressListenerSuccession {
            require(root == Path.of("/mnt/media/p0-v3/ingress-succession").resolve(binding.site) &&
                source.name.startsWith("${binding.source}-") && target.name.startsWith("${binding.target}-") &&
                source.store == RuntimeStore.CANONICAL_V2 && target.store == RuntimeStore.CANONICAL_V2 &&
                sealedRestoredBridgeSource(source, binding.source, binding.sourceFingerprint,
                    binding.site, binding.approvedHosts) &&
                (if (forBridge) target.ingress == null else target.ingress?.approvedHosts == binding.approvedHosts) &&
                (forBridge || target.ingress?.site == binding.site))
            val specs = mapOf(binding.source to source, binding.target to target)
            val pins = mapOf(binding.source to binding.sourceFingerprint, binding.target to binding.targetFingerprint)
            val runtime = PrivateDeployment.real(mapOf(source.name to binding.sourceFingerprint,
                target.name to binding.targetFingerprint))
            val observer = object : ListenerGenerationControl {
                private fun spec(generation: String, fingerprint: String): PrivateDeploymentSpec {
                    val expected = specs.getValue(generation)
                    require(pins.getValue(generation) == fingerprint)
                    return expected
                }
                override fun owned(generation: String, fingerprint: String, port: Int): PortOwner {
                    require(port in setOf(80, 443))
                    return if (runtime.status(spec(generation, fingerprint)).single { it.id == "caddy" }.state == "running")
                        PortOwner.OWNED_V3 else PortOwner.FREE
                }
                override fun hostPort(port: Int) = hostIngressPortOwner(port)
                override fun stop(generation: String, fingerprint: String) {
                    require(generation == binding.source)
                    runtime.stop(spec(generation, fingerprint))
                }
                override fun start(generation: String, fingerprint: String) {
                    require(generation == binding.target)
                    runtime.apply(spec(generation, fingerprint))
                }
                override fun stateSha256(generation: String, fingerprint: String, running: Boolean): String {
                    val states = runtime.status(spec(generation, fingerprint))
                    val caddy = states.single { it.id == "caddy" }
                    require((caddy.state == "running") == running &&
                        states.filter { it.id != "caddy" && !running }.none { it.state == "running" })
                    return ReleaseLocks.sha256(Json.encodeToString(states).toByteArray())
                }
            }
            privateControlDirectory(root.parent)
            return IngressListenerSuccession(privateControlDirectory(root), observer)
        }
    }
    private val json = Json { encodeDefaults = true }
    private val hash = Regex("[a-f0-9]{64}")
    private val generation = Regex("q-[a-f0-9]{12}")
    private val operation = Regex("r-[a-f0-9]{12}")
    private fun guard(binding: ListenerSuccessionBinding) {
        require(operation.matches(binding.operation) && binding.site.matches(Regex("[a-z][a-z0-9-]{0,39}")) &&
            root.fileName.toString() == binding.site && generation.matches(binding.source) && generation.matches(binding.target) &&
            binding.source != binding.target && hash.matches(binding.sourceFingerprint) && hash.matches(binding.targetFingerprint) &&
            binding.approvedHosts.isNotEmpty() && binding.approvedHosts.all(AcmePreflight.hostPattern::matches))
    }
    fun succeed(binding: ListenerSuccessionBinding): ListenerSuccessionOutcome {
        guard(binding)
        require(listOf(80, 443).all { control.owned(binding.source, binding.sourceFingerprint, it) == PortOwner.OWNED_V3 &&
            control.hostPort(it) == PortOwner.PROTECTED }) { "Exact old Caddy must exclusively own 80 and 443" }
        val intent = json.encodeToString(binding).toByteArray()
        // Never hold the journal lock while acquiring generation/runtime locks or invoking native effects.
        ReleasePrivateFiles.locked(root) {
            require(!Files.exists(root.resolve("listener.pending"), NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve("${binding.operation}.intent.json"), NOFOLLOW_LINKS)) { "Uncertain listener succession; reconcile without replay" }
            ReleasePrivateFiles.save(root.resolve("${binding.operation}.intent.json"), intent)
            ReleasePrivateFiles.save(root.resolve("listener.pending"), intent)
        }
        control.stop(binding.source, binding.sourceFingerprint)
        val stopped = control.stateSha256(binding.source, binding.sourceFingerprint, false)
        require(hash.matches(stopped) && listOf(80, 443).all { control.hostPort(it) == PortOwner.FREE &&
            control.owned(binding.source, binding.sourceFingerprint, it) == PortOwner.FREE }) {
            "Original listener not demonstrably stopped; target must not start"
        }
        ReleasePrivateFiles.locked(root) {
            require(ReleasePrivateFiles.read(root.resolve("listener.pending")).contentEquals(intent))
            ReleasePrivateFiles.save(root.resolve("${binding.operation}.source-stopped"), stopped.toByteArray())
        }
        control.start(binding.target, binding.targetFingerprint)
        val target = control.stateSha256(binding.target, binding.targetFingerprint, true)
        require(hash.matches(target) && listOf(80, 443).all {
            control.owned(binding.target, binding.targetFingerprint, it) == PortOwner.OWNED_V3 &&
                control.owned(binding.source, binding.sourceFingerprint, it) == PortOwner.FREE && control.hostPort(it) == PortOwner.PROTECTED
        }) { "Target did not exclusively take over both listeners" }
        val result = ListenerSuccessionOutcome(binding.operation, ReleaseLocks.sha256(intent), true, true, stopped, target)
        ReleasePrivateFiles.locked(root) {
            require(ReleasePrivateFiles.read(root.resolve("listener.pending")).contentEquals(intent))
            ReleasePrivateFiles.save(root.resolve("${binding.operation}.result.json"), json.encodeToString(result).toByteArray())
            ReleasePrivateFiles.removeExact(root.resolve("listener.pending"), intent)
        }
        return result
    }
    /** Stop-only source claim for a no-cookie private restore. The target has NO public ingress;
     * a distinct bridge starts later, and source resume still requires removal+target isolation. */
    fun quiesceForBridge(binding: ListenerSuccessionBinding): ListenerBridgeQuiesceResult {
        guard(binding)
        require(listOf(80, 443).all { control.owned(binding.source, binding.sourceFingerprint, it) == PortOwner.OWNED_V3 &&
            control.hostPort(it) == PortOwner.PROTECTED })
        val intent = json.encodeToString(binding).toByteArray()
        ReleasePrivateFiles.locked(root) {
            require(!Files.exists(root.resolve("listener.pending"), NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve("${binding.operation}.intent.json"), NOFOLLOW_LINKS))
            ReleasePrivateFiles.save(root.resolve("${binding.operation}.intent.json"), intent)
            ReleasePrivateFiles.save(root.resolve("listener.pending"), intent)
        }
        control.stop(binding.source, binding.sourceFingerprint)
        val proof = control.stateSha256(binding.source, binding.sourceFingerprint, false)
        require(hash.matches(proof) && listOf(80, 443).all { control.hostPort(it) == PortOwner.FREE &&
            control.owned(binding.source, binding.sourceFingerprint, it) == PortOwner.FREE &&
            control.owned(binding.target, binding.targetFingerprint, it) == PortOwner.FREE }) {
            "Source listener not demonstrably stopped; private bridge must remain disabled"
        }
        val result = ListenerBridgeQuiesceResult(binding.operation, ReleaseLocks.sha256(intent),
            binding.source, binding.target, proof)
        ReleasePrivateFiles.locked(root) {
            require(ReleasePrivateFiles.read(root.resolve("listener.pending")).contentEquals(intent))
            ReleasePrivateFiles.save(root.resolve("${binding.operation}.bridge-result.json"), json.encodeToString(result).toByteArray())
            ReleasePrivateFiles.removeExact(root.resolve("listener.pending"), intent)
        }
        return result
    }
    /** Direct unheld RestoreTest first quiesces ALL original members with the native
     * operation lease. This binds that one stop to the public listener, without stopping
     * Caddy a second time or calling an absent held-capture an original proof. */
    fun quiescedDirectSourceForBridge(binding: ListenerSuccessionBinding,
        quiescence: ActivationInput, source: PrivateDeploymentSpec): ListenerBridgeQuiesceResult {
        guard(binding)
        val path = Path.of(quiescence.path)
        require(path.parent?.parent == GenerationRuntime.BASE.resolve(binding.source).resolve("qualification-direct") &&
            path.fileName.toString() == "quiesce.result.json")
        val bytes = ReleasePrivateFiles.read(path, 65536)
        require(ReleaseLocks.sha256(bytes) == quiescence.sha256)
        val original = json.decodeFromString<RestoredDirectSourceQuiesce>(bytes.decodeToString(throwOnInvalidSequence = true))
        require(original.schemaVersion == 2 && original.source.id == binding.source &&
            original.target.id == binding.target && original.fences.keys == setOf(source.name) &&
            original.fences.getValue(source.name).matches(Regex("[a-z][a-z0-9-]{0,95}")))
        val stopped = control.stateSha256(binding.source, binding.sourceFingerprint, false)
        require(stopped.matches(hash) && listOf(80, 443).all {
            control.hostPort(it) == PortOwner.FREE &&
                control.owned(binding.source, binding.sourceFingerprint, it) == PortOwner.FREE &&
                control.owned(binding.target, binding.targetFingerprint, it) == PortOwner.FREE
        })
        val intent = json.encodeToString(binding).toByteArray()
        val result = ListenerBridgeQuiesceResult(binding.operation, ReleaseLocks.sha256(intent),
            binding.source, binding.target, stopped)
        ReleasePrivateFiles.locked(root) {
            require(!Files.exists(root.resolve("listener.pending"), NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve("${binding.operation}.intent.json"), NOFOLLOW_LINKS))
            ReleasePrivateFiles.save(root.resolve("${binding.operation}.intent.json"), intent)
            ReleasePrivateFiles.save(root.resolve("listener.pending"), intent)
            ReleasePrivateFiles.save(root.resolve("${binding.operation}.bridge-result.json"), json.encodeToString(result).toByteArray())
            ReleasePrivateFiles.removeExact(root.resolve("listener.pending"), intent)
        }
        return result
    }
    /** Restore's Kopia capture has ALREADY quiesced every source member. This is a
     * read-only, held-capture-bound source-stop observation; calling stop a second time
     * would violate the uncertain-effect and original source-resume contracts. */
    private fun heldSourceProof(binding: ListenerSuccessionBinding, capture: ActivationInput,
        source: PrivateDeploymentSpec): Pair<ByteArray, String> {
        guard(binding)
        require(capture.sha256.matches(hash) && source.name.startsWith("${binding.source}-"))
        val heldPath = Path.of(capture.path)
        require(heldPath.parent?.parent?.parent == GenerationRuntime.BASE.resolve(binding.source) &&
            heldPath.parent?.parent?.fileName?.toString() == "backups" &&
            heldPath.parent?.fileName?.toString()?.matches(Regex("cap-[a-f0-9]{12}")) == true &&
            heldPath.fileName.toString() == "held.json")
        val heldBytes = ReleasePrivateFiles.read(heldPath, 65536)
        require(ReleaseLocks.sha256(heldBytes) == capture.sha256)
        val held = json.decodeFromString<GenerationHeldCapture>(heldBytes.decodeToString(throwOnInvalidSequence = true))
        held.validate()
        val bundleBytes = ReleasePrivateFiles.read(GenerationRuntime.BASE.resolve(binding.source).resolve("bundle.json"))
        val sourceBundle = json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
        require(held.access.generation == binding.source && held.access.operation == heldPath.parent.fileName.toString() &&
            held.access.bundleSha256 == ReleaseLocks.sha256(bundleBytes) &&
            held.fences.keys == sourceBundle.members.map { it.member.name }.toSet() &&
            sourceBundle.members.single { it.member.name == source.name }.let {
                it.spec == source && it.runtimeFingerprint == binding.sourceFingerprint
            })
        SiteOwnerships.checkSealed(sourceBundle)
        val stopped = control.stateSha256(binding.source, binding.sourceFingerprint, false)
        require(stopped.matches(hash) && listOf(80, 443).all {
            control.hostPort(it) == PortOwner.FREE &&
                control.owned(binding.source, binding.sourceFingerprint, it) == PortOwner.FREE &&
                control.owned(binding.target, binding.targetFingerprint, it) == PortOwner.FREE
        }) { "Held Kopia original source is not independently stopped with both public ports free" }
        return heldBytes to stopped
    }
    fun heldQuiesceForBridge(binding: ListenerSuccessionBinding, capture: ActivationInput,
        source: PrivateDeploymentSpec): ListenerBridgeQuiesceResult {
        val (heldBytes, proof) = heldSourceProof(binding, capture, source)
        val intent = json.encodeToString(binding).toByteArray()
        val result = ListenerBridgeQuiesceResult(binding.operation, ReleaseLocks.sha256(intent),
            binding.source, binding.target, proof, ReleaseLocks.sha256(heldBytes),
            Path.of(capture.path).parent.fileName.toString())
        // No native STOP/START here: only generation-held proof and exact once-only journal.
        ReleasePrivateFiles.locked(root) {
            require(!Files.exists(root.resolve("listener.pending"), NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve("${binding.operation}.intent.json"), NOFOLLOW_LINKS))
            ReleasePrivateFiles.save(root.resolve("${binding.operation}.intent.json"), intent)
            ReleasePrivateFiles.save(root.resolve("listener.pending"), intent)
            ReleasePrivateFiles.save(root.resolve("${binding.operation}.bridge-result.json"),
                json.encodeToString(result).toByteArray())
            ReleasePrivateFiles.removeExact(root.resolve("listener.pending"), intent)
        }
        return result
    }
    fun readHeldQuiesce(binding: ListenerSuccessionBinding, capture: ActivationInput,
        source: PrivateDeploymentSpec, expectedIntent: String): ListenerBridgeQuiesceResult {
        require(expectedIntent.matches(hash))
        val (heldBytes, proof) = heldSourceProof(binding, capture, source)
        val intent = ReleasePrivateFiles.read(root.resolve("${binding.operation}.intent.json"))
        require(ReleaseLocks.sha256(intent) == expectedIntent &&
            intent.contentEquals(json.encodeToString(binding).toByteArray()))
        val result = ListenerBridgeQuiesceResult(binding.operation, expectedIntent,
            binding.source, binding.target, proof, ReleaseLocks.sha256(heldBytes),
            Path.of(capture.path).parent.fileName.toString())
        ReleasePrivateFiles.locked(root) {
            val pending = root.resolve("listener.pending")
            val path = root.resolve("${binding.operation}.bridge-result.json")
            if (Files.exists(pending, NOFOLLOW_LINKS)) {
                require(ReleasePrivateFiles.read(pending).contentEquals(intent))
                if (Files.exists(path, NOFOLLOW_LINKS))
                    require(ReleasePrivateFiles.read(path).contentEquals(json.encodeToString(result).toByteArray()))
                else ReleasePrivateFiles.save(path, json.encodeToString(result).toByteArray())
                ReleasePrivateFiles.removeExact(pending, intent)
            } else require(ReleasePrivateFiles.read(path).contentEquals(json.encodeToString(result).toByteArray()))
        }
        return result
    }
    /** Read-only native reconciliation after a lost stop acknowledgement. May persist the audited
     * result and clear only this exact pending journal; it NEVER invokes stop or starts a target. */
    fun readQuiesce(binding: ListenerSuccessionBinding, expectedIntent: String): ListenerBridgeQuiesceResult {
        guard(binding); require(hash.matches(expectedIntent))
        val intent = ReleasePrivateFiles.locked(root) {
            ReleasePrivateFiles.read(root.resolve("${binding.operation}.intent.json")).also {
                require(ReleaseLocks.sha256(it) == expectedIntent && it.contentEquals(json.encodeToString(binding).toByteArray()))
            }
        }
        val stopped = control.stateSha256(binding.source, binding.sourceFingerprint, false)
        require(hash.matches(stopped) && listOf(80, 443).all { control.hostPort(it) == PortOwner.FREE &&
            control.owned(binding.source, binding.sourceFingerprint, it) == PortOwner.FREE &&
            control.owned(binding.target, binding.targetFingerprint, it) == PortOwner.FREE })
        val result = ListenerBridgeQuiesceResult(binding.operation, expectedIntent, binding.source, binding.target, stopped)
        ReleasePrivateFiles.locked(root) {
            val pending = root.resolve("listener.pending")
            val path = root.resolve("${binding.operation}.bridge-result.json")
            if (Files.exists(pending, NOFOLLOW_LINKS)) {
                require(ReleasePrivateFiles.read(pending).contentEquals(intent))
                if (Files.exists(path, NOFOLLOW_LINKS)) require(ReleasePrivateFiles.read(path).contentEquals(json.encodeToString(result).toByteArray()))
                else ReleasePrivateFiles.save(path, json.encodeToString(result).toByteArray())
                ReleasePrivateFiles.removeExact(pending, intent)
            } else {
                require(ReleasePrivateFiles.read(path).contentEquals(json.encodeToString(result).toByteArray()))
            }
        }
        return result
    }
    /** Read-only lost-ack reconciliation. Never restarts the source or target. */
    fun reconcile(binding: ListenerSuccessionBinding, expectedIntent: String): ListenerSuccessionOutcome {
        guard(binding); require(hash.matches(expectedIntent))
        val intent = ReleasePrivateFiles.locked(root) {
            ReleasePrivateFiles.read(root.resolve("${binding.operation}.intent.json")).also {
                require(ReleaseLocks.sha256(it) == expectedIntent && it.contentEquals(json.encodeToString(binding).toByteArray()) &&
                    ReleasePrivateFiles.read(root.resolve("listener.pending")).contentEquals(it))
            }
        }
        val stopped = ReleasePrivateFiles.read(root.resolve("${binding.operation}.source-stopped")).decodeToString()
        require(hash.matches(stopped) && control.stateSha256(binding.source, binding.sourceFingerprint, false) == stopped &&
            listOf(80, 443).all { control.owned(binding.source, binding.sourceFingerprint, it) == PortOwner.FREE &&
                control.owned(binding.target, binding.targetFingerprint, it) == PortOwner.OWNED_V3 }) {
            "Listener ownership uncertain; do not resume source"
        }
        val target = control.stateSha256(binding.target, binding.targetFingerprint, true)
        require(hash.matches(target))
        val result = ListenerSuccessionOutcome(binding.operation, expectedIntent, true, true, stopped, target)
        ReleasePrivateFiles.locked(root) {
            require(ReleasePrivateFiles.read(root.resolve("listener.pending")).contentEquals(intent))
            val resultPath = root.resolve("${binding.operation}.result.json")
            val bytes = json.encodeToString(result).toByteArray()
            if (Files.exists(resultPath, NOFOLLOW_LINKS)) require(ReleasePrivateFiles.read(resultPath).contentEquals(bytes))
            else ReleasePrivateFiles.save(resultPath, bytes)
            ReleasePrivateFiles.removeExact(root.resolve("listener.pending"), intent)
        }
        return result
    }
}

internal fun privateControlDirectory(path: Path): Path {
    require(path.isAbsolute && path.normalize() == path && path.parent.toRealPath() == path.parent)
    if (!Files.exists(path, NOFOLLOW_LINKS)) {
        Files.createDirectory(path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(path.parent)
    }
    ReleasePrivateFiles.directory(path)
    return path
}
