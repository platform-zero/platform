package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

@Serializable internal data class OwnerCasePrepare(val caseDirectory: String, val invocationId: String,
    val evidenceKey: String, val proposedContext: ActivationInput)
@Serializable internal data class OwnerCasePrepared(val invocationId: String, val mode: String,
    val context: JsonObject)
@Serializable internal data class OwnerCaseStart(val caseDirectory: String, val caseIntentSha256: String,
    val contextSha256: String)
@Serializable internal data class OwnerCaseStarted(val invocationId: String, val mode: String,
    val client: QualificationClientNative?)
@Serializable internal data class OwnerCaseAwaited(val invocationId: String, val exitCode: Int,
    val finished: Boolean, val nativeReceipt: ActivationInput?)
@Serializable internal data class OwnerCaseFenced(val invocationId: String,
    val clientFence: ActivationInput?, val bridgeRemoval: ActivationInput?)
@Serializable internal data class OwnerCaseGate(val schemaVersion: Int = 2, val invocationId: String,
    val mode: String, val caseIntentSha256: String, val contextSha256: String,
    val client: QualificationClientNative?, val ingress: ActivationInput?,
    val sourceStopped: ActivationInput?, val privateReadiness: ActivationInput?)
@Serializable internal data class OwnerCaseNative(val caseDirectory: String, val family: String,
    val request: ActivationInput)
@Serializable internal data class OwnerCaseNativeReply(val invocationId: String, val family: String,
    val requestSha256: String, val result: JsonObject)
@Serializable internal data class OwnerCaseClosure(val schemaVersion: Int = 2, val invocationId: String,
    val caseDirectory: String, val evidenceKey: String, val mode: String, val phase: String,
    val caseIntent: ActivationInput, val context: ActivationInput, val result: ActivationInput,
    val client: QualificationClientNative?, val ingress: ActivationInput?,
    val clientFence: ActivationInput?, val bridgeRemoval: ActivationInput?)

/** Frozen distinct C2 install/remove identifiers. V1 bridge receipts use plain operation
 * filenames; INSTALL qualification ingress retains its own action-suffixed receipts. */
internal fun qualificationCaseBridgeOperation(suiteId: String, invocationId: String, action: String): String {
    require(suiteId.matches(Regex("[a-f0-9]{24}")) && action in setOf("install", "remove"))
    val uuid = invocationId.removePrefix("case-")
    require(invocationId == "case-$uuid" && uuid.matches(Regex("[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}")) &&
        java.util.UUID.fromString(uuid).toString() == uuid)
    val material = suiteId + invocationId + if (action == "remove") "\nremove" else ""
    return "r-${ReleaseLocks.sha256(material.encodeToByteArray()).take(12)}"
}

/** Browser transport consumes only the original Office/Files pair. The separate
 * files-native app-token authority is never a browser bridge or a source address. */
internal fun qualificationOfficeBrowserBridgeProjection(produced: Map<String,JsonElement>,
    isolation: String, leaves: Map<String,String>): Map<String,JsonElement> {
    require(isolation.matches(Regex("[a-f0-9]{64}")) && produced.keys == setOf("bridge","bridges") &&
        leaves.keys.containsAll(setOf("office.datamancy.net","files.datamancy.net",
            "files-native.datamancy.net")))
    val office = produced.getValue("bridge").jsonObject
    val files = produced.getValue("bridges").jsonObject
    require(files.keys == setOf("files.datamancy.net") &&
        office.getValue("originalHost").jsonPrimitive.content == "office.datamancy.net" &&
        office.getValue("port").jsonPrimitive.int == 443 &&
        office.getValue("isolationProofSha256").jsonPrimitive.content == isolation)
    val file = files.getValue("files.datamancy.net").jsonObject
    require(file.getValue("originalHost").jsonPrimitive.content == "files.datamancy.net" &&
        file.getValue("port").jsonPrimitive.int == 443 &&
        file.getValue("isolationProofSha256").jsonPrimitive.content == isolation)
    return produced
}

/** C1 accepts the Files producer's separately verified singleton native CA and
 * preserves the host-native vs QClient path without ever adding a browser bridge. */
internal fun qualificationFilesNativeCaseProjection(projection: QualificationOfficeInputs,
    dir: Path, generationId: String, bundleSha256: String, isolation: String?,
    selectedNativeLeaf: String, mode: QualificationExecutionMode): Map<String,JsonElement> {
    require(projection.context.keys == setOf("nativeApi") && projection.privateFiles.size == 1 &&
        generationId.matches(Regex("q-[a-f0-9]{12}")) &&
        bundleSha256.matches(Regex("[a-f0-9]{64}")) &&
        selectedNativeLeaf.matches(Regex("[a-f0-9]{64}")) &&
        (isolation == null || isolation.matches(Regex("[a-f0-9]{64}"))))
    val ca = projection.privateFiles.single()
    val expected = dir.resolve("owner-proofs/files-native-api-ca.pem")
    val native = projection.context.getValue("nativeApi").jsonObject
    val fields = setOf("originalHost","port","address","caFile","caSha256",
        "leafSha256","generationId","bundleSha256") +
        if (isolation == null) emptySet() else setOf("isolationProofSha256")
    require(native.keys == fields && ca.path == expected.toString() &&
        ReleaseLocks.sha256(ReleasePrivateFiles.read(expected,65536)) == ca.sha256 &&
        native.getValue("originalHost").jsonPrimitive.content == "files-native.datamancy.net" &&
        native.getValue("port").jsonPrimitive.int == 443 &&
        native.getValue("caFile").jsonPrimitive.content == "/case/owner-proofs/files-native-api-ca.pem" &&
        native.getValue("caSha256").jsonPrimitive.content == ca.sha256 &&
        native.getValue("leafSha256").jsonPrimitive.content == selectedNativeLeaf &&
        native.getValue("generationId").jsonPrimitive.content == generationId &&
        native.getValue("bundleSha256").jsonPrimitive.content == bundleSha256 &&
        (isolation == null || native.getValue("isolationProofSha256").jsonPrimitive.content == isolation))
    return if (mode == QualificationExecutionMode.QCLIENT_RUNNER) projection.context else mapOf(
        "nativeApi" to JsonObject(native + ("caFile" to JsonPrimitive(ca.path))))
}

@Serializable internal data class OwnerCaseSafetyReceipt(val schemaVersion: Int = 2,
    val invocationId: String, val generationId: String, val suiteId: String,
    val caseDirectory: String, val mode: String, val clientAttempted: Boolean,
    val bridgeAttempted: Boolean, val clientFence: ActivationInput?, val bridgeRemoval: ActivationInput?,
    val clientStopped: Boolean, val bridgeAbsent: Boolean)

/** Production-used one-use teardown state machine; test fakes supply only exact native
 * stop/remove observations. It never turns safety into a passing case. */
internal class QualificationCaseSafetyDriver(private val owner: Thread = Thread.currentThread()) {
    private var attempted = false
    fun close(clientAttempted: Boolean, bridgeAttempted: Boolean,
        stop: () -> Pair<ActivationInput?, Boolean>,
        remove: (ActivationInput?) -> Pair<ActivationInput?, Boolean>): Pair<ActivationInput?, ActivationInput?> {
        check(Thread.currentThread() === owner && !attempted)
        attempted = true
        val (fence, clientSafe) = if (clientAttempted) stop() else null to true
        require(clientSafe) { "Client identity/stop uncertain; original bridge and source stay held" }
        val (removal, bridgeSafe) = if (bridgeAttempted) remove(fence) else null to true
        require(bridgeSafe) { "Original bridge removal/absence uncertain; source stays held" }
        return fence to removal
    }
}

/** All methods run on the C1 owner thread while the generation/RSS/native cohort stays held.
 * Effects are one-use: neither a C1 retry nor a second case ID may adopt a pending native start. */
internal class QualificationCaseController(private val scope: QualificationControlScope,
    private val owner: Thread = Thread.currentThread(), private val restored: RestoredOwnerScope? = null) {
    private val json = Json { encodeDefaults = true; explicitNulls = true; ignoreUnknownKeys = false }
    private val hash = Regex("[a-f0-9]{64}")
    private val generation = GenerationRuntime.BASE.resolve(scope.generationId)
    private val bundle by lazy {
        val bytes = ReleasePrivateFiles.read(generation.resolve("bundle.json"))
        require(ReleaseLocks.sha256(bytes) == scope.bundleSha256)
        json.decodeFromString<GenerationBundle>(bytes.decodeToString(throwOnInvalidSequence = true)).also {
            SiteOwnerships.checkSealed(it)
            QualificationCanonicalTopology.require(it, restoredTarget = phase() == "RESTORE")
        }
    }
    private data class Active(val invocationId: String, val evidenceKey: String, val mode: QualificationExecutionMode,
        val service: String, val surface: String, val variant: String, val journey: String,
        val originalContext: JsonObject, val context: JsonObject, val roots: ActivationInput,
        val actorFiles: List<ActivationInput> = emptyList(),
        var intentSha256: String? = null, var contextSha256: String? = null,
        var request: QualificationClientRequest? = null, var runtime: QualificationClientRuntime? = null,
        var native: QualificationClientNative? = null, var ingress: ActivationInput? = null,
        var ingressRoot: Path? = null, var ingressActor: QualificationInstallIngress? = null,
        var bridgeActor: RestrictedRestoreBridge? = null, var bridgeBinding: RestoredBridgeBinding? = null,
        var bridgeAfterSha256: String? = null, var bridgeAttempted: Boolean = false,
        var awaited: Boolean = false, var fenceAttempted: Boolean = false, var fenced: Boolean = false,
        var safety: ActivationInput? = null, val safetyDriver: QualificationCaseSafetyDriver = QualificationCaseSafetyDriver(),
        var spool: QualificationCaseSpool? = null, var closure: ActivationInput? = null,
        var matrixCapture: QualificationMatrixCaptureActor? = null)
    private val active = mutableMapOf<Path, Active>()
    private val closed = mutableSetOf<String>()
    private fun owned() = check(Thread.currentThread() === owner) { "Qualification left retained lock owner" }
    private fun originalOwnership(): BoundSiteOwnership {
        if (phase() == "INSTALL") return requireNotNull(bundle.ownership)
        val receipt = requireNotNull(bundle.recoverySourceKopia) { "Only an authenticated Kopia original may supply RESTORE site identity" }
        val originalRoot = GenerationRuntime.BASE.resolve(receipt.generation)
        val bytes = ReleasePrivateFiles.read(originalRoot.resolve("bundle.json"))
        require(ReleaseLocks.sha256(bytes) == receipt.bundleSha256 && receipt.generation != scope.generationId)
        val original = json.decodeFromString<GenerationBundle>(bytes.decodeToString(throwOnInvalidSequence = true))
        SiteOwnerships.checkSealed(original)
        QualificationCanonicalTopology.require(original,
            allowOwnedUpdateSource = original.ownedUpdate != null)
        return requireNotNull(original.ownership)
    }
    private fun phase(): String = binding().getValue("phase").jsonPrimitive.content
    private fun binding(): JsonObject {
        val bytes = ReleasePrivateFiles.read(Path.of(scope.binding.path), 1048576)
        require(ReleaseLocks.sha256(bytes) == scope.binding.sha256)
        return json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject.also {
            require(it.getValue("generationId").jsonPrimitive.content == scope.generationId &&
                it.getValue("phase").jsonPrimitive.content in setOf("INSTALL", "RESTORE"))
        }
    }
    private fun pinned(pin: ActivationInput, limit: Int): ByteArray =
        (if (pin == scope.products || pin == scope.manifest) QualificationSuiteClosure.readPinnedDocument(pin, limit)
         else ReleasePrivateFiles.read(Path.of(pin.path), limit)).also { require(ReleaseLocks.sha256(it) == pin.sha256) }
    private fun case(path: String): Path = Path.of(path).also {
        require(it.isAbsolute && it.normalize() == it && it.parent == Path.of(scope.artifactRoot) &&
            it.fileName.toString().matches(Regex("[a-z][a-z0-9-]{0,95}(?:--[a-z0-9-]{1,95}){3}")))
        ReleasePrivateFiles.directory(it)
    }
    private fun pin(path: Path, limit: Int = 4194304): ActivationInput = ActivationInput(path.toString(),
        ReleaseLocks.sha256(ReleasePrivateFiles.read(path, limit)))
    private fun manifest(): List<JsonObject> {
        val raw = pinned(scope.manifest, 4194304)
        val manifest = json.parseToJsonElement(raw.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(manifest.getValue("schemaVersion").jsonPrimitive.int == 2)
        val cases = manifest.getValue("cases").jsonArray.map { it.jsonObject }
        require(cases.size in 1..256)
        val names = cases.map { definition ->
            val service = definition.getValue("serviceId").jsonPrimitive.content
            val surface = definition.getValue("surface").jsonPrimitive.content
            val variant = definition.getValue("variant").jsonPrimitive.content
            val journey = definition.getValue("journey").jsonPrimitive.content
            QualificationExecutionPolicy.select(raw, service, surface, variant, journey)
            "$service--$journey--${surface.lowercase()}--${variant.lowercase()}"
        }
        require(names.size == names.toSet().size)
        return cases
    }
    private fun declared(): Set<String> = manifest().map { definition ->
        "${definition.getValue("serviceId").jsonPrimitive.content}--" +
            "${definition.getValue("journey").jsonPrimitive.content}--" +
            "${definition.getValue("surface").jsonPrimitive.content.lowercase()}--" +
            definition.getValue("variant").jsonPrimitive.content.lowercase()
    }.toSet()
    private val crossCase = setOf("alloySourceOracleFile", "alloySourceOracleSha256",
        "alloySourceObservationFile", "alloySourceObservationSha256", "sourceNativeOracleFile",
        "sourceNativeOracleSha256", "sourceNativeObservationFile", "sourceNativeObservationSha256",
        "browserSourceOracleFile", "browserSourceOracleSha256", "browserSourceObservationFile",
        "browserSourceObservationSha256", "hulyBrowserSourceOracleFile", "hubBrowserSourceOracleFile",
        "hubBrowserSourceOracleSha256", "hubBrowserSourceObservationFile", "hubBrowserSourceObservationSha256",
        "originalSocialOracleFile", "sourceOfficeOracle")
    private fun completedPredecessor(proposed: JsonObject, caseDir: Path) {
        val parts = caseDir.fileName.toString().split("--")
        require(parts.size == 4)
        val dependency = QualificationExecutionPolicy.predecessor(parts[0], parts[2].uppercase(), parts[3].uppercase())
        val expected = if (phase() == "RESTORE") dependency?.restoreOriginalFields.orEmpty()
            else dependency?.fields.orEmpty()
        val socialNative = parts[0] == "mastodon" && parts[2] == "headless" && parts[3] == "native"
        val fields = expected + (if (socialNative) setOf("originalSocialOracleFile") else emptySet())
        require(proposed.keys.intersect(crossCase) == fields)
        if (socialNative) {
            val path = if (phase() == "INSTALL") caseDir.resolve("owner-proofs/social-native-original.json")
                else Path.of(proposed.getValue("sourceInvocation").jsonPrimitive.content).parent.resolve("oracle.json")
            require(proposed.getValue("originalSocialOracleFile").jsonPrimitive.content == path.toString())
        }
        if (dependency == null) return
        // RESTORE still requires the current-phase predecessor to have really completed,
        // but never substitutes that predecessor's oracle for the original INSTALL oracle.
        val entry = active.entries.singleOrNull { (_, state) -> state.service == dependency.service &&
            state.surface == dependency.surface && state.variant == dependency.variant }
            ?: error("Required current-phase predecessor has not run")
        val priorDir = entry.key; val prior = entry.value
        require(priorDir.parent == caseDir.parent && priorDir != caseDir && prior.fenced && prior.evidenceKey in closed)
        val closure = json.decodeFromString<OwnerCaseClosure>(pinned(requireNotNull(prior.closure), 65536)
            .decodeToString(throwOnInvalidSequence = true))
        require(closure.invocationId == prior.invocationId && closure.caseDirectory == priorDir.toString() &&
            closure.phase == phase() && closure.result.path == priorDir.resolve("result.json").toString())
        val result = json.parseToJsonElement(pinned(closure.result, 1048576)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        val oracleSha = pin(priorDir.resolve("oracle.json"), 1048576).sha256
        val observation = pin(priorDir.resolve("native-result.json"), 1048576).sha256
        require(result.getValue("passed").jsonPrimitive.boolean && result.getValue("finished").jsonPrimitive.boolean &&
            result.getValue("exitCode").jsonPrimitive.int == 0 &&
            result.getValue("observationSha256").jsonPrimitive.content == observation &&
            result.getValue("artifactHashes").jsonObject.getValue("oracle.json").jsonPrimitive.content == oracleSha &&
            result.getValue("invocation").jsonObject.getValue("binding") == binding() &&
            result.getValue("invocation").jsonObject.getValue("invocationId").jsonPrimitive.content == prior.invocationId)
        if (expected.isEmpty()) return // Current-phase completion is still mandatory on RESTORE.
        val sourceDir = if (phase() == "RESTORE") {
            val own = Path.of(proposed.getValue("sourceInvocation").jsonPrimitive.content).parent
            val source = own.parent.resolve(prior.evidenceKey)
            val oldIntent = json.parseToJsonElement(ReleasePrivateFiles.read(source.resolve("intent.json"),65536)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            val oldResult = json.parseToJsonElement(ReleasePrivateFiles.read(source.resolve("result.json"),1048576)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            val ownIntent = json.parseToJsonElement(ReleasePrivateFiles.read(own.resolve("intent.json"),65536)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(source != own && source.parent == own.parent &&
                oldIntent.getValue("binding") == ownIntent.getValue("binding") &&
                oldIntent.getValue("serviceId").jsonPrimitive.content == dependency.service &&
                oldIntent.getValue("surface").jsonPrimitive.content == dependency.surface &&
                oldIntent.getValue("variant").jsonPrimitive.content == dependency.variant &&
                oldResult.getValue("invocation") == oldIntent &&
                oldResult.getValue("passed").jsonPrimitive.boolean && oldResult.getValue("finished").jsonPrimitive.boolean &&
                oldResult.getValue("exitCode").jsonPrimitive.int == 0 &&
                oldResult.getValue("observationSha256").jsonPrimitive.content ==
                    pin(source.resolve("native-result.json"),1048576).sha256 &&
                oldResult.getValue("artifactHashes").jsonObject.getValue("oracle.json").jsonPrimitive.content ==
                    pin(source.resolve("oracle.json"),1048576).sha256)
            source
        } else priorDir
        val rawOracle = pin(sourceDir.resolve("oracle.json"),1048576).sha256
        val rawObservation = pin(sourceDir.resolve("native-result.json"),1048576).sha256
        for (field in expected) {
            val expectedValue = when {
                field.endsWith("ObservationFile") -> sourceDir.resolve("native-result.json").toString()
                field.endsWith("ObservationSha256") -> rawObservation
                field.endsWith("OracleFile") -> sourceDir.resolve("oracle.json").toString()
                field.endsWith("OracleSha256") -> rawOracle
                else -> error("Foreign typed predecessor field")
            }
            require(proposed.getValue(field).jsonPrimitive.content == expectedValue)
        }
    }
    private fun originalInstallSource(proposed: JsonObject, evidenceKey: String) {
        if (phase() == "INSTALL") {
            require("sourceInvocation" !in proposed && "sourceObservation" !in proposed)
            return
        }
        val expected = binding()
        val trial = expected.getValue("trialId").jsonPrimitive.content
        require(trial.matches(Regex("[a-z][a-z0-9-]{0,63}")))
        val prefix = if (scope.operation == "execute-staged") "staged" else "phase"
        val phaseResult = json.parseToJsonElement(ReleasePrivateFiles.read(Path.of(scope.journalFile).parent
            .resolve("$prefix-$trial-install.result.json"), 1048576).decodeToString(throwOnInvalidSequence = true)).jsonObject
        val originalPhase = phaseResult.getValue("invocation").jsonObject
        val originalBinding = originalPhase.getValue("binding").jsonObject
        require(phaseResult.getValue("passed").jsonPrimitive.boolean &&
            originalBinding.getValue("phase").jsonPrimitive.content == "INSTALL" &&
            originalBinding.getValue("trialId") == expected.getValue("trialId") &&
            originalBinding.getValue("candidate") == expected.getValue("candidate") &&
            originalPhase.getValue("journalHead").jsonPrimitive.content == scope.journalHeadSha256 &&
            (originalPhase["stagedOnly"]?.jsonPrimitive?.boolean ?: false) == (scope.operation == "execute-staged") &&
            originalBinding.getValue("generationId").jsonPrimitive.content ==
                requireNotNull(bundle.recoverySourceKopia).generation &&
            originalBinding.getValue("generationId").jsonPrimitive.content != scope.generationId)
        val directory = Path.of(originalPhase.getValue("artifactRoot").jsonPrimitive.content).resolve(evidenceKey)
        require(proposed.getValue("sourceInvocation").jsonPrimitive.content == directory.resolve("intent.json").toString() &&
            proposed.getValue("sourceObservation").jsonPrimitive.content == directory.resolve("native-result.json").toString())
        val original = json.parseToJsonElement(ReleasePrivateFiles.read(directory.resolve("intent.json"), 65536)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        val result = json.parseToJsonElement(ReleasePrivateFiles.read(directory.resolve("result.json"), 1048576)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(original.getValue("binding") == originalBinding && result.getValue("invocation") == original &&
            result.getValue("passed").jsonPrimitive.boolean && result.getValue("finished").jsonPrimitive.boolean &&
            result.getValue("exitCode").jsonPrimitive.int == 0 &&
            result.getValue("observationSha256").jsonPrimitive.content == pin(directory.resolve("native-result.json"), 1048576).sha256 &&
            result.getValue("artifactHashes").jsonObject.getValue("oracle.json").jsonPrimitive.content ==
                pin(directory.resolve("oracle.json"), 1048576).sha256)
    }
    fun prepare(payload: OwnerCasePrepare, rssPhaseClaimSha256: String? = null,
        hubOwnerReadback: HubOwnerReadback? = null): OwnerCasePrepared {
        owned()
        val dir = case(payload.caseDirectory)
        val id = payload.evidenceKey
        require(dir.fileName.toString() == id && id in declared() && active[dir] == null &&
            payload.invocationId.matches(Regex("case-[a-f0-9-]{36}")) &&
            active.values.none { it.invocationId == payload.invocationId } &&
            payload.proposedContext.path == dir.resolve("context.proposed.json").toString())
        val proposed = json.parseToJsonElement(pinned(payload.proposedContext, 4194304)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(proposed.isNotEmpty() && proposed.keys.none { it in setOf("caseClaimSha256", "caseIntentSha256",
            "controlSocket", "capabilityBase64", "qualificationMode", "invocation", "artifactDirectory",
            "sourceOracle", "url", "sourceStoppedSha256", "targetIsolationProofSha256",
            "restoreStartupReceiptFile", "restoreStartupReceiptSha256",
            "managedRestoreStartupReceiptPath", "managedRestoreStartupReceiptSha256", "sourceOracleFile",
            "sourceOracleFileSha256", "effectiveCredentialRevisionHeadSha256") })
        val originalMap = scope.contexts?.let { json.parseToJsonElement(pinned(it, 4194304)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject }
            ?: throw IllegalArgumentException("Original protected context map required")
        require(originalMap.keys == declared())
        val original = originalMap.getValue(id).jsonObject
        require(original.isNotEmpty() && proposed.filterKeys { it !in crossCase && it !in setOf(
            "sourceInvocation", "sourceObservation") } == original)
        originalInstallSource(proposed, id)
        completedPredecessor(proposed, dir)
        val definition = manifest().single { c ->
            "${c.getValue("serviceId").jsonPrimitive.content}--" +
                "${c.getValue("journey").jsonPrimitive.content}--" +
                "${c.getValue("surface").jsonPrimitive.content.lowercase()}--" +
                c.getValue("variant").jsonPrimitive.content.lowercase() == id
        }
        val service = definition.getValue("serviceId").jsonPrimitive.content
        require(if (service == "mastodon-rss-publisher" || service == "rss-jobs" ||
            service.startsWith("rss-pack-")) rssPhaseClaimSha256?.matches(hash) == true
            else rssPhaseClaimSha256 == null) {
            "RSS case-input producer requires owner-held authenticated phase claim"
        }
        val surface = definition.getValue("surface").jsonPrimitive.content
        val variant = definition.getValue("variant").jsonPrimitive.content
        val journey = definition.getValue("journey").jsonPrimitive.content
        val mode = QualificationExecutionPolicy.select(pinned(scope.manifest, 4194304), service, surface, variant, journey)
        require(("ownerCredentialFile" in original) == ("outsiderCredentialFile" in original)) {
            "Partial original account context cannot qualify"
        }
        if (service == "donetick") DonetickTripleActorContext.requireContext(original)
        val actors = if (service in setOf("bookstack", "erpnext", "firefly-iii", "forgejo", "donetick") &&
            "ownerCredentialFile" in original) {
            if (phase() == "INSTALL") RecoveryActorCustody.pinInstall(generation, service, original)
            else {
                val source = GenerationRuntime.BASE.resolve(requireNotNull(bundle.recoverySourceKopia).generation)
                val bytes = ReleasePrivateFiles.read(source.resolve("bundle.json"), 4194304)
                val observed = RecoveryActorCustody.project(source, generation, ReleaseLocks.sha256(bytes), service,
                    requireNotNull(scope.contexts).sha256, original)
                require(restored?.actorProjections?.get(id) == observed) {
                    "RESTORE actor context differs from owner-held stopped-source projection"
                }
                observed
            }
        } else original to emptyList()
        val sealed = QualificationCanonicalTopology.require(bundle, phase() == "RESTORE")
        require((phase() == "RESTORE") == (restored != null) &&
            (restored == null || restored.target.id == scope.generationId &&
                restored.target.bundleSha256 == scope.bundleSha256 && restored.targetPin == sealed))
        val inputs = QualificationPrerequisites.read(scope)
        require(inputs.closure.controllers.getValue("acceptance") == scope.controllerSha256 &&
            sealed.spec.name == "${scope.generationId}-v2")
        // Route authority comes from the selected generation's shared graph, not
        // the signed suite's former shorthand names or a caller-provided PEM.
        if (service in setOf("bookstack", "erpnext", "firefly-iii", "forgejo", "donetick", "planka")) {
            val host = when (service) {
                "bookstack" -> "bookstack.datamancy.net"
                "erpnext" -> "erp.datamancy.net"
                "firefly-iii" -> "firefly.datamancy.net"
                "forgejo" -> "forgejo.datamancy.net"
                "planka" -> "planka.datamancy.net"
                else -> "donetick.datamancy.net"
            }
            val projection = QualificationPrivateTls.selectedManifest(requireNotNull(sealed.spec.fragmentBinding))
            val binding = CanonicalPrivateIngressTrust.requireHost(projection, sealed.spec, service, host)
            require(binding.hostname == host)
            if (service == "bookstack" && surface == "WEB")
                CanonicalPrivateIngressTrust.requireHost(projection, sealed.spec, "keycloak", "auth.datamancy.net")
            if (service == "firefly-iii" && surface == "HEADLESS")
                CanonicalPrivateIngressTrust.requireHost(projection, sealed.spec, service,
                    "firefly-importer.datamancy.net")
        }
        // The signed Mozilla source asset remains in the source closure, but it
        // never supplies the selected private ingress trust used by a client.
        val selectedHost = if (surface == "HEADLESS" && (service == "mastodon-rss-publisher" ||
            service == "rss-jobs" || service.startsWith("rss-pack-"))) "social.datamancy.net"
            else if (surface == "HEADLESS") mapOf(
            "grafana" to "grafana.datamancy.net", "prometheus" to "metrics.datamancy.net",
            "alertmanager" to "alerts.datamancy.net", "mastodon" to "social.datamancy.net",
            "sogo" to "groupware.datamancy.net", "seafile" to "files.datamancy.net",
            "homeassistant" to "home.datamancy.net", "jellyfin" to "media.datamancy.net",
            "onlyoffice" to "office.datamancy.net",
            "jupyterhub" to "notebooks.datamancy.net", "jupyter-notebook" to "notebooks.datamancy.net",
            "ntfy" to "ntfy-native.datamancy.net",
            "qbittorrent" to "torrents.datamancy.net", "searxng" to "search.datamancy.net",
            "bookstack" to "bookstack.datamancy.net", "erpnext" to "erp.datamancy.net",
            "firefly-iii" to "firefly.datamancy.net", "forgejo" to "forgejo.datamancy.net",
            "donetick" to "donetick.datamancy.net", "planka" to "planka.datamancy.net",
            "element" to "chat.datamancy.net", "synapse" to "matrix.datamancy.net",
            "matrix-authentication-service" to "matrix-auth.datamancy.net",
            "livekit" to "matrix-rtc.datamancy.net")[service]
            else definition["url"]?.jsonPrimitive?.content?.let { java.net.URI(it).host }
        val hosts = selectedHost?.takeIf { it in originalOwnership().approvedHosts }?.let { host ->
            setOf(host) + (if (service == "seafile")
                setOf("files.datamancy.net","files-native.datamancy.net") else emptySet()) +
                (if (service == "ntfy" && surface == "WEB")
                setOf("ntfy.datamancy.net","ntfy-native.datamancy.net",
                    "auth.datamancy.net","keycloak-auth.datamancy.net") else emptySet()) +
                (if (service == "onlyoffice") setOf("office.datamancy.net",
                "files.datamancy.net","files-native.datamancy.net") else emptySet()) +
                (if (surface == "ANDROID" && service in setOf(
                    "element", "synapse", "matrix-authentication-service", "livekit"))
                setOf("chat.datamancy.net", "matrix.datamancy.net", "matrix-auth.datamancy.net",
                    "matrix-rtc.datamancy.net", "auth.datamancy.net") else emptySet()) +
                (if (service in setOf("bookstack", "erpnext", "firefly-iii",
                    "forgejo", "donetick") && surface in setOf("HEADLESS", "WEB", "ANDROID"))
                setOf("auth.datamancy.net") else emptySet()) +
                (if (service in setOf("erpnext", "donetick"))
                    setOf("keycloak-auth.datamancy.net") else emptySet()) +
                (if (service == "firefly-iii" && surface == "HEADLESS")
                    setOf("firefly-importer.datamancy.net") else emptySet())
        } ?: emptySet()
        require(hosts.all { it in originalOwnership().approvedHosts }) {
            "Auxiliary SSO/importer host is not in original approved site inventory"
        }
        val trust = if (hosts.isNotEmpty() && mode != QualificationExecutionMode.HOST_NATIVE_WITH_DENIAL_PROBE)
            QualificationPrivateTls.observe(bundle,hosts,scope.bundleSha256) else null
        require(mode == QualificationExecutionMode.HOST_NATIVE_WITH_DENIAL_PROBE || trust != null ||
            service == "mailserver" && surface == "HEADLESS" && mode == QualificationExecutionMode.HOST_NATIVE) {
            "Private original-host trust requires an exact selected graph route or sealed native mail CA"
        }
        val roots = if (service == "mailserver" && surface == "HEADLESS") {
            val file = PrivateDeployment.BASE.resolve(sealed.spec.name).resolve("mail-ca.pem")
            val bytes = ReleasePrivateFiles.read(file,65536)
            require(ReleaseLocks.sha256(bytes) == sealed.inputHashes.getValue("mail-ca.pem"))
            val staged = dir.resolve("native-mail-ca.pem")
            ReleasePrivateFiles.save(staged,bytes)
            ActivationInput(staged.toString(),ReleaseLocks.sha256(bytes))
        } else if (trust == null) QualificationPrerequisites.stageRoots(dir,inputs) else {
            val target = dir.resolve("private-ingress-ca.pem")
            ReleasePrivateFiles.save(target,trust.roots)
            ActivationInput(target.toString(),ReleaseLocks.sha256(trust.roots))
        }
        val primaryLeaf = trust?.leaves?.get(selectedHost)
        val officeFilesLeaf = if (service == "onlyoffice")
            requireNotNull(trust).leaves.getValue("files.datamancy.net") else null
        val nativeFilesLeaf = if (service == "onlyoffice")
            requireNotNull(trust).leaves.getValue("files-native.datamancy.net") else null
        if (officeFilesLeaf != null) require(proposed["sourceFilesLeafSha256"] == null ||
            proposed["sourceFilesLeafSha256"] == JsonPrimitive(officeFilesLeaf))
        if (nativeFilesLeaf != null) require(proposed["nativeFilesLeafSha256"] == null ||
            proposed["nativeFilesLeafSha256"] == JsonPrimitive(nativeFilesLeaf))
        val issuerLeaf = trust?.leaves?.get("auth.datamancy.net")
        val gatewayLeaf = trust?.leaves?.get("keycloak-auth.datamancy.net")
        if (gatewayLeaf != null) require(proposed["sourceGatewayLeafSha256"] == null ||
            proposed["sourceGatewayLeafSha256"] == JsonPrimitive(gatewayLeaf)) {
            "Caller gateway leaf pin differs from current selected auth gateway"
        }
        if (issuerLeaf != null) require(proposed["sourceIdentityLeafSha256"] == null ||
            proposed["sourceIdentityLeafSha256"] == JsonPrimitive(issuerLeaf)) {
            "Caller identity leaf pin differs from current served Keycloak ingress"
        }
        if (primaryLeaf != null) require(proposed["sourceLeafSha256"] == null ||
            proposed["sourceLeafSha256"] == JsonPrimitive(primaryLeaf)) {
            "Caller leaf pin differs from current native served selected ingress"
        }
        require(proposed["bundleSha256"] == null || proposed["bundleSha256"] == JsonPrimitive(scope.bundleSha256))
        val caseCa = if (mode == QualificationExecutionMode.QCLIENT_RUNNER) "/run/secrets/source-ca.pem" else roots.path
        require((proposed["caFile"] == null || proposed["caFile"] == JsonPrimitive(caseCa)) &&
            (proposed["caSha256"] == null || proposed["caSha256"] == JsonPrimitive(roots.sha256))) {
            "Caller CA differs from sealed current issuer or exact native mail CA"
        }
        val nativeContext = if (surface == "HEADLESS" && variant == "NATIVE" && service in setOf(
            "alloy", "loki", "node-exporter", "onlyoffice", "opensearch", "crowdsec", "qbittorrent", "mailserver"))
            QualificationNativeContexts.prepare(scope.generationId, sealed, service) else buildJsonObject { }
        val wikiHosts = if (service == "bookstack" && surface == "WEB") {
            val names = listOf("auth.datamancy.net", "bookstack.datamancy.net")
            val approved = originalOwnership().approvedHosts
            require(names.all { it in approved }) { "BookStack OIDC needs both original approved hosts" }
            val leaves = requireNotNull(trust).leaves
            require(leaves.keys.containsAll(names))
            val values = mapOf("approvedHosts" to JsonArray(names.map(::JsonPrimitive)),
                "sourceIdentityLeafSha256" to JsonPrimitive(leaves.getValue("auth.datamancy.net")),
                "sourceLeafSha256" to JsonPrimitive(leaves.getValue("bookstack.datamancy.net")))
            values.forEach { (key, value) -> require(proposed[key] == null || proposed[key] == value) {
                "Original BookStack certificate context differs from observed revision"
            } }
            values
        } else emptyMap()
        val importer = if (service == "firefly-iii" && surface == "HEADLESS") {
            val host = "firefly-importer.datamancy.net"
            val approved = originalOwnership().approvedHosts
            require(host in approved)
            val leaf = requireNotNull(trust).leaves.getValue(host)
            val values = mapOf("importerOrigin" to JsonPrimitive("https://$host/"),
                "sourceImporterLeafSha256" to JsonPrimitive(leaf))
            values.forEach { (key, value) -> require(proposed[key] == null || proposed[key] == value) {
                "Original importer context differs from observed public revision"
            } }
            values
        } else emptyMap()
        // Authority comes from the sealed r9 member and its exact materialized manifest.
        val graphServices = setOf("element", "synapse", "matrix-authentication-service", "livekit",
            "mailserver", "sogo", "mastodon", "homeassistant", "jellyfin", "onlyoffice", "seafile",
            "mastodon-rss-publisher", "rss-jobs", "ntfy")
        val social = service == "mastodon" || service in setOf("mastodon-rss-publisher", "rss-jobs") ||
            service.startsWith("rss-pack-")
        val graphContext: Map<String, JsonElement> = if (service in graphServices || social) {
            val graphBinding = requireNotNull(sealed.spec.fragmentBinding)
            QualificationPrivateTls.selectedManifest(graphBinding)
            require(graphBinding.phase == phase() && sealed.spec.name == "${scope.generationId}-v2")
            val selectedFile = PrivateDeployment.BASE.resolve("${sealed.spec.name}.json")
            require(pin(selectedFile).sha256 == sealed.manifestSha256 &&
                json.decodeFromString<PrivateDeploymentSpec>(ReleasePrivateFiles.read(selectedFile)
                    .decodeToString(throwOnInvalidSequence = true)) == sealed.spec)
            val current = copyOriginal(dir,selectedFile,"selected-manifest.json",null)
            val sourceGraph: Map<String,JsonElement> = if (phase() == "RESTORE") {
                val sourceReceipt = requireNotNull(bundle.recoverySourceKopia)
                val sourceRoot = GenerationRuntime.BASE.resolve(sourceReceipt.generation)
                val originalBytes = ReleasePrivateFiles.read(sourceRoot.resolve("bundle.json"),4194304)
                require(ReleaseLocks.sha256(originalBytes) == sourceReceipt.bundleSha256)
                val originalBundle = json.decodeFromString<GenerationBundle>(originalBytes.decodeToString())
                require(originalBundle.request.id == sourceReceipt.generation &&
                    sourceReceipt.generation != scope.generationId)
                val sourcePin = QualificationCanonicalTopology.require(originalBundle)
                val prior = PrivateDeployment.BASE.resolve("${sourcePin.spec.name}.json")
                require(pin(prior).sha256 == sourcePin.manifestSha256 &&
                    json.decodeFromString<PrivateDeploymentSpec>(ReleasePrivateFiles.read(prior)
                        .decodeToString(throwOnInvalidSequence = true)) == sourcePin.spec &&
                    requireNotNull(sourcePin.spec.fragmentBinding).phase == "INSTALL" &&
                    sourcePin.spec.fragmentBinding?.resources == graphBinding.resources)
                mapOf("originalSourceManifestFile" to JsonPrimitive(copyOriginal(dir,prior,
                    "original-source-manifest.json",null).path),
                    "sourceBundleSha256" to JsonPrimitive(sourceReceipt.bundleSha256))
            } else emptyMap()
            val values: Map<String,JsonElement> = mapOf(
                "canonicalRecipe" to JsonPrimitive(graphBinding.recipe),
                (if (service == "ntfy") "selectedR10Graph" else "selectedR9Graph") to buildJsonObject {
                    val version = if (service == "ntfy") "r10" else "r9"
                    put("indexSha256",graphBinding.resources.getValue("fragments/v3/canonical/$version/index.yaml"))
                    put("manifestSha256",graphBinding.resources.getValue("fragments/v3/canonical/$version/manifest.yaml"))
                },
                "manifest" to buildJsonObject {
                    put("path",current.path); put("sha256",current.sha256)
                    put("runtimeFingerprint",sealed.runtimeFingerprint)
                }) + sourceGraph
            val groupware: Map<String,JsonElement> = if (service == "sogo") {
                val currentLeaf = CanonicalCaddyServedLeafReadback(generation,bundle,scope.bundleSha256,
                    QualificationPrivateTls.selectedManifest(graphBinding)).verify("groupware.datamancy.net")
                require(primaryLeaf != null && trust?.leaves?.get("groupware.datamancy.net") == primaryLeaf)
                val hostTls = buildJsonObject {
                    put("originalHost","groupware.datamancy.net"); put("port",443)
                    put("leafSha256",primaryLeaf); put("caFile",
                        if (mode == QualificationExecutionMode.QCLIENT_RUNNER) "/run/secrets/source-ca.pem" else roots.path)
                    put("address",NamespaceCaddyTransport.ownedProcessAddress(sealed.spec,
                        sealed.runtimeFingerprint,"caddy","qualification-web"))
                }
                val sourceLeaf: Map<String,JsonElement> = if (phase() == "RESTORE") {
                    val priorRoot = GenerationRuntime.BASE.resolve(requireNotNull(bundle.recoverySourceKopia).generation)
                    val priorBundleBytes = ReleasePrivateFiles.read(priorRoot.resolve("bundle.json"),4194304)
                    val priorBundle = json.decodeFromString<GenerationBundle>(priorBundleBytes.decodeToString())
                    require(ReleaseLocks.sha256(priorBundleBytes) == bundle.recoverySourceKopia?.bundleSha256 &&
                        priorBundle.request.id == bundle.recoverySourceKopia?.generation)
                    val prior = priorRoot.resolve("ingress/trust/leaves/groupware.datamancy.net.json")
                    val bytes = ReleasePrivateFiles.read(prior,8192)
                    val receipt = json.decodeFromString<CaddyServedLeafReadback>(bytes.decodeToString())
                    require(receipt.generation == priorBundle.request.id &&
                        receipt.bundleSha256 == bundle.recoverySourceKopia?.bundleSha256 &&
                        receipt.member == QualificationCanonicalTopology.require(priorBundle).spec.name &&
                        receipt.hostname == "groupware.datamancy.net" && receipt.product == "sogo")
                    mapOf("originalServedLeafReceiptFile" to JsonPrimitive(copyOriginal(dir,prior,
                        "original-served-leaf.json",null).path))
                } else emptyMap()
                val localLeaf = copyOriginal(dir,Path.of(currentLeaf.path),"selected-served-leaf.json",null)
                require(localLeaf.sha256 == currentLeaf.sha256)
                mapOf("hostTls" to hostTls,
                    "selectedServedLeafReceiptFile" to JsonPrimitive(localLeaf.path),
                    "selectedServedLeafReceiptSha256" to JsonPrimitive(currentLeaf.sha256)) + sourceLeaf +
                    (if (phase() == "RESTORE") mapOf("sourceStoppedProofSha256" to
                        JsonPrimitive(requireNotNull(restored).listener.sourceStoppedProofSha256))
                    else emptyMap())
            } else emptyMap()
            val scripts: Map<String,JsonElement> = if (social) {
                val files = listOf("mastodon-bridge-scripts.json", "mastodon-redis-bridge.json")
                val sources = files.map { file ->
                    val source = PrivateDeployment.BASE.resolve(sealed.spec.name).resolve(file)
                    require(pin(source,65536).sha256 == sealed.inputHashes.getValue(file))
                    copyOriginal(dir,source,"selected-$file",null)
                }
                mapOf("selectedSocialScriptsFile" to JsonPrimitive(sources[0].path),
                    "selectedSocialScriptsSha256" to JsonPrimitive(sources[0].sha256),
                    "selectedSocialBridgeConfigFile" to JsonPrimitive(sources[1].path),
                    "selectedSocialBridgeConfigSha256" to JsonPrimitive(sources[1].sha256))
            } else emptyMap()
            val rssTransport: Map<String,JsonElement> = if (social && service != "mastodon" &&
                phase() == "INSTALL") {
                require(selectedHost == "social.datamancy.net" && primaryLeaf != null)
                val issuer = CanonicalCaddyServedLeafReadback(generation, bundle, scope.bundleSha256,
                    QualificationPrivateTls.selectedManifest(requireNotNull(sealed.spec.fragmentBinding)))
                val served = json.decodeFromString<CaddyServedLeafReadback>(ReleasePrivateFiles.read(
                    Path.of(issuer.verify("social.datamancy.net").path), 8192)
                    .decodeToString(throwOnInvalidSequence = true))
                val endpoint = java.net.URI(issuer.verifiedPrivateEndpoint("social.datamancy.net"))
                val address = NamespaceCaddyTransport.ownedProcessAddress(sealed.spec,
                    sealed.runtimeFingerprint, "caddy", "ingress-control")
                val selectedAddress = QualificationRssIngressSource.address(endpoint.toString(), address,
                    served.privateNetwork, served.caSha256, roots.sha256,
                    served.servedLeafDerSha256, primaryLeaf)
                mapOf("mastodonScopedAddress" to JsonPrimitive(selectedAddress))
            } else emptyMap()
            (values + groupware + scripts + rssTransport).forEach { (key,value) -> require(proposed[key] == null || proposed[key] == value) {
                "Proposed r9 graph authority conflicts with sealed member or current issuer"
            } }
            values + groupware + scripts + rssTransport
        } else emptyMap()
        val rssCaseInputs: Map<String,JsonElement> = if (social && phase() == "INSTALL" &&
            service != "mastodon") {
            val address = graphContext.getValue("mastodonScopedAddress").jsonPrimitive.content
            val issued = QualificationRssCaseInputs.issue(dir,bundle,scope.bundleSha256,
                service,surface,variant,phase(),payload.invocationId,requireNotNull(rssPhaseClaimSha256),
                original,roots,requireNotNull(primaryLeaf),address)
            require(issued.keys == setOf("rssPackSourceFile","rssPackSourceSha256",
                "rssPackManifestSha256","rssFeatureLedgerFile","rssFeatureLedgerSha256") &&
                issued.keys.none { it in proposed })
            issued
        } else emptyMap()
        val matrixTls: Map<String,JsonElement> = if (surface in setOf("HEADLESS", "WEB") &&
            service in setOf("element", "synapse", "matrix-authentication-service", "livekit")) {
            val selectedProbe = inputs.suite.runnerHashes.getValue("scripts/MatrixIdentityBrowserProbe.java")
            val values = QualificationMatrixTlsProjection.produce(dir, bundle, sealed,
                scope.bundleSha256, selectedProbe, original.getValue("tools").jsonObject,
                originalOwnership().approvedHosts)
            require(proposed["hostTls"] == null &&
                (proposed["selectedR9MatrixProbeSha256"] == null ||
                    proposed["selectedR9MatrixProbeSha256"] == values.getValue("selectedR9MatrixProbeSha256")))
            val projected = if (mode == QualificationExecutionMode.QCLIENT_RUNNER) {
                val hosts = values.getValue("hostTls").jsonObject
                val caseTls = buildJsonObject { for ((host, item) in hosts) {
                    val proof = item.jsonObject
                    put(host,JsonObject(proof + listOf("leafFile","caFile").associateWith { field ->
                        val path = Path.of(proof.getValue(field).jsonPrimitive.content)
                        require(path.parent == dir.resolve("owner-proofs") &&
                            path.fileName.toString().startsWith("matrix-$host-"))
                        JsonPrimitive("/case/owner-proofs/${path.fileName}")
                    }))
                } }
                values + ("hostTls" to caseTls)
            } else values
            projected + mapOf("executionMode" to JsonPrimitive(if (mode ==
                QualificationExecutionMode.QCLIENT_RUNNER) "QCLIENT_RUNNER" else "HOST_NATIVE"))
        } else emptyMap()
        val matrixOriginalNative: Map<String,JsonElement> = if (service == "element" &&
            surface == "HEADLESS" && variant == "NATIVE" && phase() == "RESTORE") {
            val originalCase = Path.of(proposed.getValue("sourceInvocation").jsonPrimitive.content).parent
            val originalContext = json.parseToJsonElement(ReleasePrivateFiles.read(
                originalCase.resolve("context.json"), 4194304)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            val originalFile = Path.of(originalContext.getValue("originalMatrixOracleFile").jsonPrimitive.content)
            val originalOracle = json.parseToJsonElement(ReleasePrivateFiles.read(originalFile, 1048576)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            val sourceOracle = json.parseToJsonElement(ReleasePrivateFiles.read(
                originalCase.resolve("oracle.json"), 1048576)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(originalFile.parent != dir &&
                originalOracle.getValue("sourceGenerationId") == sourceOracle.getValue("sourceGenerationId") &&
                originalOracle.getValue("sourceRecipeSha256") == sourceOracle.getValue("sourceRecipeSha256") &&
                originalOracle.getValue("eventId") == sourceOracle.getValue("feature").jsonObject.getValue("event") &&
                originalOracle.getValue("matrixUserId") == sourceOracle.getValue("feature").jsonObject.getValue("sender") &&
                originalOracle.getValue("sourceGenerationId").jsonPrimitive.content ==
                    requireNotNull(restored).source.id)
            val copied = copyOriginal(dir, originalFile, "original-matrix-oracle.json", null)
            mapOf("originalMatrixOracleFile" to JsonPrimitive(copied.path),
                "originalMatrixOracleSha256" to JsonPrimitive(copied.sha256))
        } else emptyMap()
        val matrixSource: Map<String,JsonElement> = if (surface == "ANDROID" &&
            service in setOf("element", "synapse", "matrix-authentication-service", "livekit")) {
            require("freshOriginalSessionFile" !in proposed &&
                "freshOriginalSessionReceiptFile" !in proposed) {
                "Only the completed Element native PKCE owner may supply Android session bytes"
            }
            // The typed predecessor is the completed original Element HOST_NATIVE case,
            // not an Android-case or caller-authored "original" oracle.
            val nativeCase = Path.of(proposed.getValue("sourceNativeOracleFile").jsonPrimitive.content).parent
            val nativeContext = json.parseToJsonElement(ReleasePrivateFiles.read(nativeCase.resolve("context.json"), 4194304)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            val nativeIntent = json.parseToJsonElement(ReleasePrivateFiles.read(nativeCase.resolve("intent.json"), 65536)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(nativeIntent.getValue("serviceId").jsonPrimitive.content == "element" &&
                nativeIntent.getValue("surface").jsonPrimitive.content == "HEADLESS" &&
                nativeIntent.getValue("variant").jsonPrimitive.content == "NATIVE" &&
                nativeIntent.getValue("contextSha256").jsonPrimitive.content == pin(nativeCase.resolve("context.json")).sha256)
            val nativeOracle = json.parseToJsonElement(ReleasePrivateFiles.read(nativeCase.resolve("oracle.json"), 1048576)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            val originalFile = Path.of(nativeContext.getValue("originalMatrixOracleFile").jsonPrimitive.content)
            val bytes = ReleasePrivateFiles.read(originalFile, 1048576)
            val source = json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
            val feature = nativeOracle.getValue("feature").jsonObject
            require(originalFile.isAbsolute && originalFile.normalize() == originalFile &&
                originalFile.parent != nativeCase &&
                source.getValue("sourceContainers") == nativeOracle.getValue("sourceContainers") &&
                source.getValue("sourceGenerationId") == nativeOracle.getValue("sourceGenerationId") &&
                source.getValue("sourceRecipeSha256") == nativeOracle.getValue("sourceRecipeSha256") &&
                source.getValue("roomId") == feature.getValue("room") &&
                source.getValue("matrixUserId") == feature.getValue("sender") &&
                source.getValue("eventId") == feature.getValue("event")) {
                "Original Matrix native feature and protected browser-produced source differ"
            }
            val copy = copyOriginal(dir, originalFile, "original-matrix-oracle.json", null)
            require(copy.sha256 == ReleaseLocks.sha256(bytes))
            val observationPath = dir.resolve("owner-proofs/matrix-native-observation.json")
            val issuer = CanonicalCaddyServedLeafReadback(generation,bundle,scope.bundleSha256,
                QualificationPrivateTls.selectedManifest(requireNotNull(sealed.spec.fragmentBinding)))
            val matrixHost = "matrix.datamancy.net"
            val matrixLeaf = json.decodeFromString<CaddyServedLeafReadback>(ReleasePrivateFiles.read(
                Path.of(issuer.verify(matrixHost).path), 8192).decodeToString(throwOnInvalidSequence = true))
            val matrixCa = CanonicalCaddyCaseTlsBundle(generation,bundle,scope.bundleSha256,
                QualificationPrivateTls.selectedManifest(requireNotNull(sealed.spec.fragmentBinding)))
                .verify(setOf(matrixHost))
            require(matrixLeaf.caSha256 == matrixCa.sha256 &&
                ReleasePrivateFiles.read(Path.of(roots.path),65536).decodeToString(
                    throwOnInvalidSequence = true).contains(ReleasePrivateFiles.read(
                    Path.of(matrixCa.path),65536).decodeToString(throwOnInvalidSequence = true).trim()))
            val matrixCaddy = QualificationMatrixActor.selectedProcess(sealed.spec,
                sealed.runtimeFingerprint,"caddy")
            val matrixAddress = QualificationRssIngressSource.address(issuer.verifiedPrivateEndpoint(matrixHost),
                matrixCaddy.getValue("networks").jsonObject.getValue(
                    "p0v3-live-${sealed.spec.name}-ingress-control").jsonPrimitive.content,
                matrixLeaf.privateNetwork,matrixLeaf.caSha256,matrixCa.sha256,
                matrixLeaf.servedLeafDerSha256,matrixLeaf.servedLeafDerSha256)
            val bridge = buildJsonObject {
                put("originalHost",matrixHost); put("port",443); put("address",matrixAddress)
                put("caFile",caseCa); put("leafSha256",matrixLeaf.servedLeafDerSha256)
            }
            val turnPolicy = dir.resolve("owner-proofs/matrix-turn-policy.json").toString()
            require((proposed["nativeMatrixBridge"] == null || proposed["nativeMatrixBridge"] == bridge) &&
                (proposed["qualificationTurnPolicyFile"] == null ||
                    proposed["qualificationTurnPolicyFile"] == JsonPrimitive(turnPolicy)))
            require(proposed["nativeObservationFile"] == null ||
                proposed["nativeObservationFile"] == JsonPrimitive(observationPath.toString()))
            val isolation: Map<String,JsonElement> = if (phase() == "RESTORE") {
                val held = requireNotNull(restored)
                val stopped = QualificationMatrixActor.stoppedSource(buildJsonObject {
                    put("originalMatrixOracleFile", copy.path)
                }, held)
                val receipt = JsonObject(stopped + mapOf("targetGenerationId" to JsonPrimitive(scope.generationId)))
                val path = dir.resolve("owner-proofs/matrix-source-isolation.json")
                ReleasePrivateFiles.save(path, json.encodeToString(receipt).encodeToByteArray())
                mapOf("sourceIsolationReceiptFile" to JsonPrimitive(path.toString()),
                    "sourceStoppedProofSha256" to stopped.getValue("sourceStoppedProofSha256"))
            } else emptyMap()
            val currentNative = active.entries.single { (_, previous) ->
                previous.service == "element" && previous.surface == "HEADLESS" &&
                    previous.variant == "NATIVE" && previous.fenced && previous.evidenceKey in closed }.key
            val sourceNativeCase = if (phase() == "RESTORE")
                Path.of(proposed.getValue("sourceNativeOracleFile").jsonPrimitive.content).parent
                else currentNative
            val session = QualificationMatrixSessionProducer.produce(dir, currentNative, sourceNativeCase,
                JsonObject(proposed + mapOf("originalMatrixOracleFile" to JsonPrimitive(copy.path))),
                source, phase(), scope.generationId, payload.invocationId,
                QualificationCanonicalTopology.require(bundle, phase() == "RESTORE"),
                if (phase() == "RESTORE") requireNotNull(restored).sourcePin else sealed, roots,
                bundle, scope.bundleSha256)
            val qclient = mapOf(
                "originalMatrixOracleFile" to JsonPrimitive("/case/owner-proofs/${Path.of(copy.path).fileName}"),
                "nativeObservationFile" to JsonPrimitive("/case/owner-proofs/${observationPath.fileName}"),
                "qualificationTurnPolicyFile" to JsonPrimitive("/case/owner-proofs/${Path.of(turnPolicy).fileName}"))
            mapOf("originalMatrixOracleFile" to qclient.getValue("originalMatrixOracleFile"),
                "originalMatrixOracleSha256" to JsonPrimitive(copy.sha256),
                "nativeObservationFile" to qclient.getValue("nativeObservationFile"),
                "nativeMatrixBridge" to bridge,
                "qualificationTurnPolicyFile" to qclient.getValue("qualificationTurnPolicyFile"),
                "targetPhase" to JsonPrimitive(phase()),
                "targetGeneration" to JsonPrimitive(scope.generationId)) +
                isolation.mapValues { (field, value) -> if (field == "sourceIsolationReceiptFile")
                    JsonPrimitive("/case/owner-proofs/${Path.of(value.jsonPrimitive.content).fileName}")
                    else value } +
                session.mapValues { (_, value) -> JsonPrimitive(
                    "/case/owner-proofs/${Path.of(value.jsonPrimitive.content).fileName}") }
        } else emptyMap()
        val piOriginal = if (service == "pi" && surface == "HEADLESS" && variant == "NATIVE" &&
            phase() == "INSTALL") {
            require(proposed["sourceBundleSha256"] == null ||
                proposed["sourceBundleSha256"]?.jsonPrimitive?.content == scope.bundleSha256)
            mapOf("sourceBundleSha256" to JsonPrimitive(scope.bundleSha256))
        } else emptyMap()
        val startup = if (phase() == "RESTORE") {
            // originalInstallSource has verified the completed INSTALL intent/result and raw
            // oracle hash. Project protected bytes; never accept a proposed startup proof.
            val oracle = Path.of(proposed.getValue("sourceInvocation").jsonPrimitive.content).parent
                .resolve("oracle.json")
            val originalResult = json.parseToJsonElement(ReleasePrivateFiles.read(oracle.parent.resolve("result.json"), 1048576)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(originalResult.getValue("artifactHashes").jsonObject.getValue("oracle.json")
                .jsonPrimitive.content == pin(oracle, 1048576).sha256)
            val originalPiCase = if (service == "pi" && variant == "NATIVE") oracle.parent else null
            originalPiCase?.let { originalDir ->
                val attempt = originalDir.resolve("pi-original-tool-attempt.result.json")
                require(originalResult.getValue("artifactHashes").jsonObject.getValue(attempt.fileName.toString())
                    .jsonPrimitive.content == pin(attempt,8192).sha256) {
                    "Original Pi tool effect is not in the completed INSTALL result closure"
                }
            }
            val copied = copyOriginal(dir, oracle, "source-oracle.json", null)
            QualificationRestoreStartupProducer.produce(dir, service, variant, copied,
                requireNotNull(restored), bundle, originalPiCase)
        } else emptyMap()
        val forgejoJob: Map<String,JsonElement> = if (service == "forgejo" &&
            surface == "HEADLESS" && variant == "NATIVE") {
            require(listOf("ciJobResultFile","ciJobResultSha256","ciJobIntentSha256",
                "ciJobOriginalInvocationId").none { it in proposed })
            // Original CI startup and the ONE post-start job precede this case,
            // never source sealing. A pending dispatch cannot be retried by C1.
            val sourceRoot = if (phase() == "RESTORE") GenerationRuntime.BASE.resolve(
                requireNotNull(restored).source.id) else generation
            val sourceBundle = if (phase() == "RESTORE") {
                val originalBytes = ReleasePrivateFiles.read(sourceRoot.resolve("bundle.json"),4194304)
                require(ReleaseLocks.sha256(originalBytes) == bundle.recoverySourceKopia?.bundleSha256)
                json.decodeFromString<GenerationBundle>(originalBytes.decodeToString(throwOnInvalidSequence=true))
            } else bundle
            val plan = requireNotNull(sourceBundle.request.forgejoCi)
            require(sourceBundle.request.id == sourceRoot.fileName.toString() &&
                plan.generation == sourceBundle.request.id)
            val ci = sourceRoot.resolve("ci")
            val intentBytes = ReleasePrivateFiles.read(ci.resolve("original-job.intent.json"),8192)
            val intent = json.decodeFromString<ForgejoCiJobIntent>(intentBytes.decodeToString(throwOnInvalidSequence=true))
            val resultBytes = ReleasePrivateFiles.read(ci.resolve("original-job.result.json"),8192)
            val job = json.decodeFromString<ForgejoCiJobResult>(resultBytes.decodeToString(throwOnInvalidSequence=true))
            val run = ReleasePrivateFiles.read(ci.resolve("original-job-run.json"),8192)
            val nativeJob = ReleasePrivateFiles.read(ci.resolve("original-job-job.json"),8192)
            val runResult = json.parseToJsonElement(run.decodeToString(throwOnInvalidSequence=true)).jsonObject
            val jobResult = json.parseToJsonElement(nativeJob.decodeToString(throwOnInvalidSequence=true)).jsonObject
            require(intent.schemaVersion == 1 && job.schemaVersion == 1 && job.terminalSuccess &&
                intent.generation == sourceBundle.request.id && job.generation == intent.generation &&
                intent.bundleSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(
                    sourceRoot.resolve("bundle.json"),4194304)) &&
                job.intentSha256 == ReleaseLocks.sha256(intentBytes) &&
                intent.repository == plan.enrollment.repository && job.repository == intent.repository &&
                intent.trustedCommit == plan.enrollment.trustedCommit && job.trustedCommit == intent.trustedCommit &&
                intent.dispatchRef == "main" && job.workflowPath == intent.workflowPath &&
                job.workflowSha256 == intent.workflowSha256 && job.workflowSha256 == plan.workflow.sha256 &&
                job.runnerId == intent.runnerId && job.runnerId > 0 &&
                job.jobImageId == intent.jobImageId && job.jobImageId == plan.jobArchive.expectedImageId &&
                job.runId > 0 && job.jobId > 0 && job.rootlessJobCid.matches(hash) &&
                listOf(job.guardCreateSha256,job.guardStartSha256,job.guardWaitSha256).all { it.matches(hash) } &&
                job.nativeRunSha256 == ReleaseLocks.sha256(run) &&
                job.nativeJobSha256 == ReleaseLocks.sha256(nativeJob) &&
                runResult.getValue("id").jsonPrimitive.long == job.runId &&
                runResult.getValue("head_sha").jsonPrimitive.content == job.trustedCommit &&
                runResult.getValue("event").jsonPrimitive.content == "workflow_dispatch" &&
                runResult.getValue("status").jsonPrimitive.content == "completed" &&
                runResult.getValue("conclusion").jsonPrimitive.content == "success" &&
                jobResult.getValue("id").jsonPrimitive.long == job.jobId &&
                jobResult.getValue("runner_id").jsonPrimitive.long == job.runnerId &&
                jobResult.getValue("status").jsonPrimitive.content == "completed" &&
                jobResult.getValue("conclusion").jsonPrimitive.content == "success") {
                "Original CI job has no trusted post-start native terminal result"
            }
            if (phase() == "RESTORE") {
                for (file in listOf("original-job.result.json","original-job-run.json","original-job-job.json"))
                    require(ReleasePrivateFiles.read(generation.resolve(
                        "recovered/controller/ci-original/$file"),8192).contentEquals(
                            ReleasePrivateFiles.read(ci.resolve(file),8192)))
                val imported = json.decodeFromString<ForgejoCiOriginalCustody>(ReleasePrivateFiles.read(
                    generation.resolve("recovered/controller/ci-original/cold-custody.json"),65536)
                    .decodeToString(throwOnInvalidSequence=true))
                require(imported.sourceGeneration == job.generation &&
                    imported.sourceBundleSha256 == intent.bundleSha256 &&
                    imported.nativeStartSha256 == intent.nativeStartSha256 &&
                    imported.jobStateSha256["create.result.json"] == job.guardCreateSha256 &&
                    imported.jobStateSha256["start.result.json"] == job.guardStartSha256 &&
                    imported.jobStateSha256["wait.result.json"] == job.guardWaitSha256)
            }
            val sourceCase = if (phase() == "RESTORE") Path.of(proposed.getValue("sourceInvocation")
                .jsonPrimitive.content).parent else dir
            val originalInvocation = if (phase() == "RESTORE") json.parseToJsonElement(
                ReleasePrivateFiles.read(sourceCase.resolve("intent.json"),65536)
                    .decodeToString(throwOnInvalidSequence=true)).jsonObject.getValue("invocationId")
                .jsonPrimitive.content else payload.invocationId
            val saved = copyOriginal(dir,ci.resolve("original-job.result.json"),"forgejo-original-job.json",null)
            mapOf("ciJobResultFile" to JsonPrimitive(saved.path),
                "ciJobResultSha256" to JsonPrimitive(saved.sha256),
                "ciJobIntentSha256" to JsonPrimitive(job.intentSha256),
                "ciJobOriginalInvocationId" to JsonPrimitive(originalInvocation))
        } else emptyMap()
        val officeRestoreBridges: Map<String,JsonElement> = if (service == "onlyoffice" &&
            phase() == "RESTORE" && surface in setOf("HEADLESS","WEB","ANDROID")) {
            val isolation = startup.getValue("targetIsolationProofSha256").jsonPrimitive.content
            val produced = QualificationOfficeCaseInputs.restoreBridges(bundle,scope.bundleSha256,
                roots,isolation,proposed)
            qualificationOfficeBrowserBridgeProjection(produced,isolation,requireNotNull(trust).leaves)
        } else {
            require(service != "onlyoffice" || "bridge" !in proposed && "bridges" !in proposed)
            emptyMap()
        }
        val seafileRestoreBridge: Map<String,JsonElement> = if (service == "seafile" &&
            phase() == "RESTORE" && surface in setOf("WEB","HEADLESS","ANDROID")) {
            require("bridge" !in proposed && "bridges" !in proposed)
            val host = "files.datamancy.net"
            val native = CanonicalCaddyServedLeafReadback(generation,bundle,
                scope.bundleSha256,QualificationPrivateTls.selectedManifest(requireNotNull(sealed.spec.fragmentBinding)))
            val receiptPin = native.verify(host)
            val receipt = json.decodeFromString<CaddyServedLeafReadback>(ReleasePrivateFiles.read(
                Path.of(receiptPin.path),65536).decodeToString(throwOnInvalidSequence=true))
            val endpoint = java.net.URI(native.verifiedPrivateEndpoint(host))
            require(receipt.servedLeafDerSha256 == primaryLeaf &&
                receipt.privateNetwork == "ingress-control" && endpoint.port == 443)
            mapOf("bridge" to buildJsonObject {
                put("originalHost",host); put("port",443)
                put("address",requireNotNull(endpoint.host))
                put("isolationProofSha256",startup.getValue("targetIsolationProofSha256"))
            })
        } else {
            require(service != "seafile" || "bridge" !in proposed && "bridges" !in proposed)
            emptyMap()
        }
        val filesNativeApi: Map<String,JsonElement> = if (service in setOf("seafile","onlyoffice")) {
            val isolation = if (phase() == "RESTORE")
                startup.getValue("targetIsolationProofSha256").jsonPrimitive.content else null
            val projection = QualificationOfficeCaseInputs.nativeApi(dir,bundle,scope.bundleSha256,
                phase(),isolation,proposed)
            val selected = requireNotNull(trust).leaves.getValue("files-native.datamancy.net")
            require(service != "onlyoffice" || selected == nativeFilesLeaf)
            qualificationFilesNativeCaseProjection(projection,dir,scope.generationId,
                scope.bundleSha256,isolation,selected,mode)
        } else emptyMap()
        val ntfySource: Map<String,JsonElement> = if (service == "ntfy") {
            require(listOf("ntfyOriginalOwnerFile","ntfyOriginalOwnerSha256",
                "ntfyCompletedPasswordFile","ntfyCompletedPasswordSha256",
                "ntfyCompletedTotpFile","ntfyCompletedTotpSha256",
                "ntfyOriginalOwnerSubject","ntfyGroupAdmissionFile","ntfyGroupAdmissionSha256",
                "ntfyBrowserSessionFile","ntfyBrowserSessionSha256").none { it in proposed })
            // The GROUP cookie is an effect of this case's genuine browser login.
            // Never require a future session before CASE_START or accept one from
            // proposed context. Owner completion validates it after QClient exit.
            val sourcePin = if (phase() == "RESTORE") requireNotNull(restored).sourcePin else sealed
            val sourceId = if (phase() == "RESTORE") requireNotNull(restored).source.id else scope.generationId
            val ownerInputs: Map<String,JsonElement> = if (surface == "WEB") {
                val owner = QualificationIdentityCaseInputs.stageInheritedOwner(sourcePin,sourceId,dir)
                val originalRoot = if (phase() == "RESTORE") Path.of(proposed.getValue(
                    "sourceInvocation").jsonPrimitive.content).parent.parent else dir.parent
                val keycloak = originalRoot.resolve("keycloak--workflow--web--browser")
                val intent = json.parseToJsonElement(ReleasePrivateFiles.read(keycloak.resolve(
                    "intent.json"),65536).decodeToString(throwOnInvalidSequence=true)).jsonObject
                val result = json.parseToJsonElement(ReleasePrivateFiles.read(keycloak.resolve(
                    "result.json"),1048576).decodeToString(throwOnInvalidSequence=true)).jsonObject
                val oracle = ReleasePrivateFiles.read(keycloak.resolve("oracle.json"),1048576)
                val originalIntent = if (phase() == "RESTORE") json.parseToJsonElement(
                    ReleasePrivateFiles.read(Path.of(proposed.getValue("sourceInvocation")
                        .jsonPrimitive.content),65536).decodeToString(throwOnInvalidSequence=true))
                    .jsonObject else null
                require(keycloak != dir && keycloak.parent == originalRoot &&
                    intent.getValue("serviceId").jsonPrimitive.content == "keycloak" &&
                    intent.getValue("surface").jsonPrimitive.content == "WEB" &&
                    intent.getValue("variant").jsonPrimitive.content == "BROWSER" &&
                    intent.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content == "INSTALL" &&
                    intent.getValue("binding").jsonObject.getValue("generationId").jsonPrimitive.content == sourceId &&
                    (originalIntent == null || intent.getValue("binding") == originalIntent.getValue("binding")) &&
                    result.getValue("invocation") == intent && result.getValue("passed").jsonPrimitive.boolean &&
                    result.getValue("finished").jsonPrimitive.boolean && result.getValue("exitCode").jsonPrimitive.int == 0 &&
                    result.getValue("artifactHashes").jsonObject.getValue("oracle.json").jsonPrimitive.content ==
                        ReleaseLocks.sha256(oracle) &&
                    json.parseToJsonElement(oracle.decodeToString(throwOnInvalidSequence=true))
                        .jsonObject.getValue("subject").jsonPrimitive.content == owner.subject)
                val password = copyOriginal(dir,keycloak.resolve("owner-proofs/identity-operator-password.txt"),
                    "identity-operator-password.txt",null)
                val totp = copyOriginal(dir,keycloak.resolve("owner-proofs/identity-browser-totp.json"),
                    "identity-browser-totp.json",null)
                require(owner.originalCustody.path == dir.resolve(
                    "owner-proofs/identity-original-owner.json").toString() &&
                    !owner.ownerFirstUse && password.sha256.matches(hash) && totp.sha256.matches(hash))
                mapOf("ntfyOriginalOwnerFile" to JsonPrimitive(
                        "/case/owner-proofs/identity-original-owner.json"),
                    "ntfyOriginalOwnerSha256" to JsonPrimitive(owner.originalCustody.sha256),
                    "ntfyCompletedPasswordFile" to JsonPrimitive("/case/owner-proofs/identity-operator-password.txt"),
                    "ntfyCompletedPasswordSha256" to JsonPrimitive(password.sha256),
                    "ntfyCompletedTotpFile" to JsonPrimitive("/case/owner-proofs/identity-browser-totp.json"),
                    "ntfyCompletedTotpSha256" to JsonPrimitive(totp.sha256),
                    "ntfyOriginalOwnerSubject" to JsonPrimitive(owner.subject))
            } else emptyMap()
            val originalGrant = Path.of(
                "/mnt/media/p0-v3/release-bootstrap-anchors/identity/ntfy-fresh/$sourceId.json")
            val grant = ReleasePrivateFiles.read(originalGrant,65536)
            val account = json.parseToJsonElement(grant.decodeToString(throwOnInvalidSequence=true)).jsonObject
            require(account.keys == setOf("schemaVersion","ssoToken","ssoHash","ssoPassword",
                "publisherToken","publisherHash","publisherPassword","ownerToken","ownerHash",
                "ownerPassword") && account.getValue("schemaVersion").jsonPrimitive.int == 1)
            val sourceConfig = PrivateDeployment.BASE.resolve(sourcePin.spec.name).resolve("ntfy-config.yml")
            val currentConfig = PrivateDeployment.BASE.resolve(sealed.spec.name).resolve("ntfy-config.yml")
            val config = ReleasePrivateFiles.read(sourceConfig,65536)
            require(ReleaseLocks.sha256(config) == sourcePin.inputHashes.getValue("ntfy-config.yml") &&
                ReleaseLocks.sha256(ReleasePrivateFiles.read(currentConfig,65536)) ==
                    sealed.inputHashes.getValue("ntfy-config.yml") &&
                ReleasePrivateFiles.read(currentConfig,65536).contentEquals(config) &&
                listOf("sso","publisher","owner").all { actor ->
                    val token = account.getValue("${actor}Token").jsonPrimitive.content
                    val stored = account.getValue("${actor}Hash").jsonPrimitive.content
                    val password = account.getValue("${actor}Password").jsonPrimitive.content
                    token.matches(Regex("tk_[A-Za-z0-9]{32}")) &&
                        password.matches(Regex("[a-f0-9]{64}")) &&
                        config.decodeToString(throwOnInvalidSequence=true).let { selected ->
                            token in selected && stored in selected
                        }
                }) { "Original ntfy scoped grants differ from selected sealed server configuration" }
            val grantCopy = copyOriginal(dir,originalGrant,"ntfy-original-grant.json",null)
            val configCopy = copyOriginal(dir,sourceConfig,"ntfy-sealed-config.yml",null)
            val selectedNtfyHost = if (surface == "WEB") "ntfy.datamancy.net"
                else "ntfy-native.datamancy.net"
            val nativeIssuer = CanonicalCaddyServedLeafReadback(generation,bundle,
                scope.bundleSha256,QualificationPrivateTls.selectedManifest(requireNotNull(sealed.spec.fragmentBinding)))
            val endpoint = java.net.URI(nativeIssuer.verifiedPrivateEndpoint(selectedNtfyHost))
            val publisher = java.net.URI(nativeIssuer.verifiedPrivateEndpoint("ntfy-native.datamancy.net"))
            val issuerEndpoint = if (surface == "WEB") java.net.URI(nativeIssuer.verifiedPrivateEndpoint(
                "auth.datamancy.net")) else null
            val gatewayEndpoint = if (surface == "WEB") java.net.URI(nativeIssuer.verifiedPrivateEndpoint(
                "keycloak-auth.datamancy.net")) else null
            require(endpoint.host == publisher.host && endpoint.port == 443 && publisher.port == 443 &&
                (surface != "WEB" || issuerEndpoint?.port == 443 && gatewayEndpoint?.port == 443 &&
                    issuerEndpoint?.host != null && gatewayEndpoint?.host != null) &&
                requireNotNull(trust).leaves.getValue(selectedNtfyHost) == primaryLeaf)
            val forbidden = setOf("ntfyOriginalGrantFile","ntfyOriginalGrantSha256",
                "ntfySealedConfigFile","ntfySealedConfigSha256","ntfyCaFile","ntfyCaSha256",
                "ntfyLeafSha256","ntfyPublisherLeafSha256","ntfyIssuerLeafSha256",
                "ntfyGatewayLeafSha256","ntfyIssuerAddress","ntfyGatewayAddress",
                "ntfyIssuerCaSha256","ntfyGatewayCaSha256","ntfySelectedHost","ntfyScopedAddress",
                "ntfyPublisherAddress","ntfyPublisherCaSha256","originalGenerationId",
                "originalNtfyGrantSha256","originalNtfyConfigSha256","bridge",
                "ntfyOriginalOwnerFile","ntfyOriginalOwnerSha256",
                "ntfyCompletedPasswordFile","ntfyCompletedPasswordSha256",
                "ntfyCompletedTotpFile","ntfyCompletedTotpSha256",
                "ntfyOriginalOwnerSubject","ntfyGroupAdmissionFile","ntfyGroupAdmissionSha256",
                "ntfyBrowserSessionFile","ntfyBrowserSessionSha256")
            require(proposed.keys.intersect(forbidden).isEmpty())
            val values = mapOf<String,JsonElement>(
                "ntfyOriginalGrantFile" to JsonPrimitive(if (mode == QualificationExecutionMode.QCLIENT_RUNNER)
                    "/case/owner-proofs/ntfy-original-grant.json" else grantCopy.path),
                "ntfyOriginalGrantSha256" to JsonPrimitive(grantCopy.sha256),
                "ntfySealedConfigFile" to JsonPrimitive(if (mode == QualificationExecutionMode.QCLIENT_RUNNER)
                    "/case/owner-proofs/ntfy-sealed-config.yml" else configCopy.path),
                "ntfySealedConfigSha256" to JsonPrimitive(configCopy.sha256),
                "ntfyCaFile" to JsonPrimitive(caseCa),"ntfyCaSha256" to JsonPrimitive(roots.sha256),
                "ntfyLeafSha256" to JsonPrimitive(requireNotNull(primaryLeaf)),
                "ntfyPublisherLeafSha256" to JsonPrimitive(requireNotNull(trust).leaves.getValue("ntfy-native.datamancy.net")),
                "ntfyPublisherCaSha256" to JsonPrimitive(roots.sha256),
                "ntfySelectedHost" to JsonPrimitive(selectedNtfyHost),
                "ntfyScopedAddress" to JsonPrimitive(requireNotNull(endpoint.host)),
                "ntfyPublisherAddress" to JsonPrimitive(requireNotNull(publisher.host)),
                "originalGenerationId" to JsonPrimitive(sourceId),
                "originalNtfyGrantSha256" to JsonPrimitive(grantCopy.sha256),
                "originalNtfyConfigSha256" to JsonPrimitive(configCopy.sha256)) +
                (if (surface == "WEB") mapOf(
                    "ntfyIssuerLeafSha256" to JsonPrimitive(requireNotNull(trust).leaves.getValue(
                        "auth.datamancy.net")),
                    "ntfyGatewayLeafSha256" to JsonPrimitive(requireNotNull(trust).leaves.getValue(
                        "keycloak-auth.datamancy.net")),
                    "ntfyIssuerAddress" to JsonPrimitive(requireNotNull(issuerEndpoint?.host)),
                    "ntfyGatewayAddress" to JsonPrimitive(requireNotNull(gatewayEndpoint?.host)),
                    "ntfyIssuerCaSha256" to JsonPrimitive(roots.sha256),
                    "ntfyGatewayCaSha256" to JsonPrimitive(roots.sha256)) else emptyMap())
            values + ownerInputs + if (phase() == "RESTORE") mapOf("bridge" to buildJsonObject {
                put("originalHost",selectedNtfyHost); put("port",443)
                put("address",requireNotNull(endpoint.host))
                put("isolationProofSha256",startup.getValue("targetIsolationProofSha256"))
            }) else emptyMap()
        } else emptyMap()
        val officeFixture: Map<String,JsonElement> = if (service == "onlyoffice" && surface == "ANDROID") {
            val peer = originalMap.getValue("seafile--workflow--android--${variant.lowercase()}")
                .jsonObject.getValue("android").jsonObject
            val sha = peer.getValue("apkSha256").jsonPrimitive.content
            val path = peer.getValue("apk").jsonPrimitive.content
            require(sha.matches(hash) && sha in inputs.closure.assets.values &&
                path != original.getValue("android").jsonObject.getValue("apk").jsonPrimitive.content)
            val values = mapOf("seafileFixtureApkFile" to JsonPrimitive(path),
                "seafileFixtureApkSha256" to JsonPrimitive(sha),
                "seafileInstalledClientReceiptFile" to JsonPrimitive(dir.resolve(
                    "owner-proofs/seafile-installed-client.json").toString()))
            values.forEach { (key, value) -> require(proposed[key] == null || proposed[key] == value) }
            values
        } else emptyMap()
        val seafileInputs: Map<String,JsonElement> = if (service == "seafile" &&
            surface in setOf("HEADLESS","WEB","ANDROID")) {
            val sourcePin = if (phase() == "RESTORE") requireNotNull(restored).sourcePin else sealed
            val projection = QualificationOfficeCaseInputs.prepareSeafile(dir,phase(),surface,sourcePin,proposed)
            require(projection.context.keys == when (surface) {
                "HEADLESS" -> setOf("credentialsFile")
                "WEB" -> setOf("scopedAccountFile")
                else -> setOf("credentialsFile","nativeCredentialsFile")
            })
            projection.privateFiles.forEach { file -> require(pin(Path.of(file.path),65536) == file) }
            projection.context.mapValues { (_, value) ->
                val path = Path.of(value.jsonPrimitive.content)
                require(path.parent == dir.resolve("owner-proofs"))
                JsonPrimitive("/case/owner-proofs/${path.fileName}")
            }
        } else emptyMap()
        val officeInputs: Map<String,JsonElement> = if (service == "onlyoffice") {
            val sourcePin = if (phase() == "RESTORE") requireNotNull(restored).sourcePin else sealed
            val originalWebCase: Path? = when {
                phase() == "INSTALL" && surface == "WEB" -> null
                phase() == "INSTALL" -> Path.of(proposed.getValue("browserSourceOracleFile")
                    .jsonPrimitive.content).parent
                else -> Path.of(proposed.getValue("sourceInvocation").jsonPrimitive.content)
                    .parent.parent.resolve("onlyoffice--workflow--web--browser")
            }
            val originalWeb = originalWebCase?.let { web ->
                val intent = json.parseToJsonElement(ReleasePrivateFiles.read(web.resolve("intent.json"),65536)
                    .decodeToString(throwOnInvalidSequence = true)).jsonObject
                val result = json.parseToJsonElement(ReleasePrivateFiles.read(web.resolve("result.json"),1048576)
                    .decodeToString(throwOnInvalidSequence = true)).jsonObject
                val oracleBytes = ReleasePrivateFiles.read(web.resolve("oracle.json"),1048576)
                require(web.parent == dir.parent || phase() == "RESTORE" &&
                    web.parent == Path.of(proposed.getValue("sourceInvocation").jsonPrimitive.content).parent.parent &&
                    intent.getValue("binding") == json.parseToJsonElement(ReleasePrivateFiles.read(
                        Path.of(proposed.getValue("sourceInvocation").jsonPrimitive.content),65536)
                        .decodeToString(throwOnInvalidSequence = true)).jsonObject.getValue("binding") &&
                    intent.getValue("binding").jsonObject.getValue("generationId").jsonPrimitive.content ==
                        requireNotNull(bundle.recoverySourceKopia).generation)
                require(intent.getValue("serviceId").jsonPrimitive.content == "onlyoffice" &&
                    intent.getValue("surface").jsonPrimitive.content == "WEB" &&
                    intent.getValue("variant").jsonPrimitive.content == "BROWSER" &&
                    intent.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content == "INSTALL" &&
                    result.getValue("invocation") == intent && result.getValue("passed").jsonPrimitive.boolean &&
                    result.getValue("finished").jsonPrimitive.boolean && result.getValue("exitCode").jsonPrimitive.int == 0 &&
                    result.getValue("artifactHashes").jsonObject.getValue("oracle.json").jsonPrimitive.content ==
                        ReleaseLocks.sha256(oracleBytes))
                json.parseToJsonElement(oracleBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
            }
            val projection = QualificationOfficeCaseInputs.prepare(dir,phase(),surface,sourcePin,
                originalWeb,proposed)
            require(projection.context.keys == when (surface) {
                "WEB" -> setOf("seafileAccountsFile")
                "HEADLESS" -> setOf("seafileCredentialsFile","officeJwtSecretFile")
                else -> setOf("scopedAccountFile","nativeCredentialsFile")
            } && projection.privateFiles.size == projection.context.size &&
                projection.privateFiles.map { it.path }.toSet() ==
                    projection.context.values.map { it.jsonPrimitive.content }.toSet())
            projection.privateFiles.forEach { file -> require(pin(Path.of(file.path),65536) == file) }
            if (mode == QualificationExecutionMode.QCLIENT_RUNNER) projection.context.mapValues { (_, value) ->
                val host = Path.of(value.jsonPrimitive.content)
                require(host.parent == dir.resolve("owner-proofs"))
                JsonPrimitive("/case/owner-proofs/${host.fileName}")
            } else projection.context
        } else emptyMap()
        // Matrix WEB runs inside QClient, which cannot see selected private-deployment
        // directories. Copy only the six original signing/config inputs and original
        // identity state; never mount a whole generation or PKCE refresh custody.
        val plankaOriginal: Map<String,JsonElement> = if (service == "planka" &&
            surface in setOf("HEADLESS","WEB")) {
            val sourcePin = if (phase() == "RESTORE") requireNotNull(restored).sourcePin else sealed
            val originalGeneration = if (phase() == "RESTORE") requireNotNull(restored).source.id
                else scope.generationId
            val sourceReceipt = if (phase() == "RESTORE") Path.of(proposed.getValue(
                "sourceInvocation").jsonPrimitive.content).parent.resolve(
                    "owner-proofs/planka-original-enrollment.json") else null
            QualificationPlankaCaseInputs.issue(dir,sealed,sourcePin,originalGeneration,
                phase(),original,sourceReceipt)
        } else emptyMap()
        val hubInputs: Map<String,JsonElement> = if (service in setOf("jupyterhub","jupyter-notebook") &&
            surface in setOf("WEB","HEADLESS")) {
            val forbidden = setOf("hubAccountFile","hubAccountSha256",
                "aliceHomeReadOnlyPath","bobHomeReadOnlyPath","hubDatabaseReadOnlyFile","hubDatabaseSha256",
                "hubOwnerVolumeCustodyFile","hubOwnerVolumeCustodySha256","hubAliceEpisodeFile",
                "hubAliceEpisodeSha256","hubBobEpisodeFile","hubBobEpisodeSha256")
            require(proposed.keys.intersect(forbidden).isEmpty())
            val proofs = dir.resolve("owner-proofs")
            if (!Files.exists(proofs,java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                Files.createDirectory(proofs,PosixFilePermissions.asFileAttribute(
                    PosixFilePermissions.fromString("rwx------")))
                ReleasePrivateFiles.sync(dir)
            }
            val owner = requireNotNull(hubOwnerReadback) { "Core selected Hub volume/episode readback absent" }
            QualificationHubCaseInputs.prepare(dir,bundle,sealed,phase(),
                if (phase() == "RESTORE") requireNotNull(restored).sourcePin else null,owner).context.also {
                require(listOf("managedHub","origin","endpoint").all { field ->
                    proposed[field] == null || proposed[field] == it.getValue(field)
                })
            }
        } else {
            require(hubOwnerReadback == null)
            emptyMap()
        }
        val identityOwner: Map<String,JsonElement> = if (service in setOf("keycloak",
            "identity-onboarding") && surface == "WEB" && variant == "BROWSER") {
            require(setOf("originalOnboardingCustodyFile", "originalOnboardingCustodySha256",
                "originalSubjectFirstUse", "newPasswordFile", "originalTotpFile", "custodyDirectory")
                .none { it in proposed }) {
                "First-use owner custody must come from the selected sealed issuer, not case context"
            }
            val sourcePin = if (phase() == "RESTORE") requireNotNull(restored).sourcePin else sealed
            val sourceId = if (phase() == "RESTORE") requireNotNull(restored).source.id else scope.generationId
            val proofs = dir.resolve("owner-proofs")
            if (!Files.exists(proofs, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                Files.createDirectory(proofs, PosixFilePermissions.asFileAttribute(
                    PosixFilePermissions.fromString("rwx------")))
                ReleasePrivateFiles.sync(dir)
            }
            ReleasePrivateFiles.directory(proofs)
            val firstUse = service == "keycloak" && phase() == "INSTALL"
            val owner = if (firstUse) QualificationIdentityCaseInputs.stageOriginalOwner(sourcePin,sourceId,dir)
                else QualificationIdentityCaseInputs.stageInheritedOwner(sourcePin,sourceId,dir)
            require(owner.originalCustody.path == proofs.resolve("identity-original-owner.json").toString() &&
                owner.subject.isNotBlank() && owner.originalCustody.sha256.matches(hash) &&
                owner.ownerFirstUse == firstUse)
            val credentials = if (firstUse) emptyMap() else {
                // The completed ORIGINAL owner, not a future test subject, is the
                // only browser identity after the one-use required actions.
                val originalKeycloak = if (phase() == "RESTORE") Path.of(
                    proposed.getValue("sourceInvocation").jsonPrimitive.content).parent.parent.resolve(
                        "keycloak--workflow--web--browser") else Path.of(
                    proposed.getValue("browserSourceOracleFile").jsonPrimitive.content).parent
                require(originalKeycloak.fileName.toString() == "keycloak--workflow--web--browser" &&
                    (if (phase() == "RESTORE") originalKeycloak.parent == Path.of(
                        proposed.getValue("sourceInvocation").jsonPrimitive.content).parent.parent
                    else originalKeycloak.parent == dir.parent))
                val intent = json.parseToJsonElement(ReleasePrivateFiles.read(
                    originalKeycloak.resolve("intent.json"),65536)
                    .decodeToString(throwOnInvalidSequence=true)).jsonObject
                val result = json.parseToJsonElement(ReleasePrivateFiles.read(
                    originalKeycloak.resolve("result.json"),1048576)
                    .decodeToString(throwOnInvalidSequence=true)).jsonObject
                val oracle = ReleasePrivateFiles.read(originalKeycloak.resolve("oracle.json"),1048576)
                require(intent.getValue("serviceId").jsonPrimitive.content == "keycloak" &&
                    intent.getValue("surface").jsonPrimitive.content == "WEB" &&
                    intent.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content == "INSTALL" &&
                    intent.getValue("binding").jsonObject.getValue("generationId").jsonPrimitive.content == sourceId &&
                    result.getValue("invocation") == intent && result.getValue("passed").jsonPrimitive.boolean &&
                    result.getValue("finished").jsonPrimitive.boolean && result.getValue("exitCode").jsonPrimitive.int == 0 &&
                    result.getValue("artifactHashes").jsonObject.getValue("oracle.json").jsonPrimitive.content ==
                        ReleaseLocks.sha256(oracle) &&
                    json.parseToJsonElement(oracle.decodeToString(throwOnInvalidSequence=true))
                        .jsonObject.getValue("subject").jsonPrimitive.content == owner.subject)
                val previous = originalKeycloak.resolve("owner-proofs")
                for (file in listOf("identity-operator-password.txt","identity-browser-totp.json"))
                    ReleasePrivateFiles.save(proofs.resolve(file),ReleasePrivateFiles.read(previous.resolve(file),8192))
                mapOf("newPasswordFile" to JsonPrimitive("/case/owner-proofs/identity-operator-password.txt"),
                    "originalTotpFile" to JsonPrimitive("/case/owner-proofs/identity-browser-totp.json"))
            }
            mapOf("originalOnboardingCustodyFile" to JsonPrimitive(
                    "/case/owner-proofs/identity-original-owner.json"),
                "originalOnboardingCustodySha256" to JsonPrimitive(owner.originalCustody.sha256),
                "originalSubjectFirstUse" to JsonPrimitive(firstUse)) +
                (if (firstUse) mapOf("newPasswordFile" to JsonPrimitive(
                    "/case/owner-proofs/identity-operator-password.txt"),
                    "custodyDirectory" to JsonPrimitive("/case/owner-proofs")) else credentials)
        } else emptyMap()
        val identityNative: Map<String,JsonElement> = if (service in setOf("keycloak","identity-onboarding") &&
            surface == "HEADLESS" && variant == "NATIVE") {
            require(setOf("retirementCustodyDirectory","sourceRetirementClientCustodyFile",
                "keycloakNativeOracleFile","originalOwnerSubjectUuid").none { it in proposed })
            val proofs = dir.resolve("owner-proofs")
            if (!Files.exists(proofs,java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                Files.createDirectory(proofs,PosixFilePermissions.asFileAttribute(
                    PosixFilePermissions.fromString("rwx------")))
                ReleasePrivateFiles.sync(dir)
            }
            ReleasePrivateFiles.directory(proofs)
            val sourcePin = if (phase() == "RESTORE") requireNotNull(restored).sourcePin else sealed
            val sourceId = if (phase() == "RESTORE") requireNotNull(restored).source.id else scope.generationId
            val selected = QualificationIdentityCaseInputs.stageInheritedOwner(sourcePin,sourceId,dir)
            val base = mapOf("originalOwnerSubjectUuid" to JsonPrimitive(selected.subject),
                "retirementCustodyDirectory" to JsonPrimitive(proofs.toString()))
            if (phase() == "INSTALL" && service == "keycloak") base else {
                val originalRoot = if (phase() == "RESTORE") Path.of(
                    proposed.getValue("sourceInvocation").jsonPrimitive.content).parent.parent else dir.parent
                val keycloak = originalRoot.resolve("keycloak--workflow--headless--native")
                require(keycloak != dir && keycloak.fileName.toString() ==
                    "keycloak--workflow--headless--native")
                val intent = json.parseToJsonElement(ReleasePrivateFiles.read(keycloak.resolve("intent.json"),65536)
                    .decodeToString(throwOnInvalidSequence=true)).jsonObject
                val result = json.parseToJsonElement(ReleasePrivateFiles.read(keycloak.resolve("result.json"),1048576)
                    .decodeToString(throwOnInvalidSequence=true)).jsonObject
                val oracle = ReleasePrivateFiles.read(keycloak.resolve("oracle.json"),1048576)
                val oracleSha = ReleaseLocks.sha256(oracle)
                val parsed = json.parseToJsonElement(oracle.decodeToString(throwOnInvalidSequence=true)).jsonObject
                require(intent.getValue("serviceId").jsonPrimitive.content == "keycloak" &&
                    intent.getValue("surface").jsonPrimitive.content == "HEADLESS" &&
                    intent.getValue("variant").jsonPrimitive.content == "NATIVE" &&
                    intent.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content == "INSTALL" &&
                    intent.getValue("binding").jsonObject.getValue("generationId").jsonPrimitive.content == sourceId &&
                    result.getValue("invocation") == intent && result.getValue("passed").jsonPrimitive.boolean &&
                    result.getValue("finished").jsonPrimitive.boolean && result.getValue("exitCode").jsonPrimitive.int == 0 &&
                    result.getValue("artifactHashes").jsonObject.getValue("oracle.json").jsonPrimitive.content == oracleSha &&
                    parsed.getValue("subject").jsonPrimitive.content == selected.subject &&
                    parsed.getValue("retirementClientName").jsonPrimitive.content ==
                        QualificationIdentityCaseInputs.retirementClientName(sourceId)) {
                    "Original retired client lacks the completed Keycloak native result"
                }
                if (service == "identity-onboarding") {
                    val current = dir.parent.resolve("keycloak--workflow--headless--native")
                    val currentIntent = json.parseToJsonElement(ReleasePrivateFiles.read(
                        current.resolve("intent.json"),65536)
                        .decodeToString(throwOnInvalidSequence=true)).jsonObject
                    val now = json.parseToJsonElement(ReleasePrivateFiles.read(current.resolve("result.json"),1048576)
                        .decodeToString(throwOnInvalidSequence=true)).jsonObject
                    require(currentIntent.getValue("serviceId").jsonPrimitive.content == "keycloak" &&
                        currentIntent.getValue("binding").jsonObject.getValue("phase").jsonPrimitive.content == phase() &&
                        currentIntent.getValue("binding").jsonObject.getValue("generationId").jsonPrimitive.content ==
                            scope.generationId && now.getValue("invocation") == currentIntent &&
                        now.getValue("passed").jsonPrimitive.boolean &&
                        now.getValue("finished").jsonPrimitive.boolean &&
                        now.getValue("exitCode").jsonPrimitive.int == 0)
                }
                val originalCustody = keycloak.resolve("owner-proofs/identity-retirement-client.json")
                val custody = ReleasePrivateFiles.read(originalCustody,8192)
                require(ReleaseLocks.sha256(custody) ==
                    parsed.getValue("retirementClientCustodySha256").jsonPrimitive.content)
                val copied = proofs.resolve("identity-retirement-client.json")
                ReleasePrivateFiles.save(copied,custody)
                base + mapOf("sourceRetirementClientCustodyFile" to JsonPrimitive(copied.toString())) +
                    (if (service == "identity-onboarding" && phase() == "INSTALL")
                        mapOf("keycloakNativeOracleFile" to JsonPrimitive(keycloak.resolve("oracle.json").toString()))
                    else emptyMap())
            }
        } else emptyMap()
        val sogoClientUsers: Map<String,JsonElement> = if (service == "sogo" &&
            surface in setOf("HEADLESS","WEB")) {
            val originalPin = if (phase() == "RESTORE") requireNotNull(restored).sourcePin else sealed
            val users = PrivateDeployment.BASE.resolve(originalPin.spec.name).resolve("mail-users.json")
            val bytes = ReleasePrivateFiles.read(users,65536)
            require(ReleaseLocks.sha256(bytes) == originalPin.inputHashes.getValue("mail-users.json") &&
                ReleaseLocks.sha256(bytes) == sealed.inputHashes.getValue("mail-users.json") &&
                Path.of(original.getValue("sogoUsersFile").jsonPrimitive.content) == users)
            val saved = dir.resolve("owner-proofs/sogo-users.json")
            ReleasePrivateFiles.save(saved,bytes)
            mapOf("sogoUsersFile" to JsonPrimitive("/case/owner-proofs/sogo-users.json"))
        } else emptyMap()
        val matrixClientFiles: Map<String,JsonElement> = if (surface == "WEB" &&
            service in setOf("element","synapse","matrix-authentication-service","livekit")) {
            val proofs = dir.resolve("owner-proofs")
            ReleasePrivateFiles.directory(proofs)
            val selectedInputs = listOf("synapse-homeserver.yaml","mas.yaml","element.json",
                "livekit.yaml","rtc-registration.yaml","mas-signing.pem")
            val currentSource = PrivateDeployment.BASE.resolve(sealed.spec.name)
            require(Path.of(original.getValue("inputsDirectory").jsonPrimitive.content) == currentSource)
            fun stageInputs(root: Path, name: String, pin: GenerationPin): String {
                val target = proofs.resolve(name)
                Files.createDirectory(target, PosixFilePermissions.asFileAttribute(
                    PosixFilePermissions.fromString("rwx------")))
                ReleasePrivateFiles.sync(proofs)
                for (file in selectedInputs) {
                    val bytes = ReleasePrivateFiles.read(root.resolve(file),1048576)
                    require(ReleaseLocks.sha256(bytes) == pin.inputHashes.getValue(file))
                    ReleasePrivateFiles.save(target.resolve(file),bytes)
                }
                if (name == "matrix-selected-inputs") {
                    val jobs = root.resolve("runtime.jobs")
                    if (Files.exists(jobs, NOFOLLOW_LINKS)) ReleasePrivateFiles.save(
                        target.resolve("runtime.jobs"),ReleasePrivateFiles.read(jobs,65536))
                    require(!Files.exists(root.resolve("runtime.jobs.tmp"), NOFOLLOW_LINKS))
                }
                return "/case/owner-proofs/$name"
            }
            val projected = mutableMapOf<String,JsonElement>(
                "inputsDirectory" to JsonPrimitive(stageInputs(currentSource,"matrix-selected-inputs",sealed)))
            if (phase() == "RESTORE") {
                val sourcePin = requireNotNull(restored).sourcePin
                val originalRoot = PrivateDeployment.BASE.resolve(sourcePin.spec.name)
                require(Path.of(original.getValue("originalSourceInputsDirectory").jsonPrimitive.content) == originalRoot)
                projected["originalSourceInputsDirectory"] = JsonPrimitive(
                    stageInputs(originalRoot,"matrix-original-inputs",sourcePin))
            }
            val identity = Path.of(original.getValue("originalIdentityStateFile").jsonPrimitive.content)
            val sourceId = if (phase() == "RESTORE") requireNotNull(restored).source.id else scope.generationId
            require(identity.isAbsolute && identity.normalize() == identity &&
                (identity.startsWith(GenerationRuntime.BASE.resolve(sourceId)) ||
                    identity.startsWith(PrivateDeployment.BASE.resolve("$sourceId-v2"))))
            val state = ReleasePrivateFiles.read(identity,1048576)
            val saved = proofs.resolve("matrix-original-identity-state.json")
            ReleasePrivateFiles.save(saved,state)
            projected["originalIdentityStateFile"] = JsonPrimitive(
                "/case/owner-proofs/matrix-original-identity-state.json")
            val custody = proofs.resolve("matrix-browser-custody")
            Files.createDirectory(custody,PosixFilePermissions.asFileAttribute(
                PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(proofs)
            projected["credentialCustodyDirectory"] = JsonPrimitive("/case/owner-proofs/matrix-browser-custody")
            projected
        } else emptyMap()
        val alertConfig: Map<String,JsonElement> = if (service == "alertmanager") {
            val value = QualificationObservabilityActor.durableAlertmanagerReceiver(sealed)
            require(proposed["receivers"] == null || proposed["receivers"] == value)
            mapOf("receivers" to value)
        } else emptyMap()
        val postStartClient = mode == QualificationExecutionMode.QCLIENT_RUNNER &&
            (service in setOf("element","synapse","matrix-authentication-service","livekit") &&
                surface == "WEB" || service == "sogo" && surface in setOf("HEADLESS","WEB"))
        val postStartPaths: Map<String,JsonElement> = if (postStartClient) mapOf(
            "selectedNativeObservationFile" to JsonPrimitive("/case/selected-native-observation.json"),
            "qualificationClientIntentFile" to JsonPrimitive("/case/qualification-client-intent.json"),
            "qualificationClientNativeFile" to JsonPrimitive("/case/qualification-client-native.json"),
            "qualificationClientPolicyFile" to JsonPrimitive("/case/qualification-client-policy.json")) +
            (if (phase() == "RESTORE") mapOf("sourceStoppedProofSha256" to
                JsonPrimitive(requireNotNull(restored).listener.sourceStoppedProofSha256)) else emptyMap())
            else emptyMap()
        require(postStartPaths.keys.none { it in proposed })
        val graphClientPaths: Map<String,JsonElement> = if (postStartClient) {
            val manifest = graphContext.getValue("manifest").jsonObject
            val currentPath = Path.of(manifest.getValue("path").jsonPrimitive.content)
            require(currentPath == dir.resolve("selected-manifest.json"))
            val values = mutableMapOf<String,JsonElement>("manifest" to JsonObject(manifest +
                ("path" to JsonPrimitive("/case/selected-manifest.json"))))
            for (field in listOf("originalSourceManifestFile", "selectedServedLeafReceiptFile",
                "originalServedLeafReceiptFile")) if (field in graphContext) {
                val path = Path.of(graphContext.getValue(field).jsonPrimitive.content)
                require(path.parent == dir)
                values[field] = JsonPrimitive("/case/${path.fileName}")
            }
            values
        } else emptyMap()
        val prepared = JsonObject(QualificationNativeContexts.merge(proposed, nativeContext) + graphContext + graphClientPaths + postStartPaths + rssCaseInputs + matrixTls + matrixOriginalNative + matrixSource + piOriginal + startup + forgejoJob + officeRestoreBridges + seafileRestoreBridge + filesNativeApi + ntfySource + officeFixture + officeInputs + seafileInputs + plankaOriginal + hubInputs + identityOwner + identityNative + sogoClientUsers + matrixClientFiles + alertConfig +
            actors.first.filterKeys { it in setOf("ownerCredentialFile", "outsiderCredentialFile",
                "bookstackApiGrantFile", "outsiderBookstackApiGrantFile") ||
                service == "donetick" && it in DonetickTripleActorContext.credentialFields } + wikiHosts + importer +
            (if (primaryLeaf != null) mapOf("sourceLeafSha256" to JsonPrimitive(primaryLeaf)) else emptyMap()) +
            (if (officeFilesLeaf != null) mapOf("sourceFilesLeafSha256" to JsonPrimitive(officeFilesLeaf)) else emptyMap()) +
            (if (nativeFilesLeaf != null) mapOf("nativeFilesLeafSha256" to JsonPrimitive(nativeFilesLeaf),
                "filesNativeOrigin" to JsonPrimitive("https://files-native.datamancy.net/")) else emptyMap()) +
            (if (issuerLeaf != null) mapOf("sourceIdentityLeafSha256" to JsonPrimitive(issuerLeaf)) else emptyMap()) +
            (if (gatewayLeaf != null) mapOf("sourceGatewayLeafSha256" to JsonPrimitive(gatewayLeaf)) else emptyMap()) + mapOf(
            "bundleSha256" to JsonPrimitive(scope.bundleSha256),
            "caFile" to JsonPrimitive(caseCa), "caSha256" to JsonPrimitive(roots.sha256)))
        require(json.encodeToString(prepared).encodeToByteArray().size < 62000) {
            "Prepared context exceeds authenticated C1 response; no implicit pin escape"
        }
        active[dir] = Active(payload.invocationId, id, mode, service, surface, variant, journey,
            original, prepared, roots, actors.second)
        return OwnerCasePrepared(payload.invocationId, mode.name, prepared)
    }
    private fun clientRequest(dir: Path, state: Active, intent: JsonObject, intentSha: String): QualificationClientRequest {
        val sealed = QualificationCanonicalTopology.require(bundle, phase() == "RESTORE")
        val spec = sealed.spec
        val approved = originalOwnership().approvedHosts
        val definition = manifest().single { it.getValue("serviceId").jsonPrimitive.content == state.service &&
            it.getValue("surface").jsonPrimitive.content == state.surface &&
            it.getValue("variant").jsonPrimitive.content == state.variant &&
            it.getValue("journey").jsonPrimitive.content == state.journey }
        val host = if (state.surface == "HEADLESS") mapOf(
            "grafana" to "grafana.datamancy.net", "prometheus" to "metrics.datamancy.net",
            "alertmanager" to "alerts.datamancy.net", "mastodon" to "social.datamancy.net",
            "sogo" to "groupware.datamancy.net",
            "seafile" to "files.datamancy.net", "homeassistant" to "home.datamancy.net",
            "jellyfin" to "media.datamancy.net", "qbittorrent" to "torrents.datamancy.net",
            "searxng" to "search.datamancy.net", "bookstack" to "bookstack.datamancy.net",
            "erpnext" to "erp.datamancy.net", "firefly-iii" to "firefly.datamancy.net",
            "forgejo" to "forgejo.datamancy.net", "donetick" to "donetick.datamancy.net")[state.service]
            ?: approved.sorted().first()
            else java.net.URI(definition.getValue("url").jsonPrimitive.content).host
        require(host in approved)
        val revisions = emptyMap<String, ActivationInput>()
        val leaf = if (state.mode == QualificationExecutionMode.HOST_NATIVE_WITH_DENIAL_PROBE)
            "0".repeat(64) else state.context.getValue("sourceLeafSha256").jsonPrimitive.content.also {
            require(it.matches(hash)) { "Current selected ingress leaf missing from sealed context" }
        }
        val inputs = QualificationPrerequisites.read(scope)
        val adapter = definition.getValue("adapter").jsonPrimitive.content
        require(adapter.matches(Regex("runners/[a-z0-9_.-]{1,95}")))
        val adapterSha = inputs.suite.runnerHashes.getValue(adapter)
        require(inputs.suite.runnerHashes.getValue(definition.getValue("runner").jsonPrimitive.content) ==
            intent.getValue("runnerSha256").jsonPrimitive.content)
        val source = if (phase() == "RESTORE") {
            val path = Path.of(state.context.getValue("sourceObservation").jsonPrimitive.content)
            pin(path, 4194304).sha256
        } else null
        val predecessors = if (phase() == "RESTORE") {
            val observation = Path.of(state.context.getValue("sourceObservation").jsonPrimitive.content)
            val old = observation.parent
            val originalIntent = old.resolve("intent.json")
            require(Path.of(state.context.getValue("sourceInvocation").jsonPrimitive.content) == originalIntent)
            val result = json.parseToJsonElement(ReleasePrivateFiles.read(old.resolve("result.json"), 1048576)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(result.getValue("passed").jsonPrimitive.boolean && result.getValue("finished").jsonPrimitive.boolean &&
                result.getValue("observationSha256").jsonPrimitive.content == source)
            val entries = mutableListOf(pin(originalIntent, 65536), pin(observation, 4194304))
            // Alertmanager RESTORE carries completed original INSTALL delivery /
            // resolution assertions. Mount only its exact protected result, never
            // a source directory or a fabricated target transient alert.
            if (state.service == "alertmanager" && state.surface == "HEADLESS")
                entries += pin(old.resolve("result.json"), 1048576)
            for ((relative, digest) in result.getValue("artifactHashes").jsonObject) {
                val item = Path.of(relative)
                require(!item.isAbsolute && item.normalize() == item && relative.isNotEmpty() &&
                    item.fileName.toString() !in setOf("intent.json", "context.json", "result.json", "native-result.json"))
                val path = old.resolve(item).normalize()
                require(path.startsWith(old) && path != old)
                val original = pin(path, 64 * 1024 * 1024)
                require(original.sha256 == digest.jsonPrimitive.content)
                entries += original
            }
            require(entries.size in 3..67 && entries.map { it.path }.toSet().size == entries.size)
            entries
        } else emptyList()
        // This typed edge is the SAME C1-verified predecessor used by the executor.
        // Only raw named files are added; never mount a whole source-case directory.
        val edge = QualificationExecutionPolicy.predecessor(state.service,state.surface,state.variant)
        val sourceFields = if (phase() == "INSTALL") edge?.fields.orEmpty() else edge?.restoreOriginalFields.orEmpty()
        val additional = sourceFields.filter { it.endsWith("OracleFile") || it.endsWith("ObservationFile") }
            .map { field ->
                val raw = pin(Path.of(state.context.getValue(field).jsonPrimitive.content),1048576)
                val shaField = field.removeSuffix("File") + "Sha256"
                if (shaField in sourceFields) require(raw.sha256 == state.context.getValue(shaField).jsonPrimitive.content)
                raw
            }.distinctBy { it.path }
        val startup = if (phase() == "RESTORE") listOf("sourceOracleFile", "restoreStartupReceiptFile")
            .map { key -> pin(Path.of(state.context.getValue(key).jsonPrimitive.content), 1048576).also {
                require(it.sha256 == state.context.getValue(if (key == "sourceOracleFile")
                    "sourceOracleFileSha256" else "restoreStartupReceiptSha256").jsonPrimitive.content)
            } } else emptyList()
        val predecessorsPinned = (predecessors + additional + startup).distinctBy { it.path }
        require(predecessorsPinned.size == (predecessors + additional + startup).map { it.path }.toSet().size)
        val image = inputs.inventory.images.single()
        val claim = if (state.surface == "HEADLESS" && state.service in setOf("alloy", "loki", "qbittorrent"))
            pin(generation.resolve("native-qualification-claims/${state.invocationId}.json"), 8192).sha256 else null
        val apk = if (state.surface == "ANDROID") {
            val original = state.originalContext.getValue("android").jsonObject
            val path = original.getValue("apk").jsonPrimitive.content
            val sha = original.getValue("apkSha256").jsonPrimitive.content
            require(sha.matches(hash) && sha in inputs.closure.assets.values)
            ActivationInput(path, sha)
        } else null
        // Only the signed QClient inventory and separately reviewed candidate signer
        // authorize the exact image-contained producer closure; never a case-context pin.
        val seafilePins = if (state.service == "seafile" && state.surface == "HEADLESS") {
            val pins = requireNotNull(inputs.seafileToolPins) {
                "Seafile source image needs its signed producer/tool inventory"
            }
            require(pins.producerPublicKeySha256 == inputs.reviewedSeafileProducerKeySha256)
            pins
        } else null
        val (suite, suiteClosure) = QualificationClientSuites.stage(scope, state.invocationId, inputs.suite, definition)
        val secondaryApk: ActivationInput? = if (state.service == "onlyoffice" && state.surface == "ANDROID") {
            // The second app is selected from the SAME candidate's sealed Seafile Android
            // context and catalog, not an Office-case path or arbitrary install request.
            val contexts = json.parseToJsonElement(pinned(requireNotNull(scope.contexts), 4194304)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            val peer = contexts.getValue("seafile--workflow--android--${state.variant.lowercase()}")
                .jsonObject.getValue("android").jsonObject
            val catalog = json.parseToJsonElement(ReleasePrivateFiles.read(suite.resolve("cases/android-apps.json"), 1048576)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            val seafile = catalog.getValue("apps").jsonArray.map { it.jsonObject }.single { app ->
                "seafile" in app.getValue("serviceIds").jsonArray.map { it.jsonPrimitive.content }
            }
            val pin = ActivationInput(peer.getValue("apk").jsonPrimitive.content,
                peer.getValue("apkSha256").jsonPrimitive.content)
            require(seafile.getValue("packageName").jsonPrimitive.content == "com.seafile.seadroid2" &&
                pin.sha256 == seafile.getValue("sha256").jsonPrimitive.content &&
                pin.sha256 in inputs.closure.assets.values && pin.path != apk?.path && pin.sha256 != apk?.sha256)
            pin
        } else null
        val seafilePrivate = if (state.service == "seafile" &&
            state.surface in setOf("HEADLESS","WEB","ANDROID")) {
            val fields = when (state.surface) {
                "HEADLESS" -> listOf("credentialsFile")
                "WEB" -> listOf("scopedAccountFile")
                else -> listOf("credentialsFile","nativeCredentialsFile")
            }
            fields.map { field -> pin(dir.resolve("owner-proofs/seafile-$field.json"),65536) }
        } else emptyList()
        val filesNativeCa = if (state.service in setOf("seafile","onlyoffice"))
            pin(dir.resolve("owner-proofs/files-native-api-ca.pem"),65536) else null
        val ntfyPrivate = if (state.service == "ntfy") {
            val fields = listOf("ntfyOriginalGrant","ntfySealedConfig") +
                if (state.surface == "WEB") listOf("ntfyOriginalOwner",
                    "ntfyCompletedPassword","ntfyCompletedTotp") else emptyList()
            fields.map { field ->
                val filename = when (field) {
                    "ntfyOriginalGrant" -> "ntfy-original-grant.json"
                    "ntfySealedConfig" -> "ntfy-sealed-config.yml"
                    "ntfyOriginalOwner" -> "identity-original-owner.json"
                    "ntfyCompletedPassword" -> "identity-operator-password.txt"
                    else -> "identity-browser-totp.json"
                }
                pin(dir.resolve("owner-proofs/$filename"),65536).also { input ->
                    require(input.sha256 == state.context.getValue("${field}Sha256").jsonPrimitive.content &&
                        state.context.getValue("${field}File").jsonPrimitive.content ==
                            "/case/owner-proofs/$filename")
                }
            }
        } else emptyList()
        val hubPrivate = if (state.service in setOf("jupyterhub","jupyter-notebook")) {
            listOf("hubAccountFile" to "hubAccountSha256", "hubDatabaseReadOnlyFile" to "hubDatabaseSha256",
                "hubOwnerVolumeCustodyFile" to "hubOwnerVolumeCustodySha256",
                "hubAliceEpisodeFile" to "hubAliceEpisodeSha256",
                "hubBobEpisodeFile" to "hubBobEpisodeSha256").map { (field,digest) ->
                pin(Path.of(state.context.getValue(field).jsonPrimitive.content),1048576).also {
                    require(it.sha256 == state.context.getValue(digest).jsonPrimitive.content)
                }
            }
        } else emptyList()
        val hubHomes = if (state.service in setOf("jupyterhub","jupyter-notebook"))
            listOf("aliceHomeReadOnlyPath","bobHomeReadOnlyPath").map {
                state.context.getValue(it).jsonPrimitive.content
            } else emptyList()
        val identityPrivate = if (state.service in setOf("keycloak","identity-onboarding") &&
            state.surface == "WEB" && state.variant == "BROWSER")
            listOf(pin(dir.resolve("owner-proofs/identity-original-owner.json"),65536)) else emptyList()
        val officePrivate = if (state.service == "onlyoffice") {
            val fields = when (state.surface) {
                "WEB" -> listOf("seafileAccountsFile")
                "ANDROID" -> listOf("scopedAccountFile", "nativeCredentialsFile")
                else -> listOf("seafileCredentialsFile", "officeJwtSecretFile")
            }
            fields.map { field -> pin(dir.resolve("owner-proofs/office-$field.json"), 65536) }
        } else emptyList()
        return QualificationClientRequest("qc-${ReleaseLocks.sha256((scope.suiteId + state.invocationId)
            .encodeToByteArray()).take(12)}", scope.generationId, sealed.runtimeFingerprint,
            state.invocationId, dir.toString(), intentSha, suite.toString(),
            intent.getValue("runnerSha256").jsonPrimitive.content,
            adapterSha, state.service, state.surface, state.variant,
            phase(), state.roots, leaf, image.imageId, image.pinnedImage,
            image.selectedManifestDigest, 4096, 2048, 512,
            officialApk = apk, secondaryOfficialApk = secondaryApk, sourceObservationSha256 = source,
            seafileToolPins = seafilePins,
            clientMode = if (state.mode == QualificationExecutionMode.HOST_NATIVE_WITH_DENIAL_PROBE)
                "NATIVE_NETWORK_DENIAL" else "NORMAL",
            grafanaNativeOracle = if (state.service == "grafana" && state.surface == "WEB" && phase() == "INSTALL")
                predecessorsPinned.first() else null,
            grafanaNativeObservation = if (state.service == "grafana" && state.surface == "WEB" && phase() == "INSTALL")
                predecessorsPinned.last() else null,
            predecessorFiles = predecessorsPinned, credentialFiles = state.actorFiles,
            officePrivateFiles = officePrivate, seafilePrivateFiles = seafilePrivate,
            identityPrivateFiles = identityPrivate, hubPrivateFiles = hubPrivate,
            hubHomeReadOnlyPaths = hubHomes, ntfyPrivateFiles = ntfyPrivate,
            filesNativeCa = filesNativeCa,
            publicCertificateRevisions = revisions,
            nativeCaseClaimSha256 = claim, suiteClosure = suiteClosure)
    }
    private fun copyOriginal(caseDir: Path, original: Path, name: String, result: Path?): ActivationInput {
        val bytes = ReleasePrivateFiles.read(original, 1048576)
        if (result != null) {
            val proof = json.parseToJsonElement(ReleasePrivateFiles.read(result, 1048576)
                .decodeToString(throwOnInvalidSequence = true)).jsonObject
            require(proof.getValue("action").jsonPrimitive.content == "install" &&
                (proof["bindingSha256"] ?: proof["intentSha256"])?.jsonPrimitive?.content == ReleaseLocks.sha256(bytes))
        }
        val dir = caseDir.resolve("owner-proofs")
        if (!Files.exists(dir, NOFOLLOW_LINKS)) {
            Files.createDirectory(dir, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(caseDir)
        }
        ReleasePrivateFiles.directory(dir)
        val destination = dir.resolve(name)
        ReleasePrivateFiles.save(destination, bytes)
        return pin(destination, 1048576)
    }
    fun start(payload: OwnerCaseStart): OwnerCaseStarted {
        owned()
        val dir = case(payload.caseDirectory)
        val state = requireNotNull(active[dir])
        require(state.intentSha256 == null && payload.caseIntentSha256.matches(hash) &&
            payload.contextSha256.matches(hash) &&
            pin(dir.resolve("intent.json"), 65536).sha256 == payload.caseIntentSha256 &&
            pin(dir.resolve("context.json"), 4194304).sha256 == payload.contextSha256)
        val intent = json.parseToJsonElement(ReleasePrivateFiles.read(dir.resolve("intent.json"), 65536)
            .decodeToString(throwOnInvalidSequence = true)).jsonObject
        val contextBytes = ReleasePrivateFiles.read(dir.resolve("context.json"), 4194304)
        require(intent.getValue("invocationId").jsonPrimitive.content == state.invocationId &&
            intent.getValue("serviceId").jsonPrimitive.content == state.service &&
            intent.getValue("surface").jsonPrimitive.content == state.surface &&
            intent.getValue("variant").jsonPrimitive.content == state.variant &&
            intent.getValue("journey").jsonPrimitive.content == state.journey &&
            intent.getValue("binding") == binding() &&
            intent.getValue("contextSha256").jsonPrimitive.content == payload.contextSha256 &&
            json.parseToJsonElement(contextBytes.decodeToString(throwOnInvalidSequence = true)) == state.context)
        // C1 has already durably committed the start intent; never repeat a failed native effect.
        state.intentSha256 = payload.caseIntentSha256
        state.contextSha256 = payload.contextSha256
        // Pin empty transport directories before any runner can replace them or enqueue work.
        spool(dir, state).requireDrained()
        require(phase() == "INSTALL" || restored?.let { it.target ==
            ReleaseGeneration(scope.generationId, scope.bundleSha256) } == true)
        if (state.mode == QualificationExecutionMode.HOST_NATIVE) {
            val rss = state.service in setOf("mastodon-rss-publisher", "rss-jobs") ||
                state.service.startsWith("rss-pack-")
            require(!rss || restored != null) {
                "INSTALL RSS host case requires its distinct registered native ingress actor"
            }
            val sourceStopped = restored?.let { ownerScope ->
                val copy = copyOriginal(dir, Path.of(ownerScope.quiescence.path), "source-stopped.json", null)
                require(copy.sha256 == ownerScope.quiescence.sha256)
                ActivationInput("owner-proofs/source-stopped.json", copy.sha256)
            }
            val readiness = restored?.let { ownerScope ->
                val copy = copyOriginal(dir, Path.of(ownerScope.readiness.path), "private-readiness.json", null)
                require(copy.sha256 == ownerScope.readiness.sha256)
                ActivationInput("owner-proofs/private-readiness.json", copy.sha256)
            }
            val ingress = if (rss) {
                val ownerScope = requireNotNull(restored)
                val sealed = QualificationCanonicalTopology.require(bundle, restoredTarget = true)
                val op = qualificationCaseBridgeOperation(scope.suiteId, state.invocationId, "install")
                val root = Path.of("/mnt/media/p0-v3/restored-bridges").resolve(ownerScope.site)
                    .resolve(scope.generationId)
                val address = NamespaceCaddyTransport.ownedClientAddress(sealed.spec,
                    sealed.runtimeFingerprint, "qualification-web")
                val clients = sealed.spec.processes.filter { "qualification-web" in it.networks && it.id != "caddy" }
                    .map { it.id }.toSet()
                val binding = RestoredBridgeBinding(op, ownerScope.site, ownerScope.source.id,
                    ownerScope.target.id, sealed.runtimeFingerprint, "qualification-web", address,
                    clients, "https", ownerScope.listener.operation, ownerScope.listener.sourceStoppedProofSha256,
                    ownerScope.readiness.sha256, ownerScope.approvedHosts, ownerScope.upstreams,
                    ownerScope.sourceCertificates, ownerScope.sourcePrivateKeys,
                    ownerScope.certificateFiles, ownerScope.keyFiles,
                    nativeClientCapabilities = setOf("rss-mastodon"))
                val bridge = RestrictedRestoreBridge.real(root, binding, sealed.spec,
                    ownerScope.sourcePin.spec, ownerScope.sourcePin.runtimeFingerprint)
                state.ingressRoot = root; state.bridgeBinding = binding; state.bridgeActor = bridge
                val observation = NamespaceCaddyTransport.real(sealed.spec, sealed.runtimeFingerprint)
                    .exchange("GET", "/config/", null, null)
                require(observation.status == 200 && observation.body.size in 1..4194304)
                val before = TransactionalCaddy.digest(json.parseToJsonElement(observation.body
                    .decodeToString(throwOnInvalidSequence = true)).jsonObject)
                state.bridgeAttempted = true
                val installed = bridge.install(before)
                require(installed.action == "install" && installed.beforeSha256 == before)
                state.bridgeAfterSha256 = installed.afterSha256
                val copied = copyOriginal(dir, root.resolve("$op.intent.json"),
                    "ingress-intent.json", root.resolve("$op.result.json"))
                state.ingress = copied; state.ingressRoot = root
                ActivationInput("owner-proofs/ingress-intent.json", copied.sha256)
            } else null
            ReleasePrivateFiles.save(dir.resolve("qualification-case-gate.json"), json.encodeToString(
                OwnerCaseGate(invocationId = state.invocationId, mode = state.mode.name,
                    caseIntentSha256 = payload.caseIntentSha256, contextSha256 = payload.contextSha256,
                    client = null, ingress = ingress, sourceStopped = sourceStopped,
                    privateReadiness = readiness)).encodeToByteArray())
            return OwnerCaseStarted(state.invocationId, state.mode.name, null)
        }
        val sealed = QualificationCanonicalTopology.require(bundle, restoredTarget = phase() == "RESTORE")
        val request = clientRequest(dir, state, intent, payload.caseIntentSha256)
        val inputs = QualificationPrerequisites.read(scope)
        val runtime = QualificationClientRuntime.real(generation, sealed.spec, sealed.runtimeFingerprint,
            inputs.inventory, originalOwnership().approvedHosts,
            reviewedSeafileProducerPublicKeySha256 = inputs.reviewedSeafileProducerKeySha256)
        state.request = request; state.runtime = runtime
        val native = runtime.start(request)
        state.native = native
        val operation = qualificationCaseBridgeOperation(scope.suiteId, state.invocationId, "install")
        val ingressRoot: Path
        val copy: ActivationInput
        val sourceStopped: ActivationInput?
        val readiness: ActivationInput?
        if (phase() == "RESTORE") {
            val ownerScope = requireNotNull(restored)
            ingressRoot = Path.of("/mnt/media/p0-v3/restored-bridges")
                .resolve(ownerScope.site).resolve(scope.generationId)
            val address = NamespaceCaddyTransport.ownedClientAddress(sealed.spec,
                sealed.runtimeFingerprint, "qualification-web")
            val allowed = sealed.spec.processes.filter { "qualification-web" in it.networks && it.id != "caddy" }
                .map { it.id }.toSet()
            val binding = RestoredBridgeBinding(operation, ownerScope.site, ownerScope.source.id,
                ownerScope.target.id, sealed.runtimeFingerprint, "qualification-web", address,
                allowed, "https", ownerScope.listener.operation, ownerScope.listener.sourceStoppedProofSha256,
                ownerScope.readiness.sha256, ownerScope.approvedHosts, ownerScope.upstreams,
                ownerScope.sourceCertificates, ownerScope.sourcePrivateKeys,
                ownerScope.certificateFiles, ownerScope.keyFiles,
                qualifierClientInvocationId = state.invocationId,
                qualifierClientContainerId = native.containerId, qualifierClientAddress = native.clientIp)
            val bridge = RestrictedRestoreBridge.real(ingressRoot, binding, sealed.spec,
                ownerScope.sourcePin.spec, ownerScope.sourcePin.runtimeFingerprint)
            state.ingressRoot = ingressRoot; state.bridgeBinding = binding; state.bridgeActor = bridge
            val observation = NamespaceCaddyTransport.real(sealed.spec, sealed.runtimeFingerprint)
                .exchange("GET", "/config/", null, null)
            require(observation.status == 200 && observation.body.size in 1..4194304)
            val before = TransactionalCaddy.digest(json.parseToJsonElement(observation.body
                .decodeToString(throwOnInvalidSequence = true)).jsonObject)
            state.bridgeAttempted = true
            val installed = bridge.install(before)
            require(installed.action == "install" && installed.beforeSha256 == before)
            state.bridgeAfterSha256 = installed.afterSha256
            copy = copyOriginal(dir, ingressRoot.resolve("$operation.intent.json"),
                "ingress-intent.json", ingressRoot.resolve("$operation.result.json"))
            val stop = copyOriginal(dir, Path.of(ownerScope.quiescence.path), "source-stopped.json", null)
            val ready = copyOriginal(dir, Path.of(ownerScope.readiness.path), "private-readiness.json", null)
            require(stop.sha256 == ownerScope.quiescence.sha256 && ready.sha256 == ownerScope.readiness.sha256)
            sourceStopped = ActivationInput("owner-proofs/source-stopped.json", stop.sha256)
            readiness = ActivationInput("owner-proofs/private-readiness.json", ready.sha256)
        } else {
            ingressRoot = Path.of("/mnt/media/p0-v3/qualification-ingress")
                .resolve(originalOwnership().contract.site).resolve(scope.generationId)
            val ingress = QualificationInstallIngress.real(ingressRoot, QualificationInstallIngressBinding(
                operation, originalOwnership().contract.site, scope.generationId, sealed.runtimeFingerprint,
                "https", "qualification-web", NamespaceCaddyTransport.ownedProcessAddress(sealed.spec,
                    sealed.runtimeFingerprint, "caddy", "qualification-web"), native.clientIp,
                state.invocationId, native.containerId, originalOwnership().approvedHosts), sealed.spec,
                { native })
            state.ingressRoot = ingressRoot; state.ingressActor = ingress; state.bridgeAttempted = true
            val installed = ingress.install()
            require(installed.action == "install")
            copy = copyOriginal(dir, ingressRoot.resolve("$operation-install.intent.json"),
                "ingress-intent.json", ingressRoot.resolve("$operation-install.result.json"))
            sourceStopped = null; readiness = null
        }
        state.ingress = copy; state.ingressRoot = ingressRoot
        ReleasePrivateFiles.save(dir.resolve("qualification-case-gate.json"), json.encodeToString(
            OwnerCaseGate(invocationId = state.invocationId, mode = state.mode.name,
                caseIntentSha256 = payload.caseIntentSha256, contextSha256 = payload.contextSha256,
                client = native, ingress = ActivationInput("owner-proofs/ingress-intent.json", copy.sha256),
                sourceStopped = sourceStopped, privateReadiness = readiness)).encodeToByteArray())
        runtime.admitAndOpen(request)
        return OwnerCaseStarted(state.invocationId, state.mode.name, native)
    }
    private fun state(path: String): Pair<Path, Active> {
        val dir = case(path)
        return dir to requireNotNull(active[dir]) { "Case was not prepared by retained owner" }
    }
    private fun spool(dir: Path, state: Active): QualificationCaseSpool = state.spool
        ?: QualificationCaseSpool(dir, generation.resolve("qualification-control/${scope.suiteId}"),
            state.invocationId).also { state.spool = it }
    private fun drained(dir: Path, state: Active) { spool(dir, state).requireDrained() }
    /** Registered private actors run on this retained owner thread. Their requests carry
     * fixed actions only; authority is reopened from the original case/claim and sealed
     * target, never accepted from adapter-supplied paths or credentials. */
    private fun typedNative(dir: Path, state: Active, request: QualificationSpoolRequest,
        requestSha256: String): OwnerCaseNativeReply {
        require(state.intentSha256 == pin(dir.resolve("intent.json"), 65536).sha256 &&
            state.contextSha256 == pin(dir.resolve("context.json")).sha256 &&
            !state.awaited && !state.fenced)
        val matrix = request.family == "MATRIX"
        require(if (matrix) state.mode == QualificationExecutionMode.QCLIENT_RUNNER &&
            state.surface == "ANDROID" && state.variant in setOf("API34", "API36") &&
            state.service in setOf("element", "synapse", "matrix-authentication-service", "livekit")
        else state.mode in setOf(QualificationExecutionMode.HOST_NATIVE,
            QualificationExecutionMode.HOST_NATIVE_WITH_DENIAL_PROBE) &&
            (request.family == "OFFICE_CALLBACK" && state.service == "onlyoffice" ||
                request.family == "OPENSEARCH" && state.service == "opensearch" ||
                request.family == "OBSERVABILITY" && state.service in setOf("alloy", "loki", "node-exporter"))) {
            "Typed native family ${request.family} actor is not registered"
        }
        val sealed = QualificationCanonicalTopology.require(bundle, phase() == "RESTORE")
        if (matrix) {
            val clientRequest = requireNotNull(state.request)
            val native = requireNotNull(state.native)
            val gate = json.decodeFromString<OwnerCaseGate>(ReleasePrivateFiles.read(
                dir.resolve("qualification-case-gate.json"), 65536).decodeToString(throwOnInvalidSequence = true))
            require(gate.invocationId == state.invocationId && gate.mode == "QCLIENT_RUNNER" &&
                gate.client == native && gate.caseIntentSha256 == state.intentSha256 &&
                gate.contextSha256 == state.contextSha256 && clientRequest.caseDirectory == dir.toString() &&
                clientRequest.caseIntentSha256 == state.intentSha256 &&
                clientRequest.serviceId == state.service && clientRequest.phase == phase() &&
                clientRequest.fingerprint == sealed.runtimeFingerprint)
            return OwnerCaseNativeReply(state.invocationId, request.family, requestSha256,
                QualificationMatrixActor.execute(request.request, scope.generationId, phase(),
                    state.invocationId, sealed.spec, sealed.manifestSha256, sealed.runtimeFingerprint,
                    clientRequest, requireNotNull(state.runtime), native, state.context, restored, sealed,
                    state.matrixCapture ?: QualificationMatrixCaptureActor().also { state.matrixCapture = it },
                    state.roots, bundle, scope.bundleSha256))
        }
        val claim = pin(generation.resolve("native-qualification-claims/${state.invocationId}.json"), 8192)
        val nativeBinding = NativeQualificationCaseBinding(scope.generationId, state.invocationId,
            dir.toString(), requireNotNull(state.intentSha256), claim.sha256, state.service, phase(),
            sealed.spec.name, sealed.runtimeFingerprint)
        val authority = NativeQualificationClaims.read(nativeBinding)
        require(authority.context == state.context &&
            authority.claim.getValue("bundleSha256").jsonPrimitive.content == scope.bundleSha256)
        if (request.family == "OBSERVABILITY") return OwnerCaseNativeReply(state.invocationId,
            request.family, requestSha256, QualificationObservabilityActor.execute(nativeBinding,
                sealed.spec, request.request, restored?.quiescence, restored?.listener?.sourceStoppedProofSha256))
        if (request.family == "OPENSEARCH") return OwnerCaseNativeReply(state.invocationId,
            request.family, requestSha256, QualificationOpenSearchActor.execute(nativeBinding,
                sealed.spec, request.request, restored?.quiescence, restored?.listener?.sourceStoppedProofSha256))
        require(request.request.keys == setOf("action", "operationKey") &&
            request.request.getValue("action").jsonPrimitive.content == "READ_LEDGER")
        val key = request.request.getValue("operationKey").jsonPrimitive.content
        require(key.matches(Regex("office-callback-v2:[a-f0-9]{64}")))
        require(sealed.spec.processes.singleOrNull { it.id == "seafile-backend" } != null)
        val observed = OfficeCallbackNativeCollector.collect(sealed.spec, scope.generationId,
            sealed.runtimeFingerprint, key)
        return OwnerCaseNativeReply(state.invocationId, request.family, requestSha256,
            json.encodeToJsonElement(observed).jsonObject)
    }
    fun native(payload: OwnerCaseNative): OwnerCaseNativeReply {
        owned()
        val (dir, state) = state(payload.caseDirectory)
        require(state.intentSha256 != null && state.mode in setOf(QualificationExecutionMode.HOST_NATIVE,
            QualificationExecutionMode.HOST_NATIVE_WITH_DENIAL_PROBE) && !state.fenced && !state.awaited)
        return requireNotNull(spool(dir, state).service(publish = false, expected = payload,
            beforeEffect = {
                if (state.mode == QualificationExecutionMode.HOST_NATIVE_WITH_DENIAL_PROBE) {
                    require(requireNotNull(state.runtime).observeExit(requireNotNull(state.request),
                        requireNotNull(state.native)) == null) { "Native denial probe exited before case effect" }
                }
            }, afterEffect = {}, actor = { request, sha -> typedNative(dir, state, request, sha) })) {
            "No original ready request for CASE_NATIVE"
        }
    }
    fun await(path: String, tick: () -> Unit): OwnerCaseAwaited {
        owned()
        val (dir, state) = state(path)
        require(state.mode == QualificationExecutionMode.QCLIENT_RUNNER && state.intentSha256 != null &&
            !state.awaited && !state.fenced)
        val request = requireNotNull(state.request)
        val runtime = requireNotNull(state.runtime)
        val native = requireNotNull(state.native)
        val channel = spool(dir, state)
        val deadline = System.nanoTime() + TimeUnit.MINUTES.toNanos(65)
        while (true) {
            tick()
            require(System.nanoTime() < deadline && RecoveryDeadline.remainingMillis() > 0)
            if (state.surface == "ANDROID") {
                val ready = dir.resolve("android-boot-ready.json")
                val boot = dir.resolve("android-boot.json")
                val guestGate = dir.resolve("qualification-guest-gate.json")
                if (!Files.exists(guestGate, NOFOLLOW_LINKS) &&
                    (Files.exists(ready, NOFOLLOW_LINKS) || Files.exists(boot, NOFOLLOW_LINKS))) {
                    val guest = runtime.auditGuest(request)
                    if (Files.exists(ready, NOFOLLOW_LINKS)) {
                        val marker = json.parseToJsonElement(ReleasePrivateFiles.read(ready, 8192)
                            .decodeToString(throwOnInvalidSequence = true)).jsonObject
                        require(marker.getValue("invocationId").jsonPrimitive.content == state.invocationId &&
                            marker.getValue("generationId").jsonPrimitive.content == scope.generationId &&
                            marker.getValue("api").jsonPrimitive.int == state.variant.removePrefix("API").toInt() &&
                            marker.getValue("serial").jsonPrimitive.content == guest.serial &&
                            marker.getValue("hostEmulatorPid").jsonPrimitive.int == guest.emulatorHostPid &&
                            marker.getValue("avd").jsonPrimitive.content == guest.avd)
                    }
                    if (state.service == "livekit") runtime.auditGuest(request, "reader")
                    if (state.service in setOf("element", "synapse", "matrix-authentication-service", "livekit")) {
                        val native = requireNotNull(state.native)
                        val policyBytes = ReleasePrivateFiles.read(generation.resolve(
                            "qualification-client/${state.invocationId}/turn-policy.json"), 65536)
                        val policy = json.decodeFromString<QualificationTurnPolicy>(policyBytes.decodeToString(
                            throwOnInvalidSequence = true))
                        require(policy.containerId == native.containerId &&
                            policy.containerNetnsInode == native.netnsInode &&
                            policy.rtcHost == "matrix-rtc.datamancy.net" &&
                            guest.containerId == native.containerId && guest.containerPid == native.pid)
                        val path = dir.resolve("owner-proofs/matrix-turn-policy.json")
                        require(!Files.exists(path, NOFOLLOW_LINKS))
                        ReleasePrivateFiles.save(path,policyBytes)
                    }
                }
                if (state.service in setOf("onlyoffice", "seafile", "element", "synapse",
                        "matrix-authentication-service", "livekit", "donetick",
                        "homeassistant", "jellyfin", "mastodon", "ntfy")) {
                    val adopted = dir.resolve("owner-proofs/guest-ca-adoption.json")
                    val reader = dir.resolve("owner-proofs/guest-ca-adoption-reader.json")
                    val trustGate = dir.resolve("qualification-guest-trust-gate.json")
                    if (Files.exists(adopted, NOFOLLOW_LINKS) &&
                        (state.service != "livekit" || Files.exists(reader, NOFOLLOW_LINKS)) &&
                        !Files.exists(trustGate, NOFOLLOW_LINKS)) {
                        val ownerSha = runtime.auditGuestTrust(request)
                        val readerSha = if (state.service == "livekit")
                            runtime.auditGuestTrust(request, "reader") else null
                        val bridgeBytes = ReleasePrivateFiles.read(generation.resolve(
                            "qualification-client/${state.invocationId}/guest-bridge.json"), 65536)
                        val officeSha = if (state.service == "onlyoffice") {
                            val issued = CanonicalCaddyServedLeafReadback(generation, bundle,
                                scope.bundleSha256, QualificationPrivateTls.selectedManifest(
                                    requireNotNull(QualificationCanonicalTopology.require(bundle,
                                        phase() == "RESTORE").spec.fragmentBinding)))
                            val filesLeaf = json.decodeFromString<CaddyServedLeafReadback>(
                                ReleasePrivateFiles.read(Path.of(issued.verify("files.datamancy.net").path), 8192)
                                    .decodeToString(throwOnInvalidSequence = true))
                            val selectedFileCa = ReleasePrivateFiles.read(PrivateDeployment.BASE.resolve(
                                "${scope.generationId}-v2").resolve("seafile-ca.pem"),65536)
                            val selectedFileCaSha = ReleaseLocks.sha256(selectedFileCa)
                            require(selectedFileCaSha == QualificationCanonicalTopology.require(bundle,
                                phase() == "RESTORE").inputHashes.getValue("seafile-ca.pem") &&
                                filesLeaf.caSha256 == selectedFileCaSha &&
                                filesLeaf.privateNetwork == "ingress-control") {
                                "Seadroid native guest uses a different original Files issuer"
                            }
                            val observed = runtime.auditOfficeFixture(request)
                            val android = state.context.getValue("android").jsonObject
                            val receipt = buildJsonObject {
                                put("schemaVersion", 1); put("invocationId", state.invocationId)
                                put("generationId", scope.generationId)
                                put("api", android.getValue("api")); put("serial", android.getValue("serial"))
                                put("packageName", observed.getValue("packageName"))
                                put("apkSha256", observed.getValue("apkSha256"))
                                put("signerSha256", observed.getValue("signerSha256"))
                                put("guestCaAdoptionSha256", ownerSha)
                            }
                            val path = dir.resolve("owner-proofs/seafile-installed-client.json")
                            ReleasePrivateFiles.save(path, json.encodeToString(receipt).encodeToByteArray())
                            pin(path, 65536).sha256
                        } else null
                        ReleasePrivateFiles.save(trustGate, buildJsonObject {
                            put("invocationId", state.invocationId); put("generationId", scope.generationId)
                            put("caSha256", state.roots.sha256)
                            put("ownerBridgeSha256", ReleaseLocks.sha256(bridgeBytes))
                            put("ownerAdoptionSha256", ownerSha)
                            if (readerSha != null) put("readerAdoptionSha256", readerSha)
                            if (officeSha != null) put("seafileInstalledClientReceiptSha256", officeSha)
                        }.toString().encodeToByteArray())
                        if (state.service == "onlyoffice") require(
                            QualificationOfficeCaseInputs.bindPostStart(dir,state.context,
                                state.invocationId,scope.generationId) == officeSha)
                    }
                }
            }
            val exit = runtime.observeExit(request, native)
            if (exit != null) {
                channel.requireDrained() // No post-exit dispatch, including a late ready marker.
                val receipt = pin(generation.resolve(
                    "qualification-client/${state.invocationId}/completion.json"),65536)
                if (state.service == "ntfy" && state.surface == "WEB" && exit == 0) {
                    // The cookie, real issuer and GROUP gateway result did not exist
                    // at CASE_PREPARE. Only this completed, same-case QClient may
                    // produce them. Never adopt caller context or replay login.
                    val completion = json.parseToJsonElement(ReleasePrivateFiles.read(
                        Path.of(receipt.path),65536).decodeToString(throwOnInvalidSequence=true)).jsonObject
                    require(completion.getValue("invocationId").jsonPrimitive.content == state.invocationId &&
                        completion.getValue("containerId").jsonPrimitive.content == native.containerId &&
                        completion.getValue("exitCode").jsonPrimitive.int == 0)
                    val observation = json.parseToJsonElement(ReleasePrivateFiles.read(
                        dir.resolve("native-result.json"),1048576).decodeToString(throwOnInvalidSequence=true)).jsonObject
                    require(observation.getValue("schemaVersion").jsonPrimitive.int == 2 &&
                        observation.getValue("invocationId").jsonPrimitive.content == state.invocationId &&
                        observation.getValue("generationId").jsonPrimitive.content == scope.generationId &&
                        observation.getValue("phase").jsonPrimitive.content == phase() &&
                        observation.getValue("serviceId").jsonPrimitive.content == "ntfy" &&
                        observation.getValue("surface").jsonPrimitive.content == "WEB")
                    val artifacts = observation.getValue("artifacts").jsonObject
                    fun observed(name: String): ActivationInput {
                        val proof = pin(dir.resolve(name),65536)
                        require(artifacts.getValue(name).jsonPrimitive.content == proof.sha256)
                        return proof
                    }
                    val source = if (phase() == "RESTORE") requireNotNull(restored).sourcePin
                        else QualificationCanonicalTopology.require(bundle)
                    val original = QualificationIdentityOriginalOwner(state.context.getValue(
                        "ntfyOriginalOwnerSubject").jsonPrimitive.content,
                        pin(dir.resolve("owner-proofs/identity-original-owner.json"),8192),
                        dir.resolve("owner-proofs/identity-operator-password.txt").toString(),
                        dir.resolve("owner-proofs/identity-browser-totp.json").toString(),false)
                    require(original.subject == QualificationIdentityCaseInputs.extractOriginalOwner(
                        ReleasePrivateFiles.read(PrivateDeployment.BASE.resolve(source.spec.name)
                            .resolve("identity-realm.json"),1048576).decodeToString(throwOnInvalidSequence=true),
                        if (phase() == "RESTORE") requireNotNull(restored).source.id else scope.generationId).first)
                    val password = pin(Path.of(original.operatorPasswordOutput),8192)
                    val totp = pin(Path.of(original.operatorTotpOutput),8192)
                    require(original.originalCustody.sha256 == state.context.getValue(
                        "ntfyOriginalOwnerSha256").jsonPrimitive.content &&
                        password.sha256 == state.context.getValue(
                            "ntfyCompletedPasswordSha256").jsonPrimitive.content &&
                        totp.sha256 == state.context.getValue(
                            "ntfyCompletedTotpSha256").jsonPrimitive.content)
                    val readback = QualificationNtfySessionProducer.capture(dir,bundle,
                        QualificationCanonicalTopology.require(bundle,phase() == "RESTORE"),
                        scope.bundleSha256,phase(),state.invocationId,requireNotNull(state.intentSha256),
                        original,password,totp,receipt,
                        observed("ntfy-web-login.intent.json"),
                        observed("ntfy-issuer-result.json"),
                        observed("ntfy-gateway-observation.json"),
                        observed("ntfy-browser-session.json"))
                    QualificationNtfyGroupReadback.verify(readback,scope.generationId,scope.bundleSha256)
                }
                state.awaited = true
                return OwnerCaseAwaited(state.invocationId, exit, true, receipt)
            }
            val forwarded = channel.service(publish = true, expected = null,
                beforeEffect = {
                    tick()
                    require(System.nanoTime() < deadline && RecoveryDeadline.remainingMillis() > 0 &&
                        runtime.observeExit(request, native) == null) { "QClient exited before native dispatch" }
                }, afterEffect = {
                    tick()
                    require(System.nanoTime() < deadline && RecoveryDeadline.remainingMillis() > 0 &&
                        runtime.observeExit(request, native) == null) { "QClient exited during native dispatch" }
                }, actor = { original, sha -> typedNative(dir, state, original, sha) })
            if (forwarded == null) Thread.sleep(50)
        }
    }
    private fun restoredInstall(state: Active): RestoredBridgeResult? {
        val root = requireNotNull(state.ingressRoot)
        val binding = requireNotNull(state.bridgeBinding)
        val actor = requireNotNull(state.bridgeActor)
        val op = qualificationCaseBridgeOperation(scope.suiteId, state.invocationId, "install")
        require(binding.operation == op)
        val intent = root.resolve("$op.intent.json")
        val result = root.resolve("$op.result.json")
        val pending = root.resolve("bridge.pending")
        if (!Files.exists(intent, NOFOLLOW_LINKS)) {
            require(!Files.exists(result, NOFOLLOW_LINKS) && !Files.exists(pending, NOFOLLOW_LINKS))
            return null // Native CAS cannot precede the protected original intent.
        }
        val bytes = ReleasePrivateFiles.read(intent, 1048576)
        val decoded = json.decodeFromString<RestoredBridgeIntent>(bytes.decodeToString(throwOnInvalidSequence = true))
        require(decoded.binding == binding && decoded.action == "install")
        val receipt = if (Files.exists(result, NOFOLLOW_LINKS)) {
            require(!Files.exists(pending, NOFOLLOW_LINKS))
            json.decodeFromString<RestoredBridgeResult>(ReleasePrivateFiles.read(result, 1048576)
                .decodeToString(throwOnInvalidSequence = true))
        } else {
            require(ReleasePrivateFiles.read(pending, 1048576).contentEquals(bytes))
            actor.reconcile(op, ReleaseLocks.sha256(bytes)) // Native observation, never a second CAS.
        }
        require(receipt.operation == op && receipt.intentSha256 == ReleaseLocks.sha256(bytes) &&
            receipt.action in setOf("install", "not-applied") &&
            receipt.beforeSha256 == TransactionalCaddy.digest(decoded.before) &&
            receipt.afterSha256 == TransactionalCaddy.digest(
                if (receipt.action == "install") decoded.after else decoded.before))
        if (state.bridgeAfterSha256 != null) require(receipt.action == "install" &&
            receipt.afterSha256 == state.bridgeAfterSha256)
        return receipt
    }
    private fun removeRestored(state: Active, fence: QualificationClientFence?): Pair<ActivationInput?, Boolean> {
        val root = requireNotNull(state.ingressRoot)
        val actor = requireNotNull(state.bridgeActor)
        val installed = restoredInstall(state) ?: return null to true
        if (installed.action == "not-applied") return null to true
        require(!Files.exists(root.resolve("client.pending"), NOFOLLOW_LINKS))
        val op = qualificationCaseBridgeOperation(scope.suiteId, state.invocationId, "remove")
        val path = root.resolve("$op.intent.json")
        val result = root.resolve("$op.result.json")
        val pending = root.resolve("bridge.pending")
        val removed = if (Files.exists(path, NOFOLLOW_LINKS)) {
            val bytes = ReleasePrivateFiles.read(path, 1048576)
            val intent = json.decodeFromString<RestoredBridgeIntent>(bytes.decodeToString(throwOnInvalidSequence = true))
            require(intent.action == "remove" && intent.binding == state.bridgeBinding &&
                TransactionalCaddy.digest(intent.before) == installed.afterSha256 &&
                TransactionalCaddy.digest(intent.after) == installed.beforeSha256)
            if (Files.exists(result, NOFOLLOW_LINKS)) {
                require(!Files.exists(pending, NOFOLLOW_LINKS))
                json.decodeFromString<RestoredBridgeResult>(ReleasePrivateFiles.read(result, 1048576)
                    .decodeToString(throwOnInvalidSequence = true))
            } else {
                require(ReleasePrivateFiles.read(pending, 1048576).contentEquals(bytes))
                actor.reconcile(op, ReleaseLocks.sha256(bytes))
            }.also { require(it.intentSha256 == ReleaseLocks.sha256(bytes)) }
        } else {
            require(!Files.exists(result, NOFOLLOW_LINKS) && !Files.exists(pending, NOFOLLOW_LINKS))
            if (fence == null) actor.remove(op, installed.afterSha256)
            else actor.remove(op, installed.afterSha256, fence)
        }
        require(removed.operation == op && removed.action == "remove" &&
            removed.beforeSha256 == installed.afterSha256 && removed.afterSha256 == installed.beforeSha256)
        return pin(result, 1048576) to true
    }
    private fun removeInstall(state: Active, fence: QualificationClientFence?): Pair<ActivationInput?, Boolean> {
        val root = requireNotNull(state.ingressRoot)
        val actor = requireNotNull(state.ingressActor)
        val op = qualificationCaseBridgeOperation(scope.suiteId, state.invocationId, "install")
        val installIntent = root.resolve("$op-install.intent.json")
        val installed = if (Files.exists(installIntent, NOFOLLOW_LINKS)) {
            val bytes = ReleasePrivateFiles.read(installIntent, 1048576)
            val intent = json.decodeFromString<QualificationInstallIngressIntent>(bytes.decodeToString(throwOnInvalidSequence = true))
            require(intent.action == "install" && intent.binding.operation == op)
            val result = root.resolve("$op-install.result.json")
            val receipt = if (Files.exists(result, NOFOLLOW_LINKS)) {
                require(!Files.exists(root.resolve("pending.json"), NOFOLLOW_LINKS))
                json.decodeFromString<QualificationInstallIngressResult>(ReleasePrivateFiles.read(result, 1048576)
                    .decodeToString(throwOnInvalidSequence = true))
            } else actor.reconcile(ReleaseLocks.sha256(bytes))
            require(receipt.action == "install" && receipt.bindingSha256 == ReleaseLocks.sha256(bytes) &&
                receipt.beforeSha256 == TransactionalCaddy.digest(intent.before) &&
                receipt.afterSha256 == TransactionalCaddy.digest(intent.after))
            true
        } else {
            require(!Files.exists(root.resolve("pending.json"), NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve("$op-install.result.json"), NOFOLLOW_LINKS))
            false
        }
        if (!installed) return null to true
        val stopped = requireNotNull(fence)
        val removeIntent = root.resolve("$op-remove.intent.json")
        val result = root.resolve("$op-remove.result.json")
        val receipt = if (Files.exists(removeIntent, NOFOLLOW_LINKS)) {
            val bytes = ReleasePrivateFiles.read(removeIntent, 1048576)
            val intent = json.decodeFromString<QualificationInstallIngressIntent>(bytes.decodeToString(throwOnInvalidSequence = true))
            require(intent.action == "remove" && intent.binding.operation == op)
            if (Files.exists(result, NOFOLLOW_LINKS)) {
                require(!Files.exists(root.resolve("pending.json"), NOFOLLOW_LINKS))
                json.decodeFromString<QualificationInstallIngressResult>(ReleasePrivateFiles.read(result, 1048576)
                    .decodeToString(throwOnInvalidSequence = true))
            } else actor.reconcile(ReleaseLocks.sha256(bytes))
                .also { require(it.bindingSha256 == ReleaseLocks.sha256(bytes)) }
        } else actor.remove(stopped)
        require(receipt.action == "remove")
        return pin(result, 1048576) to true
    }
    /** Safety is independent of semantic PASS and written only after independently observed
     * exact stop and bridge removal/absence. The case directory is writable by the client;
     * this receipt is instead under the protected generation control suite. */
    private fun closeState(dir: Path, state: Active): Pair<ActivationInput?, ActivationInput?> {
        require(state.intentSha256 != null && !state.fenceAttempted && state.safety == null)
        state.fenceAttempted = true // Before even a read-only lost-ACK reconciliation.
        val (fence, removal) = state.safetyDriver.close(state.request != null, state.bridgeAttempted,
            stop = {
                val request = requireNotNull(state.request)
                val runtime = requireNotNull(state.runtime)
                val observed = runtime.fenceKnown(request)
                if (observed == null) null to runtime.neverStarted(request)
                else {
                    require(state.native == null || observed.containerId == state.native?.containerId)
                    val exact = nativeQualificationClientFence(scope.generationId,
                        QualificationCanonicalTopology.require(bundle, phase() == "RESTORE").spec, observed)
                    require(exact == observed)
                    pin(generation.resolve("qualification-client/${state.invocationId}/fenced.json"), 65536) to true
                }
            }, remove = { stopped ->
                if (!state.bridgeAttempted) null to true
                else if (phase() == "RESTORE") removeRestored(state, stopped?.let {
                    json.decodeFromString<QualificationClientFence>(pinned(it, 65536)
                        .decodeToString(throwOnInvalidSequence = true))
                })
                else removeInstall(state, stopped?.let {
                    json.decodeFromString<QualificationClientFence>(pinned(it, 65536)
                        .decodeToString(throwOnInvalidSequence = true))
                })
            })
        val root = generation.resolve("qualification-control/${scope.suiteId}")
        ReleasePrivateFiles.directory(root)
        val safetyRoot = privateControlDirectory(root.resolve("case-safety"))
        val path = safetyRoot.resolve("${state.invocationId}.json")
        ReleasePrivateFiles.save(path, json.encodeToString(OwnerCaseSafetyReceipt(
            invocationId = state.invocationId, generationId = scope.generationId, suiteId = scope.suiteId,
            caseDirectory = dir.toString(), mode = state.mode.name,
            clientAttempted = state.request != null, bridgeAttempted = state.bridgeAttempted,
            clientFence = fence, bridgeRemoval = removal,
            clientStopped = true, bridgeAbsent = true)).encodeToByteArray())
        state.safety = pin(path, 65536)
        return fence to removal
    }
    fun fence(path: String): OwnerCaseFenced {
        owned()
        val (dir, state) = state(path)
        require(state.intentSha256 != null && !state.fenced && !state.fenceAttempted)
        val resultPath = dir.resolve("result.json")
        val passed = runCatching {
            if (!Files.exists(resultPath, NOFOLLOW_LINKS)) false else {
                val result = json.parseToJsonElement(ReleasePrivateFiles.read(resultPath, 1048576)
                    .decodeToString(throwOnInvalidSequence = true)).jsonObject
                result.getValue("passed").jsonPrimitive.boolean && result.getValue("finished").jsonPrimitive.boolean &&
                    result.getValue("exitCode").jsonPrimitive.int == 0 &&
                    result.getValue("invocation").jsonObject.getValue("invocationId").jsonPrimitive.content == state.invocationId &&
                    result.getValue("invocation").jsonObject.getValue("binding") == binding()
            }
        }.getOrDefault(false) // Malformed evidence never prevents the first legitimate teardown.
        val pendingCapture = state.matrixCapture?.abandon(dir) == true
        val pendingRoom = if (state.mode == QualificationExecutionMode.QCLIENT_RUNNER &&
            state.service == "livekit" && state.surface == "ANDROID")
            QualificationMatrixRoomActor.pending(dir) else false
        val (fencePin, removalPin) = closeState(dir, state)
        if (passed) drained(dir, state)
        state.fenced = passed && !pendingCapture && !pendingRoom && (state.mode != QualificationExecutionMode.QCLIENT_RUNNER || state.awaited) &&
            (state.ingress == null) == (removalPin == null) &&
            (state.native == null) == (fencePin == null)
        if (state.fenced) {
            closed += state.evidenceKey
            saveClosure(dir, state, fencePin, removalPin)
        }
        return OwnerCaseFenced(state.invocationId, fencePin, removalPin)
    }
    private fun saveClosure(dir: Path, state: Active, fence: ActivationInput?, removal: ActivationInput?) {
        require(state.fenced && state.intentSha256 != null && state.contextSha256 != null &&
            (state.native == null) == (fence == null) && (state.ingress == null) == (removal == null))
        val root = generation.resolve("qualification-control/${scope.suiteId}/case-closures")
        if (!Files.exists(root, NOFOLLOW_LINKS)) {
            ReleasePrivateFiles.directory(root.parent)
            Files.createDirectory(root, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(root.parent)
        }
        val receipt = OwnerCaseClosure(invocationId = state.invocationId, caseDirectory = dir.toString(),
            evidenceKey = state.evidenceKey, mode = state.mode.name, phase = phase(),
            caseIntent = pin(dir.resolve("intent.json"), 65536), context = pin(dir.resolve("context.json")),
            result = pin(dir.resolve("result.json"), 1048576), client = state.native,
            ingress = state.ingress, clientFence = fence, bridgeRemoval = removal)
        require(receipt.caseIntent.sha256 == state.intentSha256 && receipt.context.sha256 == state.contextSha256)
        val path = root.resolve("${state.invocationId}.json")
        ReleasePrivateFiles.save(path, json.encodeToString(receipt).encodeToByteArray())
        state.closure = pin(path, 65536)
    }
    fun closures(): List<ActivationInput> {
        owned(); requireDeclaredClosures()
        return active.values.sortedBy { it.evidenceKey }.map { requireNotNull(it.closure) }
    }
    /** Called only after the acceptance child has stopped, under the SAME retained locks.
     * Known starts may be stopped once; unknown starts/ingress writes retain uncertainty,
     * never attempt a fresh ID, bridge replay, or source resume. */
    fun cleanupKnown(): Boolean {
        owned()
        val failures = mutableListOf<Throwable>()
        for ((dir, state) in active) if (state.intentSha256 != null && state.safety == null && !state.fenceAttempted) {
            try { closeState(dir, state) } catch (error: Throwable) {
                if (error is InterruptedException) Thread.currentThread().interrupt()
                failures += error
            }
        }
        if (failures.isNotEmpty()) throw IllegalStateException("Qualification cleanup uncertain; source remains held")
            .also { failure -> failures.forEach(failure::addSuppressed) }
        return active.values.filter { it.intentSha256 != null }.all { it.safety != null }
    }
    fun safetyReceipts(): List<ActivationInput> {
        owned()
        require(active.values.filter { it.intentSha256 != null }.all { it.safety != null })
        return active.values.filter { it.intentSha256 != null }.sortedBy { it.evidenceKey }
            .map { requireNotNull(it.safety) }
    }
    fun requireFenced(path: String) {
        owned(); val (_, state) = state(path); require(state.fenced && state.evidenceKey in closed)
    }
    fun requireDeclaredClosures() {
        owned(); require(active.keys.map { it.fileName.toString() }.toSet() == declared() && closed == declared()) {
            "Every original declared case must fence before phase completion"
        }
    }
}
