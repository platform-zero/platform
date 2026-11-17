package net.datamancy.platform

import com.sun.security.auth.module.UnixSystem
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Independent raw-evidence readback, NOT a live namespace audit or disposition decision.
 * The production reader is protected ReleasePrivateFiles; the internal overload permits
 * synthetic read-only byte fixtures without making file selection caller-controlled. */
internal object RestoredCaseClosureEvidence {
    private val json = Json { encodeDefaults = true; explicitNulls = true; ignoreUnknownKeys = false }
    private val hex = Regex("[a-f0-9]{64}")
    private val invocation = Regex("case-[a-f0-9-]{36}")
    private val reserved = setOf("intent.json", "context.json", "context.proposed.json", "result.json",
        "native-result.json", "runner.log", "qualification-case-gate.json", "case-closure.json",
        "adapter-request.json", "adapter-result.json")
    private val reservedTrees = setOf("owner-proofs", "owner-native", "control-requests", "control-results")
    private fun sha(bytes: ByteArray) = ReleaseLocks.sha256(bytes)
    /** Only zero-length payloads use this exceptional path. Control JSON still requires
     * nonempty bytes via fixed/pinned; no unprotected empty-file shortcut is available. */
    private fun protectedBytes(path: Path, maximum: Int): ByteArray {
        if (!Files.isRegularFile(path, NOFOLLOW_LINKS) || Files.size(path) != 0L)
            return ReleasePrivateFiles.read(path, maximum)
        ReleasePrivateFiles.directory(path.parent)
        require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path &&
            Files.isRegularFile(path, NOFOLLOW_LINKS) && Files.size(path) == 0L &&
            Files.getPosixFilePermissions(path, NOFOLLOW_LINKS) == PosixFilePermissions.fromString("rw-------") &&
            (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == UnixSystem().uid &&
            (Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong() == 1L)
        Files.newInputStream(path, NOFOLLOW_LINKS).use { input -> require(input.read() == -1) }
        return byteArrayOf()
    }
    private fun obj(bytes: ByteArray): JsonObject = json.parseToJsonElement(
        bytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
    private fun value(row: JsonObject, key: String) = row.getValue(key).jsonPrimitive.content
    private fun pinned(pin: ActivationInput, max: Int, read: (Path, Int) -> ByteArray): ByteArray {
        require(hex.matches(pin.sha256))
        val path = Path.of(pin.path)
        require(path.isAbsolute && path.normalize() == path)
        return read(path, max).also { require(it.size in 1..max && sha(it) == pin.sha256) }
    }
    private fun fixed(path: Path, max: Int, read: (Path, Int) -> ByteArray): ByteArray {
        require(path.isAbsolute && path.normalize() == path)
        return read(path, max).also { require(it.size in 1..max) }
    }
    private fun payload(path: Path, max: Int, read: (Path, Int) -> ByteArray): ByteArray {
        require(path.isAbsolute && path.normalize() == path && max in 1..64 * 1024 * 1024)
        return read(path, max).also { require(it.size <= max) }
    }
    private fun caseProof(case: Path, pin: ActivationInput, name: String,
        original: ByteArray, read: (Path, Int) -> ByteArray) {
        require(pin.path == "owner-proofs/$name.json" && pin.sha256 == sha(original) &&
            fixed(case.resolve(pin.path), 1048576, read).contentEquals(original))
    }
    fun verify(scope: QualificationControlScope, proof: RestoredAggregateProof,
        targetPin: GenerationPin): List<OwnerCaseClosure> = verify(scope, proof, targetPin) { path, maximum ->
            val source = listOf(scope.products, scope.manifest).singleOrNull { Path.of(it.path) == path }
            if (source == null) protectedBytes(path, maximum)
            else QualificationSuiteClosure.readPinnedDocument(source, maximum)
        }

    internal fun verify(scope: QualificationControlScope, proof: RestoredAggregateProof,
        targetPin: GenerationPin, read: (Path, Int) -> ByteArray): List<OwnerCaseClosure> {
        val targetRoot = GenerationRuntime.BASE.resolve(scope.generationId)
        val controlRoot = targetRoot.resolve("qualification-control/${scope.suiteId}")
        require(scope.schemaVersion == 1 && scope.suiteId.matches(Regex("[a-f0-9]{24}")) &&
            scope.generationId.matches(Regex("q-[a-f0-9]{12}")) && hex.matches(scope.bundleSha256) &&
            scope.operation in setOf("execute-staged", "execute-qualified") &&
            scope.artifactRoot.let { Path.of(it).isAbsolute && Path.of(it).normalize() == Path.of(it) } &&
            proof.schemaVersion == 2 && proof.operation == scope.operation && proof.suiteId == scope.suiteId &&
            proof.target == ReleaseGeneration(scope.generationId, scope.bundleSha256) &&
            proof.source.id != scope.generationId && targetPin.member.name == targetPin.spec.name &&
            targetPin.spec.name.startsWith(scope.generationId + "-") && hex.matches(targetPin.runtimeFingerprint))
        // This file is scope.intent.json; no guessed scope.json or caller-proof substitution.
        require(fixed(controlRoot.resolve("scope.intent.json"), 65536, read).contentEquals(
            json.encodeToString(scope).encodeToByteArray()))
        val binding = obj(pinned(scope.binding, 1048576, read))
        require(value(binding, "phase") == "RESTORE" && value(binding, "generationId") == scope.generationId &&
            value(binding, "trialId").matches(Regex("[a-z][a-z0-9-]{0,63}")) &&
            binding.getValue("candidate") is JsonObject)
        val inventoryBytes = pinned(scope.products, 4194304, read)
        val manifestBytes = pinned(scope.manifest, 4194304, read)
        val originalContexts = obj(pinned(requireNotNull(scope.contexts), 4194304, read))
        val manifest = obj(manifestBytes)
        require(value(manifest, "schemaVersion") == "2")
        val declared = manifest.getValue("cases").jsonArray.map { it.jsonObject }
        require(declared.size in 1..256)
        val names = declared.map { row ->
            val service = value(row, "serviceId"); val surface = value(row, "surface")
            val variant = value(row, "variant"); val journey = value(row, "journey")
            val mode = QualificationExecutionPolicy.select(manifestBytes, service, surface, variant, journey)
            val key = "$service--$journey--${surface.lowercase()}--${variant.lowercase()}"
            Triple(key, mode, row)
        }
        require(names.map { it.first }.toSet().size == declared.size &&
            names.map { Triple(value(it.third, "serviceId"), value(it.third, "surface"),
                value(it.third, "variant")) }.toSet().size == declared.size)
        val byKey = names.associateBy { it.first }
        require(originalContexts.keys == byKey.keys && originalContexts.values.all { it.jsonObject.isNotEmpty() })
        val targetBytes = fixed(targetRoot.resolve("bundle.json"), 4194304, read)
        require(sha(targetBytes) == scope.bundleSha256)
        val target = obj(targetBytes)
        require(value(target.getValue("request").jsonObject, "id") == scope.generationId &&
            target.getValue("members").jsonArray.size == 1 &&
            json.decodeFromJsonElement<GenerationPin>(target.getValue("members").jsonArray.single()) == targetPin)
        val source = target.getValue("recoverySourceKopia").jsonObject
        require(value(source, "generation") == proof.source.id &&
            value(source, "bundleSha256") == proof.source.bundleSha256 &&
            hex.matches(proof.source.bundleSha256))
        val sourceBytes = fixed(GenerationRuntime.BASE.resolve(proof.source.id).resolve("bundle.json"), 4194304, read)
        require(sha(sourceBytes) == proof.source.bundleSha256)
        val sourceBundle = obj(sourceBytes)
        require(value(sourceBundle.getValue("request").jsonObject, "id") == proof.source.id)
        val sourceOwnership = sourceBundle.getValue("ownership").jsonObject
        val site = value(sourceOwnership.getValue("contract").jsonObject, "site")
        val originalHosts = sourceOwnership.getValue("approvedHosts").jsonArray
            .map { it.jsonPrimitive.content }.toSet()
        val sourcePin = json.decodeFromJsonElement<GenerationPin>(sourceBundle.getValue("members").jsonArray.single())
        val sourceRoutes = sourceOwnership.getValue("contract").jsonObject.getValue("routes").jsonArray
            .map { json.decodeFromJsonElement<SiteRouteOwner>(it) }
        val routeHosts = sourceRoutes.map { it.host }
        require(site.matches(Regex("[a-z][a-z0-9-]{0,39}")) && originalHosts.isNotEmpty() &&
            sourcePin.spec.name == "${proof.source.id}-v2" &&
            sourcePin.member.name == sourcePin.spec.name &&
            routeHosts.size == routeHosts.toSet().size && routeHosts.toSet().all { it in originalHosts } &&
            routeHosts.toSet() - "start.datamancy.net" == originalHosts - "start.datamancy.net")
        val expectedUpstreams = sourceRoutes.filter { it.host != "start.datamancy.net" }.associate { route ->
            require(route.process.startsWith("${sourcePin.spec.name}/") && route.port in 1..65535)
            val processId = route.process.removePrefix("${sourcePin.spec.name}/")
            require(sourcePin.spec.processes.count { it.id == processId && !it.oneShot } == 1 &&
                targetPin.spec.processes.count { it.id == processId && !it.oneShot } == 1)
            route.host to "p0v3-live-${scope.generationId}-v2-$processId:${route.port}"
        }
        val quiescence = pinned(proof.quiescence, 65536, read)
        val stopped = json.decodeFromString<ListenerBridgeQuiesceResult>(quiescence.decodeToString())
        require(stopped.sourceGeneration == proof.source.id && stopped.targetGeneration == scope.generationId &&
            stopped.operation.matches(Regex("r-[a-f0-9]{12}")) &&
            hex.matches(stopped.sourceStoppedProofSha256) &&
            proof.quiescence.path == Path.of("/mnt/media/p0-v3/ingress-succession").resolve(site)
                .resolve("${stopped.operation}.bridge-result.json").toString())
        val readiness = fixed(targetRoot.resolve("qualification-restored/${scope.suiteId}/private-readiness.json"), 65536, read)
        val audit = json.decodeFromString<RuntimeAudit>(readiness.decodeToString())
        require(audit.name == targetPin.spec.name && audit.fingerprint == targetPin.runtimeFingerprint &&
            audit.maintenanceId == null && targetPin.spec.processes.all { process ->
                audit.statuses.singleOrNull { it.id == process.id }?.let { status ->
                    if (process.oneShot) status.state in setOf("completed", "exited") && status.exitCode == 0
                    else status.state == "running"
                } == true
            })
        require(proof.caseClosures.size == names.size)
        val seen = mutableSetOf<String>()
        val clientIds = mutableSetOf<String>()
        val closures = proof.caseClosures.map { pin ->
            val path = Path.of(pin.path)
            require(path.parent == controlRoot.resolve("case-closures") &&
                path.fileName.toString().matches(Regex("case-[a-f0-9-]{36}\\.json")))
            val closure = json.decodeFromString<OwnerCaseClosure>(pinned(pin, 65536, read).decodeToString())
            require(closure.schemaVersion == 2 && invocation.matches(closure.invocationId) &&
                path.fileName.toString() == "${closure.invocationId}.json" &&
                closure.phase == "RESTORE" && seen.add(closure.evidenceKey))
            val (key, mode, definition) = requireNotNull(byKey[closure.evidenceKey])
            val dir = Path.of(scope.artifactRoot).resolve(key)
            require(closure.caseDirectory == dir.toString() && closure.mode == mode.name &&
                closure.caseIntent.path == dir.resolve("intent.json").toString() &&
                closure.context.path == dir.resolve("context.json").toString() &&
                closure.result.path == dir.resolve("result.json").toString())
            val intentBytes = pinned(closure.caseIntent, 65536, read)
            val intent = obj(intentBytes)
            val contextBytes = pinned(closure.context, 4194304, read)
            val context = obj(contextBytes)
            require(originalContexts.getValue(key).jsonObject.all { (field, original) ->
                field == "caFile" || context[field] == original
            } && value(context, "bundleSha256") == scope.bundleSha256 &&
                value(context, "caSha256").matches(hex))
            val result = obj(pinned(closure.result, 1048576, read))
            val required = definition.getValue("restoreAssertions").jsonArray.map { it.jsonPrimitive.content }
            val actual = intent.getValue("requiredAssertions").jsonArray.map { it.jsonPrimitive.content }
            require(required.isNotEmpty() && required.size == required.toSet().size &&
                required.all { it.isNotBlank() } && actual.size == actual.toSet().size && actual.toSet() == required.toSet())
            require(value(intent, "invocationId") == closure.invocationId &&
                intent.getValue("binding") == binding &&
                value(intent, "inventorySha256") == sha(inventoryBytes) &&
                value(intent, "manifestSha256") == sha(manifestBytes) &&
                value(intent, "runnerSha256").matches(hex) &&
                intent.getValue("requiredAssertions").jsonArray.isNotEmpty() &&
                value(intent, "contextSha256") == sha(contextBytes) &&
                value(intent, "serviceId") == value(definition, "serviceId") &&
                value(intent, "surface") == value(definition, "surface") &&
                value(intent, "variant") == value(definition, "variant") &&
                value(intent, "journey") == value(definition, "journey") &&
                result.getValue("invocation") == intent &&
                result.getValue("passed").jsonPrimitive.boolean &&
                result.getValue("finished").jsonPrimitive.boolean &&
                result.getValue("exitCode").jsonPrimitive.int == 0 &&
                value(result, "logSha256").matches(hex) &&
                sha(payload(dir.resolve("runner.log"), 64 * 1024 * 1024, read)) == value(result, "logSha256") &&
                result.getValue("failureType") == JsonNull)
            val acceptanceClosure = json.decodeFromString<OwnerCaseFenced>(fixed(
                dir.resolve("case-closure.json"), 65536, read).decodeToString())
            require(acceptanceClosure.invocationId == closure.invocationId &&
                acceptanceClosure.clientFence == closure.clientFence &&
                acceptanceClosure.bridgeRemoval == closure.bridgeRemoval)
            val gate = json.decodeFromString<OwnerCaseGate>(fixed(dir.resolve("qualification-case-gate.json"), 65536, read)
                .decodeToString())
            require(gate.schemaVersion == 2 && gate.invocationId == closure.invocationId &&
                gate.mode == mode.name && gate.caseIntentSha256 == sha(intentBytes) &&
                gate.contextSha256 == sha(contextBytes) && gate.client == closure.client &&
                (gate.ingress == null) == (closure.ingress == null) &&
                (gate.ingress == null || gate.ingress.path == "owner-proofs/ingress-intent.json" &&
                    gate.ingress.sha256 == closure.ingress?.sha256 &&
                    closure.ingress?.path == dir.resolve("owner-proofs/ingress-intent.json").toString()) &&
                (gate.sourceStopped != null) &&
                (gate.privateReadiness != null) &&
                (closure.client != null) == (mode != QualificationExecutionMode.HOST_NATIVE) &&
                (closure.client != null) == (closure.clientFence != null) &&
                (closure.ingress != null) == (closure.bridgeRemoval != null) &&
                (mode != QualificationExecutionMode.QCLIENT_RUNNER || closure.ingress != null) &&
                (mode != QualificationExecutionMode.HOST_NATIVE ||
                    value(definition, "serviceId").let { id ->
                        id !in setOf("mastodon-rss-publisher", "rss-jobs") && !id.startsWith("rss-pack-")
                    } || closure.ingress != null))
            caseProof(dir, requireNotNull(gate.sourceStopped), "source-stopped", quiescence, read)
            caseProof(dir, requireNotNull(gate.privateReadiness), "private-readiness", readiness, read)
            val observationBytes = fixed(dir.resolve("native-result.json"), 1048576, read)
            val observation = obj(observationBytes)
            require(result.getValue("observationSha256").jsonPrimitive.content == sha(observationBytes) &&
                value(observation, "schemaVersion") == "2" &&
                value(observation, "invocationId") == closure.invocationId &&
                value(observation, "serviceId") == value(definition, "serviceId") &&
                value(observation, "surface") == value(definition, "surface") &&
                value(observation, "variant") == value(definition, "variant") &&
                value(observation, "journey") == value(definition, "journey") &&
                value(observation, "phase") == "RESTORE" &&
                value(observation, "generationId") == scope.generationId &&
                observation.getValue("assertions").jsonObject.keys == required.toSet() &&
                observation.getValue("assertions").jsonObject.values.all { it.jsonPrimitive.boolean } &&
                observation.getValue("artifacts") == result.getValue("artifactHashes"))
            val artifacts = observation.getValue("artifacts").jsonObject
            require(artifacts.size in 1..64 && artifacts.containsKey("oracle.json"))
            var total = 0L
            artifacts.forEach { (relative, digest) ->
                val segment = Path.of(relative)
                require(relative.isNotBlank() && !segment.isAbsolute && segment.normalize() == segment &&
                    segment.nameCount > 0 && segment.getName(0).toString() !in reservedTrees &&
                    relative !in reserved && !relative.contains("\\") && hex.matches(digest.jsonPrimitive.content))
                val bytes = payload(dir.resolve(segment), 64 * 1024 * 1024, read)
                total += bytes.size
                require(total <= 256L * 1024 * 1024 && sha(bytes) == digest.jsonPrimitive.content)
            }
            val oracleBytes = fixed(dir.resolve("oracle.json"), 1048576, read)
            val oracle = obj(oracleBytes)
            require(oracle.isNotEmpty() && sha(oracleBytes) == artifacts.getValue("oracle.json").jsonPrimitive.content)
            val clientRoot = targetRoot.resolve("qualification-client/${closure.invocationId}")
            closure.client?.let { client ->
                require(client.containerId.matches(hex) && clientIds.add(client.containerId) &&
                    client.pid > 1 && client.netnsInode > 1 &&
                    client.imageId.matches(hex) && client.clientIp.isNotBlank())
                val nativeBytes = fixed(clientRoot.resolve("native.json"), 65536, read)
                require(json.decodeFromString<QualificationClientNative>(nativeBytes.decodeToString()) == client)
                val fencePin = requireNotNull(closure.clientFence)
                require(fencePin.path == clientRoot.resolve("fenced.json").toString())
                val fence = json.decodeFromString<QualificationClientFence>(pinned(fencePin, 65536, read).decodeToString())
                require(fence.invocationId == closure.invocationId && fence.generationId == scope.generationId &&
                    fence.containerId == client.containerId && fence.clientNetnsInode == client.netnsInode &&
                    fence.nativeClientReceiptSha256 == sha(nativeBytes) &&
                    hex.matches(fence.stoppedContainerStateSha256))
            }
            closure.ingress?.let { ingress ->
                val installOp = qualificationCaseBridgeOperation(scope.suiteId, closure.invocationId, "install")
                val removeOp = qualificationCaseBridgeOperation(scope.suiteId, closure.invocationId, "remove")
                val bridgeRoot = Path.of("/mnt/media/p0-v3/restored-bridges").resolve(site).resolve(scope.generationId)
                val installIntentBytes = fixed(bridgeRoot.resolve("$installOp.intent.json"), 1048576, read)
                require(pinned(ingress, 1048576, read).contentEquals(installIntentBytes))
                caseProof(dir, requireNotNull(gate.ingress), "ingress-intent", installIntentBytes, read)
                val installIntent = json.decodeFromString<RestoredBridgeIntent>(installIntentBytes.decodeToString())
                val installed = json.decodeFromString<RestoredBridgeResult>(fixed(
                    bridgeRoot.resolve("$installOp.result.json"), 1048576, read).decodeToString())
                val removeIntentBytes = fixed(bridgeRoot.resolve("$removeOp.intent.json"), 1048576, read)
                val removeIntent = json.decodeFromString<RestoredBridgeIntent>(removeIntentBytes.decodeToString())
                val removal = requireNotNull(closure.bridgeRemoval)
                require(removal.path == bridgeRoot.resolve("$removeOp.result.json").toString())
                val removed = json.decodeFromString<RestoredBridgeResult>(pinned(removal, 1048576, read).decodeToString())
                val original = installIntent.binding
                require(original == removeIntent.binding && original.operation == installOp &&
                    original.site == site && original.sourceGeneration == proof.source.id &&
                    original.targetGeneration == scope.generationId &&
                    original.targetFingerprint == targetPin.runtimeFingerprint &&
                    original.originalHosts == originalHosts &&
                    original.upstreams.size == expectedUpstreams.size &&
                    original.upstreams.map { it.host }.toSet() == expectedUpstreams.keys &&
                    original.upstreams.all { upstream ->
                        upstream.dial == expectedUpstreams.getValue(upstream.host) &&
                            runCatching { caddyOwnedUpstreamProxy(upstream, false) }.isSuccess &&
                            (upstream.trustedCaSha256 == null || run {
                                val ca = requireNotNull(upstream.trustedCaFile)
                                val sourceFile = sourcePin.spec.processes.single { it.id == "caddy" }.files
                                    .single { it.target == ca }.file
                                val targetFile = targetPin.spec.processes.single { it.id == "caddy" }.files
                                    .single { it.target == ca }.file
                                sourcePin.inputHashes[sourceFile] == upstream.trustedCaSha256 &&
                                    targetPin.inputHashes[targetFile] == upstream.trustedCaSha256 &&
                                    pinned(ActivationInput(PrivateDeployment.BASE.resolve(targetPin.spec.name)
                                        .resolve(targetFile).toString(), upstream.trustedCaSha256!!), 65536, read)
                                        .decodeToString(throwOnInvalidSequence = true)
                                        .contains("-----BEGIN CERTIFICATE-----")
                            })
                    } &&
                    original.sourceCertificates.keys == originalHosts &&
                    original.sourcePrivateKeys.keys == originalHosts &&
                    original.certificateFiles.keys == originalHosts && original.keyFiles.keys == originalHosts &&
                    originalHosts.all { host ->
                        val deployed = targetPin.spec.processes.single { it.id == "caddy" }.files
                        listOf(original.sourceCertificates.getValue(host) to original.certificateFiles.getValue(host),
                            original.sourcePrivateKeys.getValue(host) to original.keyFiles.getValue(host)).all { (input, destination) ->
                            deployed.count { it.target == destination &&
                                targetPin.inputHashes[it.file] == input.sha256 &&
                                input.path == PrivateDeployment.BASE.resolve(targetPin.spec.name).resolve(it.file).toString()
                            } == 1 && pinned(input, 65536, read).isNotEmpty()
                        }
                    } && original.clientNetwork == "qualification-web" && original.server == "https" &&
                    original.quiesceOperation == stopped.operation &&
                    original.sourceStoppedProofSha256 == stopped.sourceStoppedProofSha256 &&
                    original.targetPrivateReadinessSha256 == sha(readiness) &&
                    original.allowedClients == targetPin.spec.processes.filter {
                        "qualification-web" in it.networks && it.id != "caddy" }.map { it.id }.toSet() &&
                    original.clientAddress.isNotBlank() &&
                    (if (closure.client != null) original.nativeClientCapabilities.isEmpty() &&
                        original.qualifierClientInvocationId == closure.invocationId &&
                        original.qualifierClientContainerId == closure.client!!.containerId &&
                        original.qualifierClientAddress == closure.client!!.clientIp
                    else mode == QualificationExecutionMode.HOST_NATIVE &&
                        value(definition, "serviceId").let { it == "mastodon-rss-publisher" ||
                            it == "rss-jobs" || it.startsWith("rss-pack-") } &&
                        original.nativeClientCapabilities == setOf("rss-mastodon") &&
                        original.qualifierClientInvocationId == null &&
                        original.qualifierClientContainerId == null &&
                        original.qualifierClientAddress == null) &&
                    installIntent.action == "install" && removeIntent.action == "remove" &&
                    installed.operation == installOp && installed.action == "install" &&
                    installed.intentSha256 == sha(installIntentBytes) &&
                    removed.operation == removeOp && removed.action == "remove" &&
                    removed.intentSha256 == sha(removeIntentBytes) &&
                    installed.beforeSha256 == TransactionalCaddy.digest(installIntent.before) &&
                    installed.afterSha256 == TransactionalCaddy.digest(installIntent.after) &&
                    removed.beforeSha256 == TransactionalCaddy.digest(removeIntent.before) &&
                    removed.afterSha256 == TransactionalCaddy.digest(removeIntent.after) &&
                    installIntent.after == removeIntent.before &&
                    installIntent.before == removeIntent.after &&
                    installed.afterSha256 == removed.beforeSha256 &&
                    installed.beforeSha256 == removed.afterSha256)
            }
            closure
        }
        require(seen == byKey.keys)
        return closures
    }
}
