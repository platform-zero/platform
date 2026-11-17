package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Read-only owner-held RESTORE startup evidence. This is not a functional restore result:
 * it can only be issued with the retained stopped source and acknowledged native import. */
internal object QualificationRestoreStartupProducer {
    private val json = Json { encodeDefaults = true; explicitNulls = true; ignoreUnknownKeys = false }
    // These are the exact initializer sets consumed by the common a08/a12 startup checks.
    // Every ID must be present in the sealed INSTALL graph and absent in the restored graph.
    private val socialInitializers = setOf("mastodon-db-init", "mastodon-db-migrate",
        "mastodon-fresh-users", "mastodon-rss-feature", "mastodon-db-finalize",
        "mastodon-bridge-journal-init")
    private val initializers = mapOf(
        "mastodon" to socialInitializers,
        "onlyoffice" to setOf("seafile-schema-init", "seafile-users-init", "onlyoffice-state-init"),
        "seafile" to setOf("seafile-schema-init", "seafile-users-init"),
        "huly" to setOf("huly-database-init", "huly-elastic-config-init", "huly-elastic-users",
            "huly-account-bootstrap", "huly-redpanda-acl"),
        "homeassistant" to setOf("homeassistant-config-init"),
        "jellyfin" to setOf("jellyfin-media-init"),
        "qbittorrent" to setOf("qbittorrent-config-init"),
        "searxng" to setOf("searxng-corpus-init"),
        "crowdsec" to setOf("crowdsec-guard-init"),
        "opensearch" to setOf("opensearch-config-init", "opensearch-security-init"))

    /** Caller has already verified the completed original INSTALL result/oracle bytes.
     * All other arguments originate in the retained NativeRestoredJourneys owner scope. */
    fun produce(caseDir: Path, service: String, variant: String, originalOracle: ActivationInput,
        restored: RestoredOwnerScope, targetBundle: GenerationBundle,
        originalCase: Path? = null): Map<String, JsonElement> {
        val target = restored.target
        val source = restored.source
        val snapshot = requireNotNull(targetBundle.recoverySourceKopia)
        require(source.id != target.id && source.bundleSha256 == snapshot.bundleSha256 &&
            snapshot.generation == source.id && targetBundle.request.id == target.id &&
            restored.targetPin.spec.name == "${target.id}-v2" &&
            restored.sourcePin.spec.name == "${source.id}-v2" &&
            restored.targetPin.spec.ingress == null &&
            "ingress-egress" !in restored.targetPin.spec.networks)
        require(originalOracle.path == caseDir.resolve("owner-proofs/source-oracle.json").toString())
        val sourceBytes = ReleasePrivateFiles.read(Path.of(originalOracle.path), 1048576)
        require(ReleaseLocks.sha256(sourceBytes) == originalOracle.sha256)
        val targetRoot = GenerationRuntime.BASE.resolve(target.id)
        fun <T> document(path: Path, decode: (String) -> T): Pair<T, String> {
            val raw = ReleasePrivateFiles.read(path, 1048576)
            return decode(raw.decodeToString(throwOnInvalidSequence = true)) to ReleaseLocks.sha256(raw)
        }
        val (intent, _) = document(targetRoot.resolve("stage.intent.json")) {
            json.decodeFromString<GenerationIntent>(it)
        }
        val (stage, importSha) = document(targetRoot.resolve("stage.result.json")) {
            json.decodeFromString<GenerationOutcome>(it)
        }
        require(intent == GenerationIntent("restore-import", target.bundleSha256) &&
            stage.action == "restore-import" && stage.passed && stage.failureType == null &&
            stage.bundleSha256 == target.bundleSha256 && stage.priorIntentSha256 == null &&
            stage.fences.keys == targetBundle.members.map { it.member.name }.toSet())
        val (lineage, _) = document(targetRoot.resolve("recovery.source.json")) {
            json.decodeFromString<KopiaSnapshotReceipt>(it)
        }
        require(lineage == snapshot)
        KopiaGenerationStore.validate(lineage)
        val (checked, _) = document(targetRoot.resolve("recovery.check.json")) {
            json.decodeFromString<GenerationRecoveryCheck>(it)
        }
        require(checked.generation == source.id && checked.bundleSha256 == source.bundleSha256 &&
            checked.capsule == snapshot.id && checked.archiveSha256.isEmpty() &&
            checked.kopiaSnapshotId == snapshot.snapshotId &&
            checked.kopiaReceiptSha256 == KopiaGenerationStore.receiptHash(snapshot) &&
            !checked.runtimeImported && !checked.functionalRestoreVerified &&
            checked.members.map { it.name } == restored.sourcePin.let { listOf(it.spec.name) })
        val member = restored.targetPin
        val (memberIntent, _) = document(targetRoot.resolve("${member.spec.name}.import.intent.json")) {
            json.decodeFromString<GenerationIntent>(it)
        }
        val (memberAudit, _) = document(targetRoot.resolve("${member.spec.name}.import.result.json")) {
            json.decodeFromString<RuntimeAudit>(it)
        }
        require(memberIntent == GenerationIntent("import-member", target.bundleSha256) &&
            memberAudit.name == member.spec.name && memberAudit.fingerprint == member.runtimeFingerprint &&
            memberAudit.maintenanceId == stage.fences.getValue(member.spec.name))
        val nativeImportMarker = "p0v3-native-volume-import-v1\n${member.runtimeFingerprint}\n" +
            "${KopiaGenerationStore.receiptHash(snapshot)}\n"
        for (name in listOf("runtime.import.intent", "runtime.import.complete"))
            require(ReleasePrivateFiles.read(PrivateDeployment.BASE.resolve(member.spec.name).resolve(name), 65536)
                .contentEquals(nativeImportMarker.encodeToByteArray())) {
                "Native imported source lineage changed"
            }
        val (stopped, stoppedSha) = document(Path.of(restored.quiescence.path)) {
            json.decodeFromString<ListenerBridgeQuiesceResult>(it)
        }
        require(stoppedSha == restored.quiescence.sha256 && stopped == restored.listener &&
            stopped.sourceStoppedProofSha256.matches(Regex("[a-f0-9]{64}")))
        val (ready, readySha) = document(Path.of(restored.readiness.path)) {
            json.decodeFromString<RuntimeAudit>(it)
        }
        require(readySha == restored.readiness.sha256 && ready.name == member.spec.name &&
            ready.fingerprint == member.runtimeFingerprint && ready.maintenanceId == null &&
            ready.statuses.map { it.id }.toSet() == member.spec.processes.map { it.id }.toSet() &&
            member.spec.processes.all { process ->
                val status = ready.statuses.single { it.id == process.id }
                if (process.oneShot) status.state in setOf("completed", "exited") && status.exitCode == 0
                else status.state == "running"
            })
        // Read the immutable effective head, rather than accepting a pre-seal credential claim.
        val running = PrivateDeployment.real(mapOf(member.spec.name to member.runtimeFingerprint)).audit(member.spec)
        require(running.name == member.spec.name && running.fingerprint == member.runtimeFingerprint &&
            running.maintenanceId == null && running.statuses.map { it.id }.toSet() ==
                member.spec.processes.map { it.id }.toSet() && member.spec.processes.all { process ->
                val status = running.statuses.single { it.id == process.id }
                if (process.oneShot) status.state in setOf("completed", "exited") && status.exitCode == 0
                else status.state == "running"
            })
        val runningBytes = json.encodeToString(running).encodeToByteArray()
        ReleasePrivateFiles.save(caseDir.resolve("owner-proofs/private-running.json"), runningBytes)
        val runningSha = ReleaseLocks.sha256(runningBytes)
        val isolationBytes = json.encodeToString(buildJsonObject {
            put("sourceGeneration", source.id); put("targetGeneration", target.id)
            put("sourceStoppedProofSha256", stopped.sourceStoppedProofSha256)
            put("targetPrivateReadinessSha256", readySha)
            put("targetNativeRunningSha256", runningSha)
            put("targetManifestSha256", member.manifestSha256)
            put("targetFingerprint", member.runtimeFingerprint)
            put("targetIngressAbsent", true)
        }).encodeToByteArray()
        ReleasePrivateFiles.save(caseDir.resolve("owner-proofs/target-isolation.json"), isolationBytes)
        val isolationSha = ReleaseLocks.sha256(isolationBytes)
        val head = requireNotNull(NativeCredentialRevision.readHead(targetRoot))
        require(head.generation == target.id && head.bundleSha256 == target.bundleSha256)
        val headFile = targetRoot.resolve("credential-revisions/public/head.json")
        val headSha = ReleaseLocks.sha256(ReleasePrivateFiles.read(headFile, 65536))
        // The exact source-only initializer IDs, not a caller-proposed "not replayed" boolean.
        val expected = if (service == "mastodon-rss-publisher" || service == "rss-jobs" ||
            service.startsWith("rss-pack-")) socialInitializers else initializers[service].orEmpty()
        val sourceProcesses = restored.sourcePin.spec.processes.associateBy { it.id }
        val targetProcesses = member.spec.processes.map { it.id }.toSet()
        require(expected.all { sourceProcesses[it]?.oneShot == true && it !in targetProcesses })
        val receipt = buildJsonObject {
            put("schemaVersion", 1); put("serviceId", service); put("variant", variant)
            put("sourceGeneration", source.id); put("targetGeneration", target.id)
            put("snapshotId", snapshot.snapshotId)
            put("sourceHeldProofSha256", restored.heldCapture?.sha256 ?: stoppedSha)
            put("importProofSha256", importSha)
            put("isolationProofSha256", isolationSha)
            put("privateRunningProofSha256", runningSha)
            put("readinessProofSha256", readySha)
            put("sourceOracleSha256", originalOracle.sha256)
            put("effectiveCredentialRevisionHeadSha256", headSha)
            putJsonObject("nativeInitializerResults") {
                expected.sorted().forEach { put(it, "absent-from-restored-process-graph") }
            }
        }
        val managedPi = if (service == "pi" && variant == "NATIVE") {
            val originalDir = requireNotNull(originalCase)
            require(originalDir.fileName.toString() == "pi--workflow--headless--native" &&
                originalDir != caseDir && originalDir.resolve("oracle.json").let {
                    ReleaseLocks.sha256(ReleasePrivateFiles.read(it,1048576)) == originalOracle.sha256 })
            val attempt = originalDir.resolve("pi-original-tool-attempt.result.json")
            val bytes = ReleasePrivateFiles.read(attempt,8192)
            val original = ActivationInput(originalDir.resolve("oracle.json").toString(),originalOracle.sha256)
            val sourceAttempt = ActivationInput(attempt.toString(),ReleaseLocks.sha256(bytes))
            ManagedRestoreStartupReceiptProducer.afterNativeStart(targetBundle,targetRoot,original,sourceAttempt)
        } else { require(originalCase == null); null }
        val file = caseDir.resolve("owner-proofs/restore-startup.json")
        val bytes = json.encodeToString(receipt).encodeToByteArray()
        ReleasePrivateFiles.save(file, bytes) // create-new; a pending or conflicting attempt is never adopted
        return mapOf("restoreStartupReceiptFile" to JsonPrimitive(file.toString()),
            "restoreStartupReceiptSha256" to JsonPrimitive(ReleaseLocks.sha256(bytes)),
            "sourceOracleFile" to JsonPrimitive(originalOracle.path),
            "sourceOracleFileSha256" to JsonPrimitive(originalOracle.sha256),
            "effectiveCredentialRevisionHeadSha256" to JsonPrimitive(headSha),
            "targetIsolationProofSha256" to JsonPrimitive(isolationSha)) + (managedPi?.let {
                mapOf("managedRestoreStartupReceiptPath" to JsonPrimitive(it.path),
                    "managedRestoreStartupReceiptSha256" to JsonPrimitive(it.sha256))
            } ?: emptyMap())
    }
}
