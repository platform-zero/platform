package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class QuadletStageFailureObservation(val schemaVersion: Int = 1,
    val bundleSha256: String, val member: String, val phase: String, val failureClass: String,
    val systemdObservation: QuadletSystemdServingObservation? = null,
    val originalStartAuthorized: Boolean = false, val lastReadinessProbe: String? = null,
    /** Taken at stage failure, not a retroactive claim about the first helper denial. */
    @OptIn(kotlinx.serialization.ExperimentalSerializationApi::class)
    @kotlinx.serialization.EncodeDefault(kotlinx.serialization.EncodeDefault.Mode.NEVER)
    val postFailureOwnerProofCategory: QuadletOwnerProof? = null)
@Serializable internal data class QuadletMemberStart(val schemaVersion: Int = 1, val bundleSha256: String,
    val member: String, val process: String, val installedAuditSha256: String, val containerId: String,
    val status: RuntimeStatus)
/** Point-in-time host availability, NOT process RSS or an original lifecycle ACK. */
@Serializable internal data class QuadletStartupHeadroom(val schemaVersion: Int = 1,
    val bundleSha256: String, val member: String, val process: String, val whenObserved: String,
    val memAvailableMiB: Long, val usableDiskMiB: Long, val protectedMemoryFloorMiB: Long,
    val protectedDiskFloorMiB: Long, val nextCeilingPlusOwnerMarginMiB: Long,
    val reservedAuxiliaryMiB: Long, val workingEnvelopeSha256: String,
    val originalContainerId: String? = null)

internal fun quadletReadinessBudgetSeconds(process: RuntimeProcess): Long =
    if (process.id == "grafana") 300 else 90

/** Actual owner-side systemd actuator. Caller holds RSS/generation/member exclusion from
 * before capacity admission until final readback, including every StartUnit/StopUnit wait.
 * No PrivateDeployment.apply, Podman run, enable, restart or remove is invoked here.
 */
internal class RuntimeQuadletOwnerStage(private val generationRoot: Path, private val runtimeRoot: Path,
    private val generationBase: Path = GenerationRuntime.BASE,
    private val installed: (PrivateDeploymentSpec, RuntimeProcess) -> String = { spec, p ->
        RuntimeQuadletInstalledAudit().audit(spec, p)
    }, private val manager: QuadletUnitManager = RuntimeQuadletSystemd,
    private val resources: (PrivateDeploymentSpec, String, Map<String, String>) -> Unit = { spec, fp, hashes ->
        RuntimeQuadletResources(generationRoot, runtimeRoot).provision(spec, fp, hashes)
    }, private val ready: (PrivateDeploymentSpec, RuntimeProcess, String) -> RuntimeStatus = { spec, p, cid ->
        // A first-use Grafana volume can spend >90s on its original SQLite schema
        // migrations while the CID remains running and kernel-confined. Keep the
        // same original StartUnit and its exact HTTP /api/health barrier; do not
        // convert a migration log or a container liveness check into readiness.
        RuntimeQuadletReadiness.waitFor(spec, p, cid,
            durationSeconds = quadletReadinessBudgetSeconds(p))
    },
    private val initializerCommands: (PrivateDeploymentSpec) -> RuntimeCommands = { spec ->
        PrivateRootfulCommands(30, spec.store)
    }, private val systemdServing: (String, String, RuntimeStore) -> Unit = RuntimeQuadletSystemd::requireServing,
    private val beforeProcessStart: (RuntimeProcess) -> Unit = {}) {
    private val json = Json { encodeDefaults = true }
    /** Stop exactly the graph-owned original notebook service while the serving
     * generation owner retains its native generation and member locks. The parent
     * episode actuator consumes the original helper result; no STOP retry exists.
     */
    fun stopOriginalNotebook(bundle: GenerationBundle, expected: String, pin: GenerationPin,
        user: String): QuadletStopResult {
        require(NotebookSelectedGraph.selected(generationRoot,pin.spec) && user in setOf("alice","bob") &&
            bundle.members.singleOrNull() == pin &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"))) == expected)
        val p = pin.spec.processes.single { it.id == user }
        val start = json.decodeFromString<QuadletMemberStart>(ReleasePrivateFiles.read(
            generationRoot.resolve("quadlet-member-${pin.spec.name}-$user.result.json"),8192)
            .decodeToString(throwOnInvalidSequence=true))
        require(start.bundleSha256 == expected && start.member == pin.spec.name && start.process == user)
        RuntimeQuadletDelegation(generationRoot,runtimeRoot,generationBase,installed=installed)
            .begin(bundle.request.id,expected,pin.spec,p,"stop",pin.runtimeFingerprint)
        manager.change("stop","${RuntimeQuadlets.unit(pin.spec,p)}.service")
        val path = generationRoot.resolve("quadlet-stop-${pin.spec.name}-$user.result.json")
        val stop = json.decodeFromString<QuadletStopResult>(ReleasePrivateFiles.read(path,8192)
            .decodeToString(throwOnInvalidSequence=true))
        require(stop.stopped && stop.containerId == start.containerId &&
            stop.intentSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(generationRoot.resolve(
                "quadlet-stop-${pin.spec.name}-$user.intent.json"),8192)))
        return stop
    }
    /** Controller retains both locks through the entire serving episode. StopUnit is
     * single-use for each retained CID; missing native ACK remains uncertain and fenced.
     */
    fun stop(bundle: GenerationBundle, expected: String, pin: GenerationPin): Map<String, String> {
        require(bundle.members.singleOrNull() == pin && expected.matches(Regex("[a-f0-9]{64}")) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"))) == expected)
        val spec = pin.spec
        val delegated = RuntimeQuadletDelegation(generationRoot, runtimeRoot, generationBase, installed = installed)
        val stopped = linkedMapOf<String, String>()
        for (p in PrivateDeployment.validate(spec).asReversed()) {
            if (p.id in setOf("alice","bob") && NotebookSelectedGraph.selected(generationRoot,spec)) {
                val episodes = NotebookLifecycleEpisodes(generationRoot,spec.name,p.id,
                    RuntimeQuadlets.render(spec).specSha256,p.memoryMiB)
                val past = episodes.completed()
                if (past.isNotEmpty()) {
                    require(past.last().second.releasedWorkingReservationMiB == p.memoryMiB)
                    stopped[p.id] = past.last().second.nativeContainerId
                    continue
                }
            }
            val start = generationRoot.resolve("quadlet-member-${spec.name}-${p.id}.result.json")
            if (!Files.exists(start, NOFOLLOW_LINKS)) continue
            val original = json.decodeFromString<QuadletMemberStart>(ReleasePrivateFiles.read(start, 8192)
                .decodeToString(throwOnInvalidSequence = true))
            require(original.member == spec.name && original.process == p.id &&
                original.bundleSha256 == expected)
            delegated.begin(bundle.request.id, expected, spec, p, "stop", pin.runtimeFingerprint)
            manager.change("stop", "${RuntimeQuadlets.unit(spec, p)}.service")
            val outcome = generationRoot.resolve("quadlet-stop-${spec.name}-${p.id}.result.json")
            // A successful StopUnit return is not the helper's original native ACK. The
            // container may already have exited, or ExecStopPost may have failed after
            // StopUnit. Do not let an unhelpful NoSuchFileException suggest a safe retry.
            require(Files.exists(outcome, NOFOLLOW_LINKS)) {
                "Original stop result absent for ${p.id}; native effect uncertain, retain intent and fence; do not replay"
            }
            val result = json.decodeFromString<QuadletStopResult>(ReleasePrivateFiles.read(outcome, 8192)
                .decodeToString(throwOnInvalidSequence = true))
            require(result.schemaVersion == 1 && result.stopped && result.containerId == original.containerId &&
                result.intentSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(generationRoot.resolve(
                    "quadlet-stop-${spec.name}-${p.id}.intent.json"), 8192))) {
                "Stopped unit lacks original retained-CID result"
            }
            stopped[p.id] = result.containerId
        }
        require(stopped.size == spec.processes.size) { "Incomplete controlled systemd stop" }
        return stopped
    }
    private fun requireFreshStartupHeadroom(request: GenerationRequest, nextWorkingMiB: Long): Pair<Long,Long> {
        require(request.store == RuntimeStore.CANONICAL_V2 && nextWorkingMiB in 0..1048576)
        val row = Files.readAllLines(Path.of("/proc/meminfo")).single { it.startsWith("MemAvailable:") }
            .trim().split(Regex("\\s+"))
        require(row.size == 3 && row[2] == "kB")
        val available = row[1].toLong() / 1024
        val usable = Files.getFileStore(runtimeRoot).usableSpace / 1048576
        require(available >= Math.addExact(request.memoryHeadroomMiB,nextWorkingMiB) &&
            usable >= Math.addExact(request.diskHeadroomMiB,
                if (nextWorkingMiB == 0L) 0L else 512L)) {
            "Serialized native process start would violate protected memory/disk headroom"
        }
        return available to usable
    }

    fun stage(bundle: GenerationBundle, expected: String, pin: GenerationPin): List<RuntimeStatus> {
        require(bundle.members.contains(pin) && bundle.request.id == pin.member.name.take(14) &&
            expected.matches(Regex("[a-f0-9]{64}")) && generationRoot ==
            generationBase.resolve(bundle.request.id) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"))) == expected &&
            pin.spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
            pin.spec.store == RuntimeStore.CANONICAL_V2 &&
            bundle.recoverySourceArchiveSha256 == null &&
            (bundle.recoverySourceKopia == null || (bundle.ownership == null && pin.spec.processes.none { it.oneShot }))) {
            "Only sealed owned Quadlet generation may run installed units"
        }
        val spec = pin.spec
        val memberRoot = runtimeRoot.resolve(spec.name)
        ReleasePrivateFiles.directory(memberRoot)
        require(!Files.exists(memberRoot.resolve("runtime.owner"), NOFOLLOW_LINKS) &&
            RuntimeMaintenance.read(memberRoot, pin.runtimeFingerprint) == null)
        // Audit the complete unit set before any resource or process effect. A partial
        // installed bundle cannot run its first initializer.
        spec.processes.forEach { installed(spec, it) }
        if (bundle.recoverySourceKopia == null) resources(spec, pin.runtimeFingerprint, pin.inputHashes)
        else {
            val snapshot = requireNotNull(bundle.recoverySourceKopia)
            val imported = json.decodeFromString<GenerationOutcome>(ReleasePrivateFiles.read(
                generationRoot.resolve("import.result.json"), 8192).decodeToString())
            val receipt = json.decodeFromString<KopiaSnapshotReceipt>(ReleasePrivateFiles.read(
                generationRoot.resolve("recovery.source.json"), 8192).decodeToString())
            val volumes = json.decodeFromString<List<QuadletColdImportVolumeResult>>(ReleasePrivateFiles.read(
                generationRoot.resolve("quadlet-import-member.result.json"), 65536).decodeToString())
            require(imported.action == "restore-import" && imported.bundleSha256 == expected && imported.passed &&
                receipt == snapshot && volumes.map { it.volume } == spec.volumes.map { it.id } &&
                volumes.all { it.member == spec.name && it.fingerprint == pin.runtimeFingerprint &&
                    it.originalArchiveSha256.matches(Regex("[a-f0-9]{64}")) && it.entries > 0 }) {
                "Recovered target lacks its original native volume import and Kopia lineage"
            }
            RuntimeQuadletResources(generationRoot, runtimeRoot).auditProvisioned(spec,
                pin.runtimeFingerprint, pin.inputHashes)
        }
        val daemonEnvironment = memberRoot.resolve("runtime.quadlet.env")
        val envBytes = "P0_RUNTIME_FINGERPRINT=${pin.runtimeFingerprint}\n".toByteArray()
        if (Files.exists(daemonEnvironment, NOFOLLOW_LINKS)) {
            require(ReleasePrivateFiles.read(daemonEnvironment, 8192).contentEquals(envBytes)) {
                "Changed daemon Quadlet environment"
            }
        } else ReleasePrivateFiles.save(daemonEnvironment, envBytes)
        val ledger = RuntimeQuadletInitializer(generationRoot, spec, pin.runtimeFingerprint, runtimeRoot)
        val delegated = RuntimeQuadletDelegation(generationRoot, runtimeRoot, generationBase,
            installed = installed)
        val statuses = mutableListOf<RuntimeStatus>()
        var phase = "before-unit-start"
        try {
            for (p in PrivateDeployment.validate(spec)) {
                beforeProcessStart(p)
                val original = generationRoot.resolve("quadlet-member-${spec.name}-${p.id}.intent.json")
                val completed = generationRoot.resolve("quadlet-member-${spec.name}-${p.id}.result.json")
                require(!Files.exists(original, NOFOLLOW_LINKS) && !Files.exists(completed, NOFOLLOW_LINKS)) {
                    "Original systemd unit start already attempted"
                }
                phase = "${p.id}:original-start-preparation"
                val audit = installed(spec, p)
                val nextCeilingPlusMargin = Math.addExact(p.memoryMiB.toLong(), 512L)
                val reservedAuxiliary = GenerationManagedComponents.memoryReservationMiB(bundle.request)
                bundle.request.workingBudget?.let { budget ->
                    // The envelope estimates simultaneous *working* load, not a
                    // promise that this next start cannot consume its full cgroup
                    // limit. Serialize and admit ONE next ceiling plus 512 MiB of
                    // out-of-cgroup systemd/conmon/startup overhead against the
                    // live host floor. Never sum all 132 ceilings as resident RAM.
                    require(budget.workingMiB.getValue("${spec.name}/${p.id}") <= p.memoryMiB)
                    val (available, usable) = requireFreshStartupHeadroom(bundle.request,
                        Math.addExact(nextCeilingPlusMargin, reservedAuxiliary))
                    ReleasePrivateFiles.save(generationRoot.resolve("startup-headroom-${spec.name}-${p.id}-before.json"),
                        json.encodeToString(QuadletStartupHeadroom(bundleSha256 = expected, member = spec.name,
                            process = p.id, whenObserved = "before-original-intent", memAvailableMiB = available,
                            usableDiskMiB = usable, protectedMemoryFloorMiB = bundle.request.memoryHeadroomMiB,
                            protectedDiskFloorMiB = bundle.request.diskHeadroomMiB,
                            nextCeilingPlusOwnerMarginMiB = nextCeilingPlusMargin,
                            reservedAuxiliaryMiB = reservedAuxiliary,
                            workingEnvelopeSha256 = budget.evidence.sha256)).toByteArray())
                }
                if (p.oneShot) {
                    ledger.begin(p.id)
                    ledger.prepareEnvironment(p.id)
                }
                val intent = delegated.begin(bundle.request.id, expected, spec, p, "start", pin.runtimeFingerprint)
                ReleasePrivateFiles.save(original, json.encodeToString(intent).toByteArray())
                phase = "${p.id}:systemd-startunit"
                manager.change("start", "${RuntimeQuadlets.unit(spec, p)}.service")
                phase = "${p.id}:original-helper-cid-readback"
                // The original helper ACK and gated process result MUST both exist before
                // readiness; systemd reporting 'active' alone is insufficient.
                require(delegated.authorize(bundle.request.id, spec.name, p.id, "start", afterStartAck = true) == intent)
                val launchResult = generationRoot.resolve("quadlet-launch-${spec.name}-${p.id}.result.json")
                // conmon can notify systemd before the foreground JVM's next 200ms CID
                // poll. Wait for the *original* helper result, never reissue StartUnit.
                val ackDeadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(40)
                while (!Files.exists(launchResult, NOFOLLOW_LINKS)) {
                    require(System.nanoTime() < ackDeadline) { "No original foreground CID ACK after systemd readiness" }
                    delegated.authorize(bundle.request.id, spec.name, p.id, "start", afterStartAck = true)
                    Thread.sleep(200)
                }
                val launch = json.decodeFromString<QuadletLaunchResult>(ReleasePrivateFiles.read(
                    launchResult, 8192).decodeToString(throwOnInvalidSequence = true))
                val launchIntent = ReleasePrivateFiles.read(generationRoot.resolve(
                    "quadlet-launch-${spec.name}-${p.id}.intent.json"), 8192)
                require(launch.schemaVersion == 1 && launch.nativeAcknowledged &&
                    launch.intentSha256 == ReleaseLocks.sha256(launchIntent) &&
                    launch.imageId == p.imageId && launch.containerId.matches(Regex("[a-f0-9]{64}"))) {
                    "Systemd unit is not an acknowledged original generated process"
                }
                phase = "${p.id}:native-readiness"
                val status = if (p.oneShot) {
                    ledger.nativeComplete(p.id, initializerCommands(spec))
                    require(ledger.completed(p.id))
                    RuntimeStatus(p.id, "completed", 0)
                } else ready(spec, p, launch.containerId).also {
                    phase = "${p.id}:systemd-notify-mainpid-proof"
                    systemdServing("${RuntimeQuadlets.unit(spec, p)}.service", launch.containerId, spec.store)
                }
                require(status.id == p.id && if (p.oneShot) status.state == "completed" && status.exitCode == 0
                    else status.state == "running")
                bundle.request.workingBudget?.let { budget ->
                    val (available, usable) = requireFreshStartupHeadroom(bundle.request, reservedAuxiliary)
                    ReleasePrivateFiles.save(generationRoot.resolve("startup-headroom-${spec.name}-${p.id}-after.json"),
                        json.encodeToString(QuadletStartupHeadroom(bundleSha256 = expected, member = spec.name,
                            process = p.id, whenObserved = "after-original-readiness", memAvailableMiB = available,
                            usableDiskMiB = usable, protectedMemoryFloorMiB = bundle.request.memoryHeadroomMiB,
                            protectedDiskFloorMiB = bundle.request.diskHeadroomMiB,
                            nextCeilingPlusOwnerMarginMiB = nextCeilingPlusMargin,
                            reservedAuxiliaryMiB = reservedAuxiliary,
                            workingEnvelopeSha256 = budget.evidence.sha256,
                            originalContainerId = launch.containerId)).toByteArray())
                }
                ReleasePrivateFiles.save(completed, json.encodeToString(QuadletMemberStart(
                    bundleSha256 = expected, member = spec.name, process = p.id,
                    installedAuditSha256 = audit, containerId = launch.containerId, status = status)).toByteArray())
                statuses += status
            }
            return statuses
        } catch (failure: Exception) {
            val interrupted = Thread.interrupted() || failure is InterruptedException
            // A failed helper's FIRST proof category belongs to its original journal
            // timestamp. This later owner-side observation is distinct and non-secret.
            val postFailureProof = runCatching {
                val selected = spec.processes.singleOrNull { phase.startsWith("${it.id}:") }
                    ?: return@runCatching null
                val leaseFile = generationRoot.resolve("quadlet-delegate-${spec.name}-${selected.id}-start.intent.json")
                if (!Files.exists(leaseFile, NOFOLLOW_LINKS)) return@runCatching null
                val lease = json.decodeFromString<QuadletDelegationIntent>(
                    ReleasePrivateFiles.read(leaseFile, 8192).decodeToString())
                if (lease.bundleSha256 != expected || lease.member != spec.name ||
                    lease.ownerPid != ProcessHandle.current().pid()) return@runCatching null
                QuadletNativeLockProof.classify(lease.ownerPid, lease.ownerStartTicks,
                    generationRoot.parent.resolve("generation.lock"), memberRoot.resolve("runtime.lock"))
            }.getOrNull()
            try { ReleasePrivateFiles.save(generationRoot.resolve("quadlet-stage-failure.observation.json"),
                json.encodeToString(QuadletStageFailureObservation(bundleSha256 = expected,
                    member = spec.name, phase = phase, failureClass = failure.javaClass.simpleName,
                    systemdObservation = (failure as? QuadletServingProofFailure)?.observation,
                    lastReadinessProbe = (failure as? QuadletReadinessTimeout)?.lastProbe,
                    postFailureOwnerProofCategory = postFailureProof)).toByteArray()) }
            catch (observation: Exception) { failure.addSuppressed(observation) }
            // Predeclare every exact stop delegation BEFORE the fence. Otherwise the
            // still-owned foreground helper interprets the fence as owner death and
            // performs an emergency stop concurrently with the intended StopUnit.
            val attempted = PrivateDeployment.validate(spec).asReversed().filter { p ->
                Files.exists(generationRoot.resolve("quadlet-member-${spec.name}-${p.id}.intent.json"), NOFOLLOW_LINKS) &&
                    !Files.exists(NotebookEpisodePaths.path(generationRoot,
                        "quadlet-delegate-${spec.name}-${p.id}-stop.intent",spec.name,p.id), NOFOLLOW_LINKS)
            }
            // An already attempted original STOP (including the notebook bootstrap
            // retirement) is NEVER selected for a second systemctl StopUnit.
            for (p in attempted) try { delegated.begin(bundle.request.id, expected, spec, p,
                "stop", pin.runtimeFingerprint) }
            catch (stop: Exception) { failure.addSuppressed(stop) }
            try { RuntimeMaintenance.create(memberRoot, pin.runtimeFingerprint, "update", null) }
            catch (fence: Exception) { failure.addSuppressed(fence) }
            // Each systemd stop still targets its retained CID under the SAME owner
            // lock. Missing effects remain fenced and are never replayed here.
            for (p in attempted) {
                if (!Files.exists(NotebookEpisodePaths.path(generationRoot,
                    "quadlet-delegate-${spec.name}-${p.id}-stop.intent",spec.name,p.id), NOFOLLOW_LINKS)) continue
                try { manager.change("stop", "${RuntimeQuadlets.unit(spec, p)}.service") }
                catch (stop: Exception) { failure.addSuppressed(stop) }
            }
            if (interrupted) Thread.currentThread().interrupt()
            throw failure
        }
    }
}
