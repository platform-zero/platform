package net.datamancy.platform

import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Serializable internal data class QuadletLaunchIntent(val schemaVersion: Int = 1, val delegationSha256: String,
    val member: String, val process: String, val generatedArgvSha256: String, val fingerprint: String)
@Serializable internal data class QuadletLaunchResult(val schemaVersion: Int = 1, val intentSha256: String,
    val containerId: String, val imageId: String, val nativeAcknowledged: Boolean)
/** Bound post-error classification, saved before any helper containment. Not a native ACK. */
@Serializable internal data class QuadletHelperFailureObservation(val schemaVersion: Int = 1,
    val member: String, val process: String, val originalLaunchIntentSha256: String,
    val ownerPid: Long, val ownerStartTicks: Long, val firstFailureClass: String,
    val postFailureOwnerProof: QuadletOwnerProof, val originalLaunchResultPresent: Boolean)

/** ExecStart itself checks the living owner; ExecStartPre cannot hand a durable start
 * capability to systemd. A launch intent is durable BEFORE the only native run. No fallback
 * to the historical PrivateDeployment.apply or retry of an uncertain original is possible.
 */
internal class RuntimeQuadletUnitRun(private val root: Path,
    private val delegation: RuntimeQuadletDelegation,
    private val generated: (PrivateDeploymentSpec, RuntimeProcess) -> List<String> =
        RuntimeQuadletGeneratedStart::fromPinnedGenerator,
    private val native: RuntimeCommands = PrivateRootfulCommands(45, RuntimeStore.CANONICAL_V2),
    private val launch: (List<String>, () -> Unit) -> RuntimeCommandResult = ::ownedGeneratedLaunch,
    private val foreground: (List<String>, () -> Unit, () -> Boolean, () -> Boolean, () -> Boolean) -> RuntimeCommandResult =
        ::ownedForegroundLaunch,
    private val runtimeRoot: Path = PrivateDeployment.BASE,
    // Only mock fault tests may opt in until the helper keeps the systemd foreground
    // MainPID alive while acknowledging and supervising a serving container.
    private val mockForegroundCustody: Boolean = false,
    private val generationBase: Path = GenerationRuntime.BASE,
    private val guardInstalled: (PrivateDeploymentSpec, RuntimeProcess) -> String = { spec, p ->
        RuntimeQuadletInstalledAudit().audit(spec, p)
    },
    private val guardController: (String) -> Unit = PinnedBackupController::verify,
    private val kernelConfinement: (PrivateDeploymentSpec, RuntimeProcess, String, Long) -> Unit =
        { spec, process, cid, pid -> RuntimeQuadletKernelConfinement.verify(spec, process, cid, pid) },
    private val ownerProof: (QuadletDelegationIntent) -> QuadletOwnerProof = { lease ->
        QuadletNativeLockProof.classifyStable(lease.ownerPid, lease.ownerStartTicks,
            generationBase.resolve("generation.lock"), runtimeRoot.resolve(lease.member).resolve("runtime.lock"))
    }) {
    private val json = Json { encodeDefaults = true }
    fun run(generation: String, member: String, process: String): QuadletLaunchResult {
        val lease = delegation.authorize(generation, member, process, "start", afterStartAck = true)
        val bundle = ReleasePrivateFiles.read(root.resolve("bundle.json"), 1048576)
        require(ReleaseLocks.sha256(bundle) == lease.bundleSha256)
        val generationBundle=json.decodeFromString<GenerationBundle>(bundle.decodeToString(throwOnInvalidSequence = true))
        val spec = generationBundle.members.single { it.spec.name == member }.spec
        val p = spec.processes.single { it.id == process }
        if (p.lateEnvironmentFile != null) {
            require(p.id == "keeper")
            if (generationBundle.recoverySourceKopia != null)
                GenerationBaoColdRestore.requireLate(generationBundle,lease.bundleSha256)
            else GenerationFreshBaoStage.requireLate(generationBundle,lease.bundleSha256)
        }
        // A long-lived helper MUST itself remain the foreground systemd ExecStart.
        // The legacy short-lived mock path is exclusively injectable by unit tests.
        val argv = generated(spec, p)
        val originalInitializer = if (p.oneShot) ReleaseLocks.sha256(ReleasePrivateFiles.read(
            root.resolve("quadlet-$process.intent.json"), 8192)) else null
        val expanded = RuntimeQuadletGeneratedStart.expand(argv, spec, p, lease.fingerprint, originalInitializer)
        val intentPath = NotebookEpisodePaths.path(root,"quadlet-launch-$member-$process.intent",member,process)
        val resultPath = NotebookEpisodePaths.path(root,"quadlet-launch-$member-$process.result",member,process)
        require(!Files.exists(intentPath, NOFOLLOW_LINKS) && !Files.exists(resultPath, NOFOLLOW_LINKS)) {
            "Original Quadlet launch exists; reconcile, do not replay"
        }
        val name = "p0v3-live-$member-$process"
        val census = native.run(listOf("container", "ls", "--all", "--format", "{{.Names}}"))
        require(census.exitCode == 0 && census.output.toByteArray().size <= 2_000_000 &&
            census.output.lineSequence().none { it.trim() == name }) {
            "Named Quadlet container already exists; no replace or new launch"
        }
        val admission = ReleasePrivateFiles.read(NotebookEpisodePaths.path(root,
            "quadlet-delegate-$member-$process-start.intent",member,process), 8192)
        val intent = QuadletLaunchIntent(delegationSha256 = ReleaseLocks.sha256(admission), member = member,
            process = process, generatedArgvSha256 = ReleaseLocks.sha256(expanded.joinToString("\u0000").toByteArray()),
            fingerprint = lease.fingerprint)
        val bytes = json.encodeToString(intent).toByteArray()
        ReleasePrivateFiles.save(intentPath, bytes)
        // The owner may have died while generating or fsyncing the original intent. Check
        // again at the last possible boundary; the launch transport keeps polling it.
        val stopDelegation = NotebookEpisodePaths.path(root,
            "quadlet-delegate-$member-$process-stop.intent",member,process)
        val check = {
            if (!p.oneShot && Files.exists(stopDelegation, NOFOLLOW_LINKS)) {
                val stopping = delegation.authorize(generation, member, process, "stop")
                require(stopping.ownerPid == lease.ownerPid && stopping.ownerStartTicks == lease.ownerStartTicks &&
                    stopping.fingerprint == lease.fingerprint && stopping.bundleSha256 == lease.bundleSha256) {
                    "Foreign or dead Quadlet stop owner"
                }
            } else require(delegation.authorize(generation, member, process, "start", afterStartAck = true) == lease) {
                "Quadlet owner lost before or during generated launch"
            }
        }
        var retained: QuadletLaunchResult? = null
        fun observe(allowAbsent: Boolean): Boolean {
            check()
            val observed = native.run(listOf("container", "inspect", name))
            if (allowAbsent && observed.exitCode != 0) return false
            require(observed.exitCode == 0 && observed.output.toByteArray().size in 1..65536)
            val item = json.parseToJsonElement(observed.output).jsonArray.single().jsonObject
            val cid = item.getValue("Id").jsonPrimitive.content
            val labels = item.getValue("Config").jsonObject.getValue("Labels").jsonObject
            require(cid.matches(Regex("[a-f0-9]{64}")) && item.getValue("Name").jsonPrimitive.content == name &&
                item.getValue("Image").jsonPrimitive.content.removePrefix("sha256:") == p.imageId &&
                item.getValue("Config").jsonObject.getValue("Image").jsonPrimitive.content == p.image &&
                labels.getValue("io.p0v3.private-deployment").jsonPrimitive.content == member &&
                labels.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == lease.fingerprint &&
                (!p.oneShot || labels.getValue("io.p0v3.initializer-intent").jsonPrimitive.content == originalInitializer) &&
                item.getValue("State").jsonObject.getValue("Status").jsonPrimitive.content in
                    (if (p.oneShot) setOf("running", "exited") else setOf("created", "running")) &&
                item.getValue("State").jsonObject.getValue("Running").jsonPrimitive.content ==
                    (item.getValue("State").jsonObject.getValue("Status").jsonPrimitive.content == "running").toString()) {
                "Native generated launch identity, image or state changed"
            }
            // Podman exposes a correctly labeled CID in CREATED before its single
            // original `run` has entered RUNNING. This is PENDING, not a start ACK
            // and not evidence for a second run; keep polling the same command/CID
            // until the fixed foreground deadline. A changed identity still rejects.
            if (!p.oneShot && item.getValue("State").jsonObject.getValue("Status").jsonPrimitive.content == "created") {
                require(item.getValue("State").jsonObject.getValue("Running").jsonPrimitive.content == "false")
                check()
                return false
            }
            check()
            if (!p.oneShot) kernelConfinement(spec, p, cid,
                item.getValue("State").jsonObject.getValue("Pid").jsonPrimitive.content.toLong())
            retained = QuadletLaunchResult(intentSha256 = ReleaseLocks.sha256(bytes), containerId = cid,
                imageId = p.imageId, nativeAcknowledged = true)
            ReleasePrivateFiles.save(resultPath, json.encodeToString(requireNotNull(retained)).toByteArray())
            return true
        }
        try {
            check()
            if (!p.oneShot && !mockForegroundCustody) {
                // Persist CID while the generated Podman command AND this JVM are still
                // running. Return from ExecStart only after an owner-authorized StopUnit.
                val unit = "${RuntimeQuadlets.unit(spec, p)}.service"
                val reply = foreground(expanded, check,
                    { if (retained != null) true else observe(allowAbsent = true) },
                    {
                        // Podman 5.4.2 can return 0 immediately after conmon sends
                        // READY and transfers systemd MainPID to root conmon. Keep
                        // THIS helper alive as an owner-loss guardian while systemd
                        // supervises that exact original CID's conmon PID.
                        val cid = requireNotNull(retained).containerId
                        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(12)
                        while (true) {
                            check()
                            val nativeState = native.run(listOf("container", "inspect", name))
                            require(nativeState.exitCode == 0 && nativeState.output.toByteArray().size in 1..65536)
                            val current = json.parseToJsonElement(nativeState.output).jsonArray.single().jsonObject
                            require(current.getValue("Id").jsonPrimitive.content == cid &&
                                current.getValue("State").jsonObject.getValue("Running").jsonPrimitive.content == "true") {
                                "Original conmon-owned CID changed before supervisor custody"
                            }
                            try {
                                RuntimeQuadletSystemd.requireServing(unit, cid, spec.store)
                                break
                            } catch (notYet: QuadletServingProofFailure) {
                                require(notYet.observation.activeState == "activating" &&
                                    System.nanoTime() < deadline) {
                                    "Systemd did not bind READY and conmon MainPID to the retained CID"
                                }
                                Thread.sleep(200)
                            }
                        }
                        true
                    },
                    { Files.exists(stopDelegation, NOFOLLOW_LINKS) })
                require(Files.exists(stopDelegation, NOFOLLOW_LINKS) && retained != null) {
                    "Foreground process exited without an original controlled StopUnit"
                }
                // Podman run can return a nonzero signal status when a separate
                // systemd ExecStop successfully stops the exact CID. Never turn
                // that exit code into a second native stop or a fabricated ACK.
                // Wait for the ORIGINAL stop helper's fsynced result and verify
                // its CID, intent hash, and native terminal state instead.
                val stopIntent = NotebookEpisodePaths.path(root,"quadlet-stop-$member-$process.intent",member,process)
                val stopResult = NotebookEpisodePaths.path(root,"quadlet-stop-$member-$process.result",member,process)
                val stopDeadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(45)
                while (!Files.exists(stopResult, NOFOLLOW_LINKS)) {
                    check()
                    require(System.nanoTime() < stopDeadline) { "Original controlled stop ACK missing" }
                    Thread.sleep(200)
                }
                val stop = json.decodeFromString<QuadletStopResult>(ReleasePrivateFiles.read(stopResult, 8192)
                    .decodeToString(throwOnInvalidSequence = true))
                require(stop.stopped && stop.containerId == requireNotNull(retained).containerId &&
                    stop.intentSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(stopIntent, 8192))) {
                    "Foreign original controlled stop result"
                }
                val terminal = native.run(listOf("container", "inspect", name))
                require(terminal.exitCode == 0 && terminal.output.toByteArray().size in 1..65536)
                val item = json.parseToJsonElement(terminal.output).jsonArray.single().jsonObject
                require(item.getValue("Id").jsonPrimitive.content == stop.containerId &&
                    item.getValue("State").jsonObject.getValue("Running").jsonPrimitive.content == "false") {
                    "Controlled StopUnit did not isolate exact original CID"
                }
                check()
                return requireNotNull(retained)
            }
            val reply = launch(expanded, check)
            require(reply.exitCode == 0 && reply.output.toByteArray().size <= 4096) {
                "Generated Podman launch ACK missing or failed; original intent retained"
            }
            observe(allowAbsent = false)
            return requireNotNull(retained)
        } catch (failure: Exception) {
            val interrupted = Thread.interrupted() || failure is InterruptedException
            try {
                val proof = ownerProof(lease)
                // Capture a bounded non-secret error category BEFORE an independent
                // fence/stop can change the original owner's next admission check.
                val failureRecord = NotebookEpisodePaths.path(root,
                    "quadlet-helper-failure-$member-$process.observation",member,process)
                require(!Files.exists(failureRecord, NOFOLLOW_LINKS)) {
                    "Prior original helper failure; no second containment effect"
                }
                ReleasePrivateFiles.save(failureRecord, json.encodeToString(QuadletHelperFailureObservation(
                    member = member, process = process, originalLaunchIntentSha256 = ReleaseLocks.sha256(bytes),
                    ownerPid = lease.ownerPid, ownerStartTicks = lease.ownerStartTicks,
                    firstFailureClass = failure.javaClass.simpleName, postFailureOwnerProof = proof,
                    originalLaunchResultPresent = Files.exists(resultPath, NOFOLLOW_LINKS))).toByteArray())
                when (proof) {
                    QuadletOwnerProof.VERIFIED ->
                        containUncertainLaunch(spec, p, lease.fingerprint, name, intentPath)
                    QuadletOwnerProof.PID_MISSING, QuadletOwnerProof.START_TICKS_CHANGED ->
                        RecoveryDeadline.within(120_000) {
                            // Only a demonstrably departed original owner permits this
                            // separate serialized owner-loss native containment.
                            withBoundedOwnerLossLock(member) {
                                containUncertainLaunch(spec, p, lease.fingerprint, name, intentPath)
                            }
                        }
                    else -> error("Original owner proof $proof is uncertain; never label a living owner dead")
                }
            } catch (containment: Exception) { failure.addSuppressed(containment) }
            if (interrupted) Thread.currentThread().interrupt()
            throw failure
        }
    }

    /** Only owner-loss containment can wait for a competing helper in the same JVM.
     * Retry is limited to admission BEFORE the original callback, which has no effects
     * until locks are held. Once admitted, any exception (including overlap) is final.
     */
    private fun <T> withBoundedOwnerLossLock(member: String, action: () -> T): T {
        while (true) {
            var entered = false
            try {
                return PrivateDeployment.withOrderedNativeLocks(listOf(member), runtimeRoot) {
                    entered = true
                    action()
                }
            } catch (overlap: OverlappingFileLockException) {
                if (entered) throw overlap // No replay after any possible native effect.
                require(RecoveryDeadline.remainingMillis() > 200L) {
                    "Owner-loss member lock unavailable within original containment deadline"
                }
                Thread.sleep(100)
            }
        }
    }

    /** Independent systemd ExecStopPost guard if the foreground JVM is killed before
     * its catch/finally can run. It never accepts a new launch or replays an uncertain
     * native stop; a missing CID remains fenced and explicitly nonterminal.
     */
    fun guard(generation: String, member: String, process: String) {
        require(root == generationBase.resolve(generation) && member.startsWith("$generation-"))
        val bytes = ReleasePrivateFiles.read(root.resolve("bundle.json"), 1048576)
        val bundle = json.decodeFromString<GenerationBundle>(bytes.decodeToString(throwOnInvalidSequence = true))
        val spec = bundle.members.single { it.spec.name == member }.spec
        val p = spec.processes.single { it.id == process }
        guardController(requireNotNull(spec.fragmentBinding?.controllerSha256))
        val leaseBytes = ReleasePrivateFiles.read(NotebookEpisodePaths.path(root,
            "quadlet-delegate-$member-$process-start.intent",member,process), 8192)
        val lease = json.decodeFromString<QuadletDelegationIntent>(leaseBytes.decodeToString(throwOnInvalidSequence = true))
        require(bundle.request.id == generation && ReleaseLocks.sha256(bytes) == lease.bundleSha256 &&
            lease.schemaVersion == 1 && lease.member == member && lease.process == process &&
            lease.action == "start" && lease.fingerprint == bundle.members.single().runtimeFingerprint &&
            lease.specSha256 == RuntimeQuadlets.render(spec).specSha256 &&
            guardInstalled(spec, p) == lease.installedAuditSha256) {
            "Foreign Quadlet post-exit guard"
        }
        val launchIntent = NotebookEpisodePaths.path(root,"quadlet-launch-$member-$process.intent",member,process)
        if (!Files.exists(launchIntent, NOFOLLOW_LINKS)) return // No native launch was authorized.
        val original = ReleasePrivateFiles.read(launchIntent, 8192)
        val launch = json.decodeFromString<QuadletLaunchIntent>(original.decodeToString(throwOnInvalidSequence = true))
        require(launch.schemaVersion == 1 && launch.member == member && launch.process == process &&
            launch.fingerprint == lease.fingerprint && launch.delegationSha256 == ReleaseLocks.sha256(leaseBytes) &&
            launch.generatedArgvSha256.matches(Regex("[a-f0-9]{64}"))) {
            "Foreign original Quadlet launch intent"
        }
        val proof = ownerProof(lease)
        if (proof == QuadletOwnerProof.VERIFIED) return // Original owner retains StopUnit custody.
        require(proof == QuadletOwnerProof.PID_MISSING || proof == QuadletOwnerProof.START_TICKS_CHANGED) {
            "Original owner proof $proof is uncertain; no independent native stop"
        }
        val result = NotebookEpisodePaths.path(root,"quadlet-owner-loss-$member-$process.result",member,process)
        if (Files.exists(result, NOFOLLOW_LINKS)) return // Prior containment: no second effect.
        RecoveryDeadline.within(120_000) {
            withBoundedOwnerLossLock(member) {
                // A changed/malformed original ACK must not leave a live workload
                // unfenced. Serialize this with all other lost-owner helpers.
                val memberRoot = runtimeRoot.resolve(member)
                if (RuntimeMaintenance.read(memberRoot, lease.fingerprint) == null)
                    RuntimeMaintenance.create(memberRoot, lease.fingerprint, "update", null)
                // Original argv hash binds its fsynced attempt; generator option
                // order is not reproducible. Installed source/policy was audited above.
                val launchResult = NotebookEpisodePaths.path(root,"quadlet-launch-$member-$process.result",member,process)
                val acknowledged = if (Files.exists(launchResult, NOFOLLOW_LINKS)) {
                    json.decodeFromString<QuadletLaunchResult>(ReleasePrivateFiles.read(launchResult, 8192)
                        .decodeToString(throwOnInvalidSequence = true)).also {
                        require(it.schemaVersion == 1 && it.nativeAcknowledged &&
                            it.intentSha256 == ReleaseLocks.sha256(original) &&
                            it.containerId.matches(Regex("[a-f0-9]{64}")) && it.imageId == p.imageId) {
                            "Foreign Quadlet launch ACK in owner-loss guard"
                        }
                    }.containerId
                } else null
                containUncertainLaunch(spec, p, lease.fingerprint, "p0v3-live-$member-$process", launchIntent,
                    expectedCid = acknowledged)
            }
        }
    }

    private fun containUncertainLaunch(spec: PrivateDeploymentSpec, p: RuntimeProcess,
        fingerprint: String, name: String, launchIntent: Path, expectedCid: String? = null) {
        // A killed sudo client is NOT evidence that its detached container stopped.
        // Fence first, then independently inspect/stop only the exact retained CID.
        val memberRoot = runtimeRoot.resolve(spec.name)
        if (RuntimeMaintenance.read(memberRoot, fingerprint) == null)
            RuntimeMaintenance.create(memberRoot, fingerprint, "update", null)
        val original = ReleasePrivateFiles.read(launchIntent, 8192)
        val intent = NotebookEpisodePaths.path(root,
            "quadlet-owner-loss-${spec.name}-${p.id}.intent",spec.name,p.id)
        val result = NotebookEpisodePaths.path(root,
            "quadlet-owner-loss-${spec.name}-${p.id}.result",spec.name,p.id)
        require(!Files.exists(intent, NOFOLLOW_LINKS) && !Files.exists(result, NOFOLLOW_LINKS)) {
            "Previous owner-loss containment is uncertain"
        }
        require(listOf("intent", "result", "reconciliation").none { suffix ->
            Files.exists(NotebookEpisodePaths.path(root,
                "quadlet-stop-${spec.name}-${p.id}.$suffix",spec.name,p.id), NOFOLLOW_LINKS)
        }) { "Original native stop may have occurred; no distinct stop under a new intent" }
        val observed = native.run(listOf("container", "inspect", name))
        val cid = if (observed.exitCode == 0 && observed.output.toByteArray().size in 1..65536) {
            val item = json.parseToJsonElement(observed.output).jsonArray.single().jsonObject
            val labels = item.getValue("Config").jsonObject.getValue("Labels").jsonObject
            val value = item.getValue("Id").jsonPrimitive.content
            require(value.matches(Regex("[a-f0-9]{64}")) && (expectedCid == null || value == expectedCid) &&
                item.getValue("Name").jsonPrimitive.content == name &&
                item.getValue("Image").jsonPrimitive.content.removePrefix("sha256:") == p.imageId &&
                labels.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
                labels.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == fingerprint) {
                "Uncertain launch created a foreign or changed container"
            }
            value
        } else null
        val evidence = "quadlet-owner-loss-v1\n${ReleaseLocks.sha256(original)}\n${cid ?: "unobserved"}\n"
        ReleasePrivateFiles.save(intent, evidence.toByteArray())
        if (cid == null) return // Absence during a race is NOT terminal isolation proof.
        val state = json.parseToJsonElement(observed.output).jsonArray.single().jsonObject
            .getValue("State").jsonObject
        if (state.getValue("Running").jsonPrimitive.content == "true") {
            val stopped = native.run(listOf("container", "stop", "--time=30", cid))
            require(stopped.exitCode == 0 && stopped.output.toByteArray().size <= 4096) {
                "Emergency stop ACK missing; retain original owner-loss intent"
            }
        }
        val after = native.run(listOf("container", "inspect", name))
        require(after.exitCode == 0 && after.output.toByteArray().size in 1..65536)
        val item = json.parseToJsonElement(after.output).jsonArray.single().jsonObject
        require(item.getValue("Id").jsonPrimitive.content == cid &&
            item.getValue("State").jsonObject.getValue("Running").jsonPrimitive.content == "false") {
            "Uncertain launched container is not isolated"
        }
        ReleasePrivateFiles.save(result,
            "quadlet-owner-loss-stopped-v1\n${ReleaseLocks.sha256(evidence.toByteArray())}\n$cid\n".toByteArray())
    }
}

/** The helper stays systemd's ExecStart MainPID while Podman runs in the foreground.
 * conmon, not this JVM, sends READY via the fixed NOTIFY_SOCKET passed through sudo.
 * A CID is committed independently while Podman is alive; returning early would let
 * systemd tear down its process cgroup and make an apparent ACK meaningless.
 */
private fun ownedForegroundLaunch(argv: List<String>, checkOwner: () -> Unit,
    onObservedRunning: () -> Boolean, conmonCustody: () -> Boolean,
    stopRequested: () -> Boolean): RuntimeCommandResult {
    require(argv.firstOrNull() == "/usr/bin/podman" && argv.size in 20..256 &&
        System.getenv("NOTIFY_SOCKET") == "/run/systemd/notify") {
        "Foreground Quadlet launch requires actual systemd notification socket"
    }
    checkOwner()
    val args = listOf("/usr/bin/sudo", "-n", "/usr/bin/env", "NOTIFY_SOCKET=/run/systemd/notify") + argv
    // A daemon can emit unlimited logs. Never buffer, block on, or classify its output
    // as an ACK (the retained inspected CID is the only native launch acknowledgement).
    val child = ProcessBuilder(args).redirectOutput(ProcessBuilder.Redirect.DISCARD)
        .redirectError(ProcessBuilder.Redirect.DISCARD).apply { environment().clear() }.start()
    val startDeadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(700)
    try {
        var observed = false
        while (true) {
            if (child.waitFor(200, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                checkOwner()
                if (!observed) observed = onObservedRunning()
                require(observed) { "Foreground Podman exited before original CID was retained" }
                val exit = child.exitValue()
                if (exit == 0 && !stopRequested()) {
                    require(conmonCustody()) { "Detached conmon lacks original systemd MainPID custody" }
                    while (!stopRequested()) {
                        checkOwner()
                        Thread.sleep(200)
                    }
                    checkOwner()
                }
                return RuntimeCommandResult(exit, "")
            }
            checkOwner()
            if (!observed) {
                require(System.nanoTime() < startDeadline) { "Foreground start exceeded original deadline" }
                observed = onObservedRunning()
            }
        }
    } finally {
        if (child.isAlive) {
            child.toHandle().descendants().use { descendants ->
                descendants.toList().asReversed().forEach { it.destroyForcibly() }
            }
            child.destroyForcibly().waitFor()
        }
    }
}

private fun ownedGeneratedLaunch(argv: List<String>, checkOwner: () -> Unit): RuntimeCommandResult {
    // This transport is only used by the Type=oneshot initializer. Systemd does
    // not provide a notification socket to NotifyAccess=none oneshot units.
    require(argv.firstOrNull() == "/usr/bin/podman" && argv.size in 20..256)
    checkOwner()
    val args = listOf("/usr/bin/sudo", "-n") + argv
    val stdout = Files.createTempFile("p0v3-quadlet-run-", ".stdout")
    val stderr = Files.createTempFile("p0v3-quadlet-run-", ".stderr")
    try {
        val child = ProcessBuilder(args).redirectOutput(stdout.toFile()).redirectError(stderr.toFile())
            .apply { environment().clear() }.start()
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(700)
        try {
            while (!child.waitFor(200, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                require(System.nanoTime() < deadline) { "Generated start exceeded original deadline" }
                checkOwner()
                require(Files.size(stdout) <= 4096 && Files.size(stderr) <= 4096) {
                    "Generated launcher output exceeded bound"
                }
            }
            checkOwner()
            require(Files.size(stdout) <= 4096 && Files.size(stderr) <= 4096)
            return RuntimeCommandResult(child.exitValue(), Files.readString(stdout))
        } finally {
            if (child.isAlive) {
                child.toHandle().descendants().use { descendants ->
                    descendants.toList().asReversed().forEach { it.destroyForcibly() }
                }
                child.destroyForcibly().waitFor()
            }
        }
    } finally { Files.deleteIfExists(stdout); Files.deleteIfExists(stderr) }
}
