package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.security.SecureRandom
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class QuadletDelegationIntent(val schemaVersion: Int = 1,
    val generation: String, val bundleSha256: String, val member: String, val process: String,
    val action: String, val specSha256: String, val fingerprint: String,
    val installedAuditSha256: String, val ownerPid: Long, val ownerStartTicks: Long,
    val nonce: String)
@Serializable internal data class QuadletDelegationAck(val schemaVersion: Int = 1,
    val intentSha256: String, val action: String, val installedAuditSha256: String)
/** A failed start-owner proof permanently revokes this original start delegation.
 * Read-only diagnostic, not a systemd, native launch, stop or isolation ACK.
 */
@Serializable internal data class QuadletOwnerProofLossObservation(val schemaVersion: Int = 1,
    val intentSha256: String, val member: String, val process: String, val originalOwnerPid: Long,
    val originalOwnerStartTicks: Long, val category: QuadletOwnerProof,
    /** Separate bounded categories; neither is a continuity claim or a native ACK. */
    val firstObservation: QuadletOwnerProof? = null,
    val secondObservation: QuadletOwnerProof? = null)

/** systemd's pre/stop helper cannot take locks held by an owner waiting for systemctl.
 * Instead it verifies the owner is *still alive and holds both exact native locks*.
 * An owner death or released lock denies admission; it does not license a new attempt.
 * This protocol only delegates authorization; it does not provision or start services.
 */
internal class RuntimeQuadletDelegation(private val generationRoot: Path,
    private val runtimeRoot: Path = PrivateDeployment.BASE,
    private val generationBase: Path = GenerationRuntime.BASE,
    private val installed: (PrivateDeploymentSpec, RuntimeProcess) -> String = { spec, process ->
        RuntimeQuadletInstalledAudit().audit(spec, process)
    },
    private val lockedBy: (Path, Long) -> Boolean = QuadletNativeLockProof.nativeHeld,
    private val startTicks: (Long) -> Long = QuadletNativeLockProof.nativeTicks) {
    private val json = Json { encodeDefaults = true }
    private val hash = Regex("[a-f0-9]{64}")
    private val actions = setOf("start", "stop")
    private fun paths(member: String, process: String, action: String): Pair<Path, Path> {
        require(member.matches(Regex("q-[a-f0-9]{12}-[a-z][a-z0-9-]{0,39}")) &&
            process.matches(Regex("[a-z][a-z0-9-]{0,39}")) && action in actions)
        val stem = "quadlet-delegate-$member-$process-$action"
        return NotebookEpisodePaths.path(generationRoot,"$stem.intent",member,process) to
            NotebookEpisodePaths.path(generationRoot,"$stem.ack",member,process)
    }
    private fun lockPaths(generation: String, member: String) =
        generationRoot.parent.resolve("generation.lock") to runtimeRoot.resolve(member).resolve("runtime.lock")

    /** Owner calls this with its generation + member locks held, after installed-unit audit.
     * One start and one stop per process/generation; no second ID can bypass uncertainty.
     */
    fun begin(generation: String, bundleSha256: String, spec: PrivateDeploymentSpec,
        process: RuntimeProcess, action: String, fingerprint: String): QuadletDelegationIntent {
        require(generationRoot == generationBase.resolve(generation) && spec.name.startsWith("$generation-") &&
            process in spec.processes && spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
            hash.matches(bundleSha256) && hash.matches(fingerprint) && action in actions)
        ReleasePrivateFiles.directory(generationRoot)
        val (intentPath, ackPath) = paths(spec.name, process.id, action)
        require(!Files.exists(intentPath, NOFOLLOW_LINKS) && !Files.exists(ackPath, NOFOLLOW_LINKS)) {
            "Original Quadlet delegation exists; reconcile, never reissue"
        }
        val pid = ProcessHandle.current().pid()
        val (generationLock, memberLock) = lockPaths(generation, spec.name)
        require(lockedBy(generationLock, pid) && lockedBy(memberLock, pid)) { "Owner must hold both native locks" }
        val audit = installed(spec, process)
        require(hash.matches(audit))
        val nonce = ByteArray(32).also(SecureRandom()::nextBytes).joinToString("") { "%02x".format(it) }
        val intent = QuadletDelegationIntent(generation = generation, bundleSha256 = bundleSha256,
            member = spec.name, process = process.id, action = action,
            specSha256 = RuntimeQuadlets.render(spec).specSha256, fingerprint = fingerprint,
            installedAuditSha256 = audit, ownerPid = pid, ownerStartTicks = startTicks(pid), nonce = nonce)
        ReleasePrivateFiles.save(intentPath, json.encodeToString(intent).toByteArray())
        return intent
    }
    /** Called from ExecStartPre or ExecStop without acquiring either owner lock. It reopens
     * the sealed generation and original input bytes, rather than trusting CLI arguments.
     */
    fun authorize(generation: String, member: String, process: String, action: String,
        afterStartAck: Boolean = false): QuadletDelegationIntent {
        require(!afterStartAck || action == "start")
        require(generationRoot == generationBase.resolve(generation) && member.startsWith("$generation-"))
        ReleasePrivateFiles.directory(generationRoot)
        val (intentPath, ackPath) = paths(member, process, action)
        val intentBytes = ReleasePrivateFiles.read(intentPath, 8192)
        val intent = json.decodeFromString<QuadletDelegationIntent>(intentBytes.decodeToString(throwOnInvalidSequence = true))
        require(intent.schemaVersion == 1 && intent.generation == generation && intent.member == member &&
            intent.process == process && intent.action == action && hash.matches(intent.nonce) &&
            hash.matches(intent.bundleSha256) && hash.matches(intent.fingerprint) &&
            hash.matches(intent.installedAuditSha256) &&
            json.encodeToString(intent).toByteArray().contentEquals(intentBytes)) { "Foreign Quadlet delegation" }
        val bundleBytes = ReleasePrivateFiles.read(generationRoot.resolve("bundle.json"), 1048576)
        require(ReleaseLocks.sha256(bundleBytes) == intent.bundleSha256)
        val bundle = json.decodeFromString<GenerationBundle>(bundleBytes.decodeToString(throwOnInvalidSequence = true))
        val pin = bundle.members.singleOrNull { it.spec.name == member }
        val spec = requireNotNull(pin?.spec)
        val selected = spec.processes.single { it.id == process }
        bundle.recoverySourceKopia?.let { snapshot ->
            val recovered = json.decodeFromString<KopiaSnapshotReceipt>(ReleasePrivateFiles.read(
                generationRoot.resolve("recovery.source.json"), 8192).decodeToString())
            val imported = json.decodeFromString<GenerationOutcome>(ReleasePrivateFiles.read(
                generationRoot.resolve("import.result.json"), 8192).decodeToString())
            require(bundle.ownership == null && spec.processes.none { it.oneShot } &&
                recovered == snapshot && imported.action == "restore-import" && imported.passed &&
                imported.bundleSha256 == intent.bundleSha256 && imported.fences.containsKey(member)) {
                "Recovered Quadlet delegation lacks authenticated completed cold import"
            }
        }
        if (generationBase == GenerationRuntime.BASE) PinnedBackupController.verify(
            requireNotNull(spec.fragmentBinding?.controllerSha256))
        require(bundle.request.id == generation && bundle.request.store == RuntimeStore.CANONICAL_V2 &&
            spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
            spec.fragmentBinding?.controllerSha256 != null &&
            RuntimeQuadlets.render(spec).specSha256 == intent.specSha256 &&
            pin.runtimeFingerprint == intent.fingerprint &&
            PrivateDeployment.inputNames(spec).all { file ->
                ReleaseLocks.sha256(ReleasePrivateFiles.read(runtimeRoot.resolve(member).resolve(file))) == pin.inputHashes[file]
            } && PrivateDeployment.expectedFingerprint(spec, pin.inputHashes) == intent.fingerprint) {
            "Sealed Quadlet spec or protected inputs changed"
        }
        val (generationLock, memberLock) = lockPaths(generation, member)
        val lostProof = NotebookEpisodePaths.path(generationRoot,
            "quadlet-owner-proof-loss-$member-$process-start.observation",member,process)
        if (action == "start") require(!Files.exists(lostProof, NOFOLLOW_LINKS)) {
            "Original start owner proof was revoked; reacquisition cannot revive stale delegation"
        }
        val ownerEvidence = QuadletNativeLockProof.classifyStableEvidence(intent.ownerPid, intent.ownerStartTicks,
            generationLock, memberLock, startTicks, lockedBy)
        val ownerProof = ownerEvidence.proof
        if (ownerProof != QuadletOwnerProof.VERIFIED && action == "start") {
            ReleasePrivateFiles.save(lostProof, json.encodeToString(QuadletOwnerProofLossObservation(
                intentSha256 = ReleaseLocks.sha256(intentBytes), member = member, process = process,
                originalOwnerPid = intent.ownerPid, originalOwnerStartTicks = intent.ownerStartTicks,
                category = ownerProof, firstObservation = ownerEvidence.first,
                secondObservation = ownerEvidence.second)).toByteArray())
        }
        require(ownerProof == QuadletOwnerProof.VERIFIED) {
            "Quadlet original owner proof rejected (${ownerProof.name}); no launch or stop authorization"
        }
        val stage = json.decodeFromString<GenerationIntent>(ReleasePrivateFiles.read(
            generationRoot.resolve("stage.intent.json"), 8192).decodeToString(throwOnInvalidSequence = true))
        val installIntentBytes = ReleasePrivateFiles.read(
            generationRoot.resolve("quadlet-install-$member.intent.json"), 65536)
        val installOriginal = json.decodeFromString<QuadletInstallIntent>(
            installIntentBytes.decodeToString(throwOnInvalidSequence = true))
        val installRecord = json.decodeFromString<QuadletInstallResult>(ReleasePrivateFiles.read(
            generationRoot.resolve("quadlet-install-$member.result.json"), 8192).decodeToString(throwOnInvalidSequence = true))
        require(stage.action == "stage" && stage.bundleSha256 == intent.bundleSha256 &&
            installOriginal.schemaVersion == 1 && installOriginal.generation == generation &&
            installOriginal.bundleSha256 == intent.bundleSha256 && installOriginal.member == member &&
            installOriginal.specSha256 == intent.specSha256 &&
            installRecord.schemaVersion == 1 && installRecord.intentSha256 == ReleaseLocks.sha256(installIntentBytes) &&
            installRecord.installedAuditSha256[process] == intent.installedAuditSha256 &&
            installed(spec, selected) == intent.installedAuditSha256 &&
            (action == "stop" || (!Files.exists(generationRoot.resolve("isolate.intent.json"), NOFOLLOW_LINKS) &&
                !Files.exists(generationRoot.resolve("isolate.result.json"), NOFOLLOW_LINKS)))) {
            "Installed unit changed or generation isolated"
        }
        if (action == "start") {
            val memberRoot = runtimeRoot.resolve(member)
            val envName = if (selected.oneShot) "runtime.quadlet-${process}.env" else "runtime.quadlet.env"
            val env = ReleasePrivateFiles.read(memberRoot.resolve(envName), 8192).decodeToString(throwOnInvalidSequence = true)
            require(env.startsWith("P0_RUNTIME_FINGERPRINT=${intent.fingerprint}\n") &&
                (if (selected.oneShot) {
                    val original = ReleasePrivateFiles.read(generationRoot.resolve("quadlet-$process.intent.json"), 8192)
                    env == "P0_RUNTIME_FINGERPRINT=${intent.fingerprint}\nP0_INITIALIZER_INTENT=${ReleaseLocks.sha256(original)}\n" &&
                        !RuntimeQuadletInitializer(generationRoot, spec, intent.fingerprint, runtimeRoot).completed(process)
                } else env == "P0_RUNTIME_FINGERPRINT=${intent.fingerprint}\n") &&
                !Files.exists(memberRoot.resolve("runtime.owner"), NOFOLLOW_LINKS) &&
                (if (afterStartAck) {
                    val bytes = ReleasePrivateFiles.read(ackPath, 8192)
                    val ack = json.decodeFromString<QuadletDelegationAck>(bytes.decodeToString(throwOnInvalidSequence = true))
                    ack.schemaVersion == 1 && ack.action == "start" &&
                        ack.intentSha256 == ReleaseLocks.sha256(intentBytes) &&
                        ack.installedAuditSha256 == intent.installedAuditSha256 &&
                        bytes.contentEquals(json.encodeToString(ack).toByteArray())
                } else !Files.exists(ackPath, NOFOLLOW_LINKS)) &&
                !Files.exists(paths(member,process,"stop").first, NOFOLLOW_LINKS) &&
                RuntimeBackupLeases.read(memberRoot, member, intent.fingerprint) == null &&
                RuntimeMaintenance.read(memberRoot, intent.fingerprint) == null) {
                "Initializer or daemon admission cannot restart after ACK/fence"
            }
        }
        return intent
    }
    /** Helper acknowledgement is CREATE_NEW/fsynced. A missing ACK is uncertainty, not
     * permission for a second StartUnit. An existing ACK only admits readback for stop-post.
     */
    fun acknowledge(generation: String, member: String, process: String, action: String): QuadletDelegationAck {
        val intent = authorize(generation, member, process, action)
        val (intentPath, ackPath) = paths(member, process, action)
        val ack = QuadletDelegationAck(intentSha256 = ReleaseLocks.sha256(ReleasePrivateFiles.read(intentPath, 8192)),
            action = action, installedAuditSha256 = intent.installedAuditSha256)
        val expected = json.encodeToString(ack).toByteArray()
        if (action == "stop" && Files.exists(ackPath, NOFOLLOW_LINKS)) {
            require(ReleasePrivateFiles.read(ackPath, 8192).contentEquals(expected)) {
                "Foreign or changed original stop delegation ACK"
            }
        } else ReleasePrivateFiles.save(ackPath, expected)
        return ack
    }
}

@Serializable internal enum class QuadletOwnerProof {
    VERIFIED, PID_MISSING, START_TICKS_CHANGED, GENERATION_LOCK_MISSING,
    MEMBER_LOCK_MISSING, BOTH_LOCKS_MISSING, PROOF_UNAVAILABLE
}

internal data class QuadletStableOwnerProof(val proof: QuadletOwnerProof,
    val first: QuadletOwnerProof, val second: QuadletOwnerProof?)

internal object QuadletNativeLockProof {
    /** A bounded, non-secret classification. Evaluate BOTH locks while the original PID
     * still has the pinned start ticks: a living owner can lose POSIX locks without dying.
     * Never infer authorization from an unavailable or partial observation.
     */
    internal val nativeTicks: (Long) -> Long = ::startTicks
    internal val nativeHeld: (Path, Long) -> Boolean = ::heldBy
    /** Production uses ONE bounded /proc/locks read for both lock identities, with
     * PID start ticks and inode identities checked on both sides. Injectable test
     * transports retain separate predicates; they are never production authority.
     */
    fun classify(pid: Long, expectedTicks: Long, generation: Path, member: Path,
        ticks: (Long) -> Long = nativeTicks, held: (Path, Long) -> Boolean = nativeHeld): QuadletOwnerProof {
        if (ticks === nativeTicks && held === nativeHeld)
            return nativeClassify(pid, expectedTicks, generation, member)
        if (pid <= 1L || !Files.exists(Path.of("/proc/$pid"), NOFOLLOW_LINKS))
            return QuadletOwnerProof.PID_MISSING
        val current = runCatching { ticks(pid) }.getOrElse { return QuadletOwnerProof.PROOF_UNAVAILABLE }
        if (current != expectedTicks) return QuadletOwnerProof.START_TICKS_CHANGED
        val generationHeld = runCatching { held(generation, pid) }.getOrElse {
            return QuadletOwnerProof.PROOF_UNAVAILABLE
        }
        val memberHeld = runCatching { held(member, pid) }.getOrElse {
            return QuadletOwnerProof.PROOF_UNAVAILABLE
        }
        return category(generationHeld, memberHeld)
    }
    private fun category(generationHeld: Boolean, memberHeld: Boolean) = when {
        generationHeld && memberHeld -> QuadletOwnerProof.VERIFIED
        !generationHeld && !memberHeld -> QuadletOwnerProof.BOTH_LOCKS_MISSING
        !generationHeld -> QuadletOwnerProof.GENERATION_LOCK_MISSING
        else -> QuadletOwnerProof.MEMBER_LOCK_MISSING
    }
    private fun lockIdentity(path: Path): String {
        require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path &&
            Files.isRegularFile(path, NOFOLLOW_LINKS) &&
            (Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong() == 1L &&
            Files.getPosixFilePermissions(path) == java.nio.file.attribute.PosixFilePermissions.fromString("rw-------") &&
            (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() ==
                com.sun.security.auth.module.UnixSystem().uid)
        val device = (Files.getAttribute(path, "unix:dev", NOFOLLOW_LINKS) as Number).toLong()
        val major = (device ushr 8) and 0xfff
        val minor = (device and 0xff) or ((device ushr 12) and 0xfff00)
        val inode = (Files.getAttribute(path, "unix:ino", NOFOLLOW_LINKS) as Number).toLong()
        return "%02x:%02x:%d".format(major, minor, inode)
    }
    private fun nativeClassify(pid: Long, expectedTicks: Long, generation: Path, member: Path): QuadletOwnerProof {
        if (pid <= 1 || !Files.exists(Path.of("/proc/$pid"), NOFOLLOW_LINKS)) return QuadletOwnerProof.PID_MISSING
        return runCatching {
            val beforeTicks = startTicks(pid)
            val beforeGeneration = lockIdentity(generation)
            val beforeMember = lockIdentity(member)
            val bytes = Files.newInputStream(Path.of("/proc/locks")).use { it.readNBytes(2_000_001) }
            require(bytes.size <= 2_000_000) { "Native lock snapshot exceeded bound" }
            val afterGeneration = lockIdentity(generation)
            val afterMember = lockIdentity(member)
            val afterTicks = startTicks(pid)
            if (beforeTicks != afterTicks || beforeGeneration != afterGeneration || beforeMember != afterMember)
                return@runCatching QuadletOwnerProof.PROOF_UNAVAILABLE
            if (afterTicks != expectedTicks) return@runCatching QuadletOwnerProof.START_TICKS_CHANGED
            val held = bytes.decodeToString(throwOnInvalidSequence = true).lineSequence().mapNotNull { line ->
                val parts = line.trim().split(Regex("\\s+"))
                if (parts.size >= 8 && parts[1] == "POSIX" && parts[3] == "WRITE" &&
                    parts[4] == pid.toString() && parts[6] == "0" && parts[7] == "EOF") parts[5] else null
            }.toSet()
            category(beforeGeneration in held, beforeMember in held)
        }.getOrDefault(QuadletOwnerProof.PROOF_UNAVAILABLE)
    }
    /** One /proc/locks sample may race an unrelated lock transition. Authorization
     * still requires a complete VERIFIED sample; a persistent loss is denied with
     * its non-secret category. Never turn an unavailable sample into owner death.
     */
    fun classifyStableEvidence(pid: Long, expectedTicks: Long, generation: Path, member: Path,
        ticks: (Long) -> Long = nativeTicks, held: (Path, Long) -> Boolean = nativeHeld): QuadletStableOwnerProof {
        val first = classify(pid, expectedTicks, generation, member, ticks, held)
        if (first == QuadletOwnerProof.VERIFIED)
            return QuadletStableOwnerProof(first, first, null) // An instant, NOT continuous custody.
        Thread.sleep(50)
        val second = classify(pid, expectedTicks, generation, member, ticks, held)
        // Retain both original categories. A recovered lock cannot revive stale
        // delegation even if the same PID re-locked the same inode in between.
        return QuadletStableOwnerProof(if (first == second) first else QuadletOwnerProof.PROOF_UNAVAILABLE,
            first, second)
    }
    fun classifyStable(pid: Long, expectedTicks: Long, generation: Path, member: Path,
        ticks: (Long) -> Long = nativeTicks, held: (Path, Long) -> Boolean = nativeHeld): QuadletOwnerProof =
        classifyStableEvidence(pid, expectedTicks, generation, member, ticks, held).proof
    fun startTicks(pid: Long): Long {
        require(pid > 1)
        val stat = Files.readString(Path.of("/proc/$pid/stat"))
        require(stat.length in 32..8192)
        // comm is enclosed in parentheses and may contain spaces or closing parentheses.
        return stat.substringAfterLast(") ").split(' ')[19].toLong().also { require(it > 0) }
    }
    fun heldBy(path: Path, pid: Long): Boolean {
        require(pid > 1 && Files.isRegularFile(path, NOFOLLOW_LINKS) &&
            (Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong() == 1L &&
            Files.getPosixFilePermissions(path) == java.nio.file.attribute.PosixFilePermissions.fromString("rw-------") &&
            (Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() ==
                com.sun.security.auth.module.UnixSystem().uid)
        val device = (Files.getAttribute(path, "unix:dev", NOFOLLOW_LINKS) as Number).toLong()
        val major = (device ushr 8) and 0xfff
        val minor = (device and 0xff) or ((device ushr 12) and 0xfff00)
        val inode = (Files.getAttribute(path, "unix:ino", NOFOLLOW_LINKS) as Number).toLong()
        val identity = "%02x:%02x:%d".format(major, minor, inode)
        val locks = Files.readString(Path.of("/proc/locks"))
        require(locks.length <= 2_000_000)
        return locks.lineSequence().any { line ->
            val parts = line.trim().split(Regex("\\s+"))
            parts.size >= 8 && parts[1] == "POSIX" && parts[3] == "WRITE" &&
                parts[4] == pid.toString() && parts[5].equals(identity, ignoreCase = true) &&
                parts[6] == "0" && parts[7] == "EOF"
        }
    }
}
