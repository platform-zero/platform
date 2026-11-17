package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.security.SecureRandom
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@Serializable internal data class NotebookStopRequest(val generation: String, val member: String,
    val user: String, val ordinal: Int, val requestId: String, val startSha256: String)

/** Lives IN the original serving generation owner process. Its socket handler runs
 * under the same process-held generation/member native lock proof; one request at a
 * time and all original intents are CREATE_NEW/fsynced before systemd effects.
 * A dropped HTTP reply cannot authorize a second effect: the episode itself fences it.
 */
internal class NotebookParentActuator(private val bundle: GenerationBundle, private val pin: GenerationPin,
    private val root: Path, private val expected: String, private val owner: RuntimeQuadletOwnerStage,
    private val manager: QuadletUnitManager = RuntimeQuadletSystemd,
    private val runtimeRoot: Path = PrivateDeployment.BASE,
    private val native: RuntimeCommands = PrivateRootfulCommands(45,RuntimeStore.CANONICAL_V2),
    private val generationBase: Path = GenerationRuntime.BASE,
    private val originalStop: ((String) -> QuadletStopResult)? = null,
    private val delegateEffect: ((RuntimeProcess,String) -> Unit)? = null,
    private val verifyStart: ((RuntimeProcess) -> Unit)? = null,
    private val retiredCid: ((String,Int,Path,String) -> String)? = null,
    private val unitTerminalReadback: ((String) -> ByteArray)? = null,
    private val readiness: ((RuntimeProcess,String) -> RuntimeStatus)? = null,
    private val serving: ((RuntimeProcess,String) -> String)? = null) : NotebookParentEffects {
    private val json = Json { encodeDefaults = true }
    private val spec = pin.spec
    private val generation = bundle.request.id
    private val hex = Regex("[a-f0-9]{64}")
    private val delegated = RuntimeQuadletDelegation(root,runtimeRoot)
    private val disposition = NotebookNativeDisposition(root,spec,native,unitTerminalReadback)
    init {
        require(root == generationBase.resolve(generation) && NotebookSelectedGraph.selected(root,spec) &&
            bundle.members.singleOrNull() == pin && hex.matches(expected) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"))) == expected)
    }
    private fun beginNative(p: RuntimeProcess, action: String) {
        if (delegateEffect != null) delegateEffect.invoke(p,action)
        else delegated.begin(generation,expected,spec,p,action,pin.runtimeFingerprint)
    }
    private fun retire(user: String, ordinal: Int, stopPath: Path, cid: String) =
        retiredCid?.invoke(user,ordinal,stopPath,cid) ?: disposition.retire(user,ordinal,stopPath,cid)
    private fun requireServing(p: RuntimeProcess, cid: String): String {
        val original = serving?.invoke(p,cid) ?: json.encodeToString(RuntimeQuadletSystemd.requireServing(
            "${RuntimeQuadlets.unit(spec,p)}.service",cid,spec.store))
        require(original.length in 16..8192)
        return original
    }
    private fun ledger(user: String) = NotebookLifecycleEpisodes(root,spec.name,user,
        RuntimeQuadlets.render(spec).specSha256,spec.processes.single { it.id == user }.memoryMiB)
    private fun original(user: String, kind: String, episode: Boolean = false): Path =
        if (episode) NotebookEpisodePaths.path(root,"quadlet-$kind-${spec.name}-$user.result",spec.name,user)
        else root.resolve("quadlet-$kind-${spec.name}-$user.result.json")
    private fun originalIntent(user: String, kind: String, episode: Boolean = false): Path =
        if (episode) NotebookEpisodePaths.path(root,"quadlet-$kind-${spec.name}-$user.intent",spec.name,user)
        else root.resolve("quadlet-$kind-${spec.name}-$user.intent.json")
    private fun stopRequest(user: String, ordinal: Int, requestId: String, start: NotebookEpisodeStart) {
        val path = root.resolve("notebooks/stop-requests/$user/%04d.intent.json".format(ordinal))
        val parent = path.parent
        if (!Files.exists(parent.parent,NOFOLLOW_LINKS)) Files.createDirectory(parent.parent,
            java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.directory(parent.parent)
        if (!Files.exists(parent,NOFOLLOW_LINKS)) Files.createDirectory(parent,
            java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.directory(parent)
        require(!Files.exists(path,NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(path,json.encodeToString(NotebookStopRequest(generation,spec.name,user,ordinal,
            requestId,ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve(
                "notebooks/episodes/$user/%04d.start.json".format(ordinal)),8192)))).toByteArray())
    }
    private fun requireHeadroom(user: String, before: Boolean = true) {
        val requested = if (before) bundle.request.workingBudget?.workingMiB?.getValue("${spec.name}/$user")
            ?: spec.processes.single { it.id == user }.memoryMiB.toLong() else 0L
        require(requested in 0L..2048L && (!before || requested > 0L))
        val row = Files.readAllLines(Path.of("/proc/meminfo")).single { it.startsWith("MemAvailable:") }
            .trim().split(Regex("\\s+"))
        require(row.size == 3 && row[2] == "kB" &&
            row[1].toLong()/1024 >= Math.addExact(bundle.request.memoryHeadroomMiB,requested.toLong()) &&
            Files.getFileStore(runtimeRoot).usableSpace/1048576 >= bundle.request.diskHeadroomMiB)
    }
    /** The original stage starts two graph-declared templates to establish native
     * effective-limit proof. Before Hub controller starts, retire both via original
     * systemd StopUnit and a distinct exact-CID disposal, preserving the notebook
     * volume. No standby container remains selected as resident on-demand work.
     */
    fun retireOriginals() {
        for (user in listOf("alice","bob")) {
            val episodes = ledger(user)
            require(episodes.completed().isEmpty())
            val initial = ByteArray(16).also(SecureRandom()::nextBytes)
                .joinToString("") { "%02x".format(it) }
            val intent = episodes.begin(initial)
            val launchBytes = ReleasePrivateFiles.read(original(user,"launch"),8192)
            val launch = json.decodeFromString<QuadletLaunchResult>(launchBytes.decodeToString(throwOnInvalidSequence=true))
            val memberBytes = ReleasePrivateFiles.read(original(user,"member"),8192)
            val member = json.decodeFromString<QuadletMemberStart>(memberBytes.decodeToString(throwOnInvalidSequence=true))
            require(launch.nativeAcknowledged && launch.imageId == spec.processes.single { it.id == user }.imageId &&
                launch.containerId == member.containerId && member.status.state == "running" &&
                launch.intentSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(
                    originalIntent(user,"launch"),8192)))
            val servingReadback = requireServing(spec.processes.single { it.id == user },launch.containerId)
                .toByteArray()
            ReleasePrivateFiles.save(root.resolve("notebooks/serving-$user-0001.observation.json"),
                servingReadback)
            val started = episodes.acceptStart(intent,ReleaseLocks.sha256(launchBytes),launch.containerId,
                ReleaseLocks.sha256(servingReadback))
            val stop = originalStop?.invoke(user) ?: owner.stopOriginalNotebook(bundle,expected,pin,user)
            val stopPath = original(user,"stop")
            val dispositionSha = retire(user,1,stopPath,stop.containerId)
            val retiredIntent = ReleasePrivateFiles.read(root.resolve(
                "notebooks/retire/$user/0001.retire.intent.json"),8192)
            val evidence = json.decodeFromString<NotebookCidRetireIntent>(retiredIntent.decodeToString(throwOnInvalidSequence=true))
            require(evidence.cid == launch.containerId && evidence.stopResultSha256 ==
                ReleaseLocks.sha256(ReleasePrivateFiles.read(stopPath,8192)))
            episodes.terminal(intent,started,ReleaseLocks.sha256(ReleasePrivateFiles.read(stopPath,8192)),
                evidence.terminalInspectionSha256,dispositionSha)
        }
    }
    private fun start(user: String, requestId: String): NotebookParentReply {
        requireHeadroom(user)
        val episodes = ledger(user)
        require(episodes.active() == null)
        val previous = episodes.completed().lastOrNull() ?: error("Original notebook episode not retired")
        val p = spec.processes.single { it.id == user }
        val intent = episodes.begin(requestId)
        // A previously stopped container was separately removed, not replaced by
        // generated Podman run. A missing retirement ACK permanently fences begin.
        val prior = root.resolve("notebooks/retire/$user/%04d.retire.result.json".format(intent.ordinal-1))
        val result = json.decodeFromString<NotebookCidRetireResult>(ReleasePrivateFiles.read(prior,8192)
            .decodeToString(throwOnInvalidSequence=true))
        require(result.nativeRemoveAcknowledged && result.cid == previous.second.nativeContainerId)
        beginNative(p,"start")
        manager.change("start","${RuntimeQuadlets.unit(spec,p)}.service")
        val resultPath = original(user,"launch",episode=true)
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(40)
        while (!Files.exists(resultPath,NOFOLLOW_LINKS)) {
            require(System.nanoTime() < deadline) { "Episode original launch ACK missing; intent remains fenced" }
            if (verifyStart != null) verifyStart.invoke(p)
            else delegated.authorize(generation,spec.name,user,"start",afterStartAck=true)
            Thread.sleep(200)
        }
        val bytes = ReleasePrivateFiles.read(resultPath,8192)
        val launch = json.decodeFromString<QuadletLaunchResult>(bytes.decodeToString(throwOnInvalidSequence=true))
        require(launch.nativeAcknowledged && launch.imageId == p.imageId && hex.matches(launch.containerId) &&
            launch.intentSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(
                originalIntent(user,"launch",episode=true),8192)) &&
            (verifyStart?.let { it(p); true } ?:
                (delegated.authorize(generation,spec.name,user,"start",afterStartAck=true).fingerprint ==
                    pin.runtimeFingerprint)))
        val status = readiness?.invoke(p,launch.containerId) ?: RuntimeQuadletReadiness.waitFor(spec,p,
            launch.containerId,durationSeconds=quadletReadinessBudgetSeconds(p))
        require(status.state == "running" && status.id == user)
        val servingReadback = requireServing(p,launch.containerId).toByteArray()
        ReleasePrivateFiles.save(root.resolve("notebooks/serving-$user-%04d.observation.json".format(intent.ordinal)),
            servingReadback)
        episodes.acceptStart(intent,ReleaseLocks.sha256(bytes),launch.containerId,
            ReleaseLocks.sha256(servingReadback))
        try { requireHeadroom(user,before=false) }
        catch (headroom: Exception) {
            // This is a *new, already acknowledged* episode: contain the exact
            // CID with its sole original StopUnit, never replay the START.
            val request = ByteArray(16).also(SecureRandom()::nextBytes)
                .joinToString("") { "%02x".format(it) }
            try { stop(user,request) } catch (isolation: Exception) { headroom.addSuppressed(isolation) }
            throw headroom
        }
        return NotebookParentReply(201)
    }
    private fun stop(user: String, requestId: String): NotebookParentReply {
        val episodes = ledger(user)
        val (intent,started) = requireNotNull(episodes.active())
        val start = requireNotNull(started) { "No acknowledged native start to stop" }
        require(intent.ordinal >= 2)
        stopRequest(user,intent.ordinal,requestId,start)
        val p = spec.processes.single { it.id == user }
        beginNative(p,"stop")
        manager.change("stop","${RuntimeQuadlets.unit(spec,p)}.service")
        val stopPath = original(user,"stop",episode=true)
        val bytes = ReleasePrivateFiles.read(stopPath,8192)
        val result = json.decodeFromString<QuadletStopResult>(bytes.decodeToString(throwOnInvalidSequence=true))
        require(result.stopped && result.containerId == start.nativeContainerId &&
            result.intentSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(
                originalIntent(user,"stop",episode=true),8192)))
        val disposed = retire(user,intent.ordinal,stopPath,result.containerId)
        val evidence = json.decodeFromString<NotebookCidRetireIntent>(ReleasePrivateFiles.read(root.resolve(
            "notebooks/retire/$user/%04d.retire.intent.json".format(intent.ordinal)),8192)
            .decodeToString(throwOnInvalidSequence=true))
        require(evidence.cid == start.nativeContainerId && evidence.stopResultSha256 == ReleaseLocks.sha256(bytes))
        episodes.terminal(intent,start,ReleaseLocks.sha256(bytes),evidence.terminalInspectionSha256,disposed)
        return NotebookParentReply(204)
    }
    fun retireForShutdown() {
        for (user in listOf("bob","alice")) {
            val current = ledger(user).active() ?: continue
            require(current.second != null) { "Unacknowledged notebook START remains fenced at generation shutdown" }
            val request = ByteArray(16).also(SecureRandom()::nextBytes)
                .joinToString("") { "%02x".format(it) }
            require(stop(user,request).status == 204)
        }
    }
    override fun apply(user: String, action: NotebookParentAction, intent: String?): NotebookParentReply {
        require(user in setOf("alice","bob") && root == generationBase.resolve(generation) &&
            RuntimeMaintenance.read(runtimeRoot.resolve(spec.name),pin.runtimeFingerprint) == null &&
            !Files.exists(root.resolve("quadlet-serve-stop.intent.json"),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("isolate.intent.json"),NOFOLLOW_LINKS))
        val stagePath = root.resolve("stage.result.json")
        if (!Files.exists(stagePath,NOFOLLOW_LINKS)) {
            // A restored Hub may poll a previously named server while its own
            // controller is still starting. Both originals were already retired
            // before the socket was bound; read-only STOPPED is safe. POST is not.
            require(action == NotebookParentAction.STATE &&
                listOf("alice","bob").all { ledger(it).active() == null && ledger(it).completed().isNotEmpty() }) {
                "Hub cannot request notebook effects before whole member native readiness"
            }
            return NotebookParentReply(200,"{\"state\":\"stopped\"}")
        }
        val stage = json.decodeFromString<GenerationOutcome>(ReleasePrivateFiles.read(stagePath,8192)
            .decodeToString(throwOnInvalidSequence=true))
        require(stage.action == "stage" && stage.bundleSha256 == expected && stage.passed) {
            "Hub cannot request notebook effects before whole member native readiness"
        }
        return when (action) {
            NotebookParentAction.START -> start(user,requireNotNull(intent))
            NotebookParentAction.STOP -> stop(user,requireNotNull(intent))
            NotebookParentAction.STATE -> {
                // An open episode with a missing START ACK is uncertainty, not stopped.
                val active = ledger(user).active()
                if (active == null) NotebookParentReply(200,"{\"state\":\"stopped\"}")
                else if (active.second == null) NotebookParentReply(503,"{\"state\":\"uncertain\"}")
                else {
                    val cid = active.second!!.nativeContainerId
                    requireServing(spec.processes.single { it.id == user },cid)
                    NotebookParentReply(200,"{\"state\":\"running\"}")
                }
            }
        }
    }
}
