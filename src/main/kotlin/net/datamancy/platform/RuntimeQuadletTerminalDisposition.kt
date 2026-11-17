package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Independent terminal *capacity* disposition. Never a retroactive stop/serve
 * ACK, never an isolation, successful activation or backup receipt. Accepts an
 * original stop whose ACK is absent only when its original owner is dead, a
 * maintenance fence is held, every original CID is *still* exited, and every
 * installed unit has no process, job or live cgroup. Recheck under native locks
 * at EACH later admission; changed/late original evidence fails closed.
 */
@Serializable internal data class QuadletSeparateTerminalDisposition(val schemaVersion: Int = 1,
    val generation: String, val bundleSha256: String, val member: String, val fingerprint: String,
    val fenceId: String, val originalOwnerPid: Long, val originalOwnerStartTicks: Long,
    val stageResultSha256: String, val originalEvidenceSha256: Map<String,String?>,
    val originalCids: Map<String,String>, val observedExitCodes: Map<String,Int>,
    val installedPolicy: Map<String,String>, val unitTerminalHashes: Map<String,String>,
    val overlappingOriginalStopAndGuardian: Set<String> = emptySet(),
    val originalStopAcknowledged: Boolean = false, val originalServeAcknowledged: Boolean = false,
    val originalIsolationAcknowledged: Boolean = false, val publicActivation: Boolean = false)

internal object RuntimeQuadletTerminalDisposition {
    private const val NAME = "quadlet-terminal-disposition.observation.json"
    private val json = Json { encodeDefaults=true; ignoreUnknownKeys=false }
    private val hash = Regex("[a-f0-9]{64}")
    private fun name(spec: PrivateDeploymentSpec, p: RuntimeProcess) =
        "p0v3-live-${spec.name}-${p.id}"
    private fun slot(root: Path, file: String): String? =
        if (Files.exists(root.resolve(file),NOFOLLOW_LINKS)) ReleaseLocks.sha256(
            ReleasePrivateFiles.read(root.resolve(file),8192)) else null
    private fun slotNames(member: String, process: String) = listOf(
        "quadlet-delegate-$member-$process-stop.intent.json",
        "quadlet-delegate-$member-$process-stop.ack.json",
        "quadlet-stop-$member-$process.intent.json",
        "quadlet-stop-$member-$process.result.json",
        "quadlet-stop-$member-$process.reconciliation.json",
        "quadlet-owner-loss-$member-$process.intent.json",
        "quadlet-owner-loss-$member-$process.result.json",
        "quadlet-helper-failure-$member-$process.observation.json")
    internal fun terminalUnitReadback(unit: String, oneShot: Boolean): ByteArray {
        require(unit.matches(Regex("p0v3-q-[a-f0-9]{12}-[a-z0-9-]+\\.service")))
        val child = ProcessBuilder("/usr/bin/systemctl","show","--no-pager",
            "--property=LoadState,ActiveState,SubState,MainPID,ControlPID,Job,UnitFileState,ControlGroup",unit)
            .redirectErrorStream(true).apply { environment().clear() }.start()
        try {
            require(child.waitFor(20,TimeUnit.SECONDS) && child.exitValue()==0)
            val raw = child.inputStream.use { it.readNBytes(8193) }
            require(raw.size in 1..8192)
            val values = raw.decodeToString(throwOnInvalidSequence=true).lineSequence().filter { '=' in it }
                .associate { it.substringBefore('=') to it.substringAfter('=') }
            require(values["LoadState"] == "loaded" && values["UnitFileState"] == "generated" &&
                ((values["ActiveState"] in setOf("inactive","failed")) ||
                    (oneShot && values["ActiveState"] == "active" && values["SubState"] == "exited")) &&
                values["MainPID"] == "0" && values["ControlPID"] == "0" &&
                values["Job"] in setOf("0", "")) { "Native unit still owns a process or job" }
            val group = values["ControlGroup"].orEmpty()
            require(group.isEmpty() || group == "/system.slice/$unit")
            if (group.isNotEmpty()) {
                val path = Path.of("/sys/fs/cgroup$group")
                if (Files.exists(path,NOFOLLOW_LINKS)) {
                    val children = Files.walk(path,4).use { it.toList() }
                    require(children.size <= 128 && children.all { entry ->
                        if (!Files.isDirectory(entry,NOFOLLOW_LINKS)) true else {
                            val procs = entry.resolve("cgroup.procs")
                            !Files.exists(procs,NOFOLLOW_LINKS) || Files.readString(procs).isBlank()
                        }
                    }) { "Native unit cgroup retains a process" }
                }
            }
            return raw
        } finally { if (child.isAlive) child.destroyForcibly() }
    }
    private fun source(root: Path, bundle: GenerationBundle, expected: String,
        runtimeRoot: Path, ownerDead: (Long)->Boolean): QuadletSeparateTerminalDisposition {
        val pin = bundle.members.single()
        val spec = pin.spec
        require(bundle.request.id == root.fileName.toString() && spec.name.startsWith("${bundle.request.id}-") &&
            spec.executionBackend == RuntimeExecutionBackend.QUADLET_V2 &&
            bundle.request.store == RuntimeStore.CANONICAL_V2 &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"),1048576)) == expected)
        val stageIntent = json.decodeFromString<GenerationIntent>(ReleasePrivateFiles.read(
            root.resolve("stage.intent.json"),8192).decodeToString(throwOnInvalidSequence=true))
        val stageBytes = ReleasePrivateFiles.read(root.resolve("stage.result.json"),8192)
        val stage = json.decodeFromString<GenerationOutcome>(stageBytes.decodeToString(throwOnInvalidSequence=true))
        require(stageIntent.action == "stage" && stageIntent.bundleSha256 == expected &&
            stage.action == "stage" && stage.bundleSha256 == expected && stage.passed &&
            !Files.exists(root.resolve("isolate.result.json"),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("quadlet-serve.result.json"),NOFOLLOW_LINKS)) {
            "Separate disposition cannot replace original serving/isolation ACK"
        }
        val installedIntent = ReleasePrivateFiles.read(root.resolve("quadlet-install-${spec.name}.intent.json"),65536)
        val installRequest = json.decodeFromString<QuadletInstallIntent>(
            installedIntent.decodeToString(throwOnInvalidSequence=true))
        val install = json.decodeFromString<QuadletInstallResult>(ReleasePrivateFiles.read(root.resolve(
            "quadlet-install-${spec.name}.result.json"),8192).decodeToString(throwOnInvalidSequence=true))
        require(installRequest.generation == bundle.request.id && installRequest.member == spec.name &&
            installRequest.bundleSha256 == expected && install.intentSha256 == ReleaseLocks.sha256(installedIntent) &&
            install.installedAuditSha256.keys == spec.processes.map { it.id }.toSet())
        val originals = linkedMapOf<String,String?>()
        val cids = linkedMapOf<String,String>()
        val overlapping = linkedSetOf<String>()
        var pid = 0L; var ticks = 0L
        for (p in spec.processes) {
            val id = p.id
            val delegateName = "quadlet-delegate-${spec.name}-$id-start.intent.json"
            val start = ReleasePrivateFiles.read(root.resolve(delegateName),8192)
            val lease = json.decodeFromString<QuadletDelegationIntent>(start.decodeToString(throwOnInvalidSequence=true))
            val delegateAck = json.decodeFromString<QuadletDelegationAck>(ReleasePrivateFiles.read(root.resolve(
                "quadlet-delegate-${spec.name}-$id-start.ack.json"),8192).decodeToString(throwOnInvalidSequence=true))
            val memberIntent=ReleasePrivateFiles.read(root.resolve("quadlet-member-${spec.name}-$id.intent.json"),8192)
            val resultName = "quadlet-launch-${spec.name}-$id.result.json"
            val launch = json.decodeFromString<QuadletLaunchResult>(ReleasePrivateFiles.read(root.resolve(resultName),8192)
                .decodeToString(throwOnInvalidSequence=true))
            val launchIntentBytes=ReleasePrivateFiles.read(root.resolve("quadlet-launch-${spec.name}-$id.intent.json"),8192)
            val launchIntent=ReleaseLocks.sha256(launchIntentBytes)
            val nativeLaunch=json.decodeFromString<QuadletLaunchIntent>(launchIntentBytes.decodeToString(throwOnInvalidSequence=true))
            val member = json.decodeFromString<QuadletMemberStart>(ReleasePrivateFiles.read(root.resolve(
                "quadlet-member-${spec.name}-$id.result.json"),8192).decodeToString(throwOnInvalidSequence=true))
            require(lease.schemaVersion == 1 && lease.generation == bundle.request.id &&
                lease.bundleSha256 == expected && lease.member == spec.name && lease.process == id &&
                lease.action == "start" && lease.fingerprint == pin.runtimeFingerprint &&
                lease.installedAuditSha256 == install.installedAuditSha256[id] &&
                delegateAck.intentSha256 == ReleaseLocks.sha256(start) && delegateAck.action == "start" &&
                delegateAck.installedAuditSha256 == lease.installedAuditSha256 &&
                memberIntent.contentEquals(start) &&
                lease.ownerPid > 1 && lease.ownerStartTicks > 0 &&
                (pid == 0L || pid == lease.ownerPid && ticks == lease.ownerStartTicks) &&
                nativeLaunch.delegationSha256 == ReleaseLocks.sha256(start) &&
                nativeLaunch.member == spec.name && nativeLaunch.process == id &&
                nativeLaunch.fingerprint == pin.runtimeFingerprint &&
                launch.schemaVersion == 1 && launch.nativeAcknowledged && launch.intentSha256 == launchIntent &&
                launch.imageId == p.imageId && hash.matches(launch.containerId) &&
                member.schemaVersion == 1 && member.bundleSha256 == expected &&
                member.member == spec.name && member.process == id && member.containerId == launch.containerId &&
                member.installedAuditSha256 == lease.installedAuditSha256 &&
                member.status.id == id && (if (p.oneShot) member.status.state == "completed" &&
                    member.status.exitCode == 0 else member.status.state == "running")) {
                "Original CID, installed unit or owner is not exact"
            }
            pid=lease.ownerPid; ticks=lease.ownerStartTicks
            cids[id]=launch.containerId
            val stopName="quadlet-stop-${spec.name}-$id"
            val stopResult=root.resolve("$stopName.result.json")
            if (Files.exists(stopResult,NOFOLLOW_LINKS)) {
                val stopIntent=ReleasePrivateFiles.read(root.resolve("$stopName.intent.json"),8192)
                val stop=json.decodeFromString<QuadletStopResult>(ReleasePrivateFiles.read(stopResult,8192)
                    .decodeToString(throwOnInvalidSequence=true))
                require(stop.stopped && stop.containerId == launch.containerId &&
                    stop.intentSha256 == ReleaseLocks.sha256(stopIntent))
            }
            val lossName="quadlet-owner-loss-${spec.name}-$id"
            val lossResult=root.resolve("$lossName.result.json")
            if (Files.exists(lossResult,NOFOLLOW_LINKS)) {
                val lossIntent=ReleasePrivateFiles.read(root.resolve("$lossName.intent.json"),8192)
                val loss=ReleasePrivateFiles.read(lossResult,8192).decodeToString(throwOnInvalidSequence=true)
                require(loss == "quadlet-owner-loss-stopped-v1\n${ReleaseLocks.sha256(lossIntent)}\n${launch.containerId}\n")
            }
            if (Files.exists(stopResult,NOFOLLOW_LINKS) && Files.exists(lossResult,NOFOLLOW_LINKS)) {
                // A historical guardian and an original StopUnit can both have
                // written their distinct results. Preserve both and the overlap;
                // neither result is promoted into the other's ACK.
                overlapping += id
            }
            (listOf(delegateName,"quadlet-delegate-${spec.name}-$id-start.ack.json",
                "quadlet-launch-${spec.name}-$id.intent.json",resultName,
                "quadlet-member-${spec.name}-$id.intent.json",
                "quadlet-member-${spec.name}-$id.result.json") + slotNames(spec.name,id)).forEach { file ->
                originals[file]=slot(root,file)
            }
        }
        require(ownerDead(pid)) { "Original process could still issue native effects" }
        val fence = requireNotNull(RuntimeMaintenance.read(runtimeRoot.resolve(spec.name),pin.runtimeFingerprint))
        return QuadletSeparateTerminalDisposition(generation=bundle.request.id,bundleSha256=expected,
            member=spec.name,fingerprint=pin.runtimeFingerprint,fenceId=fence.id,
            originalOwnerPid=pid,originalOwnerStartTicks=ticks,stageResultSha256=ReleaseLocks.sha256(stageBytes),
            originalEvidenceSha256=originals,originalCids=cids,observedExitCodes=emptyMap(),
            installedPolicy=install.installedAuditSha256,unitTerminalHashes=emptyMap(),
            overlappingOriginalStopAndGuardian=overlapping)
    }
    fun read(root: Path, bundle: GenerationBundle, expected: String,
        runtimeRoot: Path = PrivateDeployment.BASE,
        ownerDead: (Long)->Boolean = { !Files.exists(Path.of("/proc/$it"),NOFOLLOW_LINKS) }):
        QuadletSeparateTerminalDisposition? {
        val file = root.resolve(NAME)
        if (!Files.exists(file,NOFOLLOW_LINKS)) return null
        val saved = json.decodeFromString<QuadletSeparateTerminalDisposition>(ReleasePrivateFiles.read(file,65536)
            .decodeToString(throwOnInvalidSequence=true))
        val base = source(root,bundle,expected,runtimeRoot,ownerDead)
        require(saved.schemaVersion == 1 && !saved.originalStopAcknowledged &&
            !saved.originalServeAcknowledged && !saved.originalIsolationAcknowledged && !saved.publicActivation &&
            saved.copy(observedExitCodes=emptyMap(),unitTerminalHashes=emptyMap()) == base &&
            saved.observedExitCodes.keys == base.originalCids.keys &&
            saved.unitTerminalHashes.keys == base.originalCids.keys) {
            "Changed separate terminal disposition; original ACKs remain missing"
        }
        return saved
    }
    fun record(root: Path,bundle: GenerationBundle,expected: String,
        runtimeRoot: Path = PrivateDeployment.BASE,
        audit: (PrivateDeploymentSpec,RuntimeProcess)->String = { spec,p -> RuntimeQuadletInstalledAudit().audit(spec,p) },
        units: (String,Boolean)->ByteArray = ::terminalUnitReadback,
        census: RuntimeCapacityCensus = RuntimeCapacityCensus(),
        commands: RuntimeCommands = PrivateRootfulCommands(45,RuntimeStore.CANONICAL_V2),
        ownerDead: (Long)->Boolean = { !Files.exists(Path.of("/proc/$it"),NOFOLLOW_LINKS) },
        persist: Boolean = true): QuadletSeparateTerminalDisposition {
        require(runtimeRoot == PrivateDeployment.BASE && (!persist || !Files.exists(root.resolve(NAME),NOFOLLOW_LINKS)))
        val pin=bundle.members.single(); val spec=pin.spec
        return PrivateDeployment.withOrderedNativeLocks(listOf(spec.name),runtimeRoot) {
            val base=source(root,bundle,expected,runtimeRoot,ownerDead)
            require(spec.processes.associate { it.id to audit(spec,it) } == base.installedPolicy)
            val observed=census.snapshot(spec.store)
            require(census.quiescent(listOf(RuntimeCapacityCensus.Member(spec,pin.runtimeFingerprint)),observed) &&
                RuntimeQuadletCapacityTerminal.matchesOriginalCids(spec.name,base.originalCids,observed) &&
                observed.filter { it.member == spec.name }.all { it.state == "exited" }) {
                "Original CIDs no longer all physically exited under their fixed owner labels"
            }
            val exits=linkedMapOf<String,Int>()
            val unitHashes=linkedMapOf<String,String>()
            for (p in spec.processes) {
                val cid=base.originalCids.getValue(p.id)
                val show=units("${RuntimeQuadlets.unit(spec,p)}.service",p.oneShot)
                require(show.size in 1..8192)
                unitHashes[p.id]=ReleaseLocks.sha256(show)
                val inspection=commands.run(listOf("container","inspect",cid))
                require(inspection.exitCode==0 && inspection.output.toByteArray().size in 1..65536)
                val item=json.parseToJsonElement(inspection.output).jsonArray.single().jsonObject
                val state=item.getValue("State").jsonObject
                val labels=item.getValue("Config").jsonObject.getValue("Labels").jsonObject
                val exit=state.getValue("ExitCode").jsonPrimitive.content.toInt()
                require(item.getValue("Id").jsonPrimitive.content == cid && item.getValue("Name").jsonPrimitive.content ==
                    name(spec,p) && item.getValue("Image").jsonPrimitive.content.removePrefix("sha256:") == p.imageId &&
                    labels.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
                    labels.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == pin.runtimeFingerprint &&
                    state.getValue("Running").jsonPrimitive.content == "false" &&
                    state.getValue("Status").jsonPrimitive.content == "exited" &&
                    state.getValue("Pid").jsonPrimitive.content == "0" && exit in 0..255) {
                    "Foreign or still-active original CID cannot release capacity"
                }
                exits[p.id]=exit
            }
            val receipt=base.copy(observedExitCodes=exits,unitTerminalHashes=unitHashes)
            if (persist) ReleasePrivateFiles.save(root.resolve(NAME),json.encodeToString(receipt).toByteArray())
            receipt
        }
    }
    fun requireCurrentUnits(root: Path,bundle: GenerationBundle,receipt: QuadletSeparateTerminalDisposition) {
        require(root.fileName.toString()==receipt.generation)
        val spec=bundle.members.single().spec
        for (p in spec.processes) {
            require(RuntimeQuadletInstalledAudit().audit(spec,p) == receipt.installedPolicy[p.id]) {
                "Installed retired unit policy changed after physical disposition"
            }
            val raw=terminalUnitReadback("${RuntimeQuadlets.unit(spec,p)}.service",p.oneShot)
            // Raw `systemctl show` can change benign timing fields, but all live
            // predicates and generated policy are independently checked above.
            require(raw.size in 1..8192)
        }
    }
}
