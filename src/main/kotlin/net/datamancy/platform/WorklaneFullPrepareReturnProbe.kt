package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*

/** One isolated native production ManagedLaneRuntime.operate(PREPARE), not a
 * release generation. Includes OCI load, actual Worklane import, fresh status,
 * zero-container native Podman isolation, backend attestation and final result. */
@Serializable internal data class WorklaneFullPrepareProbeResult(
    val schemaVersion:Int=1,val generation:String,val originalQ583TerminalSha256:String,
    val sourceManifestSha256:String,val preparedIntentSha256:String,val preparedResultSha256:String,
    val imageId:String,val worklaneState:String,val nativeContainers:Int,
    val graphAllocatedBytes:Long,val graphEntries:Long,val brokerSocketAbsent:Boolean,
    val productionBackendAttested:Boolean=true,val originalGenerationImportAcknowledged:Boolean=false,
    val applicationStarted:Boolean=false,val qualificationEvidence:Boolean=false)
internal object WorklaneFullPrepareReturnProbe {
    const val generation="q-186d9a43b73a"
    const val terminalSha="ed8954b21a9b30337cf7cc1eaf0cdb403064bfdf3b13d9fb277c51d2a02bc685"
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    val base:Path=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/native-probes/$generation")
    private val managed=base.resolve("managed")
    private val control=managed.resolve("control")
    private val worklane=managed.resolve("worklane")
    private val manifest=managed.resolve("inputs/target-lane.toml")
    private val storage=control.resolve("storage.conf")
    private const val laneId="aa179f31-2637-42ea-a9db-aa9c1c2ebb8f"
    private const val subject="adb4143d-d8f7-496a-8f37-02986f600d0a"
    private fun dir(path:Path) {
        Files.createDirectory(path,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(path.parent)
    }
    private fun bytes(path:Path,max:Int=1048576)=ReleasePrivateFiles.read(path,max)
    private fun sha(path:Path,max:Int=1048576)=ReleaseLocks.sha256(bytes(path,max))
    fun issue():ActivationInput {
        require(!Files.exists(base,NOFOLLOW_LINKS) && !Files.exists(GenerationRuntime.BASE.resolve(generation),NOFOLLOW_LINKS))
        val terminal=Path.of("/mnt/media/p0-v3/release-generations/${Q583PreparedNoStartTerminal.generation}/prepared-no-start-native-absent-import-semantic-v1.disposition.json")
        Q583PreparedNoStartTerminal.verify(ActivationInput(terminal.toString(),terminalSha))
        val originalRoot=GenerationRuntime.BASE.resolve(Q583PreparedNoStartTerminal.generation)
        val bundle=json.decodeFromString<GenerationBundle>(bytes(originalRoot.resolve("bundle.json"),4194304)
            .decodeToString(throwOnInvalidSequence=true))
        require(bundle.request.id==Q583PreparedNoStartTerminal.generation &&
            sha(originalRoot.resolve("bundle.json"),4194304)==Q583PreparedNoStartTerminal.bundleSha)
        val image=GenerationNormalizedWorklaneImage.requireSelected(
            requireNotNull(bundle.request.managedLanes).native.imageArchive)
        val bin=ActivationInput(WorklaneLateBrokerImportProof.binaryPath,WorklaneLateBrokerImportProof.binarySha)
        WorklaneLateBrokerImportProof.verifySelected(bin)
        val podman=ActivationInput("/usr/bin/podman",RecoveryCapsule.fileHash(Path.of("/usr/bin/podman")))
        require(podman.sha256=="6e4993e061eb88205003892252e2e13bbf49c12a6f67f519881b9b3c94e980e6" &&
            Files.getFileStore(base.parent).usableSpace >= image.maximumUnpackedBytes + 10L*1024*1024*1024)
        ReleasePrivateFiles.directory(base.parent)
        dir(base);dir(base.resolve("native-locks"));dir(managed);dir(managed.resolve("inputs"));dir(control)
        listOf("home","config","data","run").forEach { dir(control.resolve(it)) }
        ManagedLaneKind.entries.forEach { dir(managed.resolve(it.name.lowercase())) }
        val manifestBytes="""schema_version = 5
id = "$laneId"
name = "p0v3-managed"
container_name = "worklane-p0v3-managed-$laneId"
session_name = "p0v3-managed"
container_home = "/home/dev"
profile_name = "v3"
created_at = "2026-11-09T00:00:00Z"
image_digest = "${image.expectedImageId}"
[profile]
image = "${image.expectedImageId}"
agent = "pi"
terminal_backend = "tuios-v3"
embedded_containerfile = false
network = "none"
runtime = "systemd"
mount_codex_credentials = false
mount_gh_credentials = false
[[profile.mounts]]
source = "${control.resolve("run/broker.sock")}" 
target = "/run/worklane-pi/broker.sock"
read_only = true
""".toByteArray()
        val storageBytes="""[storage]
driver = "vfs"
graphroot = "${control.resolve("data/containers/storage")}" 
runroot = "${control.resolve("run/containers")}" 
rootless_storage_path = "${control.resolve("data/containers/storage")}" 
""".toByteArray()
        ReleasePrivateFiles.save(manifest,manifestBytes)
        ReleasePrivateFiles.save(storage,storageBytes)
        val lanes=ManagedLaneKind.entries.map { kind -> ManagedLaneSpec(kind,laneId,subject,"p0v3-managed",
            "home","home/workspace",if(kind==ManagedLaneKind.WORKLANE)4096 else 0,
            if(kind==ManagedLaneKind.WORKLANE)16384 else 0) }
        val brokerConfig=managed.resolve("inputs/broker.json")
        val configBytes=json.encodeToString(ManagedBrokerConfiguration(generation,laneId,
            "p0v3-managed",subject,"https://auth.datamancy.net/realms/p0v3")).toByteArray()
        ReleasePrivateFiles.save(brokerConfig,configBytes) // No bearer/authority enrolled.
        val controller=Path.of("/mnt/media/p0-v3/runtime-supervision/releases/2e22df88210887c87d9cbdcf0738f52324657b96ab343ce6fb0cac3f91b9ff77")
        PinnedBackupController.verifyDistribution(controller,controller.fileName.toString(),"p0-v3-platform")
        val plan=ManagedLanePlan(generation,lanes,ManagedLaneHostBinding(bin,podman,
            ActivationInput(manifest.toString(),sha(manifest)),ActivationInput(storage.toString(),sha(storage)),
            ManagedBrokerServiceBinding(controller.fileName.toString(),RecoveryCapsule.fileHash(controller.resolve("bin/p0-v3-platform")),
                ActivationInput(brokerConfig.toString(),sha(brokerConfig))),imageArchive=image))
        plan.validate(generation)
        val source=managed.resolve("isolated-managed-plan.json")
        ReleasePrivateFiles.save(source,json.encodeToString(plan).toByteArray())
        val backend=NativeManagedLaneBackend(Path.of(bin.path),Path.of(podman.path),storage,manifest,
            control.resolve("home"),control.resolve("config"),control.resolve("data"),control.resolve("run"),image,
            mapOf("worklane" to bin.sha256,"podman" to podman.sha256,"storageConfig" to sha(storage),
                "manifest" to sha(manifest),"imageArchive" to image.archive.sha256))
        val lane=lanes.single { it.kind==ManagedLaneKind.WORKLANE }
        backend.validateTargetManifest(manifestBytes,lane,worklane)
        val probeIntent=base.resolve("full-production-prepare.intent.json")
        val probeResult=base.resolve("full-production-prepare.result.json")
        val input=json.encodeToString(mapOf("action" to "isolated-full-production-managed-prepare",
            "generation" to generation,"originalQ583TerminalSha256" to terminalSha,
            "planSha256" to sha(source),"sourceManifestSha256" to sha(manifest),
            "worklaneBinarySha256" to bin.sha256,"imageArchiveSha256" to image.archive.sha256))
            .toByteArray()
        ReleasePrivateFiles.save(probeIntent,input)
        // Exactly one isolated native effect, under its own member locks. Native
        // import/manifest/status/result cannot be repeated if interrupted.
        return RecoveryDeadline.within(TimeUnit.MINUTES.toMillis(30)) {
            PrivateDeployment.withPreparationNamespace("$generation-v2",base.resolve("native-locks")) { first ->
            require(first) { "Isolated scratch member already bound; never replay PREPARE" }
            val deadline=System.currentTimeMillis()+TimeUnit.MINUTES.toMillis(29)
            val attested=ManagedLaneRuntime(managed,plan,backend).operate(lane,
                ManagedLaneOperation.PREPARE,"isolated-full-return",deadlineEpochMillis=deadline)
            require(attested.operation==ManagedLaneOperation.PREPARE && attested.isolated &&
                attested.generation==generation && attested.laneId==laneId &&
                attested.intentSha256==sha(worklane.resolve("prepare-isolated-full-return.intent.json"),8192))
            val actual=worklane.resolve("prepare-isolated-full-return.result.json")
            require(json.decodeFromString<ManagedLaneEvidence>(bytes(actual,8192).decodeToString(throwOnInvalidSequence=true))==attested)
            val census=RootlessVfsGraphCensus.observe(control.resolve("data/containers/storage"),
                image.maximumUnpackedBytes)
            val record=WorklaneFullPrepareProbeResult(generation=generation,originalQ583TerminalSha256=terminalSha,
                sourceManifestSha256=sha(manifest),preparedIntentSha256=attested.intentSha256,
                preparedResultSha256=sha(actual,8192),imageId=image.expectedImageId,
                worklaneState="absent",nativeContainers=0,
                graphAllocatedBytes=census.getValue("allocatedBytes").jsonPrimitive.long,
                graphEntries=census.getValue("entries").jsonPrimitive.long,
                brokerSocketAbsent=!Files.exists(control.resolve("run/broker.sock"),NOFOLLOW_LINKS))
            require(record.brokerSocketAbsent && record.graphAllocatedBytes>=4294967296L &&
                record.graphEntries>1 && managedPrepareNativeIsolation(
                    buildJsonObject { put("state",record.worklaneState) },JsonArray(emptyList())))
            val raw=json.encodeToString(record).toByteArray()
            ReleasePrivateFiles.save(probeResult,raw)
            ActivationInput(probeResult.toString(),ReleaseLocks.sha256(raw))
            }
        }
    }
    /** Production post-return native readback under the probe's retained
     * member lock; safe for NEW preseal, never an original-generation ACK. */
    fun verifyLive(pin:ActivationInput):WorklaneFullPrepareProbeResult {
        val saved=verify(pin)
        return RecoveryDeadline.within(TimeUnit.MINUTES.toMillis(5)) {
            PrivateDeployment.withOrderedNativeLocks(listOf("$generation-v2"),base.resolve("native-locks")) {
                val plan=json.decodeFromString<ManagedLanePlan>(bytes(managed.resolve("isolated-managed-plan.json"),65536)
                    .decodeToString(throwOnInvalidSequence=true))
                val lane=plan.lanes.single { it.kind==ManagedLaneKind.WORKLANE }
                val native=plan.native
                val image=requireNotNull(native.imageArchive)
                val backend=NativeManagedLaneBackend(Path.of(native.worklane.path),Path.of(native.podman.path),
                    Path.of(native.storageConfig.path),Path.of(native.manifest.path),
                    control.resolve("home"),control.resolve("config"),control.resolve("data"),control.resolve("run"),
                    image,mapOf("worklane" to native.worklane.sha256,"podman" to native.podman.sha256,
                        "storageConfig" to native.storageConfig.sha256,"manifest" to native.manifest.sha256,
                        "imageArchive" to image.archive.sha256))
                val actual=worklane.resolve("prepare-isolated-full-return.result.json")
                val evidence=json.decodeFromString<ManagedLaneEvidence>(bytes(actual,8192)
                    .decodeToString(throwOnInvalidSequence=true))
                require(backend.attest(lane,worklane,evidence)==evidence && evidence.isolated &&
                    evidence.operation==ManagedLaneOperation.PREPARE && evidence.intentSha256==saved.preparedIntentSha256)
                val graph=RootlessVfsGraphCensus.observe(control.resolve("data/containers/storage"),
                    image.maximumUnpackedBytes)
                require(graph.getValue("entries").jsonPrimitive.long>=saved.graphEntries/2 &&
                    graph.getValue("allocatedBytes").jsonPrimitive.long>=4294967296L &&
                    !Files.exists(control.resolve("run/broker.sock"),NOFOLLOW_LINKS))
                saved
            }
        }
    }
    fun verify(pin:ActivationInput):WorklaneFullPrepareProbeResult {
        val result=base.resolve("full-production-prepare.result.json")
        require(pin.path==result.toString() && pin.sha256==sha(result))
        val record=json.decodeFromString<WorklaneFullPrepareProbeResult>(bytes(result).decodeToString(throwOnInvalidSequence=true))
        val intent=base.resolve("full-production-prepare.intent.json")
        val actual=worklane.resolve("prepare-isolated-full-return.result.json")
        require(Files.isRegularFile(intent,NOFOLLOW_LINKS) &&
            record.generation==generation && record.originalQ583TerminalSha256==terminalSha &&
            record.sourceManifestSha256==sha(manifest) && record.preparedResultSha256==sha(actual,8192) &&
            record.preparedIntentSha256==sha(worklane.resolve("prepare-isolated-full-return.intent.json"),8192) &&
            record.imageId==GenerationNormalizedWorklaneImage.requireSelected(
                json.decodeFromString<ManagedLanePlan>(bytes(managed.resolve("isolated-managed-plan.json"),65536)
                    .decodeToString(throwOnInvalidSequence=true))
                    .native.imageArchive).expectedImageId &&
            record.worklaneState=="absent" && record.nativeContainers==0 &&
            record.graphAllocatedBytes>=4294967296L && record.graphEntries>1 &&
            record.brokerSocketAbsent && !Files.exists(control.resolve("run/broker.sock"),NOFOLLOW_LINKS) &&
            record.productionBackendAttested && !record.originalGenerationImportAcknowledged &&
            !record.applicationStarted && !record.qualificationEvidence &&
            managedPrepareNativeIsolation(buildJsonObject { put("state",record.worklaneState) },JsonArray(emptyList())))
        return record
    }
}
