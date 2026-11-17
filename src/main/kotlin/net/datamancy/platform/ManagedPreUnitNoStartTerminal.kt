package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/** Failed original foreground serve, NOT an unattempted PREPARE. The stage and
 * managed-initial intents remain original and unresolved. An append-only
 * terminal may describe native absence, never acknowledge START or replay it. */
@Serializable internal data class ManagedPreUnitNoStartDisposition(
    val schemaVersion:Int=1,val generation:String,val member:String,
    val bundleSha256:String,val originalStageIntentSha256:String,
    val originalManagedInitialIntentSha256:String,val predecessorPreparedNoStartSha256:String,
    val priorFailedPreparationTerminalSha256:String,
    val originalManagedArchiveSha256:String,val originalOwnerPid:Int=3459480,
    val originalOwnerAbsent:Boolean=true,val nativeSystemdUnitsSha256:String,val nativeSystemdUnitFilesSha256:String,
    val nativeQuadletPreflightPassed:Boolean=true,val rootlessGraphEmpty:Boolean=true,
    val managedLaneIntentsAbsent:Boolean=true,val stageResultAbsent:Boolean=true,
    val applicationUnitStarted:Boolean=false,val qualificationCycles:Int=0)
@Serializable internal data class ManagedPreUnitNoStartResult(val intentSha256:String,
    val dispositionSha256:String,val passed:Boolean=true)

internal object ManagedPreUnitNoStartTerminal {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    private const val generation="q-dd36ebcf43ef"
    private const val expected="0944da3c53f1abb03b4fafbb07da475beb421ec8f1036939feb49226268e302a"
    private val root=GenerationRuntime.BASE.resolve(generation)
    private val intent=root.resolve("failed-pre-unit-stage-v1.intent.json")
    private val disposition=root.resolve("failed-pre-unit-stage-v1.disposition.json")
    private val result=root.resolve("failed-pre-unit-stage-v1.result.json")
    private fun pin(path:Path,max:Int=1048576)=ReleaseLocks.sha256(ReleasePrivateFiles.read(path,max))
    private fun unitReadback(vararg args:String):ByteArray {
        val child=ProcessBuilder(listOf("/usr/bin/sudo","-n","/usr/bin/systemctl")+args)
            .redirectErrorStream(true).start()
        val bytes=child.inputStream.readNBytes(1048577)
        val completed=child.waitFor(30,TimeUnit.SECONDS)
        val noMatch=completed && args.firstOrNull()=="list-unit-files" &&
            child.exitValue()==1 && bytes.isEmpty()
        require(completed && bytes.size<=1048576 && (child.exitValue()==0 || noMatch)) {
            "Failed original unit ownership unknown" }
        return bytes
    }
    fun observe(bundle:GenerationBundle,actual:String):ActivationInput {
        require(actual==expected && bundle.request.id==generation && bundle.members.size==1 &&
            bundle.members.single().spec.processes.size==134 && bundle.ownership!=null &&
            bundle.request.preparedNoStartPredecessor?.sha256==
                "6f7b62cc78299a4e4ca365ffea595411165e7e33917d6ae160abd439a36ce6ef" &&
            bundle.request.abandonedPreparation?.priorGeneration=="q-5962a9fda75b" &&
            pin(root.resolve("bundle.json"),4194304)==expected)
        val member=bundle.members.single().spec.name
        require(member=="$generation-v2")
        for (name in listOf("stage.result.json","${member}.stage.result.json",
            "quadlet-serve-stop.intent.json","quadlet-serve.result.json",
            "quadlet-install-$member.intent.json","quadlet-install-$member.result.json",
            "managed-initial.result.json","managed-import.intent.json","managed-import.result.json",
            "managed-start.intent.json","managed-start.result.json","failed-pre-unit-stage-v1.intent.json",
            "failed-pre-unit-stage-v1.disposition.json","failed-pre-unit-stage-v1.result.json"))
            require(!Files.exists(root.resolve(name),NOFOLLOW_LINKS)) { "Original first stage may own a native effect: $name" }
        val stageBytes=ReleasePrivateFiles.read(root.resolve("stage.intent.json"),8192)
        val stage=json.decodeFromString<GenerationIntent>(stageBytes.decodeToString(throwOnInvalidSequence=true))
        require(stage.action=="stage" && stage.bundleSha256==expected)
        val managedBytes=ReleasePrivateFiles.read(root.resolve("managed-initial.intent.json"),8192)
        val fields=managedBytes.decodeToString(throwOnInvalidSequence=true).trimEnd('\n').split('|')
        require(fields.size==4 && fields[0]==generation && fields[1]==expected &&
            fields[2]==ReleaseLocks.sha256(json.encodeToString(requireNotNull(bundle.request.managedLanes))
                .encodeToByteArray()) && fields[3].toLongOrNull()!=null)
        val managed=root.resolve("managed")
        ReleasePrivateFiles.directory(managed)
        val expectedFiles=setOf("inputs/broker.json","inputs/target-lane.toml","control/storage.conf")
        val existing=Files.walk(managed,6).use { paths -> paths.filter {
            Files.isRegularFile(it,NOFOLLOW_LINKS) || Files.isSymbolicLink(it) }.map {
            require(!Files.isSymbolicLink(it));managed.relativize(it).toString() }.toList().toSet() }
        require(existing==expectedFiles &&
            listOf("control/podman-graph","control/podman-run","worklane","pi","tuios",
                "control/home","control/config","control/data","control/run","control/leases")
                .all { part -> val dir=managed.resolve(part); ReleasePrivateFiles.directory(dir)
                    Files.list(dir).use { !it.findAny().isPresent } }) {
            "Managed first stage or rootless graph might own a native operation"
        }
        require(!Files.exists(Path.of("/proc/3459480"),NOFOLLOW_LINKS)) {
            "Original foreground owner still active; do not terminalize"
        }
        ForgejoCiNativeSourceAdmission.requirePristineAccountNamespace(requireNotNull(bundle.request.forgejoCi))
        RuntimeQuadletPreflight.verify(bundle.members.single().spec)
        val units=unitReadback("list-units","--all","--plain","--no-legend","p0v3-$member-*")
        val files=unitReadback("list-unit-files","--no-legend","p0v3-$member-*")
        require(units.decodeToString(throwOnInvalidSequence=true).isBlank() &&
            files.decodeToString(throwOnInvalidSequence=true).isBlank() &&
            !Files.exists(Path.of("/etc/containers/systemd/$member"),NOFOLLOW_LINKS))
        val archive=Path.of(requireNotNull(bundle.request.managedLanes).native.imageArchive!!.archive.path)
        val archiveSha=RecoveryCapsule.fileHash(archive)
        require(archiveSha==requireNotNull(bundle.request.managedLanes.native.imageArchive).archive.sha256)
        // The source-only archive diagnosis is retained separately; this is a
        // native-absence record, not an invented successful managed OCI import.
        val record=ManagedPreUnitNoStartDisposition(generation=generation,member=member,bundleSha256=expected,
            originalStageIntentSha256=ReleaseLocks.sha256(stageBytes),
            originalManagedInitialIntentSha256=ReleaseLocks.sha256(managedBytes),
            predecessorPreparedNoStartSha256=requireNotNull(bundle.request.preparedNoStartPredecessor).sha256,
            priorFailedPreparationTerminalSha256=requireNotNull(bundle.request.abandonedPreparation).terminal.sha256,
            originalManagedArchiveSha256=archiveSha,
            nativeSystemdUnitsSha256=ReleaseLocks.sha256(units),
            nativeSystemdUnitFilesSha256=ReleaseLocks.sha256(files))
        val bytes=json.encodeToString(record).encodeToByteArray()
        val intentBytes=json.encodeToString(mapOf("action" to "terminal-observe-failed-pre-unit-stage",
            "generation" to generation,"bundleSha256" to expected,
            "stageIntentSha256" to record.originalStageIntentSha256,
            "managedInitialIntentSha256" to record.originalManagedInitialIntentSha256)).encodeToByteArray()
        ReleasePrivateFiles.save(intent,intentBytes)
        ReleasePrivateFiles.save(disposition,bytes)
        ReleasePrivateFiles.save(result,json.encodeToString(ManagedPreUnitNoStartResult(
            ReleaseLocks.sha256(intentBytes),ReleaseLocks.sha256(bytes))).encodeToByteArray())
        return ActivationInput(disposition.toString(),ReleaseLocks.sha256(bytes))
    }
    fun verify(evidence:ActivationInput):ManagedPreUnitNoStartDisposition {
        require(evidence.path==disposition.toString())
        val bytes=ReleasePrivateFiles.read(disposition,1048576)
        require(ReleaseLocks.sha256(bytes)==evidence.sha256)
        val record=json.decodeFromString<ManagedPreUnitNoStartDisposition>(bytes.decodeToString())
        val receipt=json.decodeFromString<ManagedPreUnitNoStartResult>(ReleasePrivateFiles.read(result,8192)
            .decodeToString(throwOnInvalidSequence=true))
        require(record.generation==generation && record.bundleSha256==expected &&
            record.stageResultAbsent && record.originalOwnerAbsent && !record.applicationUnitStarted &&
            record.qualificationCycles==0 &&
            receipt.passed && receipt.dispositionSha256==evidence.sha256 &&
            receipt.intentSha256==pin(intent,8192) &&
            record.originalStageIntentSha256==pin(root.resolve("stage.intent.json"),8192) &&
            record.originalManagedInitialIntentSha256==pin(root.resolve("managed-initial.intent.json"),8192) &&
            !Files.exists(root.resolve("stage.result.json"),NOFOLLOW_LINKS))
        return record
    }
}
