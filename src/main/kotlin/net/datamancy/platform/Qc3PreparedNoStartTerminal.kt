package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** Original qc3 owned preparation succeeded, but a single original serve
 * refused at pre-effect capacity admission. This closes only qc3's own intent;
 * it does NOT assert q4d's imported graph empty or release that reservation. */
@Serializable internal data class Qc3PreparedNoStartDisposition(
    val schemaVersion:Int=1,val generation:String,val member:String,val bundleSha256:String,
    val assemblyResultSha256:String,val originalServeRefusalSha256:String,
    val originalQ4dUncertainImportTerminalSha256:String,
    val originalIsolatedProbeSha256:String,val rootfulNamespaceSha256:Map<String,String>,
    val systemdUnitsSha256:String,val systemdUnitFilesSha256:String,
    val localManagedControlPresent:Boolean,val rootlessGraphAbsent:Boolean,
    val stageIntentAbsent:Boolean=true,val nativePrepareIntentAbsent:Boolean=true,
    val originalServeAcknowledged:Boolean=false,val qualificationCycles:Int=0)
@Serializable internal data class Qc3PreparedNoStartResult(val intentSha256:String,
    val dispositionSha256:String,val passed:Boolean=true)
internal object Qc3PreparedNoStartTerminal {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    private const val generation="q-c3a7a9e29391"
    private const val bundleHash="f8419d6064822cef7d6e8d6b82dfeabae1612da5fc778bb399bf6df2100f5b22"
    private const val refusalHash="9d0b99667f1404ceed0b47d6c634b0b8517f860442aaade1bf529167da17a0d9"
    private val root=GenerationRuntime.BASE.resolve(generation)
    private val intent=root.resolve("qc3-pre-native-capacity-no-start-v1.intent.json")
    private val disposition=root.resolve("qc3-pre-native-capacity-no-start-v1.disposition.json")
    private val result=root.resolve("qc3-pre-native-capacity-no-start-v1.result.json")
    private fun pin(path:Path,max:Int)=ReleaseLocks.sha256(ReleasePrivateFiles.read(path,max))
    private fun systemd(vararg args:String):ByteArray {
        val process=ProcessBuilder(listOf("/usr/bin/sudo","-n","/usr/bin/systemctl")+args)
            .redirectErrorStream(true).start()
        val bytes=process.inputStream.readNBytes(1048577)
        val completed=process.waitFor(30,TimeUnit.SECONDS)
        require(completed && bytes.size<=1048576 &&
            (process.exitValue()==0 || args.firstOrNull()=="list-unit-files" &&
                process.exitValue()==1 && bytes.isEmpty()))
        return bytes
    }
    private fun native(kind:String):ByteArray {
        val args=if(kind=="container") listOf(kind,"ls","--all","--format","{{.Names}}")
            else listOf(kind,"ls","--format","{{.Name}}")
        val reply=PrivateRootfulCommands(30,RuntimeStore.CANONICAL_V2).run(args)
        val bytes=reply.output.toByteArray()
        require(reply.exitCode==0 && bytes.size<=1048576 &&
            bytes.decodeToString(throwOnInvalidSequence=true).lineSequence().none {
                it.trim().startsWith("p0v3-live-$generation-v2-") })
        return bytes
    }
    /** Call only beneath the namespace/member native locks, never after START. */
    fun observe(bundle:GenerationBundle,expected:String):ActivationInput {
        require(bundle.request.id==generation && expected==bundleHash && bundle.ownership!=null &&
            bundle.members.single().spec.name=="$generation-v2" &&
            bundle.members.single().spec.processes.size==134 && pin(root.resolve("bundle.json"),4194304)==expected)
        GenerationAfterNativeImportLineage.verify(
            requireNotNull(bundle.request.uncertainNativeImportPredecessor),
            requireNotNull(bundle.request.isolatedRootlessProbePredecessor))
        val prepared=json.decodeFromString<AssemblyPreparationOutcome>(ReleasePrivateFiles.read(
            root.resolve("assembly.result.json"),8192).decodeToString(throwOnInvalidSequence=true))
        require(prepared.passed && prepared.bundleSha256==expected &&
            prepared.assemblySha256==pin(root.resolve("assembly.intent.json"),4194304))
        val originalLog=Path.of("/home/gerald/p0_v3/.coord/rapid-completion/core-qc3-v2-retained-lock-foreground-serve-once-1192.log")
        require(Files.isRegularFile(originalLog,NOFOLLOW_LINKS) && !Files.isSymbolicLink(originalLog) &&
            Files.size(originalLog) in 1..8192 &&
            ReleaseLocks.sha256(Files.readAllBytes(originalLog))==refusalHash &&
            Files.readString(originalLog).trim()==
                "Quadlet serving episode uncertain (IllegalArgumentException); inspect original unit and CID records, do not replay")
        for(file in listOf("stage.intent.json","stage.result.json","managed-initial.intent.json",
            "managed-initial.result.json","managed/worklane/prepare-managed-initial.intent.json",
            "managed/worklane/prepare-managed-initial.result.json","managed-start.intent.json",
            "quadlet-serve-stop.intent.json","quadlet-serve.result.json","isolate.intent.json",
            "ci/runner-binary-install.intent.json","ci/account-stage.intent.json",
            "qc3-pre-native-capacity-no-start-v1.intent.json","qc3-pre-native-capacity-no-start-v1.disposition.json",
            "qc3-pre-native-capacity-no-start-v1.result.json"))
            require(!Files.exists(root.resolve(file),NOFOLLOW_LINKS)) { "qc3 original native effect or terminal already exists: $file" }
        val control=root.resolve("managed/control")
        require(Files.isDirectory(control,NOFOLLOW_LINKS) &&
            !Files.exists(control.resolve("data/containers/storage"),NOFOLLOW_LINKS) &&
            !Files.exists(control.resolve("run/containers"),NOFOLLOW_LINKS) &&
            !Files.exists(control.resolve("home"),NOFOLLOW_LINKS))
        RuntimeQuadletPreflight.verify(bundle.members.single().spec)
        val namespace=listOf("container","network","volume","secret").associateWith { kind ->
            ReleaseLocks.sha256(native(kind)) }
        val units=systemd("list-units","--all","--plain","--no-legend","p0v3-$generation-v2-*")
        val files=systemd("list-unit-files","--no-legend","p0v3-$generation-v2-*")
        require(units.isEmpty() && files.isEmpty() &&
            !Files.exists(Path.of("/etc/containers/systemd/$generation-v2"),NOFOLLOW_LINKS) &&
            !Files.exists(Path.of("/etc/systemd/system/p0v3-$generation-v2.target"),NOFOLLOW_LINKS))
        val record=Qc3PreparedNoStartDisposition(generation=generation,member="$generation-v2",
            bundleSha256=expected,assemblyResultSha256=pin(root.resolve("assembly.result.json"),8192),
            originalServeRefusalSha256=refusalHash,
            originalQ4dUncertainImportTerminalSha256=GenerationAfterNativeImportLineage.terminalSha,
            originalIsolatedProbeSha256=GenerationAfterNativeImportLineage.probeSha,
            rootfulNamespaceSha256=namespace,systemdUnitsSha256=ReleaseLocks.sha256(units),
            systemdUnitFilesSha256=ReleaseLocks.sha256(files),localManagedControlPresent=true,rootlessGraphAbsent=true)
        val claim=json.encodeToString(mapOf("action" to "qc3-terminal-pre-native-capacity-no-start",
            "generation" to generation,"bundleSha256" to expected,"originalServeRefusalSha256" to refusalHash)).toByteArray()
        val bytes=json.encodeToString(record).toByteArray()
        ReleasePrivateFiles.save(intent,claim)
        ReleasePrivateFiles.save(disposition,bytes)
        ReleasePrivateFiles.save(result,json.encodeToString(Qc3PreparedNoStartResult(
            ReleaseLocks.sha256(claim),ReleaseLocks.sha256(bytes))).toByteArray())
        return ActivationInput(disposition.toString(),ReleaseLocks.sha256(bytes))
    }
    fun verify(proof:ActivationInput):Qc3PreparedNoStartDisposition {
        require(proof.path==disposition.toString() && pin(disposition,1048576)==proof.sha256)
        val record=json.decodeFromString<Qc3PreparedNoStartDisposition>(ReleasePrivateFiles.read(disposition,1048576)
            .decodeToString(throwOnInvalidSequence=true))
        val receipt=json.decodeFromString<Qc3PreparedNoStartResult>(ReleasePrivateFiles.read(result,8192)
            .decodeToString(throwOnInvalidSequence=true))
        require(receipt.passed && receipt.intentSha256==pin(intent,8192) &&
            receipt.dispositionSha256==proof.sha256 && record.generation==generation &&
            record.bundleSha256==bundleHash && record.originalServeRefusalSha256==refusalHash &&
            record.originalQ4dUncertainImportTerminalSha256==GenerationAfterNativeImportLineage.terminalSha &&
            record.originalIsolatedProbeSha256==GenerationAfterNativeImportLineage.probeSha &&
            record.rootlessGraphAbsent && record.stageIntentAbsent && record.nativePrepareIntentAbsent &&
            !record.originalServeAcknowledged && record.qualificationCycles==0 &&
            pin(root.resolve("bundle.json"),4194304)==bundleHash &&
            !Files.exists(root.resolve("stage.intent.json"),NOFOLLOW_LINKS))
        return record
    }
}
