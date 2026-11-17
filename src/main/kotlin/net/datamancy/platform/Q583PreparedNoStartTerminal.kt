package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** The original q583 PREPARED bundle has NO serve attempt: the frozen
 * controller's pre-serve semantic refusal was diagnosed read-only. Its fresh
 * inputs remain sealed, but are never usable as another candidate's ACK. */
@Serializable internal data class Q583PreparedNoStartDisposition(
    val schemaVersion:Int=1,val generation:String,val member:String,val bundleSha256:String,
    val assemblyResultSha256:String,val frozenControllerSha256:String,
    val originalPreServeSemanticRefusalSha256:String,val q273UncertainImportTerminalSha256:String,
    val selectedWorklaneSha256:String,val isolatedImportResultSha256:String,
    val rootfulNamespaceSha256:Map<String,String>,val systemdUnitsSha256:String,
    val systemdUnitFilesSha256:String,val nativeStageIntentAbsent:Boolean=true,
    val nativeManagedIntentAbsent:Boolean=true,val rootlessGraphAbsent:Boolean=true,
    val originalServeAttempted:Boolean=false,val originalServeAcknowledged:Boolean=false,
    val qualificationCycles:Int=0)
@Serializable internal data class Q583PreparedNoStartResult(val intentSha256:String,
    val dispositionSha256:String,val passed:Boolean=true)
internal object Q583PreparedNoStartTerminal {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    const val generation="q-58321c79fde9"
    const val bundleSha="06470511c18780d36f919cb6a9259c15d04b0e8781c5a3bdc42e0151aa5f52f2"
    private const val controller="324629e65f1ff8e4075b8846fe5eae6ae66f5b17f384c1b48dd9389990468adb"
    private const val semanticLogSha="10c616e12dce94e9e3c2617cbb3028c6974f8200ec77f808711f228902d2490d"
    private val root=GenerationRuntime.BASE.resolve(generation)
    private val name="prepared-no-start-native-absent-import-semantic-v1"
    private val intent=root.resolve("$name.intent.json")
    private val disposition=root.resolve("$name.disposition.json")
    private val result=root.resolve("$name.result.json")
    private fun pin(path:Path,max:Int)=ReleaseLocks.sha256(ReleasePrivateFiles.read(path,max))
    private fun systemd(vararg args:String):ByteArray {
        val p=ProcessBuilder(listOf("/usr/bin/sudo","-n","/usr/bin/systemctl")+args)
            .redirectErrorStream(true).start()
        val bytes=p.inputStream.readNBytes(1048577)
        require(p.waitFor(30,TimeUnit.SECONDS) && bytes.size<=1048576 &&
            (p.exitValue()==0 || args.firstOrNull()=="list-unit-files" && p.exitValue()==1 && bytes.isEmpty()))
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
    /** Exactly once under generation and member native locks. No Podman load. */
    fun observe(bundle:GenerationBundle,expected:String):ActivationInput {
        require(bundle.request.id==generation && expected==bundleSha && bundle.ownership!=null &&
            bundle.members.single().spec.name=="$generation-v2" && bundle.members.single().spec.processes.size==134 &&
            pin(root.resolve("bundle.json"),4194304)==expected &&
            bundle.request.releaseCandidateSha256==controller &&
            bundle.request.managedLanes?.native?.worklane?.sha256==WorklaneLateBrokerImportProof.binarySha)
        GenerationAfterQ273Lineage.verify(requireNotNull(bundle.request.q273UncertainImportPredecessor),
            requireNotNull(bundle.request.qc3PreparedNoStartPredecessor),
            requireNotNull(bundle.request.uncertainNativeImportPredecessor),
            requireNotNull(bundle.request.isolatedRootlessProbePredecessor))
        val prepared=json.decodeFromString<AssemblyPreparationOutcome>(ReleasePrivateFiles.read(
            root.resolve("assembly.result.json"),8192).decodeToString(throwOnInvalidSequence=true))
        require(prepared.passed && prepared.bundleSha256==expected &&
            prepared.assemblySha256==pin(root.resolve("assembly.intent.json"),4194304))
        val log=Path.of("/home/gerald/p0_v3/.coord/rapid-completion/core-q583-frozen-controller-actual-import-semantic-readonly-1270.log")
        require(Files.isRegularFile(log,NOFOLLOW_LINKS) && !Files.isSymbolicLink(log) &&
            Files.size(log) in 1..8192 && ReleaseLocks.sha256(Files.readAllBytes(log))==semanticLogSha &&
            Files.readString(log).contains("state=absent nativeContainers=0 productionManagedPrepareIsolation=false"))
        for(file in listOf("stage.intent.json","stage.result.json","managed-initial.intent.json",
            "managed-initial.result.json","managed/worklane/prepare-managed-initial.intent.json",
            "managed/worklane/prepare-managed-initial.result.json","managed-start.intent.json",
            "quadlet-serve.intent.json","quadlet-serve.result.json","isolate.intent.json",
            "ci/runner-binary-install.intent.json","ci/account-stage.intent.json",
            "$name.intent.json","$name.disposition.json","$name.result.json"))
            require(!Files.exists(root.resolve(file),NOFOLLOW_LINKS)) { "q583 native or terminal already attempted: $file" }
        val control=root.resolve("managed/control")
        require(Files.isDirectory(control,NOFOLLOW_LINKS) &&
            !Files.exists(control.resolve("data/containers/storage"),NOFOLLOW_LINKS) &&
            !Files.exists(control.resolve("run/containers"),NOFOLLOW_LINKS) &&
            !Files.exists(control.resolve("home"),NOFOLLOW_LINKS) &&
            Files.isRegularFile(control.resolve("storage.conf"),NOFOLLOW_LINKS) &&
            Files.isRegularFile(root.resolve("managed/inputs/target-lane.toml"),NOFOLLOW_LINKS))
        RuntimeQuadletPreflight.verify(bundle.members.single().spec)
        val namespaces=listOf("container","network","volume","secret").associateWith {
            ReleaseLocks.sha256(native(it)) }
        val units=systemd("list-units","--all","--plain","--no-legend","p0v3-$generation-v2-*")
        val files=systemd("list-unit-files","--no-legend","p0v3-$generation-v2-*")
        require(units.isEmpty() && files.isEmpty() &&
            !Files.exists(Path.of("/etc/containers/systemd/$generation-v2"),NOFOLLOW_LINKS) &&
            !Files.exists(Path.of("/etc/systemd/system/p0v3-$generation-v2.target"),NOFOLLOW_LINKS))
        val record=Q583PreparedNoStartDisposition(generation=generation,member="$generation-v2",
            bundleSha256=expected,assemblyResultSha256=pin(root.resolve("assembly.result.json"),8192),
            frozenControllerSha256=controller,originalPreServeSemanticRefusalSha256=semanticLogSha,
            q273UncertainImportTerminalSha256=GenerationAfterQ273Lineage.predecessorSha,
            selectedWorklaneSha256=WorklaneLateBrokerImportProof.binarySha,
            isolatedImportResultSha256=WorklaneLateBrokerImportProof.importResultSha,
            rootfulNamespaceSha256=namespaces,systemdUnitsSha256=ReleaseLocks.sha256(units),
            systemdUnitFilesSha256=ReleaseLocks.sha256(files))
        val claim=json.encodeToString(mapOf("action" to "q583-prepared-no-start-before-native-serve",
            "generation" to generation,"bundleSha256" to expected,"semanticRefusalSha256" to semanticLogSha))
            .toByteArray()
        val bytes=json.encodeToString(record).toByteArray()
        ReleasePrivateFiles.save(intent,claim)
        ReleasePrivateFiles.save(disposition,bytes)
        ReleasePrivateFiles.save(result,json.encodeToString(Q583PreparedNoStartResult(
            ReleaseLocks.sha256(claim),ReleaseLocks.sha256(bytes))).toByteArray())
        return ActivationInput(disposition.toString(),ReleaseLocks.sha256(bytes))
    }
    fun verify(input:ActivationInput):Q583PreparedNoStartDisposition {
        require(input.path==disposition.toString() && pin(disposition,1048576)==input.sha256)
        val record=json.decodeFromString<Q583PreparedNoStartDisposition>(ReleasePrivateFiles.read(disposition,1048576)
            .decodeToString(throwOnInvalidSequence=true))
        val receipt=json.decodeFromString<Q583PreparedNoStartResult>(ReleasePrivateFiles.read(result,8192)
            .decodeToString(throwOnInvalidSequence=true))
        require(receipt.passed && receipt.intentSha256==pin(intent,8192) &&
            receipt.dispositionSha256==input.sha256 && record.generation==generation &&
            record.bundleSha256==bundleSha && record.frozenControllerSha256==controller &&
            record.originalPreServeSemanticRefusalSha256==semanticLogSha &&
            record.q273UncertainImportTerminalSha256==GenerationAfterQ273Lineage.predecessorSha &&
            record.selectedWorklaneSha256==WorklaneLateBrokerImportProof.binarySha &&
            record.isolatedImportResultSha256==WorklaneLateBrokerImportProof.importResultSha &&
            record.rootlessGraphAbsent && record.nativeStageIntentAbsent && record.nativeManagedIntentAbsent &&
            !record.originalServeAttempted && !record.originalServeAcknowledged && record.qualificationCycles==0 &&
            pin(root.resolve("bundle.json"),4194304)==bundleSha &&
            !Files.exists(root.resolve("stage.intent.json"),NOFOLLOW_LINKS))
        return record
    }
}
