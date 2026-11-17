package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** A successful owned PREPARE is not a failed prepare or a native INSTALL ACK.
 * This append-only terminal observes the *absence* of any first native effect;
 * it neither changes the historical bundle nor authorizes its replay.
 */
@Serializable internal data class PreparedNoStartDisposition(
    val schemaVersion: Int = 1, val generation: String, val member: String,
    val bundleSha256: String, val assemblyResultSha256: String,
    val earlierFailedPreparationTerminalSha256: String,
    val runnerBinarySha256: String, val pinnedContextMode: String,
    val executableHostBinaryMode: String, val nativeNamespaceReadbackSha256: Map<String,String>,
    val systemdUnitsReadbackSha256: String, val systemdUnitFilesReadbackSha256: String,
    val ownerUnitFilesAbsent: Boolean, val priorReadOnlyRefusalSha256: String,
    val stageIntentAbsent: Boolean = true,
    val nativeEffectObserved: Boolean = false, val qualificationCycles: Int = 0)
@Serializable internal data class PreparedNoStartResult(val intentSha256: String,
    val dispositionSha256: String, val passed: Boolean = true)

internal object PreparedNoStartTerminal {
    private val json=Json { encodeDefaults=true; ignoreUnknownKeys=false }
    private const val old="q-5712d9335843"
    private const val oldBundle="54be7fc1a1d8d863a394555e35e8ef899f7faa8c4a02da9fb754e61ac9e4be81"
    private const val runnerHash="0c4a3f0c4a60632a5914981752a7afe9791a98bdd481296992b412abef5faf0a"
    private val hostBinary=Path.of("/mnt/media/p0-v3/ci-runner/bin/forgejo-runner-v3.5.1")
    private val root=GenerationRuntime.BASE.resolve(old)
    private val intent=root.resolve("prepared-no-start-v2.intent.json")
    private val disposition=root.resolve("prepared-no-start-v2.disposition.json")
    private val result=root.resolve("prepared-no-start-v2.result.json")
    private val priorRefusal=Path.of("/home/gerald/p0_v3/.coord/rapid-completion/core-q5712-prepared-no-start-terminal-first-1018.log")
    private fun pin(path:Path,max:Int)=ReleaseLocks.sha256(ReleasePrivateFiles.read(path,max))
    private fun output(args:List<String>):ByteArray {
        val reply=PrivateRootfulCommands(30,RuntimeStore.CANONICAL_V2).run(args)
        val bytes=reply.output.encodeToByteArray()
        require(reply.exitCode==0 && bytes.size<=1048576) { "Native namespace absence unknown" }
        return bytes
    }
    private fun systemd(vararg args:String):ByteArray {
        val child=ProcessBuilder(listOf("/usr/bin/sudo","-n","/usr/bin/systemctl")+args)
            .redirectErrorStream(true).start()
        val bytes=child.inputStream.readNBytes(1048577)
        val completed=child.waitFor(30,java.util.concurrent.TimeUnit.SECONDS)
        val noMatch=completed && args.firstOrNull()=="list-unit-files" &&
            child.exitValue()==1 && bytes.isEmpty()
        require(completed && bytes.size<=1048576 && (child.exitValue()==0 || noMatch)) {
            "Native systemd absence unknown" }
        return bytes
    }
    fun observe(bundle:GenerationBundle, expected:String):ActivationInput {
        require(bundle.request.id==old && expected==oldBundle && bundle.members.size==1 &&
            bundle.members.single().spec.processes.size==134 && bundle.ownership!=null &&
            bundle.request.abandonedPreparation?.priorGeneration=="q-5962a9fda75b" &&
            pin(root.resolve("bundle.json"),4194304)==expected)
        val member=bundle.members.single().spec.name
        require(member=="$old-v2" && bundle.members.single().spec.executionBackend==RuntimeExecutionBackend.QUADLET_V2)
        val outcome=json.decodeFromString<AssemblyPreparationOutcome>(ReleasePrivateFiles.read(
            root.resolve("assembly.result.json"),8192).decodeToString(throwOnInvalidSequence=true))
        require(outcome.passed && outcome.bundleSha256==expected &&
            outcome.assemblySha256==pin(root.resolve("assembly.intent.json"),4194304))
        for (name in listOf("stage.intent.json","stage.result.json","quadlet-serve-stop.intent.json",
            "quadlet-serve.result.json","isolate.intent.json","import.intent.json",
            "managed-start.intent.json","managed-start.result.json","original-job.intent.json",
            "prepared-no-start.intent.json","prepared-no-start.disposition.json","prepared-no-start.result.json",
            "prepared-no-start-v2.intent.json","prepared-no-start-v2.disposition.json","prepared-no-start-v2.result.json"))
            require(!Files.exists(root.resolve(name),NOFOLLOW_LINKS)) { "Original generation already attempted $name" }
        require(!Files.exists(root.resolve("ci/original-job.intent.json"),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("ci/runner-binary-install.intent.json"),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("ci/account-stage.intent.json"),NOFOLLOW_LINKS) &&
            !Files.exists(Path.of("/mnt/media/p0-v3/rootless-ci-account-owner"),NOFOLLOW_LINKS))
        val binary=Path.of(requireNotNull(bundle.request.forgejoCi).runnerBinary.path)
        require(binary.toString()=="/mnt/media/p0-v3/image-acquisition-receipts/forgejo-ci-runner-minimal-r2/context/forgejo-runner" &&
            Files.isRegularFile(binary,NOFOLLOW_LINKS) && !Files.isSymbolicLink(binary) &&
            Files.getPosixFilePermissions(binary)==PosixFilePermissions.fromString("rw-------") &&
            Files.size(binary) in 1024L..24000000L && RecoveryCapsule.fileHash(binary)==runnerHash &&
            Files.isRegularFile(hostBinary,NOFOLLOW_LINKS) && !Files.isSymbolicLink(hostBinary) &&
            Files.getPosixFilePermissions(hostBinary)==PosixFilePermissions.fromString("rwx------") &&
            Files.size(hostBinary) in 1024L..24000000L && RecoveryCapsule.fileHash(hostBinary)==runnerHash) { "Sealed source defect or original built host executable changed" }
        RuntimeQuadletPreflight.verify(bundle.members.single().spec)
        val prefix="p0v3-live-$member-"
        val native=listOf("container","network","volume","secret").associateWith { kind ->
            val args=when(kind) {
                "container"->listOf(kind,"ls","--all","--format","{{.Names}}")
                else->listOf(kind,"ls","--format","{{.Name}}")
            }
            val bytes=output(args)
            require(bytes.decodeToString(throwOnInvalidSequence=true).lineSequence().none {
                it.trim().startsWith(prefix) }) { "Native original namespace observed: $kind" }
            ReleaseLocks.sha256(bytes)
        }
        val pattern="p0v3-$member-*"
        val units=systemd("list-units","--all","--plain","--no-legend",pattern)
        val unitFiles=systemd("list-unit-files","--no-legend",pattern)
        require(units.decodeToString(throwOnInvalidSequence=true).isBlank() &&
            unitFiles.decodeToString(throwOnInvalidSequence=true).isBlank() &&
            !Files.exists(Path.of("/etc/containers/systemd/$member"),NOFOLLOW_LINKS) &&
            !Files.exists(Path.of("/etc/systemd/system/p0v3-$member.target"),NOFOLLOW_LINKS)) {
            "Original systemd unit ownership or installed unit present" }
        val oldTerminal=pin(Path.of(requireNotNull(bundle.request.abandonedPreparation).terminal.path),1048576)
        require(oldTerminal==bundle.request.abandonedPreparation.terminal.sha256)
        require(Files.isRegularFile(priorRefusal,NOFOLLOW_LINKS) && !Files.isSymbolicLink(priorRefusal) &&
            Files.size(priorRefusal) in 1L..8192L)
        val oldLog=Files.readAllBytes(priorRefusal)
        require(ReleaseLocks.sha256(oldLog)=="e095c5eed4c39681506472f2986129465010d97241ef919a504d66dd18c78ece" &&
            oldLog.decodeToString(throwOnInvalidSequence=true).trim()==
            "Prepared no-start terminal observation refused (IllegalArgumentException); preserve original sealed bundle and native absence")
        val oldLogSha=ReleaseLocks.sha256(oldLog)
        val record=PreparedNoStartDisposition(generation=old,member=member,bundleSha256=expected,
            assemblyResultSha256=pin(root.resolve("assembly.result.json"),8192),
            earlierFailedPreparationTerminalSha256=oldTerminal,runnerBinarySha256=runnerHash,
            pinnedContextMode="0600",executableHostBinaryMode="0700",
            nativeNamespaceReadbackSha256=native,
            systemdUnitsReadbackSha256=ReleaseLocks.sha256(units),
            systemdUnitFilesReadbackSha256=ReleaseLocks.sha256(unitFiles),ownerUnitFilesAbsent=true,
            priorReadOnlyRefusalSha256=oldLogSha)
        val intentBytes=json.encodeToString(mapOf("action" to "terminal-observe-prepared-no-start-v2",
            "priorReadOnlyRefusalSha256" to oldLogSha,
            "generation" to old,"bundleSha256" to expected,"originalAssemblyResultSha256" to record.assemblyResultSha256))
            .encodeToByteArray()
        ReleasePrivateFiles.save(intent,intentBytes)
        val bytes=json.encodeToString(record).encodeToByteArray()
        ReleasePrivateFiles.save(disposition,bytes)
        ReleasePrivateFiles.save(result,json.encodeToString(PreparedNoStartResult(
            ReleaseLocks.sha256(intentBytes),ReleaseLocks.sha256(bytes))).encodeToByteArray())
        return ActivationInput(disposition.toString(),ReleaseLocks.sha256(bytes))
    }
    /** Future successor source binds both this completed no-start observation and
     * the older q5962 failed-preparation terminal; no q5712 state is imported. */
    fun verify(evidence:ActivationInput):PreparedNoStartDisposition {
        require(evidence.path==disposition.toString())
        val bytes=ReleasePrivateFiles.read(disposition,1048576)
        require(ReleaseLocks.sha256(bytes)==evidence.sha256)
        val record=json.decodeFromString<PreparedNoStartDisposition>(bytes.decodeToString(throwOnInvalidSequence=true))
        val receipt=json.decodeFromString<PreparedNoStartResult>(ReleasePrivateFiles.read(result,8192)
            .decodeToString(throwOnInvalidSequence=true))
        require(record.generation==old && record.bundleSha256==oldBundle && record.stageIntentAbsent &&
            !record.nativeEffectObserved && record.qualificationCycles==0 && receipt.passed &&
            receipt.dispositionSha256==evidence.sha256 && receipt.intentSha256==pin(intent,8192) &&
            pin(root.resolve("bundle.json"),4194304)==record.bundleSha256 &&
            pin(root.resolve("assembly.result.json"),8192)==record.assemblyResultSha256 &&
            !Files.exists(root.resolve("stage.intent.json"),NOFOLLOW_LINKS))
        return record
    }
}
