package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** The q07 original INSTALL copied disabled source/drop-in files and reloaded
 * systemd, but its first non-root installed audit could not traverse sudo's
 * mode-0700 new drop-in directory. Do NOT retry, chmod or invent the result. */
@Serializable internal data class Q07PartialInstalledUnitDisposition(
    val schemaVersion:Int=1,val generation:String,val member:String,val bundleSha256:String,
    val originalInstallIntentSha256:String,val originalSpecSha256:String,
    val copiedRootOwnedFiles:Map<String,String>,val generatedUnitHashes:Map<String,String>,
    val observedUnitStates:Map<String,String>,val sudoUmaskRestrictedDirectories:Int,
    val rootfulContainerListingSha256:String,val originalInstallResultAbsent:Boolean=true,
    val stageIntentAbsent:Boolean=true,val managedPrepareAbsent:Boolean=true,
    val applicationStarted:Boolean=false,val qualificationCycles:Int=0,
    val ownerPid:Long=2892365L)
@Serializable internal data class Q07PartialInstalledUnitResult(val intentSha256:String,
    val dispositionSha256:String,val passed:Boolean=true)
internal object Q07PartialInstalledUnitTerminal {
    const val generation="q-083e9b7d2a64"
    const val bundleSha="acb6a27eee51d95e46412704f894d601892e7875dbc035bdd7e843742af8c82f"
    private val root=GenerationRuntime.BASE.resolve(generation)
    private const val name="partial-disabled-quadlet-install-umask-v1"
    private val intent=root.resolve("$name.intent.json")
    private val record=root.resolve("$name.disposition.json")
    private val result=root.resolve("$name.result.json")
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    private fun hash(path:Path,max:Int=4194304)=ReleaseLocks.sha256(ReleasePrivateFiles.read(path,max))
    private fun child(command:List<String>,max:Int=8192):String {
        val child=ProcessBuilder(command).redirectErrorStream(true).apply { environment().clear() }.start()
        try {
            val bytes=child.inputStream.readNBytes(max+1)
            require(child.waitFor(30,TimeUnit.SECONDS) && child.exitValue()==0 && bytes.size in 1..max) {
                "Root read-only installed-unit inventory unavailable; retain q07 original intent"
            }
            return bytes.decodeToString(throwOnInvalidSequence=true)
        } finally { if(child.isAlive)child.destroyForcibly() }
    }
    private fun rootFile(path:Path,expected:String):String {
        require(path.toString().matches(Regex(
            "/etc/containers/systemd/p0-v3/p0v3-q-083e9b7d2a64-v2-[a-z0-9-]+\\.container|"+
            "/etc/systemd/system/p0v3-q-083e9b7d2a64-v2-[a-z0-9-]+\\.service\\.d/50-p0-lifecycle\\.conf")))
        val info=child(listOf("/usr/bin/sudo","-n","/usr/bin/stat","-c","%u %h %a %F","--",path.toString()))
            .trim()
        require(info=="0 1 644 regular file") { "Unsafe root-owned original Quadlet file" }
        val digest=child(listOf("/usr/bin/sudo","-n","/usr/bin/sha256sum","--",path.toString()))
            .substringBefore(' ')
        require(digest==expected) { "Root-owned original installed source differs" }
        return info
    }
    private fun observed(bundle:GenerationBundle,expected:String):Q07PartialInstalledUnitDisposition {
        require(expected==bundleSha && bundle.request.id==generation && bundle.ownership!=null &&
            hash(root.resolve("bundle.json"))==bundleSha && bundle.members.size==1 &&
            !ProcessHandle.of(2892365L).map { it.isAlive }.orElse(false))
        val spec=bundle.members.single().spec
        require(spec.name=="$generation-v2" && spec.processes.size==134)
        for (file in listOf("quadlet-install-${spec.name}.result.json","stage.intent.json",
                "stage.result.json","managed-initial.intent.json","managed-initial.result.json",
                "managed-start.intent.json","quadlet-serve.result.json"))
            require(!Files.exists(root.resolve(file),NOFOLLOW_LINKS)) { "Original q07 result/start changed: $file" }
        require(!Files.exists(root.resolve("managed/control/data/containers/storage"),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("managed/control/run/broker.sock"),NOFOLLOW_LINKS))
        val i=root.resolve("quadlet-install-${spec.name}.intent.json")
        val originalBytes=ReleasePrivateFiles.read(i,65536)
        val original=json.decodeFromString<QuadletInstallIntent>(originalBytes.decodeToString(throwOnInvalidSequence=true))
        val rendered=RuntimeQuadlets.render(spec)
        val expectedPaths=rendered.files.mapKeys { (relative,_) ->
            (if(relative.endsWith(".container")) Path.of("/etc/containers/systemd/p0-v3")
             else Path.of("/etc/systemd/system")).resolve(relative).toString()
        }.mapValues { ReleaseLocks.sha256(it.value.toByteArray()) }
        require(original.generation==generation && original.member==spec.name &&
            original.bundleSha256==bundleSha && original.specSha256==rendered.specSha256 &&
            original.stagedDestinations==expectedPaths.keys.toList() &&
            original.filesSha256==expectedPaths && expectedPaths.size==268)
        // Root-only READ of the original mode-0700 drop-in parents. No chmod,
        // replacement, daemon-reload or sudo unit start is allowed here.
        val fileModes=expectedPaths.mapValues { (path,sha)->rootFile(Path.of(path),sha) }
        val restricted=expectedPaths.keys.filter { it.endsWith("/50-p0-lifecycle.conf") }.count { path ->
            val mode=child(listOf("/usr/bin/sudo","-n","/usr/bin/stat","-c","%u %a %F","--",
                Path.of(path).parent.toString())).trim()
            require(mode=="0 700 directory" || mode=="0 755 directory")
            mode=="0 700 directory"
        }
        require(restricted==134)
        val generated=mutableMapOf<String,String>()
        val states=mutableMapOf<String,String>()
        for(p in spec.processes) {
            val unit=RuntimeQuadlets.unit(spec,p)+".service"
            val path=Path.of("/run/systemd/generator/$unit")
            require(Files.isRegularFile(path,NOFOLLOW_LINKS))
            val bytes=Files.readAllBytes(path)
            require(bytes.size in 1..65536 && bytes.decodeToString(throwOnInvalidSequence=true)
                .lineSequence().any { it=="SourcePath=/etc/containers/systemd/p0-v3/${unit.removeSuffix(".service")}.container" })
            generated[unit]=ReleaseLocks.sha256(bytes)
            val show=child(listOf("/usr/bin/systemctl","show","--no-pager",
                "--property=LoadState,ActiveState,SubState,UnitFileState,MainPID,ControlPID,Job,SourcePath,DropInPaths",unit))
            val fields=show.lineSequence().filter { '=' in it }
                .associate { it.substringBefore('=') to it.substringAfter('=') }
            require(fields["LoadState"]=="loaded" && fields["UnitFileState"]=="generated" &&
                fields["ActiveState"]=="inactive" && fields["SubState"]=="dead" &&
                fields["MainPID"]=="0" && fields["ControlPID"]=="0" &&
                fields["Job"] in setOf("0","") &&
                fields["SourcePath"]=="/etc/containers/systemd/p0-v3/${unit.removeSuffix(".service")}.container" &&
                fields["DropInPaths"]=="/etc/systemd/system/${unit}.d/50-p0-lifecycle.conf") {
                "q07 installed unit is live, foreign or not generated"
            }
            states[unit]="loaded:generated:inactive:dead:pid0:job0"
        }
        val census=PrivateRootfulCommands(60,spec.store).run(listOf("container","ls","--all","--format","{{.Names}}"))
        require(census.exitCode==0 && census.output.toByteArray().size<=2000000 &&
            census.output.lineSequence().none { it.trim().startsWith("p0v3-live-${spec.name}-") })
        return Q07PartialInstalledUnitDisposition(generation=generation,member=spec.name,bundleSha256=expected,
            originalInstallIntentSha256=ReleaseLocks.sha256(originalBytes),originalSpecSha256=rendered.specSha256,
            copiedRootOwnedFiles=fileModes,generatedUnitHashes=generated,observedUnitStates=states,
            sudoUmaskRestrictedDirectories=restricted,
            rootfulContainerListingSha256=ReleaseLocks.sha256(census.output.toByteArray()))
    }
    fun observe(bundle:GenerationBundle,expected:String):ActivationInput {
        require(listOf(intent,record,result).none { Files.exists(it,NOFOLLOW_LINKS) })
        val state=observed(bundle,expected)
        val original=json.encodeToString(mapOf("action" to "observe-partial-disabled-quadlet-install",
            "generation" to generation,"bundleSha256" to expected,
            "originalInstallIntentSha256" to state.originalInstallIntentSha256)).toByteArray()
        val bytes=json.encodeToString(state).toByteArray()
        ReleasePrivateFiles.save(intent,original);ReleasePrivateFiles.save(record,bytes)
        ReleasePrivateFiles.save(result,json.encodeToString(Q07PartialInstalledUnitResult(
            hash(intent,8192),ReleaseLocks.sha256(bytes))).toByteArray())
        return ActivationInput(record.toString(),ReleaseLocks.sha256(bytes))
    }
    fun verify(pin:ActivationInput):Q07PartialInstalledUnitDisposition {
        require(pin.path==record.toString() && pin.sha256==hash(record,262144))
        val d=json.decodeFromString<Q07PartialInstalledUnitDisposition>(ReleasePrivateFiles.read(record,262144)
            .decodeToString(throwOnInvalidSequence=true))
        val r=json.decodeFromString<Q07PartialInstalledUnitResult>(ReleasePrivateFiles.read(result,8192)
            .decodeToString(throwOnInvalidSequence=true))
        require(r.passed && r.intentSha256==hash(intent,8192) && r.dispositionSha256==pin.sha256 &&
            d.generation==generation && d.bundleSha256==bundleSha &&
            d.copiedRootOwnedFiles.size==268 && d.generatedUnitHashes.size==134 &&
            d.observedUnitStates.size==134 && d.sudoUmaskRestrictedDirectories==134 &&
            d.originalInstallResultAbsent && d.stageIntentAbsent && d.managedPrepareAbsent &&
            !d.applicationStarted && d.qualificationCycles==0)
        return d
    }
    fun verifyLive(bundle:GenerationBundle,pin:ActivationInput):Q07PartialInstalledUnitDisposition {
        val original=verify(pin)
        require(observed(bundle,bundleSha)==original) { "q07 retained partial install/native absence changed" }
        return original
    }
}
