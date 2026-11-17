package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*

/** q9b completed all three genuine cold PREPAREs but never installed a systemd
 * unit. This terminal is only a locked observation of its failed STAGE; it
 * cannot convert the missing stage result into a success or replay PREPARE. */
@Serializable internal data class Q9bColdPreparedUninstalledDisposition(
    val schemaVersion:Int=1,val generation:String,val bundleSha256:String,val member:String,
    val originalStageIntentSha256:String,val originalManagedIntentSha256:String,
    val originalManagedResultSha256:String,val originalLaneIntentSha256:Map<ManagedLaneKind,String>,
    val originalLaneResultSha256:Map<ManagedLaneKind,String>,val originalLaneEvidence:Map<ManagedLaneKind,ManagedLaneEvidence>,
    val registrySha256:String,val manifestSha256:String,val rootlessImageId:String,
    val rootlessImageBytes:Long,val rootlessLayersSha256:String,val graphRoot:String,
    val graphAllocatedBytes:Long,val graphEntries:Long,val unitListingSha256:String,
    val unitFileListingSha256:String,val ownerPid:Long=2478186L,
    val originalManagedPrepareAcknowledged:Boolean=true,val originalStageResultAbsent:Boolean=true,
    val installedUnitsAbsent:Boolean=true,val nativeContainersAbsent:Boolean=true,
    val applicationStarted:Boolean=false,val qualificationCycles:Int=0)
@Serializable internal data class Q9bColdPreparedUninstalledResult(val intentSha256:String,
    val dispositionSha256:String,val passed:Boolean=true)
internal object Q9bColdPreparedUninstalledTerminal {
    const val generation="q-9bfa8ec0eb64"
    const val bundleSha="905a66e7ef75d856e1c0272dd745eb9fded69e5347a0e497efc3dc7724cb96ce"
    private const val stageSha="153d0df5ce63b9535133d416c91e51d41ae5006195b0a15a70257b86d0c38e55"
    private const val managedSha="54a2449f01443062758be3cc24dc9a73aafa4457789725faafc2459c96f80d78"
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    private val root=GenerationRuntime.BASE.resolve(generation)
    private const val name="cold-three-lane-prepare-uninstalled-stage-v1"
    private val intent=root.resolve("$name.intent.json")
    private val record=root.resolve("$name.disposition.json")
    private val result=root.resolve("$name.result.json")
    private fun hash(path:Path,max:Int=4194304)=ReleaseLocks.sha256(ReleasePrivateFiles.read(path,max))
    private fun list(vararg args:String):ByteArray {
        val child=ProcessBuilder(listOf("/usr/bin/sudo","-n","/usr/bin/systemctl")+args)
            .redirectErrorStream(true).start()
        try {
            val bytes=child.inputStream.readNBytes(1048577)
            require(child.waitFor(30,TimeUnit.SECONDS) && bytes.size<=1048576 &&
                (child.exitValue()==0 || args.firstOrNull()=="list-unit-files" &&
                    child.exitValue()==1 && bytes.isEmpty()))
            return bytes
        } finally { if(child.isAlive)child.destroyForcibly() }
    }
    private fun current(bundle:GenerationBundle,expected:String):Q9bColdPreparedUninstalledDisposition {
        require(bundle.request.id==generation && expected==bundleSha && bundle.ownership!=null &&
            hash(root.resolve("bundle.json"))==bundleSha && bundle.members.single().spec.name=="$generation-v2" &&
            bundle.members.single().spec.processes.size==134 &&
            hash(root.resolve("stage.intent.json"),8192)==stageSha &&
            hash(root.resolve("managed-initial.intent.json"),8192)==managedSha &&
            !ProcessHandle.of(2478186L).map { it.isAlive }.orElse(false))
        for (file in listOf("stage.result.json","managed-start.intent.json","managed-start.result.json",
                "quadlet-serve.result.json","quadlet-install-$generation-v2.intent.json",
                "quadlet-install-$generation-v2.result.json"))
            require(!Files.exists(root.resolve(file),NOFOLLOW_LINKS)) { "Original q9b native state changed: $file" }
        require(Files.isRegularFile(root.resolve("managed/home/.worklane/lane.toml"),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("managed/control/run/broker.sock"),NOFOLLOW_LINKS))
        val units=list("list-units","--all","--plain","--no-legend","p0v3-$generation-v2-*")
        val unitFiles=list("list-unit-files","--no-legend","p0v3-$generation-v2-*")
        require(units.isEmpty() && unitFiles.isEmpty() &&
            !Files.exists(Path.of("/etc/containers/systemd/p0-v3/p0v3-$generation-v2-postgres-init.container"),NOFOLLOW_LINKS) &&
            !Files.exists(Path.of("/run/systemd/generator/p0v3-$generation-v2-postgres-init.service"),NOFOLLOW_LINKS))
        val managed= json.decodeFromString<ManagedInitialPreparation>(ReleasePrivateFiles.read(
            root.resolve("managed-initial.result.json"),65536).decodeToString(throwOnInvalidSequence=true))
        require(managed.generation==generation && managed.bundleSha256==expected &&
            managed.intentSha256==managedSha && managed.preparations.keys==ManagedLaneKind.entries.toSet())
        val plan=requireNotNull(bundle.request.managedLanes)
        val native=plan.native
        val laneIntent=mutableMapOf<ManagedLaneKind,String>()
        val laneResult=mutableMapOf<ManagedLaneKind,String>()
        val backend=NativeManagedLaneBackend(Path.of(native.worklane.path),Path.of(native.podman.path),
            Path.of(native.storageConfig.path),Path.of(native.manifest.path),
            root.resolve("managed/control/home"),root.resolve("managed/control/config"),
            root.resolve("managed/control/data"),root.resolve("managed/control/run"),
            requireNotNull(native.imageArchive),mapOf("worklane" to native.worklane.sha256,
                "podman" to native.podman.sha256,"storageConfig" to native.storageConfig.sha256,
                "manifest" to native.manifest.sha256,"imageArchive" to requireNotNull(native.imageArchive).archive.sha256))
        for(kind in ManagedLaneKind.entries) {
            val directory=root.resolve("managed/${kind.name.lowercase()}")
            val i=directory.resolve("prepare-managed-initial.intent.json")
            val r=directory.resolve("prepare-managed-initial.result.json")
            val evidence=json.decodeFromString<ManagedLaneEvidence>(ReleasePrivateFiles.read(r,8192)
                .decodeToString(throwOnInvalidSequence=true))
            val original=json.decodeFromString<ManagedLaneIntent>(ReleasePrivateFiles.read(i,8192)
                .decodeToString(throwOnInvalidSequence=true))
            require(evidence==managed.preparations[kind] && evidence.generation==generation &&
                evidence.operation==ManagedLaneOperation.PREPARE && evidence.operationId=="managed-initial" &&
                evidence.intentSha256==hash(i,8192) && evidence.isolated &&
                original.laneId==evidence.laneId && original.operation==evidence.operation &&
                backend.attest(plan.lanes.single { it.kind==kind },directory,evidence)==evidence)
            laneIntent[kind]=hash(i,8192);laneResult[kind]=hash(r,8192)
        }
        val image=backend.uncertainImportedImage(root.resolve("managed/worklane"))
        val graph=root.resolve("managed/control/data/containers/storage")
        val census=RootlessVfsGraphCensus.observe(graph,requireNotNull(native.imageArchive).maximumUnpackedBytes)
        val layers=image.getValue("RootFS").jsonObject.getValue("Layers").jsonArray.map { it.jsonPrimitive.content }
        require(layers.size==8 && census.getValue("allocatedBytes").jsonPrimitive.long>=4294967296L)
        return Q9bColdPreparedUninstalledDisposition(generation=generation,bundleSha256=expected,
            member=bundle.members.single().spec.name,originalStageIntentSha256=stageSha,
            originalManagedIntentSha256=managedSha,originalManagedResultSha256=hash(root.resolve("managed-initial.result.json"),65536),
            originalLaneIntentSha256=laneIntent,originalLaneResultSha256=laneResult,
            originalLaneEvidence=managed.preparations,
            registrySha256=hash(root.resolve("managed/control/data/worklane/worklane-v5.db"),1048576),
            manifestSha256=hash(root.resolve("managed/home/.worklane/lane.toml"),1048576),
            rootlessImageId=image.getValue("Id").jsonPrimitive.content,
            rootlessImageBytes=image.getValue("Size").jsonPrimitive.long,
            rootlessLayersSha256=ReleaseLocks.sha256(json.encodeToString(layers).toByteArray()),
            graphRoot=graph.toString(),graphAllocatedBytes=census.getValue("allocatedBytes").jsonPrimitive.long,
            graphEntries=census.getValue("entries").jsonPrimitive.long,
            unitListingSha256=ReleaseLocks.sha256(units),unitFileListingSha256=ReleaseLocks.sha256(unitFiles))
    }
    fun observe(bundle:GenerationBundle,expected:String):ActivationInput {
        require(listOf(intent,record,result).none { Files.exists(it,NOFOLLOW_LINKS) })
        val proof=current(bundle,expected)
        val i=json.encodeToString(mapOf("action" to "terminal-observe-cold-prepared-uninstalled-stage",
            "generation" to generation,"bundleSha256" to expected,"stageIntentSha256" to stageSha)).toByteArray()
        val bytes=json.encodeToString(proof).toByteArray()
        ReleasePrivateFiles.save(intent,i);ReleasePrivateFiles.save(record,bytes)
        ReleasePrivateFiles.save(result,json.encodeToString(Q9bColdPreparedUninstalledResult(
            hash(intent,8192),ReleaseLocks.sha256(bytes))).toByteArray())
        return ActivationInput(record.toString(),ReleaseLocks.sha256(bytes))
    }
    fun verify(pin:ActivationInput):Q9bColdPreparedUninstalledDisposition {
        require(pin.path==record.toString() && pin.sha256==hash(record))
        val d=json.decodeFromString<Q9bColdPreparedUninstalledDisposition>(ReleasePrivateFiles.read(record,1048576)
            .decodeToString(throwOnInvalidSequence=true))
        val r=json.decodeFromString<Q9bColdPreparedUninstalledResult>(ReleasePrivateFiles.read(result,8192)
            .decodeToString(throwOnInvalidSequence=true))
        require(r.passed && r.intentSha256==hash(intent,8192) && r.dispositionSha256==pin.sha256 &&
            d.generation==generation && d.bundleSha256==bundleSha &&
            d.originalStageIntentSha256==stageSha && d.originalManagedIntentSha256==managedSha &&
            d.originalManagedPrepareAcknowledged && d.originalStageResultAbsent &&
            d.installedUnitsAbsent && d.nativeContainersAbsent && !d.applicationStarted && d.qualificationCycles==0 &&
            d.originalLaneEvidence.keys==ManagedLaneKind.entries.toSet())
        return d
    }
    fun verifyLive(bundle:GenerationBundle,pin:ActivationInput):Q9bColdPreparedUninstalledDisposition {
        val old=verify(pin);val now=current(bundle,bundleSha)
        require(now.copy(graphAllocatedBytes=old.graphAllocatedBytes,graphEntries=old.graphEntries)==old &&
            now.graphAllocatedBytes>=4294967296L) {
            "Retained q9b original ACK, image, registry or native absence changed"
        }
        return now
    }
}
