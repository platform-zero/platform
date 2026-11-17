package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*

/** q4d terminal evidence: a native image was OBSERVED after an unresolved
 * Worklane PREPARE intent. No fabricated result, replay, import ACK or cleanup. */
@Serializable internal data class ManagedUncertainImageImportDisposition(
    val schemaVersion:Int=1,val generation:String,val member:String,val bundleSha256:String,
    val priorPreUnitTerminalSha256:String,val originalStageIntentSha256:String,
    val originalManagedIntentSha256:String,val originalWorklanePrepareIntentSha256:String,
    val originalOwnerPid:Int,val originalOwnerAbsent:Boolean,val rootlessImageId:String,
    val rootlessImageSize:Long,val rootlessLayerListSha256:String,
    val observedGraphRoot:String,val observedRunRoot:String,val observedGraphMetadataSha256:String,
    val observedGraphAllocatedBytes:Long,val observedGraphEntries:Long,
    val rootlessImages:Int=1,val rootlessContainers:Int=0,
    val nativeSystemdUnitsSha256:String,val nativeSystemdUnitFilesSha256:String,
    val rootfulNamespaceAbsent:Boolean=true,val originalPrepareResultAbsent:Boolean=true,
    val applicationUnitStarted:Boolean=false,val nativeImportAcknowledged:Boolean=false,
    val qualificationCycles:Int=0)
@Serializable internal data class ManagedUncertainImageImportResult(val intentSha256:String,
    val dispositionSha256:String,val passed:Boolean=true)
internal object ManagedUncertainImageImportTerminal {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    private const val generation="q-4d3c1cb287e5"
    private const val expected="88a9c83dee3fc4ceae3b85a4e12d1d1897ea8beeb44e06545bfad0161b91f5ea"
    private const val laneSha="690281332bb099ae6c35f6098c858e24dbbdc8bdc56b5385d0b1864fffc69fdd"
    private const val predecessor="1ffd7dea5f9b6c5141f19d263e9f817ceaf9180ce39d413579fa06e94bfd0ee3"
    private val root=GenerationRuntime.BASE.resolve(generation)
    private val name="uncertain-native-worklane-import-v1"
    private val intent=root.resolve("$name.intent.json")
    private val record=root.resolve("$name.disposition.json")
    private val result=root.resolve("$name.result.json")
    private fun pin(path:Path,max:Int=1048576)=ReleaseLocks.sha256(ReleasePrivateFiles.read(path,max))
    private fun systemd(vararg args:String):ByteArray {
        val child=ProcessBuilder(listOf("/usr/bin/sudo","-n","/usr/bin/systemctl")+args)
            .redirectErrorStream(true).start()
        val output=child.inputStream.readNBytes(1048577)
        val done=child.waitFor(30,TimeUnit.SECONDS)
        require(done && output.size<=1048576 && (child.exitValue()==0 ||
            args.firstOrNull()=="list-unit-files" && child.exitValue()==1 && output.isEmpty()))
        return output
    }
    /** Actual rootless VFS includes unreadable subuid-owned 0700 layer entries.
     * Root is allowed to enumerate metadata ONLY, without following layer links.
     * This cannot load an image or convert the missing PREPARE result into an ACK. */
    private fun graph(graph:Path,limit:Long):Pair<String,Pair<Long,Long>> {
        val fixed=root.resolve("managed/control/data/containers/storage")
        require(graph==fixed && graph.toRealPath()==graph &&
            Files.isDirectory(graph,NOFOLLOW_LINKS) && limit==34359738368L)
        val script="""import hashlib,json,os,stat,sys
root='/mnt/media/p0-v3/release-generations/q-4d3c1cb287e5/managed/control/data/containers/storage'
assert os.path.realpath(root)==root and stat.S_ISDIR(os.lstat(root).st_mode)
assert os.lstat(root).st_uid==int(os.environ['SUDO_UID'])
h=hashlib.sha256();count=0;blocks=0;links=0
pending=[(root,'')]
while pending:
 path,rel=pending.pop()
 s=os.lstat(path);count+=1
 assert count<=4000000 and (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode))
 blocks+=s.st_blocks*512
 assert 0<=blocks<=34359738368
 if stat.S_ISLNK(s.st_mode):links+=1
 h.update((rel+'|'+str(s.st_mode)+'|'+str(s.st_uid)+'|'+str(s.st_gid)+'|'+str(s.st_size)+'|'+str(s.st_blocks)+'\n').encode())
 if stat.S_ISDIR(s.st_mode):
  with os.scandir(path) as directory:
   entries=sorted(directory,key=lambda e:e.name,reverse=True)
  for e in entries:
   assert e.name not in ('.','..') and '/' not in e.name
   pending.append((e.path,rel+'/'+e.name))
assert count>1
print(json.dumps({'sha256':h.hexdigest(),'allocatedBytes':blocks,'entries':count,'symlinks':links},sort_keys=True))
""".trimIndent()
        val child=ProcessBuilder("/usr/bin/sudo","-n","/usr/bin/python3","-I","-c",script)
            .redirectError(ProcessBuilder.Redirect.DISCARD).start()
        val output=child.inputStream.readNBytes(8193)
        val done=child.waitFor(90,TimeUnit.SECONDS)
        require(done && child.exitValue()==0 && output.size in 64..8192) {
            "Selected rootless subuid VFS metadata census unavailable; preserve original import intent" }
        val result=json.parseToJsonElement(output.decodeToString(throwOnInvalidSequence=true)).jsonObject
        val allocated=result.getValue("allocatedBytes").jsonPrimitive.long
        val entries=result.getValue("entries").jsonPrimitive.long
        val hash=result.getValue("sha256").jsonPrimitive.content
        require(result.keys==setOf("sha256","allocatedBytes","entries","symlinks") &&
            hash.matches(Regex("[a-f0-9]{64}")) && allocated in 1..limit && entries in 2..4000000 &&
            result.getValue("symlinks").jsonPrimitive.long in 0..entries)
        return hash to (allocated to entries)
    }
    /** Call ONLY under the same retained namespace/member native locks as serving. */
    fun observe(bundle:GenerationBundle,bundleHash:String):ActivationInput {
        require(bundle.request.id==generation && bundleHash==expected && bundle.ownership!=null &&
            bundle.members.single().spec.name=="$generation-v2" &&
            bundle.members.single().spec.processes.size==134 && pin(root.resolve("bundle.json"),4194304)==expected &&
            bundle.request.failedPreUnitStagePredecessor?.sha256==predecessor &&
            !Files.exists(Path.of("/proc/53155"),NOFOLLOW_LINKS))
        val stage=root.resolve("stage.intent.json")
        val managed=root.resolve("managed-initial.intent.json")
        val lane=root.resolve("managed/worklane/prepare-managed-initial.intent.json")
        require(pin(stage,8192)=="210e5827665258420321cd4d25514cc00fbd2179e6f9855499354178952fe868" &&
            pin(managed,8192)=="86d03453d58ad2fb37d0e519a5d83901108e4256e2bb2760fc39bd9e4f3e61dc" &&
            pin(lane,8192)==laneSha)
        for (file in listOf("stage.result.json","managed-initial.result.json",
            "managed/worklane/prepare-managed-initial.result.json","quadlet-serve.result.json",
            "managed-start.intent.json","managed-start.result.json",
            "$name.intent.json","$name.disposition.json","$name.result.json"))
            require(!Files.exists(root.resolve(file),NOFOLLOW_LINKS)) { "Uncertain q4d native state is already terminal or acknowledged: $file" }
        require(!Files.exists(Path.of("/etc/containers/systemd/$generation-v2"),NOFOLLOW_LINKS))
        val spec=bundle.members.single().spec
        RuntimeQuadletPreflight.verify(spec) // Exact rootful namespace/CID absence; never install.
        ForgejoCiNativeSourceAdmission.requirePristineAccountNamespace(requireNotNull(bundle.request.forgejoCi))
        val units=systemd("list-units","--all","--plain","--no-legend","p0v3-$generation-v2-*")
        val files=systemd("list-unit-files","--no-legend","p0v3-$generation-v2-*")
        require(units.isEmpty() && files.isEmpty())
        val plan=requireNotNull(bundle.request.managedLanes)
        val native=plan.native
        val image=requireNotNull(native.imageArchive)
        val control=root.resolve("managed/control")
        val rootless=NativeManagedLaneBackend(Path.of(native.worklane.path),Path.of(native.podman.path),
            Path.of(native.storageConfig.path),Path.of(native.manifest.path),
            control.resolve("home"),control.resolve("config"),control.resolve("data"),control.resolve("run"),
            image,mapOf("worklane" to native.worklane.sha256,"podman" to native.podman.sha256,
                "storageConfig" to native.storageConfig.sha256,"manifest" to native.manifest.sha256,
                "imageArchive" to image.archive.sha256))
        val imported=rootless.uncertainImportedImage(root.resolve("managed/worklane"))
        val actual=control.resolve("data/containers/storage")
        val (metadata,allocation)=graph(actual,image.maximumUnpackedBytes)
        val layers=imported.getValue("RootFS").jsonObject.getValue("Layers").jsonArray
            .map { it.jsonPrimitive.content }
        val disposition=ManagedUncertainImageImportDisposition(generation=generation,member=spec.name,
            bundleSha256=bundleHash,priorPreUnitTerminalSha256=predecessor,
            originalStageIntentSha256=pin(stage,8192),originalManagedIntentSha256=pin(managed,8192),
            originalWorklanePrepareIntentSha256=laneSha,originalOwnerPid=53155,originalOwnerAbsent=true,
            rootlessImageId=imported.getValue("Id").jsonPrimitive.content,
            rootlessImageSize=imported.getValue("Size").jsonPrimitive.long,
            rootlessLayerListSha256=ReleaseLocks.sha256(json.encodeToString(layers).toByteArray()),
            observedGraphRoot=actual.toString(),observedRunRoot=control.resolve("run/containers").toString(),
            observedGraphMetadataSha256=metadata,observedGraphAllocatedBytes=allocation.first,
            observedGraphEntries=allocation.second,nativeSystemdUnitsSha256=ReleaseLocks.sha256(units),
            nativeSystemdUnitFilesSha256=ReleaseLocks.sha256(files))
        val claim=json.encodeToString(mapOf("action" to "terminal-observe-uncertain-native-worklane-import",
            "generation" to generation,"bundleSha256" to bundleHash,
            "originalLaneIntentSha256" to laneSha)).toByteArray()
        val bytes=json.encodeToString(disposition).toByteArray()
        ReleasePrivateFiles.save(intent,claim)
        ReleasePrivateFiles.save(record,bytes)
        ReleasePrivateFiles.save(result,json.encodeToString(ManagedUncertainImageImportResult(
            ReleaseLocks.sha256(claim),ReleaseLocks.sha256(bytes))).toByteArray())
        return ActivationInput(record.toString(),ReleaseLocks.sha256(bytes))
    }
    /** Native-lock-only, fresh capacity proof. Releases NO disk allocation and
     * never changes q4d's Worklane PREPARE result; just tests inactive runtime. */
    fun verifyLiveInactive(bundle:GenerationBundle):Long {
        val saved=verify(ActivationInput(record.toString(),this.pin(record,1048576)))
        require(bundle.request.id==generation && bundle.members.single().spec.name==saved.member &&
            bundle.request.managedLanes?.native?.imageArchive==GenerationNormalizedWorklaneImage.requireSelected(
                bundle.request.managedLanes?.native?.imageArchive) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"),4194304))==expected &&
            Files.isDirectory(root.resolve("managed/control/data/containers/storage"),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("stage.result.json"),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("managed-initial.result.json"),NOFOLLOW_LINKS) &&
            !Files.exists(root.resolve("managed/worklane/prepare-managed-initial.result.json"),NOFOLLOW_LINKS))
        RuntimeQuadletPreflight.verify(bundle.members.single().spec)
        val units=systemd("list-units","--all","--plain","--no-legend","p0v3-$generation-v2-*")
        val files=systemd("list-unit-files","--no-legend","p0v3-$generation-v2-*")
        require(units.isEmpty() && files.isEmpty() &&
            !Files.exists(Path.of("/etc/containers/systemd/$generation-v2"),NOFOLLOW_LINKS))
        val plan=requireNotNull(bundle.request.managedLanes).native
        val image=requireNotNull(plan.imageArchive)
        val control=root.resolve("managed/control")
        val backend=NativeManagedLaneBackend(Path.of(plan.worklane.path),Path.of(plan.podman.path),
            Path.of(plan.storageConfig.path),Path.of(plan.manifest.path),control.resolve("home"),
            control.resolve("config"),control.resolve("data"),control.resolve("run"),image,
            mapOf("worklane" to plan.worklane.sha256,"podman" to plan.podman.sha256,
                "storageConfig" to plan.storageConfig.sha256,"manifest" to plan.manifest.sha256,
                "imageArchive" to image.archive.sha256))
        val observed=backend.uncertainImportedImage(root.resolve("managed/worklane"))
        require(observed.getValue("Id").jsonPrimitive.content==saved.rootlessImageId &&
            observed.getValue("Size").jsonPrimitive.long==saved.rootlessImageSize &&
            ReleaseLocks.sha256(json.encodeToString(observed.getValue("RootFS").jsonObject.getValue("Layers")
                .jsonArray.map { it.jsonPrimitive.content }).toByteArray())==saved.rootlessLayerListSha256)
        val (metadata,physical)=graph(control.resolve("data/containers/storage"),image.maximumUnpackedBytes)
        require(metadata.matches(Regex("[a-f0-9]{64}")) &&
            physical.first>=4294967296L && physical.first<=image.maximumUnpackedBytes &&
            physical.second>=saved.observedGraphEntries/2) {
            "q4d original physical VFS import is no longer safely bounded" }
        return physical.first
    }
    fun verify(pin:ActivationInput):ManagedUncertainImageImportDisposition {
        require(pin.path==record.toString() && pin.sha256==this.pin(record,1048576))
        val receipt=json.decodeFromString<ManagedUncertainImageImportResult>(ReleasePrivateFiles.read(result,8192)
            .decodeToString(throwOnInvalidSequence=true))
        val observed=json.decodeFromString<ManagedUncertainImageImportDisposition>(ReleasePrivateFiles.read(record,1048576)
            .decodeToString(throwOnInvalidSequence=true))
        require(receipt.passed && receipt.dispositionSha256==pin.sha256 &&
            receipt.intentSha256==this.pin(intent,8192) && observed.generation==generation &&
            observed.bundleSha256==expected && observed.priorPreUnitTerminalSha256==predecessor &&
            observed.originalWorklanePrepareIntentSha256==laneSha && observed.originalOwnerAbsent &&
            observed.rootlessImages==1 && observed.rootlessContainers==0 &&
            !observed.nativeImportAcknowledged && !observed.applicationUnitStarted &&
            observed.qualificationCycles==0 && observed.observedGraphEntries>1 &&
            observed.originalStageIntentSha256==this.pin(root.resolve("stage.intent.json"),8192) &&
            observed.originalManagedIntentSha256==this.pin(root.resolve("managed-initial.intent.json"),8192) &&
            observed.originalWorklanePrepareIntentSha256==this.pin(root.resolve("managed/worklane/prepare-managed-initial.intent.json"),8192) &&
            !Files.exists(root.resolve("managed/worklane/prepare-managed-initial.result.json"),NOFOLLOW_LINKS))
        return observed
    }
}
