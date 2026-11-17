package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*

/** Observed IMPORT/manifest checkpoint, never the missing original PREPARE result. */
@Serializable internal data class Q273UncertainImportDisposition(
    val schemaVersion:Int=1, val generation:String, val member:String, val bundleSha256:String,
    val originalStageIntentSha256:String, val originalManagedIntentSha256:String,
    val originalWorklanePrepareIntentSha256:String, val manifestSha256:String,
    val sourceManifestSha256:String, val sourceManifestPath:String,
    val rootlessImageId:String, val rootlessImageBytes:Long, val rootlessLayersSha256:String,
    val graphRoot:String, val graphAllocatedBytes:Long, val graphEntries:Long,
    val preservedHomeDirectories:List<String>, val nativeSystemdUnitsSha256:String,
    val nativeSystemdUnitFilesSha256:String, val rootfulNamespaceAbsent:Boolean=true,
    val originalResultsAbsent:Boolean=true, val importedImageAcknowledged:Boolean=false,
    val applicationUnitStarted:Boolean=false, val qualificationCycles:Int=0)
@Serializable internal data class Q273UncertainImportResult(val intentSha256:String,
    val dispositionSha256:String, val passed:Boolean=true)
internal object Q273UncertainManagedImportTerminal {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    const val generation="q-273337d6772c"
    const val bundleSha="7826bd461494986207f873304d0eef490368b4e3a3030d474f8ca01e12da0468"
    private const val stageSha="846f9aa2f7dbc3499699081065ef4ac8349c70f191ecd6f1322cfac274441470"
    private const val managedSha="22bbaaa6d210e2e5ce40088a624c2ed4b9cfecf1d26cf2d2be9e112940b710fc"
    private const val prepareSha="58971c1aa065c10d8d786124022e1a5383a9e7b1f225f0fac60f48dec5e78f82"
    private const val manifestSha="1aac2ee5bb9bc39121dc9c005c90c24c441ed5e6d49af9712c84702c16b7f33d"
    private val root=GenerationRuntime.BASE.resolve(generation)
    private const val name="uncertain-native-worklane-manifest-import-v1"
    private val claim=root.resolve("$name.intent.json")
    private val record=root.resolve("$name.disposition.json")
    private val result=root.resolve("$name.result.json")
    private fun pin(path:Path,max:Int=1048576)=ReleaseLocks.sha256(ReleasePrivateFiles.read(path,max))
    private fun systemd(vararg args:String):ByteArray {
        val process=ProcessBuilder(listOf("/usr/bin/sudo","-n","/usr/bin/systemctl")+args)
            .redirectErrorStream(true).start()
        val bytes=process.inputStream.readNBytes(1048577)
        require(process.waitFor(30,TimeUnit.SECONDS) && bytes.size<=1048576 &&
            (process.exitValue()==0 || args.firstOrNull()=="list-unit-files" &&
                process.exitValue()==1 && bytes.isEmpty()))
        return bytes
    }
    private val absent=listOf("stage.result.json","managed-initial.result.json",
        "managed/worklane/prepare-managed-initial.result.json","quadlet-serve.intent.json",
        "quadlet-serve.result.json","managed-start.intent.json","managed-start.result.json",
        "managed/worklane/lane.json")
    private val homes=listOf("managed/home/workspace","managed/home/.pi/agent/sessions",
        "managed/manifests","managed/control/data/worklane")
    private fun fresh(bundle:GenerationBundle,hash:String):Q273UncertainImportDisposition {
        require(bundle.request.id==generation && hash==bundleSha && bundle.ownership!=null &&
            pin(root.resolve("bundle.json"),4194304)==bundleSha && bundle.members.size==1 &&
            bundle.members.single().spec.name=="$generation-v2" &&
            bundle.members.single().spec.processes.size==134 &&
            pin(root.resolve("stage.intent.json"),8192)==stageSha &&
            pin(root.resolve("managed-initial.intent.json"),8192)==managedSha &&
            pin(root.resolve("managed/worklane/prepare-managed-initial.intent.json"),8192)==prepareSha &&
            pin(root.resolve("managed/home/.worklane/lane.toml"),1048576)==manifestSha)
        absent.forEach { require(!Files.exists(root.resolve(it),NOFOLLOW_LINKS)) { "Uncertain q273 result/native checkpoint changed: $it" } }
        homes.forEach { require(Files.isDirectory(root.resolve(it),NOFOLLOW_LINKS) &&
            root.resolve(it).toRealPath()==root.resolve(it)) }
        require(!Files.exists(Path.of("/etc/containers/systemd/$generation-v2"),NOFOLLOW_LINKS))
        RuntimeQuadletPreflight.verify(bundle.members.single().spec)
        val units=systemd("list-units","--all","--plain","--no-legend","p0v3-$generation-v2-*")
        val files=systemd("list-unit-files","--no-legend","p0v3-$generation-v2-*")
        require(units.isEmpty() && files.isEmpty())
        val native=requireNotNull(bundle.request.managedLanes).native
        val image=requireNotNull(native.imageArchive)
        val source=Path.of(native.manifest.path)
        require(pin(source)==native.manifest.sha256 && source.toRealPath()==source)
        val control=root.resolve("managed/control")
        val backend=NativeManagedLaneBackend(Path.of(native.worklane.path),Path.of(native.podman.path),
            Path.of(native.storageConfig.path),source,control.resolve("home"),control.resolve("config"),
            control.resolve("data"),control.resolve("run"),image,
            mapOf("worklane" to native.worklane.sha256,"podman" to native.podman.sha256,
                "storageConfig" to native.storageConfig.sha256,"manifest" to native.manifest.sha256,
                "imageArchive" to image.archive.sha256))
        val imported=backend.uncertainImportedImage(root.resolve("managed/worklane"))
        val graph=control.resolve("data/containers/storage")
        val census=RootlessVfsGraphCensus.observe(graph,image.maximumUnpackedBytes)
        val layers=imported.getValue("RootFS").jsonObject.getValue("Layers").jsonArray.map { it.jsonPrimitive.content }
        require(layers.size==8 && census.getValue("allocatedBytes").jsonPrimitive.long>=4294967296L)
        return Q273UncertainImportDisposition(generation=generation,member=bundle.members.single().spec.name,
            bundleSha256=hash,originalStageIntentSha256=stageSha,
            originalManagedIntentSha256=managedSha,originalWorklanePrepareIntentSha256=prepareSha,
            manifestSha256=manifestSha,sourceManifestSha256=native.manifest.sha256,
            sourceManifestPath=source.toString(),rootlessImageId=imported.getValue("Id").jsonPrimitive.content,
            rootlessImageBytes=imported.getValue("Size").jsonPrimitive.long,
            rootlessLayersSha256=ReleaseLocks.sha256(json.encodeToString(layers).toByteArray()),
            graphRoot=graph.toString(),graphAllocatedBytes=census.getValue("allocatedBytes").jsonPrimitive.long,
            graphEntries=census.getValue("entries").jsonPrimitive.long,
            preservedHomeDirectories=homes,nativeSystemdUnitsSha256=ReleaseLocks.sha256(units),
            nativeSystemdUnitFilesSha256=ReleaseLocks.sha256(files))
    }
    /** Called under generation and native member locks; append-only, exactly once. */
    fun observe(bundle:GenerationBundle,hash:String):ActivationInput {
        require(listOf(claim,record,result).none { Files.exists(it,NOFOLLOW_LINKS) })
        val observed=fresh(bundle,hash)
        val intent=json.encodeToString(mapOf("action" to "observe-uncertain-native-worklane-manifest-import",
            "generation" to generation,"bundleSha256" to hash,
            "originalPrepareIntentSha256" to prepareSha)).toByteArray()
        val bytes=json.encodeToString(observed).toByteArray()
        ReleasePrivateFiles.save(claim,intent)
        ReleasePrivateFiles.save(record,bytes)
        ReleasePrivateFiles.save(result,json.encodeToString(Q273UncertainImportResult(
            pin(claim,8192),pin(record))).toByteArray())
        return ActivationInput(record.toString(),ReleaseLocks.sha256(bytes))
    }
    fun verify(input:ActivationInput):Q273UncertainImportDisposition {
        require(input.path==record.toString() && input.sha256==pin(record))
        val observed=json.decodeFromString<Q273UncertainImportDisposition>(ReleasePrivateFiles.read(record,1048576)
            .decodeToString(throwOnInvalidSequence=true))
        val receipt=json.decodeFromString<Q273UncertainImportResult>(ReleasePrivateFiles.read(result,8192)
            .decodeToString(throwOnInvalidSequence=true))
        require(receipt.passed && receipt.intentSha256==pin(claim,8192) &&
            receipt.dispositionSha256==input.sha256 && observed.generation==generation &&
            observed.bundleSha256==bundleSha && observed.originalStageIntentSha256==stageSha &&
            observed.originalManagedIntentSha256==managedSha &&
            observed.originalWorklanePrepareIntentSha256==prepareSha &&
            observed.manifestSha256==manifestSha && observed.preservedHomeDirectories==homes &&
            observed.graphAllocatedBytes>=4294967296L && observed.graphEntries>1 &&
            observed.originalResultsAbsent && observed.rootfulNamespaceAbsent &&
            !observed.importedImageAcknowledged && !observed.applicationUnitStarted &&
            observed.qualificationCycles==0)
        return observed
    }
    /** Fresh locked readback releases inactive RAM only; preserved physical disk remains charged. */
    fun verifyLiveInactive(bundle:GenerationBundle):Long {
        val saved=verify(ActivationInput(record.toString(),pin(record)))
        val current=fresh(bundle,bundleSha)
        require(current.member==saved.member && current.rootlessImageId==saved.rootlessImageId &&
            current.rootlessImageBytes==saved.rootlessImageBytes &&
            current.rootlessLayersSha256==saved.rootlessLayersSha256 &&
            current.manifestSha256==saved.manifestSha256 &&
            current.sourceManifestSha256==saved.sourceManifestSha256 &&
            current.graphAllocatedBytes>=4294967296L)
        return current.graphAllocatedBytes
    }
}
