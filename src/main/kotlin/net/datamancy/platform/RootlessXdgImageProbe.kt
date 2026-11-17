package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.*

/** One-use, non-deployment native probe of the selected immutable OCI archive.
 * It owns its own empty VFS graph and cannot transfer image state or native ACK
 * into any release generation. No container or application is ever started. */
internal object RootlessXdgImageProbe {
    private const val successor="q-c3a7a9e29391"
    private const val terminal="d731a2136e435d3e1bfa5b183a0c74a6cf987788376c7f5df292c4315c7451bb"
    private val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/native-probes/$successor-rootless-image-r1")
    private val perms=PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
    private fun create(path:Path) {
        Files.createDirectory(path,perms);ReleasePrivateFiles.sync(path.parent)
    }
    private fun attest(graph:Path):JsonObject {
        require(graph==root.resolve("control/data/containers/storage") &&
            Files.isDirectory(graph,NOFOLLOW_LINKS) && graph.toRealPath()==graph)
        val script="""import hashlib,json,os,stat
root='/mnt/media/p0-v3/release-bootstrap-anchors/native-probes/q-c3a7a9e29391-rootless-image-r1/control/data/containers/storage'
assert os.path.realpath(root)==root and stat.S_ISDIR(os.lstat(root).st_mode)
assert os.lstat(root).st_uid==int(os.environ['SUDO_UID'])
h=hashlib.sha256();count=0;bytes=0;links=0
pending=[(root,'')]
while pending:
 path,rel=pending.pop();s=os.lstat(path);count+=1
 assert count<=4000000 and (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode))
 bytes+=s.st_blocks*512
 assert 0<=bytes<=34359738368
 if stat.S_ISLNK(s.st_mode): links+=1
 h.update((rel+'|'+str(s.st_mode)+'|'+str(s.st_uid)+'|'+str(s.st_gid)+'|'+str(s.st_size)+'|'+str(s.st_blocks)+'\n').encode())
 if stat.S_ISDIR(s.st_mode):
  with os.scandir(path) as directory: children=sorted(directory,key=lambda e:e.name,reverse=True)
  for e in children:
   assert e.name not in ('.','..') and '/' not in e.name
   pending.append((e.path,rel+'/'+e.name))
assert count>1
print(json.dumps({'sha256':h.hexdigest(),'allocatedBytes':bytes,'entries':count,'symlinks':links},sort_keys=True))
""".trimIndent()
        val child=ProcessBuilder("/usr/bin/sudo","-n","/usr/bin/python3","-I","-c",script)
            .redirectError(ProcessBuilder.Redirect.DISCARD).start()
        val bytes=child.inputStream.readNBytes(8193)
        require(child.waitFor(90,TimeUnit.SECONDS) && child.exitValue()==0 && bytes.size in 64..8192)
        return Json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence=true)).jsonObject.also {
            require(it.keys==setOf("sha256","allocatedBytes","entries","symlinks") &&
                it.getValue("sha256").jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")) &&
                it.getValue("allocatedBytes").jsonPrimitive.long in 1..34359738368L &&
                it.getValue("entries").jsonPrimitive.long in 2..4000000L)
        }
    }
    fun issue(value:String):ActivationInput = RecoveryDeadline.within(TimeUnit.MINUTES.toMillis(15)) {
        require(value==successor && !Files.exists(GenerationRuntime.BASE.resolve(value),NOFOLLOW_LINKS) &&
            !Files.exists(root,NOFOLLOW_LINKS))
        ManagedUncertainImageImportTerminal.verify(ActivationInput(
            "/mnt/media/p0-v3/release-generations/q-4d3c1cb287e5/uncertain-native-worklane-import-v1.disposition.json",terminal))
        val plan=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/q-4d3c1cb287e5/managed-plan-v3.json")
        val bytes=ReleasePrivateFiles.read(plan,65536)
        val old=Json.decodeFromString<ManagedLanePlan>(bytes.decodeToString(throwOnInvalidSequence=true))
        val image=requireNotNull(old.native.imageArchive)
        require(image==GenerationNormalizedWorklaneImage.planned() && image.maximumUnpackedBytes==34359738368L)
        RuntimeLockBudget.requireAvailable(RuntimeLockBudget.available(PrivateRootfulCommands(25,RuntimeStore.CANONICAL_V2),
            RuntimeStore.CANONICAL_V2),workers=1)
        require(Files.getFileStore(root.parent.parent).usableSpace>=image.maximumUnpackedBytes+10240L*1048576L)
        ReleasePrivateFiles.directory(root.parent.parent)
        if (!Files.exists(root.parent,NOFOLLOW_LINKS))create(root.parent)
        ReleasePrivateFiles.directory(root.parent)
        create(root)
        val control=root.resolve("control");create(control)
        for(name in listOf("home","config","data","run","podman-graph","podman-run"))create(control.resolve(name))
        val config=control.resolve("storage.conf")
        val graph=control.resolve("data/containers/storage")
        val run=control.resolve("run/containers")
        val configBytes="""[storage]
driver = "vfs"
graphroot = "$graph"
runroot = "$run"
rootless_storage_path = "$graph"
""".toByteArray()
        ReleasePrivateFiles.save(config,configBytes)
        val intent=buildJsonObject {
            put("schemaVersion",1);put("successorReserved",successor)
            put("q4dTerminalSha256",terminal);put("sourceArchive",image.archive.path)
            put("sourceArchiveSha256",image.archive.sha256)
            put("expectedImageId",image.expectedImageId)
            put("storageConfigSha256",ReleaseLocks.sha256(configBytes))
            put("scope","isolated-rootless-native-image-probe-no-app-no-generation-state")
        }.toString().toByteArray()
        ReleasePrivateFiles.save(root.resolve("probe.intent.json"),intent)
        val podman=old.native.podman
        val worklane=old.native.worklane
        val backend=NativeManagedLaneBackend(Path.of(worklane.path),Path.of(podman.path),config,config,
            control.resolve("home"),control.resolve("config"),control.resolve("data"),control.resolve("run"),
            image,mapOf("worklane" to worklane.sha256,"podman" to podman.sha256,
                "storageConfig" to ReleaseLocks.sha256(configBytes),"manifest" to ReleaseLocks.sha256(configBytes),
                "imageArchive" to image.archive.sha256))
        val observed=backend.probeRootlessImage(graph,run)
        val graphProof=attest(graph)
        val proof=buildJsonObject {
            put("schemaVersion",1);put("intentSha256",ReleaseLocks.sha256(intent))
            put("generationRootCreated",false);put("applicationStarted",false)
            put("nativeImageImported",true);put("imageImportAcknowledged",true)
            put("isolatedProbeOnly",true);put("qualificationEvidence",false)
            put("q4dOriginalImportAcknowledged",false)
            put("rootlessGraph",graph.toString());put("rootlessRun",run.toString())
            put("nativeImageIdRaw",observed.getValue("Id"))
            put("nativeSize",observed.getValue("Size"))
            put("nativeLayers",observed.getValue("RootFS").jsonObject.getValue("Layers"))
            put("nativeGraphMetadata",graphProof)
        }.toString().toByteArray()
        val target=root.resolve("probe.result.json")
        ReleasePrivateFiles.save(target,proof)
        ActivationInput(target.toString(),ReleaseLocks.sha256(proof))
    }
}
