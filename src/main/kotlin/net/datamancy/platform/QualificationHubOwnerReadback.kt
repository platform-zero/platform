package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.*

/** Selected owner observation; never accepts paths from the case runner. The
 * only effect is a case-local, SQLite-consistent read-only source backup. */
internal object QualificationHubOwnerReadback {
    private val hash = Regex("[a-f0-9]{64}")
    private fun volume(spec: PrivateDeploymentSpec, fingerprint: String, id: String,
        native: RuntimeCommands): Path {
        require(id in setOf("hub", "alice", "bob") && spec.volumes.any { it.id == id } &&
            spec.store == RuntimeStore.CANONICAL_V2)
        val name = "p0v3-live-${spec.name}-volume-$id"
        val reply = native.run(listOf("volume", "inspect", name))
        require(reply.exitCode == 0 && reply.output.toByteArray().size in 2..65536)
        val observed = Json.parseToJsonElement(reply.output).jsonArray.single().jsonObject
        val labels = observed.getValue("Labels").jsonObject
        val path = Path.of(observed.getValue("Mountpoint").jsonPrimitive.content)
        val exact = Path.of(spec.store.graph).resolve("volumes/$name/_data")
        require(observed.getValue("Name").jsonPrimitive.content == name &&
            labels.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
            labels.getValue("io.p0v3.runtime-fingerprint").jsonPrimitive.content == fingerprint &&
            path == exact && path.isAbsolute && path.normalize() == path &&
            Files.isDirectory(path, NOFOLLOW_LINKS) && path.toRealPath() == path) {
            "Selected Hub native volume does not match graph-owned mountpoint" }
        return path
    }
    private fun pinned(path: Path, maximum: Int = 8192): ActivationInput =
        ActivationInput(path.toString(), ReleaseLocks.sha256(ReleasePrivateFiles.read(path, maximum)))

    /** Owner is invoked before C1.prepare. Claim its case-local proof directory
     * exactly once, under selected caller-owned caseDir, before snapshot intent.
     * Never adopt a pre-existing/symlinked or foreign directory as a retry. */
    internal fun createOwnerProofDirectory(caseDir: Path): Path {
        ReleasePrivateFiles.directory(caseDir)
        val proofDir=caseDir.resolve("owner-proofs")
        require(!Files.exists(proofDir,NOFOLLOW_LINKS)) { "Hub owner proof attempt already exists" }
        Files.createDirectory(proofDir,PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(caseDir)
        ReleasePrivateFiles.directory(proofDir)
        return proofDir
    }

    fun observe(caseDir: Path, bundle: GenerationBundle, selected: GenerationPin,
        native: RuntimeCommands = PrivateRootfulCommands(45, RuntimeStore.CANONICAL_V2)): HubOwnerReadback {
        val generation = bundle.request.id
        val spec = selected.spec
        val root = GenerationRuntime.BASE.resolve(generation)
        require(bundle.members.singleOrNull() == selected &&
            spec.name == "$generation-v2" && NotebookSelectedGraph.selected(root, spec) &&
            caseDir.isAbsolute && caseDir.normalize() == caseDir &&
            caseDir.fileName.toString().matches(Regex("jupyter(?:hub|-notebook)--workflow--(?:web--browser|headless--native)")) &&
            ReleaseLocks.sha256(ReleasePrivateFiles.read(root.resolve("bundle.json"), 4194304)) ==
                ReleaseLocks.sha256(Json { encodeDefaults = true }.encodeToString(GenerationBundle.serializer(), bundle).toByteArray()))
        val hub = volume(spec, selected.runtimeFingerprint, "hub", native)
        val alice = volume(spec, selected.runtimeFingerprint, "alice", native)
        val bob = volume(spec, selected.runtimeFingerprint, "bob", native)
        val db = hub.resolve("hub.sqlite")
        require(Files.isRegularFile(db, NOFOLLOW_LINKS) && db.toRealPath() == db &&
            Files.size(db) in 1..(64L * 1048576))
        val episodes = root.resolve("notebooks/episodes")
        require(Files.isDirectory(episodes.resolve("alice"), NOFOLLOW_LINKS) &&
            Files.isDirectory(episodes.resolve("bob"), NOFOLLOW_LINKS))
        val specHash = RuntimeQuadlets.render(spec).specSha256
        val aliceLedger = NotebookLifecycleEpisodes(root, spec.name, "alice", specHash)
        val bobLedger = NotebookLifecycleEpisodes(root, spec.name, "bob", specHash)
        // `active` verifies a currently active episode and every earlier completed
        // episode. Original ordinal 1 has its own start/terminal proof in both modes.
        aliceLedger.active()
        bobLedger.active()
        val a = episodes.resolve("alice/0001.start.json")
        val b = episodes.resolve("bob/0001.terminal.json")
        val aliceStart = Json.decodeFromString(NotebookEpisodeStart.serializer(),
            ReleasePrivateFiles.read(a,8192).decodeToString(throwOnInvalidSequence = true))
        val bobTerminal = Json.decodeFromString(NotebookEpisodeTerminal.serializer(),
            ReleasePrivateFiles.read(b,8192).decodeToString(throwOnInvalidSequence = true))
        val aliceIntent = pinned(episodes.resolve("alice/0001.intent.json"))
        val bobStart = pinned(episodes.resolve("bob/0001.start.json"))
        val bobStop = pinned(root.resolve("quadlet-stop-${spec.name}-bob.result.json"))
        val bobRetire = pinned(root.resolve("notebooks/retire/bob/0001.retire.result.json"))
        require(aliceStart.intentSha256 == aliceIntent.sha256 &&
            aliceStart.originalStartAckSha256 == pinned(root.resolve("quadlet-launch-${spec.name}-alice.result.json")).sha256 &&
            aliceStart.nativeSystemdReadbackSha256 == pinned(root.resolve("notebooks/serving-alice-0001.observation.json")).sha256 &&
            aliceStart.nativeContainerId.matches(hash) &&
            bobTerminal.startSha256 == bobStart.sha256 &&
            bobTerminal.originalStopAckSha256 == bobStop.sha256 &&
            bobTerminal.retainedContainerDispositionSha256 == bobRetire.sha256 &&
            bobTerminal.nativeContainerId.matches(hash)) { "Hub original notebook episode lacks native start/retire receipts" }
        val proofDir = createOwnerProofDirectory(caseDir)
        val intentPath = proofDir.resolve("hub-db-snapshot.intent.json")
        val copy = proofDir.resolve("hub.sqlite")
        val custody = proofDir.resolve("hub-volume-custody.json")
        require(listOf(intentPath,copy,custody).none { Files.exists(it,NOFOLLOW_LINKS) }) {
            "Hub source snapshot attempt exists; never replace an uncertain copy" }
        ReleasePrivateFiles.save(intentPath, buildJsonObject {
            put("generation",generation); put("member",spec.name)
            put("runtimeFingerprint",selected.runtimeFingerprint)
            put("sourceVolume",hub.toString()); put("database",db.toString())
        }.toString().toByteArray())
        val script = """import os,sqlite3,stat,sys
src,dst=sys.argv[1:]
f=os.open(src,os.O_RDONLY|os.O_NOFOLLOW)
try:
 s=os.fstat(f)
 if not stat.S_ISREG(s.st_mode) or s.st_size<1 or s.st_size>67108864: sys.exit(10)
finally: os.close(f)
u=sqlite3.connect('file:'+src+'?mode=ro',uri=True,timeout=10)
try:
 v=os.open(dst,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600); os.close(v)
 c=sqlite3.connect(dst,timeout=10)
 try:
  u.backup(c,pages=128,sleep=0.01)
  if c.execute('pragma quick_check').fetchone()[0]!='ok': sys.exit(11)
  c.commit()
 finally: c.close()
finally: u.close()
""".trimIndent()
        val child = ProcessBuilder("/usr/bin/python3", "-c", script, db.toString(), copy.toString())
            .redirectError(ProcessBuilder.Redirect.DISCARD).start()
        try {
            require(child.waitFor(90, TimeUnit.SECONDS) && child.exitValue() == 0 &&
                Files.isRegularFile(copy, NOFOLLOW_LINKS) && Files.size(copy) in 1..(64L * 1048576)) {
                "Hub SQLite native read-only snapshot was not completed; preserve intent" }
        } finally { if (child.isAlive) child.destroyForcibly() }
        val snapshot = pinned(copy, 64 * 1048576)
        val aliceEpisode = pinned(a)
        val bobEpisode = pinned(b)
        ReleasePrivateFiles.save(custody, buildJsonObject {
            put("schemaVersion",1); put("generation",generation); put("member",spec.name)
            put("runtimeFingerprint", selected.runtimeFingerprint)
            put("volumes", buildJsonArray { listOf("hub","alice","bob").forEach { add(it) } })
            put("aliceHome",alice.toString()); put("bobHome",bob.toString())
            put("hubDatabaseSha256",snapshot.sha256)
            put("aliceEpisodeSha256",aliceEpisode.sha256); put("bobEpisodeSha256",bobEpisode.sha256)
        }.toString().toByteArray())
        return HubOwnerReadback(generation, spec.name,selected.runtimeFingerprint,
            alice,bob,snapshot,aliceEpisode,bobEpisode,pinned(custody))
    }
}
