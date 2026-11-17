package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Serializable internal data class NotebookCidRetireIntent(val generation: String, val member: String,
    val user: String, val ordinal: Int, val cid: String, val stopResultSha256: String,
    val terminalInspectionSha256: String, val unitTerminalReadbackSha256: String)
@Serializable internal data class NotebookCidRetireResult(val intentSha256: String, val cid: String,
    val nativeRemoveAcknowledged: Boolean, val nameAbsentReadbackSha256: String)

/** A separate, one-use *terminal disposal* effect, never an original STOP ACK.
 * A stopped named Podman container blocks the next Quadlet `run --replace=false`.
 * Only the exact native STOP-result CID may be removed after unit terminal proof;
 * persist intent before effect and refuse to replay on lost remove ACK. Notebook
 * home is a separate graph volume, never removed by this command.
 */
internal class NotebookNativeDisposition(private val root: Path, private val spec: PrivateDeploymentSpec,
    private val native: RuntimeCommands = PrivateRootfulCommands(45,RuntimeStore.CANONICAL_V2),
    private val unitReadback: ((String) -> ByteArray)? = null) {
    private val json = Json { encodeDefaults = true }
    private val hash = Regex("[a-f0-9]{64}")
    private fun inspect(cid: String): ByteArray {
        val reply = native.run(listOf("container","inspect",cid))
        require(reply.exitCode == 0 && reply.output.toByteArray().size in 1..65536)
        return reply.output.toByteArray()
    }
    private fun terminalUnit(unit: String): ByteArray {
        val child = ProcessBuilder("/usr/bin/systemctl","show","--no-pager",
            "--property=ActiveState,MainPID,ControlPID,Job",unit)
            .redirectErrorStream(true).apply { environment().clear() }.start()
        try {
            require(child.waitFor(20,TimeUnit.SECONDS) && child.exitValue() == 0)
            val raw = child.inputStream.use { it.readNBytes(8193) }
            require(raw.size in 1..8192)
            val values = raw.decodeToString(throwOnInvalidSequence=true).lineSequence().filter { '=' in it }
                .associate { it.substringBefore('=') to it.substringAfter('=') }
            require(values["ActiveState"] in setOf("inactive","failed") && values["MainPID"] == "0" &&
                values["ControlPID"] == "0" && values["Job"] in setOf("0",""))
            return raw
        } finally { if (child.isAlive) child.destroyForcibly() }
    }
    fun retire(user: String, ordinal: Int, stopPath: Path, cid: String): String {
        require(NotebookSelectedGraph.selected(root,spec) && user in setOf("alice","bob") &&
            ordinal in 1..64 && hash.matches(cid) && stopPath.parent == root &&
            stopPath == if (ordinal == 1) root.resolve("quadlet-stop-${spec.name}-$user.result.json") else
                NotebookEpisodePaths.path(root,"quadlet-stop-${spec.name}-$user.result",spec.name,user))
        val p = spec.processes.single { it.id == user }
        val stopBytes = ReleasePrivateFiles.read(stopPath,8192)
        val result = json.decodeFromString<QuadletStopResult>(stopBytes.decodeToString(throwOnInvalidSequence=true))
        // The original helper may acknowledge an already-exited exact CID without
        // issuing Podman stop. Retain that fact; native terminal + unit proofs below
        // separately authorize disposal, not a fabricated original stop command.
        require(result.stopped && result.containerId == cid &&
            result.intentSha256 == ReleaseLocks.sha256(ReleasePrivateFiles.read(
                if (ordinal == 1) root.resolve("quadlet-stop-${spec.name}-$user.intent.json") else
                    NotebookEpisodePaths.path(root,"quadlet-stop-${spec.name}-$user.intent",spec.name,user),8192)))
        val inspection = inspect(cid)
        val item = json.parseToJsonElement(inspection.decodeToString(throwOnInvalidSequence=true)).jsonArray.single().jsonObject
        val labels = item.getValue("Config").jsonObject.getValue("Labels").jsonObject
        require(item.getValue("Id").jsonPrimitive.content == cid &&
            item.getValue("Name").jsonPrimitive.content == "p0v3-live-${spec.name}-$user" &&
            item.getValue("Image").jsonPrimitive.content.removePrefix("sha256:") == p.imageId &&
            labels.getValue("io.p0v3.private-deployment").jsonPrimitive.content == spec.name &&
            item.getValue("State").jsonObject.getValue("Running").jsonPrimitive.content == "false" &&
            item.getValue("State").jsonObject.getValue("Pid").jsonPrimitive.content == "0")
        val unitState = unitReadback?.invoke("${RuntimeQuadlets.unit(spec,p)}.service")
            ?: terminalUnit("${RuntimeQuadlets.unit(spec,p)}.service")
        require(unitState.size in 1..8192)
        val retireRoot = root.resolve("notebooks/retire")
        if (!Files.exists(retireRoot,NOFOLLOW_LINKS)) Files.createDirectory(retireRoot,
            java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.directory(retireRoot)
        val userRoot = retireRoot.resolve(user)
        if (!Files.exists(userRoot,NOFOLLOW_LINKS)) Files.createDirectory(userRoot,
            java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.directory(userRoot)
        val stem = userRoot.resolve("%04d.retire".format(ordinal))
        val intentPath = Path.of("$stem.intent.json")
        val resultPath = Path.of("$stem.result.json")
        require(!Files.exists(intentPath,NOFOLLOW_LINKS) && !Files.exists(resultPath,NOFOLLOW_LINKS)) {
            "Notebook CID retirement already attempted; original remove effect uncertain"
        }
        val intent = NotebookCidRetireIntent(root.fileName.toString(),spec.name,user,ordinal,cid,
            ReleaseLocks.sha256(stopBytes),ReleaseLocks.sha256(inspection),ReleaseLocks.sha256(unitState))
        val bytes = json.encodeToString(intent).toByteArray()
        ReleasePrivateFiles.save(intentPath,bytes)
        val reply = native.run(listOf("container","rm",cid))
        require(reply.exitCode == 0 && reply.output.toByteArray().size <= 4096)
        val absence = native.run(listOf("container","ls","--all","--format","{{.Names}}"))
        require(absence.exitCode == 0 && absence.output.toByteArray().size <= 2_000_000 &&
            absence.output.lineSequence().none { it.trim() == "p0v3-live-${spec.name}-$user" } &&
            native.run(listOf("container","inspect",cid)).exitCode != 0)
        val resultBytes = json.encodeToString(NotebookCidRetireResult(ReleaseLocks.sha256(bytes),cid,true,
            ReleaseLocks.sha256(absence.output.toByteArray()))).toByteArray()
        ReleasePrivateFiles.save(resultPath,resultBytes)
        return ReleaseLocks.sha256(resultBytes)
    }
}
