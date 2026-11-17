package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.json.*

/** Separate isolated *actual CLI* import and failed START, not a generation ACK.
 * Verify before a NEW seal; the old q273 original binary and intents stay frozen. */
internal object WorklaneLateBrokerImportProof {
    const val binarySha="3ac8cf43714e0cc2fdf8ebd31dc5034e0732adbcfcbcb91502d04e439d3c5cac"
    const val binaryPath="/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/worklane-host-late-broker-r1/worklane"
    const val importResultSha="cc963d3ebd99982187bde6e8848fc735c7ee95e817cdbac78a39159dd833a588"
    const val missingStartResultSha="ec57d9de25457d795ec067a1bc252a14fa7e4b402a6a5b9c1eb79cca925797b5"
    const val fullPrepareReturnSha="2b690650b0a24f77f362f115d9be817560084264b702d46059a565808cffda32"
    private val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/native-probes/worklane-late-broker-import-r1")
    private fun read(name:String):ByteArray=ReleasePrivateFiles.read(root.resolve(name),1048576)
    private fun obj(name:String)=Json.parseToJsonElement(read(name).decodeToString(throwOnInvalidSequence=true)).jsonObject
    private fun sha(name:String)=ReleaseLocks.sha256(read(name))
    private fun field(record:JsonObject,key:String)=record.getValue(key).jsonPrimitive.content
    fun verifySelected(binary:ActivationInput) {
        require(binary.path==binaryPath && binary.sha256==binarySha &&
            Files.isRegularFile(Path.of(binaryPath),NOFOLLOW_LINKS) &&
            RecoveryCapsule.fileHash(Path.of(binaryPath))==binarySha)
        val pinned=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/worklane-host-late-broker-r1/pin.result.json")
        require(ReleaseLocks.sha256(ReleasePrivateFiles.read(pinned,8192))==
            "4088ef510735fc70bd1beda1df2d501b43455fa722037c5ef7c2f71754553133")
        val importIntent=obj("import.intent.json")
        val importResult=obj("import.result.json")
        val startIntent=obj("missing-broker-start.intent.json")
        val startResult=obj("missing-broker-start.result.json")
        val manifest=root.resolve("project/.worklane/lane.toml")
        val socket=root.resolve("control/run/broker.sock")
        require(sha("import.result.json")==importResultSha &&
            sha("missing-broker-start.result.json")==missingStartResultSha &&
            field(importIntent,"hostBinarySha256")==binarySha &&
            field(importIntent,"podmanSha256")=="6e4993e061eb88205003892252e2e13bbf49c12a6f67f519881b9b3c94e980e6" &&
            field(importIntent,"manifestSha256")==ReleaseLocks.sha256(ReleasePrivateFiles.read(manifest,8192)) &&
            field(importResult,"intentSha256")==sha("import.intent.json") &&
            field(importResult,"laneId")==field(startIntent,"laneId") &&
            field(startIntent,"importResultSha256")==importResultSha &&
            field(startResult,"intentSha256")==sha("missing-broker-start.intent.json") &&
            field(importResult,"state")=="absent" &&
            // The actual host CLI import state must be accepted by the SAME
            // predicate used after production Worklane PREPARE's native readback.
            // A registry record alone, or an unknown/running state, cannot pass.
            managedPrepareNativeIsolation(buildJsonObject { put("state",field(importResult,"state")) },
                JsonArray(emptyList())) &&
            startResult.getValue("expectedMissingMountRefusal").jsonPrimitive.boolean &&
            startResult.getValue("rootlessContainersBefore").jsonPrimitive.int==0 &&
            startResult.getValue("rootlessContainersAfter").jsonPrimitive.int==0 &&
            !startResult.getValue("nativeContainerStarted").jsonPrimitive.boolean &&
            !startResult.getValue("applicationStarted").jsonPrimitive.boolean &&
            !importResult.getValue("originalQ273PrepareResultAcknowledged").jsonPrimitive.boolean &&
            !Files.exists(socket,NOFOLLOW_LINKS) &&
            Files.isRegularFile(root.resolve("data/worklane/worklane-v5.db"),NOFOLLOW_LINKS) &&
            manifest.toRealPath()==manifest && socket.toString() in ReleasePrivateFiles.read(manifest,8192)
                .decodeToString(throwOnInvalidSequence=true)) {
            "Isolated actual Worklane import/missing-broker START proof changed or is not cold"
        }
        WorklaneFullPrepareReturnProbe.verify(ActivationInput(
            WorklaneFullPrepareReturnProbe.base.resolve("full-production-prepare.result.json").toString(),
            fullPrepareReturnSha))
    }
}
