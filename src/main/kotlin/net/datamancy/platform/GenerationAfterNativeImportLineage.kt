package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.json.*

/** Typed predecessor of qc3. A scratch-probe ACK is never a release import ACK. */
internal object GenerationAfterNativeImportLineage {
    const val generation="q-c3a7a9e29391"
    const val terminalSha="d731a2136e435d3e1bfa5b183a0c74a6cf987788376c7f5df292c4315c7451bb"
    const val probeSha="007117f9ef65a30db4d41838b74490a4f9b0fa3f0a07a03c2627c836c47b5fd5"
    val terminal=ActivationInput(
        "/mnt/media/p0-v3/release-generations/q-4d3c1cb287e5/uncertain-native-worklane-import-v1.disposition.json",terminalSha)
    val probe=ActivationInput(
        "/mnt/media/p0-v3/release-bootstrap-anchors/native-probes/q-c3a7a9e29391-rootless-image-r1/probe.result.json",probeSha)
    fun verify(predecessor:ActivationInput,probePin:ActivationInput) {
        require(predecessor==terminal && probePin==probe)
        val disposition=ManagedUncertainImageImportTerminal.verify(predecessor)
        require(disposition.generation=="q-4d3c1cb287e5" && !disposition.nativeImportAcknowledged &&
            disposition.rootlessImages==1 && disposition.rootlessContainers==0 &&
            disposition.qualificationCycles==0 && !disposition.applicationUnitStarted)
        val bytes=ReleasePrivateFiles.read(Path.of(probe.path),8192)
        require(ReleaseLocks.sha256(bytes)==probe.sha256)
        val state=Json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence=true)).jsonObject
        val root=Path.of(probe.path).parent
        val intent=ReleasePrivateFiles.read(root.resolve("probe.intent.json"),8192)
        require(state.getValue("intentSha256").jsonPrimitive.content==ReleaseLocks.sha256(intent) &&
            state.getValue("isolatedProbeOnly").jsonPrimitive.boolean &&
            state.getValue("nativeImageImported").jsonPrimitive.boolean &&
            state.getValue("imageImportAcknowledged").jsonPrimitive.boolean &&
            !state.getValue("q4dOriginalImportAcknowledged").jsonPrimitive.boolean &&
            !state.getValue("generationRootCreated").jsonPrimitive.boolean &&
            !state.getValue("applicationStarted").jsonPrimitive.boolean &&
            !state.getValue("qualificationEvidence").jsonPrimitive.boolean &&
            state.getValue("nativeImageIdRaw").jsonPrimitive.content==
                "422379fcd6f2e005985bec96b2017978188de673d90122f600b9dd65294b5248" &&
            state.getValue("nativeGraphMetadata").jsonObject.getValue("allocatedBytes").jsonPrimitive.long in 1..34359738368L &&
            state.getValue("rootlessGraph").jsonPrimitive.content==root.resolve("control/data/containers/storage").toString() &&
            state.getValue("rootlessRun").jsonPrimitive.content==root.resolve("control/run/containers").toString() &&
            Files.isDirectory(root,NOFOLLOW_LINKS) && !Files.exists(root.resolve("probe.application-start.result.json"),NOFOLLOW_LINKS))
    }
    fun beforeSourceIssue(generation:String) {
        if (generation==this.generation) {
            require(!Files.exists(GenerationRuntime.BASE.resolve(generation),NOFOLLOW_LINKS))
            verify(terminal,probe)
        }
    }
}
