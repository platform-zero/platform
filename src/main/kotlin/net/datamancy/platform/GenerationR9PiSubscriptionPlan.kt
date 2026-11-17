package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** Fresh generation-bound managed plan. The selected, re-observed OCI image
 * is reusable artifact content; the lane subjects and secrets are always new.
 * Upstream is a Pi OAuth custody result, never access/refresh material.
 */
internal object GenerationR9PiSubscriptionPlan {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    fun issue(generation:String,controllerSha256:String):ActivationInput {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) && controllerSha256.matches(Regex("[a-f0-9]{64}")))
        val controller=Path.of("/mnt/media/p0-v3/runtime-supervision/releases/$controllerSha256")
        PinnedBackupController.verifyDistribution(controller,controllerSha256,"p0-v3-platform")
        val executable=RecoveryCapsule.fileHash(controller.resolve("bin/p0-v3-platform"))
        val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$generation")
        ReleasePrivateFiles.directory(root)
        val seed=json.decodeFromString<R9ManagedSeed>(ReleasePrivateFiles.read(root.resolve("source-seed.json"),65536)
            .decodeToString(throwOnInvalidSequence=true))
        require(seed.generation==generation && seed.sourceOnly && !seed.nativeIssuerEnrolled &&
            seed.lanes.map { it.kind }==ManagedLaneKind.entries &&
            seed.selectedWorklane.sha256==(if(generation in setOf(GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation)) WorklaneLateBrokerImportProof.binarySha else
                "9a5d277c7fb7da3f5e2d61739e11aae5445e9b1723e8188d0f8c4e550be31016"))
        if(generation in setOf(GenerationAfterQ273Lineage.generation,
                GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
                GenerationAfterQ07Lineage.generation)) WorklaneLateBrokerImportProof.verifySelected(seed.selectedWorklane)
        for(pin in listOf(seed.agentSecret,seed.readerSecret)) require(
            ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(pin.path),8192))==pin.sha256)
        val normalized=generation in setOf("q-4d3c1cb287e5",GenerationAfterNativeImportLineage.generation,
            GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
            GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
            GenerationAfterQ07Lineage.generation)
        GenerationAfterNativeImportLineage.beforeSourceIssue(generation)
        GenerationAfterCapacityRefusalLineage.beforeSourceIssue(generation)
        GenerationAfterQ273Lineage.beforeSourceIssue(generation)
        GenerationAfterQ583Lineage.beforeSourceIssue(generation)
        GenerationAfterQ9bLineage.beforeSourceIssue(generation)
        GenerationAfterQ07Lineage.beforeSourceIssue(generation)
        val bindingBytes=ReleasePrivateFiles.read(root.resolve(if(normalized)
            "worklane-normalized-image-binding.json" else "worklane-observed-image-binding.json"),16384)
        val image=json.decodeFromString<ManagedLaneImageBinding>(bindingBytes.decodeToString(throwOnInvalidSequence=true))
        if(normalized) require(image==GenerationNormalizedWorklaneImage.verify(generation))
        else {
            require(ReleaseLocks.sha256(bindingBytes)=="405f836b19f15c750dd7294caa74bdeea32ee40187acd6725c527a0b84cee0bd")
            val selectedArchive=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/q-5962a9fda75b/worklane-observed.oci.tar")
            require(image.archive.path==selectedArchive.toString() &&
                RecoveryCapsule.fileHash(selectedArchive)==image.archive.sha256 &&
                Files.size(Path.of(image.archive.path))==image.archiveBytes)
        }
        val genRoot=GenerationRuntime.BASE.resolve(generation)
        val fourth=Files.exists(root.resolve("managed-plan-v3.json"),NOFOLLOW_LINKS)
        val fifth=Files.exists(root.resolve("managed-plan-v4.json"),NOFOLLOW_LINKS)
        val sixth=Files.exists(root.resolve("managed-plan-v5.json"),NOFOLLOW_LINKS)
        if (sixth) {
            // The first v6 issuance was refused by the pre-member disposition
            // verifier before any source-plan write. Never replay that command:
            // bind its exact retained failure log and use a separately named v7.
            val refused=Path.of("/home/gerald/p0_v3/.coord/rapid-completion/core-q5962-member-managed-plan-v6-722.log")
            require(Files.isRegularFile(refused,NOFOLLOW_LINKS) && Files.size(refused) in 1..4096 &&
                ReleaseLocks.sha256(Files.readAllBytes(refused))==
                "44369ff3d317710a8eb99dc8f0649ed28c5dcd163abb798878d5aa28dc35b76e" &&
                !Files.exists(root.resolve("managed-plan-v6.json"),NOFOLLOW_LINKS)) {
                "Refused v6 source plan cannot be replayed or adopted"
            }
            GenerationCiMemberPreEffectContinuation.verify(genRoot,
                GenerationCiMemberPreEffectContinuation.binding(genRoot),beforeEffects=true)
        } else if (fourth && generation!="q-5712d9335843") {
            val pin=GenerationCiPreEffectContinuation.binding(genRoot)
            GenerationCiPreEffectContinuation.verify(genRoot,pin,beforeEffects=true)
        } else require(!Files.exists(genRoot,NOFOLLOW_LINKS))
        val dir=genRoot.resolve("managed")
        val config=dir.resolve("inputs/target-lane.toml")
        val storage=dir.resolve("control/storage.conf")
        val broker=dir.resolve("inputs/broker.json")
        val original=root.resolve("managed-plan.json")
        val second=root.resolve("managed-plan-v2.json")
        val third=Files.exists(second,NOFOLLOW_LINKS)
        val revision=Files.exists(original,NOFOLLOW_LINKS)
        val planFile=root.resolve(if(sixth) "managed-plan-v7.json" else if(fifth) "managed-plan-v5.json" else if(fourth) "managed-plan-v4.json" else if(third) "managed-plan-v3.json" else if(revision) "managed-plan-v2.json" else "managed-plan.json")
        require(!Files.exists(planFile,NOFOLLOW_LINKS) &&
            (fourth || listOf(config,storage,broker).none { Files.exists(it,NOFOLLOW_LINKS) }))
        if (revision) {
            val previous=json.decodeFromString<ManagedLanePlan>(ReleasePrivateFiles.read(if (sixth) root.resolve("managed-plan-v5.json") else if (fifth) root.resolve("managed-plan-v4.json") else if (fourth) root.resolve("managed-plan-v3.json") else if (third) second else original,65536)
                .decodeToString(throwOnInvalidSequence=true))
            previous.validate(generation)
            require(previous.native.brokerHost?.authenticationMode=="pi-openai-oauth-v2" &&
                previous.native.broker?.controllerSha256==if(normalized) {
                    require(!fourth && !fifth && !sixth &&
                        previous.lanes==seed.lanes &&
                        previous.native.imageArchive==image &&
                        previous.native.broker?.configuration?.path==broker.toString() &&
                        !Files.exists(genRoot,NOFOLLOW_LINKS))
                    if (generation==GenerationAfterNativeImportLineage.generation) {
                        require(!third)
                        "fb612091f1709e885f8b6ace64f841a0f36b70ceb5e0ba37a5b04d1f06733408"
                    } else if (generation==GenerationAfterQ273Lineage.generation) {
                        require(!third && ReleaseLocks.sha256(ReleasePrivateFiles.read(original,65536))==
                            "56f2f33bb6a290591d24f50dded72c9687471fa3540eb363fed7a5d47369ba64")
                        "d621da21261ce6b26532b255279194f36b2b99c70acc5d8f5cc3a9746c23aa5f"
                    } else if (third) "695f19996aa0b9c42c958517137c52008037bcb0c7c2c48185395a9e769cc342"
                    else "d15f8870f65a2a45612ac5eeed013402fbd585a2fa8cbb2d1b6d9509fc99ae5c"
                } else if(generation=="q-dd36ebcf43ef")
                    if(third) "913dbaa2970459116c513b4398d2f9ddd94e4b4b47da096101e9df8a7b7756c0"
                    else "ca5495b01a8192db33802f3131c5c6bd3be3512564ac999a6959c2aa5512f653"
                else if(generation=="q-5712d9335843")
                    if (fourth) "453cb671b681aa65b35e0d699882eced9ee73a9c1c0bed1e6f07d480aa65a245"
                    else if (third) "e091e6b491fda808b528228c73f500fd0d6f95ff02938c301da093fe66a16915"
                    else "3703b5fcfbfdf2ee1a66944e4d62c14b341a9a38f0f7d312901ef9f6942f5c78"
                else if(sixth)
                    "49ea46615e661cbc31394e9e97187685f5918951989eb8fe297975efbb7d5e9a" else if(fifth)
                    "91520dae277383db91239a00467b7d936c755a78e373786e6715e1d0d93b00de" else if(fourth)
                    GenerationCiPreEffectContinuation.ORIGINAL_CONTROLLER else if(third)
                    "e07b40bcd887512cc1e2628621a3aed117688027a49d347cb92286837a63929f"
                else "730590e41ab11b8bc7f3992cb3f0ff190c2408a7b89aee08b0661491a6247df3")
        }
        val selected=ManagedPiSubscriptionCustody.verify()
        val marker=Path.of("/home/gerald/.local/share/p0-v3-subscription/openai-only/script-v3.result.json")
        require(ReleaseLocks.sha256(ReleasePrivateFiles.read(marker,8192))==selected)
        val lane=seed.lanes.first()
        val manifest="""schema_version = 5
id = "${lane.laneId}"
name = "${lane.session}"
container_name = "worklane-${lane.session}-${lane.laneId}"
session_name = "${lane.session}"
container_home = "/home/dev"
profile_name = "v3"
created_at = "2026-11-09T00:00:00Z"
image_digest = "${image.expectedImageId}"
[profile]
image = "${if(normalized) image.expectedImageId else image.sourceImageReference}"
agent = "pi"
terminal_backend = "tuios-v3"
embedded_containerfile = false
network = "none"
runtime = "systemd"
mount_codex_credentials = false
mount_gh_credentials = false
[[profile.mounts]]
source = "${dir.resolve("control/run/broker.sock")}" 
target = "/run/worklane-pi/broker.sock"
read_only = true
""".toByteArray()
        val storageBytes=if (generation in setOf(GenerationAfterNativeImportLineage.generation,
            GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
            GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
            GenerationAfterQ07Lineage.generation)) {
            val graph=dir.resolve("control/data/containers/storage")
            val run=dir.resolve("control/run/containers")
            """[storage]
driver = "vfs"
graphroot = "$graph"
runroot = "$run"
rootless_storage_path = "$graph"
""".toByteArray()
        } else """[storage]
driver = "vfs"
graphroot = "${dir.resolve("control/podman-graph")}" 
runroot = "${dir.resolve("control/podman-run")}" 
""".toByteArray()
        val brokerBytes=json.encodeToString(ManagedBrokerConfiguration(generation,lane.laneId,
            lane.session,lane.subject,"https://auth.datamancy.net/realms/p0v3")).toByteArray()
        fun pin(path:Path,bytes:ByteArray)=ActivationInput(path.toString(),ReleaseLocks.sha256(bytes))
        val podman=Path.of("/usr/bin/podman")
        require(Files.isRegularFile(podman,NOFOLLOW_LINKS))
        val plan=ManagedLanePlan(generation,seed.lanes,ManagedLaneHostBinding(seed.selectedWorklane,
            ActivationInput(podman.toString(),RecoveryCapsule.fileHash(podman)),pin(config,manifest),
            pin(storage,storageBytes),ManagedBrokerServiceBinding(controllerSha256,executable,pin(broker,brokerBytes)),
            ManagedBrokerHostBinding(seed.agentSecret,seed.readerSecret,ActivationInput(marker.toString(),selected),
                graphOwnedLatePublicTrust=true,authenticationMode="pi-openai-oauth-v2"),image),
            readerSubject=seed.readerSubjectUuid,ownerSubject=seed.ownerSubjectUuid)
        plan.validate(generation)
        if (normalized) {
            // Exercise the very same strict startup TOML/profile/mount parser
            // before writing a new source plan or sealing the generation.
            val control=dir.resolve("control")
            NativeManagedLaneBackend(Path.of(seed.selectedWorklane.path),podman,storage,config,
                control.resolve("home"),control.resolve("config"),control.resolve("data"),
                control.resolve("run"),image,emptyMap())
                .validateTargetManifest(manifest,lane,dir.resolve("worklane"))
        }
        if (fourth && generation!="q-5712d9335843")
            GenerationCiPreEffectContinuation.unchangedInputs(genRoot,plan)
        for((name,value) in listOf("source-target-lane.toml" to manifest,"source-storage.conf" to storageBytes,
            "source-broker.json" to brokerBytes)) {
            val target=root.resolve(name)
            if (revision) require(ReleasePrivateFiles.read(target,1048576).contentEquals(value))
            else ReleasePrivateFiles.save(target,value)
        }
        val bytes=json.encodeToString(plan).toByteArray()
        ReleasePrivateFiles.save(planFile,bytes)
        return ActivationInput(planFile.toString(),ReleaseLocks.sha256(bytes))
    }
}
