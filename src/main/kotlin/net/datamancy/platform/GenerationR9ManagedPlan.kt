package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json

/** Only an operator-authorized NEW OpenAI project key for the fixed OpenAI
 * broker endpoint is admissible. Existing Pi OAuth refresh/access tokens and
 * OpenRouter personal keys are unrelated credentials, never imported/copied.
 */
@Serializable internal data class R9ModelAuthority(val schemaVersion:Int=1,val generation:String,
    val provider:String,val model:String,val scope:String,val origin:String,
    val keySha256:String)
internal object GenerationR9ManagedPlan {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    fun issue(generation:String,controllerSha256:String): ActivationInput =
        GenerationR9PiSubscriptionPlan.issue(generation,controllerSha256)

    /** Retained source for historical audit; no caller may issue it. */
    private fun historicalProjectKeyIssue(generation:String,controllerSha256:String): ActivationInput {
        require(generation=="q-5962a9fda75b" && controllerSha256.matches(Regex("[a-f0-9]{64}")))
        val controller=Path.of("/mnt/media/p0-v3/runtime-supervision/releases/$controllerSha256")
        PinnedBackupController.verifyDistribution(controller,controllerSha256,"p0-v3-platform")
        val bin=controller.resolve("bin/p0-v3-platform")
        val executable=RecoveryCapsule.fileHash(bin)
        val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$generation")
        ReleasePrivateFiles.directory(root)
        val seedBytes=ReleasePrivateFiles.read(root.resolve("source-seed.json"),65536)
        val seed=json.decodeFromString<R9ManagedSeed>(seedBytes.decodeToString(throwOnInvalidSequence=true))
        require(seed.generation==generation && seed.sourceOnly && !seed.nativeIssuerEnrolled &&
            seed.lanes.map { it.kind }==ManagedLaneKind.entries && seed.selectedWorklane.sha256==
                "9a5d277c7fb7da3f5e2d61739e11aae5445e9b1723e8188d0f8c4e550be31016")
        for (pin in listOf(seed.agentSecret,seed.readerSecret)) require(
            ReleaseLocks.sha256(ReleasePrivateFiles.read(Path.of(pin.path),8192))==pin.sha256)
        val bindingBytes=ReleasePrivateFiles.read(root.resolve("worklane-observed-image-binding.json"),16384)
        require(ReleaseLocks.sha256(bindingBytes)=="405f836b19f15c750dd7294caa74bdeea32ee40187acd6725c527a0b84cee0bd")
        val image=json.decodeFromString<ManagedLaneImageBinding>(bindingBytes.decodeToString(throwOnInvalidSequence=true))
        require(image.archive.path==root.resolve("worklane-observed.oci.tar").toString() &&
            RecoveryCapsule.fileHash(Path.of(image.archive.path))==image.archive.sha256 &&
            Files.size(Path.of(image.archive.path))==image.archiveBytes)
        val authorityBytes=ReleasePrivateFiles.read(root.resolve("upstream-openai-authority.json"),8192)
        val authority=json.decodeFromString<R9ModelAuthority>(authorityBytes.decodeToString(throwOnInvalidSequence=true))
        val upstream=root.resolve("upstream-openai-key")
        val key=ReleasePrivateFiles.read(upstream,8192)
        require(authority==R9ModelAuthority(1,generation,"openai","gpt-6-sol",
            "owner-approved-fresh-managed-broker-only","operator-provisioned-new-project-key",
            ReleaseLocks.sha256(key)) && key.size in 40..4096 &&
            key.decodeToString(throwOnInvalidSequence=true).trimEnd('\n').matches(Regex("sk-proj-[A-Za-z0-9_-]{20,4096}"))) {
            "Need an owner-authorized fresh OpenAI PROJECT key, not a personal Pi OAuth/OpenRouter credential"
        }
        key.fill(0)
        val podman=Path.of("/usr/bin/podman")
        require(Files.isRegularFile(podman,NOFOLLOW_LINKS))
        val genRoot=GenerationRuntime.BASE.resolve(generation)
        require(!Files.exists(genRoot,NOFOLLOW_LINKS)) { "Managed sources must precede full generation preparation" }
        val dir=genRoot.resolve("managed")
        val config=dir.resolve("inputs/target-lane.toml")
        val storage=dir.resolve("control/storage.conf")
        val broker=dir.resolve("inputs/broker.json")
        val planFile=root.resolve("managed-plan.json")
        require(!Files.exists(planFile,NOFOLLOW_LINKS) &&
            listOf(config,storage,broker).none { Files.exists(it,NOFOLLOW_LINKS) })
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
image = "${image.sourceImageReference}"
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
        val storageBytes="""[storage]
driver = "vfs"
graphroot = "${dir.resolve("control/podman-graph")}"
runroot = "${dir.resolve("control/podman-run")}"
""".toByteArray()
        val brokerBytes=json.encodeToString(ManagedBrokerConfiguration(generation,lane.laneId,
            lane.session,lane.subject,"https://auth.datamancy.net/realms/p0v3")).toByteArray()
        fun pin(path:Path,bytes:ByteArray)=ActivationInput(path.toString(),ReleaseLocks.sha256(bytes))
        val plan=ManagedLanePlan(generation,seed.lanes,ManagedLaneHostBinding(seed.selectedWorklane,
            ActivationInput(podman.toString(),RecoveryCapsule.fileHash(podman)),pin(config,manifest),
            pin(storage,storageBytes),ManagedBrokerServiceBinding(controllerSha256,executable,
                pin(broker,brokerBytes)),ManagedBrokerHostBinding(seed.agentSecret,seed.readerSecret,
                ActivationInput(upstream.toString(),authority.keySha256),graphOwnedLatePublicTrust=true),image),
            readerSubject=seed.readerSubjectUuid,ownerSubject=seed.ownerSubjectUuid)
        plan.validate(generation)
        // Source-only before the generation directory exists. The generation
        // owner copies exact planned hashes AFTER its assembly intent, before
        // input preparation, never an out-of-band precreated member root.
        for ((name,value) in listOf("source-target-lane.toml" to manifest,
            "source-storage.conf" to storageBytes,"source-broker.json" to brokerBytes))
            ReleasePrivateFiles.save(root.resolve(name),value)
        val bytes=json.encodeToString(plan).toByteArray()
        ReleasePrivateFiles.save(planFile,bytes)
        return ActivationInput(planFile.toString(),ReleaseLocks.sha256(bytes))
    }
    fun materialize(plan:ManagedLanePlan,generationRoot:Path) {
        val generation=plan.generation
        require(generation in setOf("q-5962a9fda75b", "q-5712d9335843", "q-dd36ebcf43ef", "q-4d3c1cb287e5", GenerationAfterNativeImportLineage.generation,
            GenerationAfterCapacityRefusalLineage.generation,GenerationAfterQ273Lineage.generation,
            GenerationAfterQ583Lineage.generation,GenerationAfterQ9bLineage.generation,
            GenerationAfterQ07Lineage.generation) &&
            generationRoot==GenerationRuntime.BASE.resolve(generation))
        val source=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$generation")
        val fourth=source.resolve("managed-plan-v4.json")
        val third=source.resolve("managed-plan-v3.json")
        val second=source.resolve("managed-plan-v2.json")
        val selected=if (generation=="q-dd36ebcf43ef") {
            if(Files.exists(third,NOFOLLOW_LINKS)) third else
                if(Files.exists(second,NOFOLLOW_LINKS)) second else source.resolve("managed-plan.json")
        } else if (generation=="q-5712d9335843") {
            val versioned=if (Files.exists(fourth,NOFOLLOW_LINKS)) fourth else
                if (Files.exists(third,NOFOLLOW_LINKS)) third else second
            require(Files.isRegularFile(versioned, NOFOLLOW_LINKS)) {
                "Successor requires distinct versioned managed source, not the old controller plan" }
            versioned
        } else if (Files.exists(third,NOFOLLOW_LINKS)) third else
            if (Files.exists(second,NOFOLLOW_LINKS)) second else source.resolve("managed-plan.json")
        val sealed=ReleasePrivateFiles.read(selected,65536)
        require(json.decodeFromString<ManagedLanePlan>(sealed.decodeToString(throwOnInvalidSequence=true))==plan)
        val dir=generationRoot.resolve("managed")
        require(!Files.exists(dir,NOFOLLOW_LINKS))
        Files.createDirectory(dir,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        ReleasePrivateFiles.sync(generationRoot)
        for (path in listOf(dir.resolve("inputs"),dir.resolve("control"))) {
            Files.createDirectory(path,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            ReleasePrivateFiles.sync(dir)
        }
        val pinned=listOf("source-target-lane.toml" to plan.native.manifest,
            "source-storage.conf" to plan.native.storageConfig,
            "source-broker.json" to requireNotNull(plan.native.broker).configuration)
        for ((name,target) in pinned) {
            val bytes=ReleasePrivateFiles.read(source.resolve(name),1048576)
            require(ReleaseLocks.sha256(bytes)==target.sha256 && Path.of(target.path).startsWith(dir))
            ReleasePrivateFiles.save(Path.of(target.path),bytes)
        }
    }
}
