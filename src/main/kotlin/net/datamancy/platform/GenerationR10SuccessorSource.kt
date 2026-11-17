package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*

/** New unbudgeted INSTALL request: new-generation grants plus explicitly
 * reusable image content. No q5712 subject, secret, state, bundle or ACK is
 * transferable. The two terminal ancestors are pinned independently. */
internal object GenerationR10SuccessorSource {
    private val json=Json { encodeDefaults=true; ignoreUnknownKeys=false }
    private const val generation="q-dd36ebcf43ef"
    private const val predecessor="q-5712d9335843"
    private const val oldRequestHash="690a41439d4d4578d87987d3557ce53d87248605c93f95166f0505e29f4a4d2d"
    private const val terminalHash="6f7b62cc78299a4e4ca365ffea595411165e7e33917d6ae160abd439a36ce6ef"
    private val anchor=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$generation")
    private val managed=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$generation")
    private fun raw(path:Path,max:Int=2097152):ByteArray=ReleasePrivateFiles.read(path,max)
    private fun objectAt(path:Path,max:Int=2097152):JsonObject=json.parseToJsonElement(
        raw(path,max).decodeToString(throwOnInvalidSequence=true)).jsonObject
    private fun binding(path:Path):JsonObject=buildJsonObject {
        put("path",path.toString());put("sha256",ReleaseLocks.sha256(raw(path))) }
    fun issue(controller:String):ActivationInput {
        require(controller.matches(Regex("[a-f0-9]{64}")) &&
            !Files.exists(GenerationRuntime.BASE.resolve(generation),NOFOLLOW_LINKS))
        val terminal=Path.of("/mnt/media/p0-v3/release-generations/$predecessor/prepared-no-start-v2.disposition.json")
        PreparedNoStartTerminal.verify(ActivationInput(terminal.toString(),terminalHash))
        PinnedBackupController.verifyDistribution(Path.of("/mnt/media/p0-v3/runtime-supervision/releases/$controller"),
            controller,"p0-v3-platform")
        ReleasePrivateFiles.directory(anchor); ReleasePrivateFiles.directory(managed)
        val original=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$predecessor/assembly-request.r10-v4.budgeted.json")
        val oldBytes=raw(original,4194304)
        require(ReleaseLocks.sha256(oldBytes)==oldRequestHash)
        val old=json.parseToJsonElement(oldBytes.decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(old.getValue("id").jsonPrimitive.content==predecessor &&
            old.getValue("selections").jsonArray.single().jsonObject.getValue("recipe").jsonPrimitive.content==
                CanonicalSharedYamlGraph.R10_ASSEMBLY_RECIPE)
        val inventory=anchor.resolve("inventory.json")
        val identity=objectAt(Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/identity/fresh/$generation.json"),8192)
        val plan=objectAt(managed.resolve("managed-plan.json"),65536)
        val ci=objectAt(anchor.resolve("forgejo-ci-source.r3-executable.json"),65536)
        val closure=anchor.resolve("rss-source-artifact-closure.r10-v2.json")
        val routeBytes=raw(anchor.resolve("graph-portal-routes.r10-v2.json"))
        val routes=json.parseToJsonElement(routeBytes.decodeToString(throwOnInvalidSequence=true)).jsonArray
        val scripts=objectAt(anchor.resolve("mastodon-rendered-script-binding-v2.json"),8192)
            .getValue("config").jsonObject
        val planka=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/planka/$generation/grant.json")
        val lineage=old.getValue("abandonedPreparation").jsonObject
        require(lineage.getValue("priorGeneration").jsonPrimitive.content=="q-5962a9fda75b" &&
            lineage.getValue("terminal").jsonObject.getValue("sha256").jsonPrimitive.content==
                PreparedNoStartTerminal.verify(ActivationInput(terminal.toString(),terminalHash))
                    .earlierFailedPreparationTerminalSha256 &&
            plan.getValue("generation").jsonPrimitive.content==generation &&
            plan.getValue("native").jsonObject.getValue("broker").jsonObject
                .getValue("controllerSha256").jsonPrimitive.content==controller &&
            ci==json.parseToJsonElement(json.encodeToString(
                ForgejoCiSourcePlan.serializer(),GenerationR10CiExecutableSource.bind(generation))).jsonObject &&
            scripts.getValue("path").jsonPrimitive.content.contains("/$generation/"))
        val request=buildJsonObject {
            for (key in listOf("schemaVersion","purpose","store","selections","diskHeadroomMiB",
                "diskReservationMiB","memoryHeadroomMiB","gatewayDenialProducer","abandonedPreparation"))
                put(key,old.getValue(key))
            put("id",generation);put("inventorySha256",ReleaseLocks.sha256(raw(inventory)))
            put("candidateSha256",controller);put("releaseCandidateSha256",controller)
            put("quadletControllerSha256",controller);put("freshIdentity",identity)
            put("managedLanes",plan);put("forgejoCi",ci)
            put("freshPlankaActorGrant",binding(planka));put("portalRoutes",routes)
            put("mastodonRedisScripts",scripts)
            put("baoBootstrapOperation",buildJsonObject { put("generation",generation) })
            put("preparedNoStartPredecessor",binding(terminal))
            put("rssPlan",buildJsonObject {
                for (key in listOf("schemaVersion","intervalSeconds","mastodonOrigin"))
                    put(key,old.getValue("rssPlan").jsonObject.getValue(key))
                put("controllerSha256",controller);put("artifactClosure",binding(closure))
            })
        }
        val text=request.toString()
        require(text.contains("$predecessor/prepared-no-start-v2.disposition.json") &&
            text.split(predecessor).size==2 && !text.contains("/release-generations/$predecessor/managed") &&
            !text.contains("/assembly/$predecessor"))
        val bytes=(text+"\n").encodeToByteArray()
        val typed=json.decodeFromString<AssemblyRequest>(bytes.decodeToString())
        val prospective=GenerationAssembly().plan(typed,raw(inventory))
        require(prospective.specs.size==1 && prospective.specs.single().processes.size==134 &&
            prospective.generation.preparedNoStartPredecessor?.sha256==terminalHash)
        val file=anchor.resolve("assembly-request.r10-fresh.unbudgeted.json")
        require(!Files.exists(file,NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(file,bytes)
        return ActivationInput(file.toString(),ReleaseLocks.sha256(bytes))
    }
    /** The first pre-seal CI source was too small for VFS ancestry. Preserve
     * its request and envelope; bind a separately reviewed r4 archive budget,
     * separately pinned controller and managed plan. No generation is sealed. */
    fun issueV2(controller:String):ActivationInput {
        require(controller.matches(Regex("[a-f0-9]{64}")) &&
            !Files.exists(GenerationRuntime.BASE.resolve(generation),NOFOLLOW_LINKS))
        PinnedBackupController.verifyDistribution(Path.of("/mnt/media/p0-v3/runtime-supervision/releases/$controller"),
            controller,"p0-v3-platform")
        val original=anchor.resolve("assembly-request.r10-fresh.budgeted.json")
        val sourceBytes=raw(original,4194304)
        require(ReleaseLocks.sha256(sourceBytes)=="ceb5146ca2c33e098710c86c4b623b3aa450094f9c69caa634d101d115480514")
        val old=json.parseToJsonElement(sourceBytes.decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(old.getValue("candidateSha256").jsonPrimitive.content==
            "ca5495b01a8192db33802f3131c5c6bd3be3512564ac999a6959c2aa5512f653" &&
            old.getValue("preparedNoStartPredecessor").jsonObject.getValue("sha256").jsonPrimitive.content==terminalHash)
        val plan=objectAt(managed.resolve("managed-plan-v2.json"),65536)
        val ci=objectAt(anchor.resolve("forgejo-ci-source.r4-vfs-budget.json"),65536)
        require(plan.getValue("generation").jsonPrimitive.content==generation &&
            plan.getValue("native").jsonObject.getValue("broker").jsonObject
                .getValue("controllerSha256").jsonPrimitive.content==controller &&
            ci==json.parseToJsonElement(json.encodeToString(ForgejoCiSourcePlan.serializer(),
                GenerationR10CiExecutableSource.rebudgeted(generation))).jsonObject)
        val closure=anchor.resolve("rss-source-artifact-closure.r10-v2.json")
        val request=buildJsonObject {
            old.forEach { (name,value) -> if(name!="workingBudget") put(name,value) }
            put("candidateSha256",controller);put("releaseCandidateSha256",controller)
            put("quadletControllerSha256",controller);put("managedLanes",plan);put("forgejoCi",ci)
            put("rssPlan",buildJsonObject {
                old.getValue("rssPlan").jsonObject.forEach { (name,value) -> put(name,value) }
                put("controllerSha256",controller);put("artifactClosure",binding(closure))
            })
        }
        val bytes=(request.toString()+"\n").encodeToByteArray()
        val typed=json.decodeFromString<AssemblyRequest>(bytes.decodeToString())
        val prospective=GenerationAssembly().plan(typed,raw(anchor.resolve("inventory.json")))
        require(prospective.specs.size==1 && prospective.specs.single().processes.size==134)
        val file=anchor.resolve("assembly-request.r10-fresh-v2.unbudgeted.json")
        require(!Files.exists(file,NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(file,bytes)
        return ActivationInput(file.toString(),ReleaseLocks.sha256(bytes))
    }
    /** The first owned-prepare refused BEFORE generation creation because the
     * old ownership projector omitted the new predecessor pin. Version source
     * again and bind the corrected projector hash; never replay that attempt. */
    fun issueV3(controller:String):ActivationInput {
        require(controller.matches(Regex("[a-f0-9]{64}")) &&
            !Files.exists(GenerationRuntime.BASE.resolve(generation),NOFOLLOW_LINKS))
        PinnedBackupController.verifyDistribution(Path.of("/mnt/media/p0-v3/runtime-supervision/releases/$controller"),
            controller,"p0-v3-platform")
        val prior=anchor.resolve("assembly-request.r10-fresh-v2.budgeted.json")
        val bytes=raw(prior,4194304)
        require(ReleaseLocks.sha256(bytes)=="010859c9c8e69431171ffcf1e5264096c97722dfe15084bfd846d9de36bbb390")
        val old=json.parseToJsonElement(bytes.decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(old.getValue("candidateSha256").jsonPrimitive.content==
            "913dbaa2970459116c513b4398d2f9ddd94e4b4b47da096101e9df8a7b7756c0")
        val source=Path.of("/home/gerald/p0_v3/platform/src/main/kotlin/net/datamancy/platform/SiteOwnership.kt")
        val ownershipSourceSha=ReleaseLocks.sha256(Files.readAllBytes(source))
        val lineage=buildJsonObject {
            old.getValue("abandonedPreparation").jsonObject.forEach { (name,value) -> put(name,value) }
            put("correctedOwnershipSourceSha256",ownershipSourceSha)
        }
        val plan=objectAt(managed.resolve("managed-plan-v3.json"),65536)
        require(plan.getValue("native").jsonObject.getValue("broker").jsonObject
            .getValue("controllerSha256").jsonPrimitive.content==controller)
        val request=buildJsonObject {
            old.forEach { (name,value) -> if(name!="workingBudget") put(name,value) }
            put("candidateSha256",controller);put("releaseCandidateSha256",controller)
            put("quadletControllerSha256",controller);put("managedLanes",plan)
            put("abandonedPreparation",lineage)
            put("rssPlan",buildJsonObject {
                old.getValue("rssPlan").jsonObject.forEach { (name,value) -> put(name,value) }
                put("controllerSha256",controller)
            })
        }
        val updated=(request.toString()+"\n").encodeToByteArray()
        val typed=json.decodeFromString<AssemblyRequest>(updated.decodeToString())
        val prospective=GenerationAssembly().plan(typed,raw(anchor.resolve("inventory.json")))
        require(prospective.specs.size==1 && prospective.specs.single().processes.size==134 &&
            prospective.generation.preparedNoStartPredecessor?.sha256==terminalHash)
        val file=anchor.resolve("assembly-request.r10-fresh-v3.unbudgeted.json")
        require(!Files.exists(file,NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(file,updated)
        return ActivationInput(file.toString(),ReleaseLocks.sha256(updated))
    }
    /** Versioned request after the separate one-use capacity envelope has
     * been issued. Do not mint a second envelope on a budget-copy refusal. */
    fun budgeted(v2:Boolean=false,v3:Boolean=false):ActivationInput {
        require(!(v2 && v3))
        val unbudgeted=anchor.resolve(if(v3) "assembly-request.r10-fresh-v3.unbudgeted.json" else
            if(v2) "assembly-request.r10-fresh-v2.unbudgeted.json" else
            "assembly-request.r10-fresh.unbudgeted.json")
        val source=objectAt(unbudgeted,4194304)
        require(source.getValue("id").jsonPrimitive.content==generation && source["workingBudget"]==null &&
            !Files.exists(GenerationRuntime.BASE.resolve(generation),NOFOLLOW_LINKS))
        val evidence=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/workload/$generation/${if(v3) "envelope-v3" else if(v2) "envelope-v2" else "envelope"}.json")
        val envelope=objectAt(evidence,4194304)
        require(envelope.getValue("generation").jsonPrimitive.content==generation &&
            envelope.getValue("candidateSha256").jsonPrimitive.content==source.getValue("candidateSha256").jsonPrimitive.content &&
            envelope.getValue("scope").jsonPrimitive.content=="r10-complete-private-first-start-prospective-not-rss")
        val map=buildJsonObject { for (row in envelope.getValue("prospectiveRows").jsonArray) {
            val item=row.jsonObject
            put(item.getValue("process").jsonPrimitive.content,item.getValue("prospectiveMiB"))
        } }
        require(map.size==134)
        val budget=buildJsonObject {
            put("scope","r10-full-private-incremental-first-start")
            put("evidence",binding(evidence));put("workingMiB",map)
        }
        val request=buildJsonObject { source.forEach { (name,value) -> put(name,value) }
            put("workingBudget",budget) }
        val bytes=(request.toString()+"\n").encodeToByteArray()
        val typed=json.decodeFromString<AssemblyRequest>(bytes.decodeToString())
        val plan=GenerationAssembly().plan(typed,raw(anchor.resolve("inventory.json")))
        GenerationWorkingEnvelopeIssuer.verify(plan.generation,plan.specs)
        val file=anchor.resolve(if(v3) "assembly-request.r10-fresh-v3.budgeted.json" else
            if(v2) "assembly-request.r10-fresh-v2.budgeted.json" else
            "assembly-request.r10-fresh.budgeted.json")
        require(!Files.exists(file,NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(file,bytes)
        return ActivationInput(file.toString(),ReleaseLocks.sha256(bytes))
    }
}
