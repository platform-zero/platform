package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.*

/** New INSTALL after an independently terminalized pre-unit stage. All three
 * ancestors contribute only their typed terminal lineage, never their state,
 * human identities, managed subjects, runner registration or provider ACK. */
internal object GenerationAfterPreUnitSource {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    private const val generation="q-4d3c1cb287e5"
    private const val terminalHash="1ffd7dea5f9b6c5141f19d263e9f817ceaf9180ce39d413579fa06e94bfd0ee3"
    private val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$generation")
    private val managed=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$generation")
    private fun bytes(path:Path,max:Int=2097152)=ReleasePrivateFiles.read(path,max)
    private fun objectAt(path:Path,max:Int=2097152)=json.parseToJsonElement(
        bytes(path,max).decodeToString(throwOnInvalidSequence=true)).jsonObject
    private fun pin(path:Path)=buildJsonObject {
        put("path",path.toString());put("sha256",ReleaseLocks.sha256(bytes(path))) }
    private fun terminal():JsonObject {
        val path=Path.of("/mnt/media/p0-v3/release-generations/q-dd36ebcf43ef/failed-pre-unit-stage-v1.disposition.json")
        ManagedPreUnitNoStartTerminal.verify(ActivationInput(path.toString(),terminalHash))
        return pin(path)
    }
    fun issue(controller:String):ActivationInput {
        require(controller.matches(Regex("[a-f0-9]{64}")) &&
            !Files.exists(GenerationRuntime.BASE.resolve(generation),NOFOLLOW_LINKS))
        PinnedBackupController.verifyDistribution(Path.of("/mnt/media/p0-v3/runtime-supervision/releases/$controller"),
            controller,"p0-v3-platform")
        ReleasePrivateFiles.directory(root);ReleasePrivateFiles.directory(managed)
        val original=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-dd36ebcf43ef/assembly-request.r10-fresh-v3.budgeted.json")
        val oldBytes=bytes(original,4194304)
        require(ReleaseLocks.sha256(oldBytes)=="30ba9531ce1d9194679ba27fe80563de264f04b052baccf3925e724e96f395b4")
        val old=json.parseToJsonElement(oldBytes.decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(old.getValue("id").jsonPrimitive.content=="q-dd36ebcf43ef" &&
            old.getValue("selections").jsonArray.single().jsonObject.getValue("recipe").jsonPrimitive.content==
                CanonicalSharedYamlGraph.R10_ASSEMBLY_RECIPE)
        val identity=objectAt(Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/identity/fresh/$generation.json"),8192)
        val firstPlan=objectAt(managed.resolve("managed-plan.json"),65536)
        val intermediate=objectAt(managed.resolve("managed-plan-v2.json"),65536)
        val plan=objectAt(managed.resolve("managed-plan-v3.json"),65536)
        require(firstPlan.getValue("native").jsonObject.getValue("broker").jsonObject
            .getValue("controllerSha256").jsonPrimitive.content==
                "d15f8870f65a2a45612ac5eeed013402fbd585a2fa8cbb2d1b6d9509fc99ae5c" &&
            intermediate.getValue("native").jsonObject.getValue("broker").jsonObject
                .getValue("controllerSha256").jsonPrimitive.content==
                "695f19996aa0b9c42c958517137c52008037bcb0c7c2c48185395a9e769cc342" &&
            firstPlan.getValue("generation")==plan.getValue("generation") &&
            firstPlan.getValue("lanes")==plan.getValue("lanes") &&
            firstPlan.getValue("lanes")==intermediate.getValue("lanes") &&
            firstPlan.getValue("native").jsonObject.getValue("imageArchive")==
                plan.getValue("native").jsonObject.getValue("imageArchive") &&
            firstPlan.getValue("native").jsonObject.getValue("imageArchive")==
                intermediate.getValue("native").jsonObject.getValue("imageArchive")) {
            "Distinct versioned managed plan must preserve original lanes and r3 image custody" }
        val ci=objectAt(root.resolve("forgejo-ci-source.r4-vfs-budget.json"),65536)
        val selected=GenerationR10CiExecutableSource.freshAfterPreUnit(generation)
        require(ci==json.parseToJsonElement(json.encodeToString(ForgejoCiSourcePlan.serializer(),selected)).jsonObject &&
            plan.getValue("generation").jsonPrimitive.content==generation &&
            plan.getValue("native").jsonObject.getValue("broker").jsonObject
                .getValue("controllerSha256").jsonPrimitive.content==controller)
        val lineage=buildJsonObject {
            old.getValue("abandonedPreparation").jsonObject.forEach { (k,v)->put(k,v) }
            val source=Path.of("/home/gerald/p0_v3/platform/src/main/kotlin/net/datamancy/platform/SiteOwnership.kt")
            put("correctedOwnershipSourceSha256",ReleaseLocks.sha256(Files.readAllBytes(source)))
        }
        val routes=json.parseToJsonElement(bytes(root.resolve("graph-portal-routes.r10-v2.json"))
            .decodeToString(throwOnInvalidSequence=true)).jsonArray
        val scripts=objectAt(root.resolve("mastodon-rendered-script-binding-v2.json"),8192)
            .getValue("config").jsonObject
        val planka=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/planka/$generation/grant.json")
        val closure=root.resolve("rss-source-artifact-closure.r10-v2.json")
        val request=buildJsonObject {
            for (key in listOf("schemaVersion","purpose","store","selections","diskHeadroomMiB",
                "diskReservationMiB","memoryHeadroomMiB","gatewayDenialProducer"))
                put(key,old.getValue(key))
            put("id",generation);put("inventorySha256",ReleaseLocks.sha256(bytes(root.resolve("inventory.json"))))
            put("candidateSha256",controller);put("releaseCandidateSha256",controller)
            put("quadletControllerSha256",controller);put("abandonedPreparation",lineage)
            put("preparedNoStartPredecessor",old.getValue("preparedNoStartPredecessor"))
            put("failedPreUnitStagePredecessor",terminal())
            put("freshIdentity",identity);put("managedLanes",plan);put("forgejoCi",ci)
            put("freshPlankaActorGrant",pin(planka));put("portalRoutes",routes)
            put("mastodonRedisScripts",scripts)
            put("baoBootstrapOperation",buildJsonObject { put("generation",generation) })
            put("rssPlan",buildJsonObject {
                for (key in listOf("schemaVersion","intervalSeconds","mastodonOrigin"))
                    put(key,old.getValue("rssPlan").jsonObject.getValue(key))
                put("controllerSha256",controller);put("artifactClosure",pin(closure))
            })
        }
        val text=request.toString()
        require(text.split("q-dd36ebcf43ef").size==2 &&
            !text.contains("/managed-lanes/q-dd36ebcf43ef/") &&
            !text.contains("/assembly/q-dd36ebcf43ef/"))
        val encoded=(text+"\n").encodeToByteArray()
        val prospective=GenerationAssembly().plan(json.decodeFromString<AssemblyRequest>(encoded.decodeToString()),
            bytes(root.resolve("inventory.json")))
        require(prospective.specs.size==1 && prospective.specs.single().processes.size==134)
        val file=root.resolve("assembly-request.r10-after-preunit.unbudgeted.json")
        require(!Files.exists(file,NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(file,encoded)
        return ActivationInput(file.toString(),ReleaseLocks.sha256(encoded))
    }
    fun budgeted():ActivationInput {
        val source=objectAt(root.resolve("assembly-request.r10-after-preunit.unbudgeted.json"),4194304)
        require(source.getValue("id").jsonPrimitive.content==generation && source["workingBudget"]==null &&
            !Files.exists(GenerationRuntime.BASE.resolve(generation),NOFOLLOW_LINKS))
        val evidence=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/workload/$generation/envelope.json")
        val envelope=objectAt(evidence,4194304)
        require(envelope.getValue("generation").jsonPrimitive.content==generation &&
            envelope.getValue("candidateSha256").jsonPrimitive.content==source.getValue("candidateSha256").jsonPrimitive.content &&
            envelope.getValue("scope").jsonPrimitive.content=="r10-complete-private-first-start-prospective-not-rss")
        val rows=buildJsonObject { for (entry in envelope.getValue("prospectiveRows").jsonArray) {
            val item=entry.jsonObject;put(item.getValue("process").jsonPrimitive.content,item.getValue("prospectiveMiB"))
        } }
        require(rows.size==134)
        val request=buildJsonObject {
            source.forEach { (name,value)->put(name,value) }
            put("workingBudget",buildJsonObject {
                put("scope","r10-full-private-incremental-first-start")
                put("evidence",pin(evidence));put("workingMiB",rows)
            })
        }
        val encoded=(request.toString()+"\n").encodeToByteArray()
        val prospective=GenerationAssembly().plan(json.decodeFromString<AssemblyRequest>(encoded.decodeToString()),
            bytes(root.resolve("inventory.json")))
        GenerationWorkingEnvelopeIssuer.verify(prospective.generation,prospective.specs)
        val file=root.resolve("assembly-request.r10-after-preunit.budgeted.json")
        require(!Files.exists(file,NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(file,encoded)
        return ActivationInput(file.toString(),ReleaseLocks.sha256(encoded))
    }
}
