package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** New r10 original source: old q273 bundle supplies only pinned *selection*,
 * never its Worklane registry, image import, broker, or missing result. */
internal object GenerationAfterQ273Source {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    private const val id=GenerationAfterQ273Lineage.generation
    private val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$id")
    private val managed=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$id")
    private fun bytes(path:Path,max:Int=4194304)=ReleasePrivateFiles.read(path,max)
    private fun objectAt(path:Path,max:Int=4194304)=json.parseToJsonElement(
        bytes(path,max).decodeToString(throwOnInvalidSequence=true)).jsonObject
    private fun pin(path:Path)=buildJsonObject {
        put("path",path.toString());put("sha256",ReleaseLocks.sha256(bytes(path))) }
    fun issue(controller:String):ActivationInput {
        require(controller.matches(Regex("[a-f0-9]{64}")) &&
            !Files.exists(GenerationRuntime.BASE.resolve(id),NOFOLLOW_LINKS))
        GenerationAfterQ273Lineage.beforeSourceIssue(id)
        PinnedBackupController.verifyDistribution(Path.of("/mnt/media/p0-v3/runtime-supervision/releases/$controller"),
            controller,"p0-v3-platform")
        val oldPath=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-273337d6772c/assembly-request.r10-after-capacity-refusal.budgeted.json")
        val oldBytes=bytes(oldPath)
        require(ReleaseLocks.sha256(oldBytes)=="990e0df8877e02e4fa15f5bb95c1f66e5f064fceff28d58be08ea4ce2c31163d")
        val old=json.parseToJsonElement(oldBytes.decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(old.getValue("id").jsonPrimitive.content==Q273UncertainManagedImportTerminal.generation &&
            old.getValue("selections").jsonArray.single().jsonObject.getValue("recipe").jsonPrimitive.content==
                CanonicalSharedYamlGraph.R10_ASSEMBLY_RECIPE &&
            old.getValue("qc3PreparedNoStartPredecessor").jsonObject.getValue("sha256")
                .jsonPrimitive.content==GenerationAfterCapacityRefusalLineage.qc3Sha &&
            old.getValue("uncertainNativeImportPredecessor").jsonObject.getValue("sha256")
                .jsonPrimitive.content==GenerationAfterNativeImportLineage.terminalSha)
        val plan=objectAt(managed.resolve("managed-plan-v2.json"),65536)
        val ci=objectAt(root.resolve("forgejo-ci-source.r4-vfs-budget.json"),65536)
        val identity=objectAt(Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/identity/fresh/$id.json"),8192)
        require(plan.getValue("generation").jsonPrimitive.content==id &&
            plan.getValue("native").jsonObject.getValue("worklane").jsonObject.getValue("sha256")
                .jsonPrimitive.content==WorklaneLateBrokerImportProof.binarySha &&
            plan.getValue("native").jsonObject.getValue("broker").jsonObject.getValue("controllerSha256")
                .jsonPrimitive.content==controller &&
            plan.getValue("native").jsonObject.getValue("imageArchive")==
                json.parseToJsonElement(json.encodeToString(GenerationNormalizedWorklaneImage.verify(id))) &&
            ci==json.parseToJsonElement(json.encodeToString(GenerationR10CiExecutableSource.freshAfterPreUnit(id))))
        val storage=Path.of(plan.getValue("native").jsonObject.getValue("storageConfig").jsonObject.getValue("path").jsonPrimitive.content)
        val actual=bytes(managed.resolve("source-storage.conf"),8192)
        require(storage==GenerationRuntime.BASE.resolve(id).resolve("managed/control/storage.conf") &&
            plan.getValue("native").jsonObject.getValue("storageConfig").jsonObject.getValue("sha256")
                .jsonPrimitive.content==ReleaseLocks.sha256(actual) &&
            actual.decodeToString().contains("rootless_storage_path = \"${GenerationRuntime.BASE.resolve(id).resolve("managed/control/data/containers/storage")}\""))
        val routes=json.parseToJsonElement(bytes(root.resolve("graph-portal-routes.r10-v2.json"))
            .decodeToString(throwOnInvalidSequence=true))
        val scripts=objectAt(root.resolve("mastodon-rendered-script-binding-v2.json"),8192).getValue("config")
        val planka=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/planka/$id/grant.json")
        val closure=root.resolve("rss-source-artifact-closure.r10-v2.json")
        val request=buildJsonObject {
            for(key in listOf("schemaVersion","purpose","store","selections","diskHeadroomMiB",
                "diskReservationMiB","memoryHeadroomMiB","gatewayDenialProducer",
                "preparedNoStartPredecessor","failedPreUnitStagePredecessor"))put(key,old.getValue(key))
            val lineage=old.getValue("abandonedPreparation").jsonObject
            put("abandonedPreparation",buildJsonObject {
                lineage.forEach { (name,value)->put(name,value) }
                put("correctedOwnershipSourceSha256",ReleaseLocks.sha256(Files.readAllBytes(Path.of(
                    "/home/gerald/p0_v3/platform/src/main/kotlin/net/datamancy/platform/SiteOwnership.kt"))))
            })
            put("id",id);put("inventorySha256",ReleaseLocks.sha256(bytes(root.resolve("inventory.json"))))
            put("candidateSha256",controller);put("releaseCandidateSha256",controller)
            put("quadletControllerSha256",controller)
            put("uncertainNativeImportPredecessor",json.encodeToJsonElement(GenerationAfterNativeImportLineage.terminal))
            put("isolatedRootlessProbePredecessor",json.encodeToJsonElement(GenerationAfterNativeImportLineage.probe))
            put("qc3PreparedNoStartPredecessor",json.encodeToJsonElement(GenerationAfterCapacityRefusalLineage.qc3))
            put("q273UncertainImportPredecessor",json.encodeToJsonElement(GenerationAfterQ273Lineage.predecessor))
            put("freshIdentity",identity);put("managedLanes",plan);put("forgejoCi",ci)
            put("freshPlankaActorGrant",pin(planka));put("portalRoutes",routes)
            put("mastodonRedisScripts",scripts)
            put("baoBootstrapOperation",buildJsonObject { put("generation",id) })
            put("rssPlan",buildJsonObject {
                for(key in listOf("schemaVersion","intervalSeconds","mastodonOrigin"))
                    put(key,old.getValue("rssPlan").jsonObject.getValue(key))
                put("controllerSha256",controller);put("artifactClosure",pin(closure))
            })
        }
        val encoded=(request.toString()+"\n").toByteArray()
        val prospective=GenerationAssembly().plan(json.decodeFromString<AssemblyRequest>(encoded.decodeToString()),
            bytes(root.resolve("inventory.json")))
        require(prospective.specs.single().processes.size==134 &&
            SiteOwnerships.project(prospective.summary.request)==prospective.generation)
        val target=root.resolve("assembly-request.r10-after-q273-import.unbudgeted-v2.json")
        require(!Files.exists(target,NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(target,encoded)
        return ActivationInput(target.toString(),ReleaseLocks.sha256(encoded))
    }
    fun budgeted():ActivationInput {
        val source=objectAt(root.resolve("assembly-request.r10-after-q273-import.unbudgeted-v2.json"))
        require(source.getValue("id").jsonPrimitive.content==id && source["workingBudget"]==null &&
            !Files.exists(GenerationRuntime.BASE.resolve(id),NOFOLLOW_LINKS))
        val evidence=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/workload/$id/envelope.json")
        val envelope=objectAt(evidence)
        require(envelope.getValue("generation").jsonPrimitive.content==id &&
            envelope.getValue("candidateSha256").jsonPrimitive.content==source.getValue("candidateSha256").jsonPrimitive.content &&
            envelope.getValue("qc3PreparedNoStartPredecessor").jsonObject.getValue("sha256").jsonPrimitive.content==
                GenerationAfterCapacityRefusalLineage.qc3Sha &&
            envelope.getValue("q273UncertainImportPredecessor").jsonObject.getValue("sha256").jsonPrimitive.content==
                GenerationAfterQ273Lineage.predecessorSha &&
            envelope.getValue("scope").jsonPrimitive.content=="r10-complete-private-first-start-prospective-not-rss")
        val rows=buildJsonObject { for(entry in envelope.getValue("prospectiveRows").jsonArray) {
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
        val encoded=(request.toString()+"\n").toByteArray()
        val prospective=GenerationAssembly().plan(json.decodeFromString<AssemblyRequest>(encoded.decodeToString()),
            bytes(root.resolve("inventory.json")))
        GenerationWorkingEnvelopeIssuer.verify(prospective.generation,prospective.specs)
        require(SiteOwnerships.project(prospective.summary.request)==prospective.generation)
        val target=root.resolve("assembly-request.r10-after-q273-import.budgeted-v2.json")
        require(!Files.exists(target,NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(target,encoded)
        return ActivationInput(target.toString(),ReleaseLocks.sha256(encoded))
    }
}
