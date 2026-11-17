package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Fresh qc3 source: only prior typed terminal/probe evidence transfers,
 * never the predecessor's runtime state, identities, managed lanes or ACKs. */
internal object GenerationAfterNativeImportSource {
    private val json=Json { encodeDefaults=true;ignoreUnknownKeys=false }
    private const val id=GenerationAfterNativeImportLineage.generation
    private val root=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/$id")
    private val managed=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/managed-lanes/$id")
    private fun bytes(path:Path,max:Int=4194304)=ReleasePrivateFiles.read(path,max)
    private fun objectAt(path:Path,max:Int=4194304)=json.parseToJsonElement(
        bytes(path,max).decodeToString(throwOnInvalidSequence=true)).jsonObject
    private fun pin(path:Path)=buildJsonObject {
        put("path",path.toString());put("sha256",ReleaseLocks.sha256(bytes(path))) }
    fun issue(controller:String,revision:Boolean=false):ActivationInput {
        require(controller.matches(Regex("[a-f0-9]{64}")) &&
            !Files.exists(GenerationRuntime.BASE.resolve(id),NOFOLLOW_LINKS))
        GenerationAfterNativeImportLineage.verify(GenerationAfterNativeImportLineage.terminal,
            GenerationAfterNativeImportLineage.probe)
        PinnedBackupController.verifyDistribution(Path.of("/mnt/media/p0-v3/runtime-supervision/releases/$controller"),
            controller,"p0-v3-platform")
        val old=objectAt(Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-4d3c1cb287e5/assembly-request.r10-after-preunit.budgeted.json"))
        require(old.getValue("id").jsonPrimitive.content=="q-4d3c1cb287e5" &&
            old.getValue("selections").jsonArray.single().jsonObject.getValue("recipe").jsonPrimitive.content==
                CanonicalSharedYamlGraph.R10_ASSEMBLY_RECIPE &&
            old.getValue("failedPreUnitStagePredecessor").jsonObject.getValue("sha256").jsonPrimitive.content==
                "1ffd7dea5f9b6c5141f19d263e9f817ceaf9180ce39d413579fa06e94bfd0ee3")
        if (revision) {
            require(ReleaseLocks.sha256(bytes(root.resolve("assembly-request.r10-after-native-import.unbudgeted.json")))==
                "dfd2cbd522390b2856c30f569064a3969ac3e4a1ec125387b3c5022cf4538e75" &&
                ReleaseLocks.sha256(bytes(managed.resolve("managed-plan.json")))==
                "9d4c4246731e8cd60be9d60d02ca794da4dbdb02764ca6edf47c065c2daa7946" &&
                ReleaseLocks.sha256(Files.readAllBytes(Path.of(
                    "/home/gerald/p0_v3/.coord/rapid-completion/core-qc3-full-prospective-native-preseal-1174.log")))==
                "1b46357276fcedde6bad790941d8ea811fcaaee4aff5bb4d5922dcaeed2c80d1")
        }
        val plan=objectAt(managed.resolve(if(revision) "managed-plan-v2.json" else "managed-plan.json"),65536)
        val ci=objectAt(root.resolve("forgejo-ci-source.r4-vfs-budget.json"),65536)
        val identity=objectAt(Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/identity/fresh/$id.json"),8192)
        require(plan.getValue("generation").jsonPrimitive.content==id &&
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
        val routes=json.parseToJsonElement(bytes(root.resolve("graph-portal-routes.r10-v2.json")).decodeToString(throwOnInvalidSequence=true))
        val scripts=objectAt(root.resolve("mastodon-rendered-script-binding-v2.json"),8192)
            .getValue("config")
        val planka=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/planka/$id/grant.json")
        val closure=root.resolve("rss-source-artifact-closure.r10-v2.json")
        val request=buildJsonObject {
            for(key in listOf("schemaVersion","purpose","store","selections","diskHeadroomMiB",
                "diskReservationMiB","memoryHeadroomMiB","gatewayDenialProducer",
                "preparedNoStartPredecessor","failedPreUnitStagePredecessor"))put(key,old.getValue(key))
            val lineage=old.getValue("abandonedPreparation").jsonObject
            put("abandonedPreparation",if(revision)buildJsonObject {
                lineage.forEach { (name,value)->put(name,value) }
                put("correctedOwnershipSourceSha256",ReleaseLocks.sha256(Files.readAllBytes(Path.of(
                    "/home/gerald/p0_v3/platform/src/main/kotlin/net/datamancy/platform/SiteOwnership.kt"))))
            } else lineage)
            put("id",id);put("inventorySha256",ReleaseLocks.sha256(bytes(root.resolve("inventory.json"))))
            put("candidateSha256",controller);put("releaseCandidateSha256",controller)
            put("quadletControllerSha256",controller)
            put("uncertainNativeImportPredecessor",json.encodeToJsonElement(GenerationAfterNativeImportLineage.terminal))
            put("isolatedRootlessProbePredecessor",json.encodeToJsonElement(GenerationAfterNativeImportLineage.probe))
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
        val target=root.resolve(if(revision) "assembly-request.r10-after-native-import.unbudgeted-v2.json" else
            "assembly-request.r10-after-native-import.unbudgeted.json")
        require(!Files.exists(target,NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(target,encoded)
        return ActivationInput(target.toString(),ReleaseLocks.sha256(encoded))
    }
    fun budgeted(revision:Boolean=false):ActivationInput {
        val source=objectAt(root.resolve(if(revision) "assembly-request.r10-after-native-import.unbudgeted-v2.json" else
            "assembly-request.r10-after-native-import.unbudgeted.json"))
        require(source.getValue("id").jsonPrimitive.content==id && source["workingBudget"]==null &&
            !Files.exists(GenerationRuntime.BASE.resolve(id),NOFOLLOW_LINKS))
        val evidence=Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/workload/$id/${if(revision) "envelope-v2.json" else "envelope.json"}")
        val envelope=objectAt(evidence)
        require(envelope.getValue("generation").jsonPrimitive.content==id &&
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
        val encoded=(request.toString()+"\n").toByteArray()
        val prospective=GenerationAssembly().plan(json.decodeFromString<AssemblyRequest>(encoded.decodeToString()),
            bytes(root.resolve("inventory.json")))
        GenerationWorkingEnvelopeIssuer.verify(prospective.generation,prospective.specs)
        require(SiteOwnerships.project(prospective.summary.request)==prospective.generation)
        val target=root.resolve(if(revision) "assembly-request.r10-after-native-import.budgeted-v2.json" else
            "assembly-request.r10-after-native-import.budgeted.json")
        require(!Files.exists(target,NOFOLLOW_LINKS))
        ReleasePrivateFiles.save(target,encoded)
        return ActivationInput(target.toString(),ReleaseLocks.sha256(encoded))
    }
}
