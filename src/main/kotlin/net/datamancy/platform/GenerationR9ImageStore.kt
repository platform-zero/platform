package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

/** Only artifact import in the canonical store. No container, pull, direct
 * application startup, tag substitution or retroactive original pull ACK.
 * Each load has a distinct immutable intent and original result/readback.
 */
@Serializable internal data class R9ImageImportIntent(val generation: String,
    val inventorySha256: String, val product: String, val imageId: String,
    val manifestDigest: String, val archiveSha256: String, val sourceResultSha256: String)
@Serializable internal data class R9ImageImportResult(val intentSha256: String,
    val imageId: String, val manifestDigest: String, val nativeStore: String,
    val originalLoadAcknowledged: Boolean)
internal object GenerationR9ImageStore {
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val anchor = Path.of("/mnt/media/p0-v3/release-bootstrap-anchors/assembly")
    private val archives = Path.of("/mnt/media/p0-v3/image-acquisition-receipts/full-private-r9-bound-oci-r1")
    private val seven = setOf("huly-caddy-adapted","huly-elasticsearch-adapted","huly-kvs-adapted",
        "keykeeper-adapted","mail-bootstrap-adapted","mailserver-adapted","keycloak-auth-gateway")
    private val store = RuntimeStore.CANONICAL_V2
    private val commands = PrivateRootfulCommands(900, store)
    private fun result(args: List<String>, max: Int = 131072): String {
        val reply=commands.run(args)
        require(reply.exitCode == 0 && reply.output.toByteArray().size in 1..max) {
            "Canonical image-store operation has no original ACK; preserve original intent"
        }
        return reply.output
    }
    private fun inspect(image: AcquiredImage): Boolean {
        val reply=commands.run(listOf("image","inspect",image.pinnedImage))
        if (reply.exitCode != 0) {
            require(reply.output.toByteArray().size <= 8192)
            return false
        }
        require(reply.output.toByteArray().size in 1..131072)
        val found=json.parseToJsonElement(reply.output).jsonArray.single().jsonObject
        require(found.getValue("Id").jsonPrimitive.content.removePrefix("sha256:")==image.imageId &&
            found.getValue("Digest").jsonPrimitive.content==image.selectedManifestDigest &&
            found.getValue("Os").jsonPrimitive.content=="linux" &&
            found.getValue("Architecture").jsonPrimitive.content=="amd64") {
            "Native canonical image content differs from selected immutable inventory"
        }
        return true
    }
    private fun preflight(maximumArchiveMiB: Long) {
        store.verifyConfiguration()
        val info=json.parseToJsonElement(result(listOf("info","--format","json"),2097152)).jsonObject
        val paths=info.getValue("store").jsonObject
        val security=info.getValue("host").jsonObject.getValue("security").jsonObject
        require(paths.getValue("graphRoot").jsonPrimitive.content==store.graph &&
            paths.getValue("runRoot").jsonPrimitive.content==store.run &&
            security.getValue("rootless").jsonPrimitive.content=="false" &&
            security.getValue("apparmorEnabled").jsonPrimitive.content=="true" &&
            security.getValue("seccompEnabled").jsonPrimitive.content=="true")
        val memory=Files.readAllLines(Path.of("/proc/meminfo")).single { it.startsWith("MemAvailable:") }
            .trim().split(Regex("\\s+"))[1].toLong()/1024
        require(memory >= 16384+2048 &&
            Files.getFileStore(anchor).usableSpace/1048576 >= 10240+4096+3*maximumArchiveMiB) {
            "Canonical image import would violate protected memory/disk floor"
        }
        RuntimeLockBudget.requireAvailable(RuntimeLockBudget.available(commands,store),workers=2)
    }
    /** Current read-only pre-stage admission; the earlier 66/66 receipt is
     * lineage, never substituted for an unchanged effective image store. */
    fun verifySelected(generation: String, spec: PrivateDeploymentSpec): ActivationInput {
        require(generation.matches(Regex("q-[a-f0-9]{12}")) && spec.name == "$generation-v2" &&
            spec.fragmentBinding?.phase == FragmentPhase.INSTALL.name)
        val dir=anchor.resolve(generation)
        val raw=ReleasePrivateFiles.read(dir.resolve("inventory.json"),2097152)
        val inventory=json.decodeFromString<AcquiredInventory>(raw.decodeToString(throwOnInvalidSequence=true))
        require(inventory.images.size == 66 && inventory.images.map { it.product }.distinct().size==66 &&
            spec.processes.all { process -> inventory.images.any {
                it.imageId == process.imageId && it.pinnedImage == process.image
            } })
        val receiptPath=dir.resolve("whole-image-store.readback.json")
        val receipt=ReleasePrivateFiles.read(receiptPath,8192)
        val saved=json.parseToJsonElement(receipt.decodeToString(throwOnInvalidSequence=true)).jsonObject
        require(saved.getValue("generation").jsonPrimitive.content==generation &&
            saved.getValue("inventorySha256").jsonPrimitive.content==ReleaseLocks.sha256(raw) &&
            saved.getValue("nativeImageCount").jsonPrimitive.int==66 &&
            saved.getValue("originalArchiveLoadResults").jsonPrimitive.int in 0..seven.size &&
            !saved.getValue("applicationStarted").jsonPrimitive.boolean &&
            !saved.getValue("qualificationEvidence").jsonPrimitive.boolean)
        var actualLoads=0
        for (product in seven) {
            val image=inventory.images.single { it.product==product }
            val base=dir.resolve("$product.native-image-load")
            val intentPath=base.resolveSibling(base.fileName.toString()+".intent.json")
            val resultPath=base.resolveSibling(base.fileName.toString()+".result.json")
            val attempted=Files.exists(intentPath,NOFOLLOW_LINKS)
            require(attempted==Files.exists(resultPath,NOFOLLOW_LINKS)) {
                "Unacknowledged image load cannot become a native store readback"
            }
            if (!attempted) continue // Already-present immutable content is observed, NOT a fabricated load ACK.
            actualLoads++
            val intentBytes=ReleasePrivateFiles.read(intentPath,8192)
            val intent=json.decodeFromString<R9ImageImportIntent>(intentBytes.decodeToString(throwOnInvalidSequence=true))
            val loaded=json.decodeFromString<R9ImageImportResult>(ReleasePrivateFiles.read(resultPath,8192)
                .decodeToString(throwOnInvalidSequence=true))
            require(intent.generation==generation && intent.inventorySha256==ReleaseLocks.sha256(raw) &&
                intent.product==product && intent.imageId==image.imageId &&
                intent.manifestDigest==image.selectedManifestDigest &&
                loaded.intentSha256==ReleaseLocks.sha256(intentBytes) &&
                loaded.imageId==image.imageId && loaded.manifestDigest==image.selectedManifestDigest &&
                loaded.nativeStore==store.graph && loaded.originalLoadAcknowledged)
        }
        require(actualLoads==saved.getValue("originalArchiveLoadResults").jsonPrimitive.int) {
            "Fresh-generation image receipt misstates original archive loads"
        }
        preflight(0)
        require(inventory.images.all(::inspect)) { "Selected native image store changed after original import" }
        return ActivationInput(receiptPath.toString(),ReleaseLocks.sha256(receipt))
    }
    fun importAndVerify(generation: String): Int {
        require(generation.matches(Regex("q-[a-f0-9]{12}")))
        val dir=anchor.resolve(generation)
        ReleasePrivateFiles.directory(dir)
        return ReleasePrivateFiles.locked(dir) {
            val raw=ReleasePrivateFiles.read(dir.resolve("inventory.json"),2097152)
            val inventory=json.decodeFromString<AcquiredInventory>(raw.decodeToString(throwOnInvalidSequence=true))
            require(inventory.images.size==66 && inventory.images.map { it.product }.distinct().size==66 &&
                inventory.status=="r9-complete-private-source-inventory-native-image-store-unverified")
            val requested=inventory.images.associateBy { it.product }
            require(requested.keys.containsAll(seven))
            preflight(1024)
            val missing=inventory.images.filterNot(::inspect)
            require(missing.all { it.product in seven }) { "Unknown missing whole-family image: no generic pull" }
            // No partial app cohort: artifact import is source preparation only.
            for (image in missing) {
                val product=image.product
                val archive=archives.resolve("$product.oci.tar")
                val proofPath=archives.resolve("$product.index-bind.result.json")
                val proof=json.parseToJsonElement(ReleasePrivateFiles.read(proofPath,8192)
                    .decodeToString(throwOnInvalidSequence=true)).jsonObject
                val archiveHash=RecoveryCapsule.fileHash(archive)
                val sourceHash=ReleaseLocks.sha256(ReleasePrivateFiles.read(proofPath,8192))
                require(Files.isRegularFile(archive,NOFOLLOW_LINKS) && !Files.isSymbolicLink(archive) &&
                    proof.getValue("archiveSha256").jsonPrimitive.content==archiveHash &&
                    proof.getValue("imageId").jsonPrimitive.content==image.imageId &&
                    proof.getValue("ociManifestDigest").jsonPrimitive.content==image.selectedManifestDigest &&
                    !proof.getValue("applicationStarted").jsonPrimitive.boolean &&
                    !proof.getValue("nativeStoreImported").jsonPrimitive.boolean)
                preflight((Files.size(archive)+1048575)/1048576)
                val intent=R9ImageImportIntent(generation,ReleaseLocks.sha256(raw),product,image.imageId,
                    image.selectedManifestDigest,archiveHash,sourceHash)
                val base=dir.resolve("$product.native-image-load")
                require(!Files.exists(base.resolveSibling(base.fileName.toString()+".intent.json"),NOFOLLOW_LINKS) &&
                    !Files.exists(base.resolveSibling(base.fileName.toString()+".result.json"),NOFOLLOW_LINKS)) {
                    "Original OCI import attempted; missing ACK must not be replayed"
                }
                val bytes=json.encodeToString(intent).toByteArray()
                ReleasePrivateFiles.save(base.resolveSibling(base.fileName.toString()+".intent.json"),bytes)
                result(listOf("load","--input",archive.toString()),8192)
                require(inspect(image)) { "OCI load returned without exact native image identity; keep original intent" }
                ReleasePrivateFiles.save(base.resolveSibling(base.fileName.toString()+".result.json"),
                    json.encodeToString(R9ImageImportResult(ReleaseLocks.sha256(bytes),image.imageId,
                        image.selectedManifestDigest,store.graph,true)).toByteArray())
            }
            preflight(0)
            require(inventory.images.all(::inspect)) { "Whole-family native image store still incomplete" }
            val audit=dir.resolve("whole-image-store.readback.json")
            require(!Files.exists(audit,NOFOLLOW_LINKS)) { "Previously sealed native image readback cannot be replaced" }
            ReleasePrivateFiles.save(audit,buildJsonObject {
                put("schemaVersion",1);put("generation",generation);put("inventorySha256",ReleaseLocks.sha256(raw))
                put("canonicalStore",store.graph);put("nativeImageCount",inventory.images.size)
                put("originalArchiveLoadResults",missing.size);put("applicationStarted",false)
                put("qualificationEvidence",false)
            }.toString().toByteArray())
            missing.size
        }
    }
}
