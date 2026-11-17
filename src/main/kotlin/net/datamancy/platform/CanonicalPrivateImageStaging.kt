package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Serializable internal data class CanonicalImageStageObservation(val schemaVersion: Int = 1,
    val product: String, val pinnedImage: String, val imageId: String,
    val inventorySha256: String, val runtimeStore: RuntimeStore = RuntimeStore.CANONICAL_V2,
    val originalPullAcknowledged: Boolean = false, val alreadyPresent: Boolean = false,
    val privateOnly: Boolean = true, val qualificationEvidence: Boolean = false)

/** Serialized, digest-pinned artifact acquisition, NOT application deployment.
 * A failed/unknown pull remains a one-use intent; neither an existing image
 * nor a later inspect may be substituted for its absent original ACK.
 */
internal class CanonicalPrivateImageStaging(private val root: Path = ROOT,
    private val commands: RuntimeCommands = PrivateRootfulCommands(900, RuntimeStore.CANONICAL_V2),
    private val testAdmission: (() -> Unit)? = null) {
    companion object { val ROOT: Path = Path.of(
        "/mnt/media/p0-v3/image-acquisition-receipts/canonical-private-assembled-stack-images") }
    private val json = Json { encodeDefaults = true; ignoreUnknownKeys = false }
    private val digest = Regex("[a-f0-9]{64}")
    private fun memoryMiB(): Long {
        val mem = Files.readAllLines(Path.of("/proc/meminfo")).single { it.startsWith("MemAvailable:") }
            .trim().split(Regex("\\s+"))
        require(mem.size == 3 && mem[2] == "kB")
        return mem[1].toLong() / 1024
    }
    private fun capacityAdmission() {
        testAdmission?.let { it(); return }
        require(memoryMiB() >= 16384L + 1024L &&
            Files.getFileStore(root).usableSpace / 1048576 >= 10240L + 4096L) {
            "Image pull cannot preserve host headroom and staging allowance"
        }
        RuntimeLockBudget.requireAvailable(RuntimeLockBudget.available(
            PrivateRootfulCommands(45, RuntimeStore.CANONICAL_V2), RuntimeStore.CANONICAL_V2), workers = 2)
    }
    private fun native(args: List<String>, max: Int = 2_000_000): String {
        val observed = commands.run(args)
        require(observed.exitCode == 0 && observed.output.toByteArray().size in 1..max) {
            "Canonical store or pinned image inspection failed"
        }
        return observed.output
    }
    private fun image(inventoryBytes: ByteArray, product: String): Pair<AcquiredImage, String> {
        require(product.matches(Regex("[a-z][a-z0-9-]{0,63}")) && inventoryBytes.size in 1..2000000)
        val inventory = json.decodeFromString<AcquiredInventory>(inventoryBytes.decodeToString(throwOnInvalidSequence = true))
        require(inventory.schemaVersion == 1 && inventory.status == "downloaded-candidates-not-a-reviewed-compatible-release" &&
            inventory.images.size in 1..256 && inventory.images.map { it.product }.distinct().size == inventory.images.size)
        val chosen = inventory.images.single { it.product == product }
        require(chosen.imageId.matches(digest) && chosen.selectedManifestDigest.matches(Regex("sha256:[a-f0-9]{64}")) &&
            chosen.pinnedImage.endsWith("@${chosen.selectedManifestDigest}") &&
            chosen.pinnedImage.matches(Regex("[a-z0-9./_-]+@sha256:[a-f0-9]{64}")) &&
            chosen.os == "linux" && chosen.architecture == "amd64")
        return chosen to ReleaseLocks.sha256(inventoryBytes)
    }
    private fun storePreflight() {
        val observed = json.parseToJsonElement(native(listOf("info", "--format", "json"))).jsonObject
        val store = observed.getValue("store").jsonObject
        val security = observed.getValue("host").jsonObject.getValue("security").jsonObject
        require(store.getValue("graphRoot").jsonPrimitive.content == RuntimeStore.CANONICAL_V2.graph &&
            store.getValue("runRoot").jsonPrimitive.content == RuntimeStore.CANONICAL_V2.run &&
            security.getValue("rootless").jsonPrimitive.content == "false" &&
            security.getValue("apparmorEnabled").jsonPrimitive.content == "true" &&
            security.getValue("seccompEnabled").jsonPrimitive.content == "true") {
            "Canonical artifact store or confinement changed"
        }
    }
    private fun inspect(image: AcquiredImage): CanonicalImageStageObservation? {
        val observed = commands.run(listOf("image", "inspect", image.pinnedImage))
        if (observed.exitCode != 0) {
            require(observed.output.toByteArray().size <= 8192)
            return null
        }
        require(observed.output.toByteArray().size in 1..65536)
        val actual = json.parseToJsonElement(observed.output).jsonArray.single().jsonObject
        require(actual.getValue("Id").jsonPrimitive.content.removePrefix("sha256:") == image.imageId &&
            actual.getValue("Digest").jsonPrimitive.content == image.selectedManifestDigest &&
            actual.getValue("Architecture").jsonPrimitive.content == image.architecture &&
            actual.getValue("Os").jsonPrimitive.content == image.os) {
            "Pinned image exists but native content identity differs; no pull"
        }
        return CanonicalImageStageObservation(product = image.product,
            pinnedImage = image.pinnedImage, imageId = image.imageId, inventorySha256 = "0".repeat(64), alreadyPresent = true)
    }
    fun audit(inventoryBytes: ByteArray, product: String): CanonicalImageStageObservation? {
        val (image, inventorySha) = image(inventoryBytes, product)
        require(root.isAbsolute && root.normalize() == root &&
            (root == ROOT || commands !is PrivateRootfulCommands))
        storePreflight(); capacityAdmission()
        return inspect(image)?.copy(inventorySha256 = inventorySha)
    }
    /** All-or-nothing, read-only native re-audit. It can never fill a missing
     * receipt, resubmit a pull or turn a retained uncertain intent into an ACK.
     */
    fun auditAll(inventoryBytes: ByteArray, order: List<String>): List<CanonicalImageStageObservation> {
        val inventory = json.decodeFromString<AcquiredInventory>(inventoryBytes.decodeToString(throwOnInvalidSequence = true))
        require(inventory.schemaVersion == 1 && inventory.status == "downloaded-candidates-not-a-reviewed-compatible-release" &&
            order.size == inventory.images.size && order.size in 1..256 && order.distinct().size == order.size &&
            order.toSet() == inventory.images.map { it.product }.toSet() &&
            root.isAbsolute && root.normalize() == root &&
            (root == ROOT || commands !is PrivateRootfulCommands) && Files.isDirectory(root, NOFOLLOW_LINKS))
        ReleasePrivateFiles.directory(root)
        // Reject incomplete or conflicting historical effects before any native audit.
        val saved = order.map { product ->
            val (image, inventorySha) = image(inventoryBytes, product)
            val intent = root.resolve("$product.pull.intent.json")
            val result = root.resolve("$product.pull.result.json")
            val present = root.resolve("$product.already-present.observation.json")
            val original = listOf(result, present).filter { Files.exists(it, NOFOLLOW_LINKS) }
            require(original.size == 1 && (Files.exists(intent, NOFOLLOW_LINKS) == (original.single() == result))) {
                "Missing, conflicting or uncertain original image staging outcome"
            }
            if (original.single() == result) {
                val originalIntent = json.decodeFromString<CanonicalImageStageObservation>(
                    ReleasePrivateFiles.read(intent, 8192).decodeToString())
                require(originalIntent == CanonicalImageStageObservation(product = product,
                    pinnedImage = image.pinnedImage, imageId = image.imageId, inventorySha256 = inventorySha)) {
                    "Original pinned image pull intent changed"
                }
            }
            json.decodeFromString<CanonicalImageStageObservation>(
                ReleasePrivateFiles.read(original.single(), 8192).decodeToString()).also {
                require(it.product == product && it.imageId == image.imageId &&
                    it.pinnedImage == image.pinnedImage && it.inventorySha256 == inventorySha &&
                    it.runtimeStore == RuntimeStore.CANONICAL_V2 && it.privateOnly && !it.qualificationEvidence &&
                    (it.originalPullAcknowledged == (original.single() == result)) &&
                    (it.alreadyPresent == (original.single() == present))) {
                    "Native image staging receipt differs from pinned inventory"
                }
            }
        }
        return order.zip(saved).map { (product, original) ->
            val live = requireNotNull(audit(inventoryBytes, product)) { "Previously acknowledged image missing" }
            require(live.imageId == original.imageId && live.pinnedImage == original.pinnedImage &&
                live.inventorySha256 == original.inventorySha256)
            original
        }
    }
    /** One serialized assembled-artifact closure. Completed original ACKs are
     * read and natively re-audited, never resubmitted. A dangling pull intent
     * stops the entire dependency order before touching the next image.
     */
    fun stageAll(inventoryBytes: ByteArray, order: List<String>): List<CanonicalImageStageObservation> {
        val inventory = json.decodeFromString<AcquiredInventory>(inventoryBytes.decodeToString(throwOnInvalidSequence = true))
        require(inventory.schemaVersion == 1 && inventory.status == "downloaded-candidates-not-a-reviewed-compatible-release" &&
            order.size == inventory.images.size && order.size in 1..256 && order.distinct().size == order.size &&
            order.toSet() == inventory.images.map { it.product }.toSet()) {
            "Assembled candidate image order must cover every pinned artifact once"
        }
        require(root.isAbsolute && root.normalize() == root &&
            (root == ROOT || commands !is PrivateRootfulCommands) && Files.isDirectory(root, NOFOLLOW_LINKS))
        ReleasePrivateFiles.directory(root)
        return order.map { product ->
            val (image, inventorySha) = image(inventoryBytes, product)
            val pullIntent = root.resolve("$product.pull.intent.json")
            val pullResult = root.resolve("$product.pull.result.json")
            val existing = root.resolve("$product.already-present.observation.json")
            require(!Files.exists(pullIntent, NOFOLLOW_LINKS) || Files.exists(pullResult, NOFOLLOW_LINKS)) {
                "Uncertain previous pinned image pull; retain intent and stop assembly"
            }
            val completed = listOf(pullResult, existing).filter { Files.exists(it, NOFOLLOW_LINKS) }
            require(completed.size <= 1 && (completed.isEmpty() ||
                (Files.exists(pullIntent, NOFOLLOW_LINKS) == (completed.single() == pullResult)))) {
                "Conflicting original image staging evidence"
            }
            if (completed.isEmpty()) stage(inventoryBytes, product) else {
                val saved = json.decodeFromString<CanonicalImageStageObservation>(
                    ReleasePrivateFiles.read(completed.single(), 8192).decodeToString())
                require(saved.product == product && saved.imageId == image.imageId &&
                    saved.pinnedImage == image.pinnedImage && saved.inventorySha256 == inventorySha &&
                    saved.privateOnly && !saved.qualificationEvidence &&
                    (saved.originalPullAcknowledged xor saved.alreadyPresent)) {
                    "Original image staging receipt changed"
                }
                val live = requireNotNull(audit(inventoryBytes, product)) { "Previously acknowledged image missing" }
                require(live.imageId == saved.imageId && live.pinnedImage == saved.pinnedImage &&
                    live.inventorySha256 == inventorySha)
                saved
            }
        }
    }
    fun stage(inventoryBytes: ByteArray, product: String): CanonicalImageStageObservation {
        val (image, inventorySha) = image(inventoryBytes, product)
        require(root.isAbsolute && root.normalize() == root &&
            (root == ROOT || commands !is PrivateRootfulCommands) && Files.isDirectory(root, NOFOLLOW_LINKS))
        ReleasePrivateFiles.directory(root)
        return ReleasePrivateFiles.locked(root) {
            storePreflight(); capacityAdmission()
            val observed = inspect(image)
            require(!Files.exists(root.resolve("$product.pull.intent.json"), NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve("$product.pull.result.json"), NOFOLLOW_LINKS) &&
                !Files.exists(root.resolve("$product.already-present.observation.json"), NOFOLLOW_LINKS)) {
                "Prior artifact staging record exists; never replay uncertain pull"
            }
            if (observed != null) {
                observed.copy(inventorySha256 = inventorySha).also {
                    ReleasePrivateFiles.save(root.resolve("$product.already-present.observation.json"),
                        json.encodeToString(it).toByteArray())
                }
            } else {
                val intent = CanonicalImageStageObservation(product = product, pinnedImage = image.pinnedImage,
                    imageId = image.imageId, inventorySha256 = inventorySha)
                ReleasePrivateFiles.save(root.resolve("$product.pull.intent.json"), json.encodeToString(intent).toByteArray())
                val pull = commands.run(listOf("pull", "--quiet", "--platform=linux/amd64", image.pinnedImage))
                require(pull.exitCode == 0 && pull.output.toByteArray().size <= 4096) {
                    "Original pinned image pull lacks a native ACK; retain intent, inspect without replay"
                }
                requireNotNull(inspect(image)) { "Original pull ACK has no matching digest readback" }
                capacityAdmission()
                intent.copy(originalPullAcknowledged = true).also {
                    ReleasePrivateFiles.save(root.resolve("$product.pull.result.json"), json.encodeToString(it).toByteArray())
                }
            }
        }
    }
}
