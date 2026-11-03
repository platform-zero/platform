package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

@Serializable data class AcquiredImage(val product: String, val source: String, val reference: String,
    val pinnedImage: String, val imageId: String, val repoDigests: List<String>,
    val selectedManifestDigest: String, val architecture: String, val os: String)
@Serializable data class AcquiredInventory(val schemaVersion: Int, val status: String, val images: List<AcquiredImage>)
data class RuntimeCommandResult(val exitCode: Int, val output: String)
internal fun interface RuntimeCommands { fun run(args: List<String>): RuntimeCommandResult }
internal class PrivateCommandTimeout : IllegalStateException("Private Podman command timed out")

/** Fixed-store command transport. Does not run shell strings, publish ports or manage systemd. */
internal class PrivateRootfulCommands(private val timeoutSeconds: Long = 900, val store: RuntimeStore = RuntimeStore.LEGACY) : RuntimeCommands {
    fun scoped(store: RuntimeStore) = PrivateRootfulCommands(timeoutSeconds, store)
    companion object {
        const val ROOT = "/mnt/media/p0-v3/release-runtime/graph"
        const val RUN = "/run/p0-v3-release-runtime/store"
        const val NETWORK = "/mnt/media/p0-v3/release-runtime/network-config"
        val prefix = listOf("sudo", "-n", "podman", "--remote=false", "--root=$ROOT", "--runroot=$RUN", "--network-config-dir=$NETWORK")
    }
    override fun run(args: List<String>): RuntimeCommandResult {
        store.verifyConfiguration()
        val log = Files.createTempFile("p0v3-image-command-", ".log",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        val errors = Files.createTempFile("p0v3-command-errors-", ".log",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
        try {
            val process = ProcessBuilder(store.prefix() + args).redirectOutput(log.toFile()).redirectError(errors.toFile()).apply {
                listOf("CONTAINER_HOST", "CONTAINER_CONNECTION", "DOCKER_HOST", "PODMAN_HOST").forEach(environment()::remove)
                if (store != RuntimeStore.LEGACY) listOf("CONTAINERS_CONF", "CONTAINERS_CONF_OVERRIDE", "CONTAINERS_STORAGE_CONF").forEach(environment()::remove)
            }.start()
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.toHandle().descendants().use { children -> children.toList().asReversed().forEach { it.destroyForcibly() } }
                process.destroyForcibly().waitFor()
                throw PrivateCommandTimeout()
            }
            require(Files.size(log) <= 2_000_000 && Files.size(errors) <= 2_000_000) { "Podman command output too large" }
            return RuntimeCommandResult(process.exitValue(), Files.readString(log))
        } finally { Files.deleteIfExists(log); Files.deleteIfExists(errors) }
    }
}

/** Real content-addressed image staging. This does not claim product compatibility or release acceptance. */
internal class ImageStaging(private val commands: RuntimeCommands) {
    companion object {
        private val json = Json { ignoreUnknownKeys = false }
        fun inventory(path: Path): AcquiredInventory {
            require(Files.isRegularFile(path) && Files.size(path) in 1..2_000_000) { "Missing or oversized image inventory" }
            return json.decodeFromString(Files.readString(path))
        }
        fun real() = ImageStaging(PrivateRootfulCommands())
    }
    fun stage(inventory: AcquiredInventory): List<String> {
        val digest = Regex("sha256:[a-f0-9]{64}")
        require(inventory.schemaVersion == 1 && inventory.images.size in 1..256 &&
            inventory.images.map { it.product }.distinct().size == inventory.images.size) { "Invalid candidate inventory" }
        inventory.images.forEach { image ->
            require(image.product.matches(Regex("[a-z][a-z0-9-]{0,63}")) &&
                image.imageId.matches(Regex("[a-f0-9]{64}")) && digest.matches(image.selectedManifestDigest) &&
                image.pinnedImage.matches(Regex("[a-z0-9.-]+/[a-zA-Z0-9/_.-]+@sha256:[a-f0-9]{64}")) &&
                image.pinnedImage.endsWith("@${image.selectedManifestDigest}") &&
                image.architecture == "amd64" && image.os == "linux") { "Unpinned or unsupported image: ${image.product}" }
        }
        val info = commands.run(listOf("info", "--format", "json"))
        check(info.exitCode == 0) { "Cannot inspect private Podman store" }
        val store = Json.parseToJsonElement(info.output).jsonObject.getValue("store").jsonObject
        require(store.getValue("graphRoot").jsonPrimitive.content == PrivateRootfulCommands.ROOT &&
            store.getValue("runRoot").jsonPrimitive.content == PrivateRootfulCommands.RUN) { "Podman private-store mismatch" }
        return inventory.images.sortedBy { it.product }.map { image ->
            var inspection = commands.run(listOf("image", "inspect", image.pinnedImage))
            if (inspection.exitCode != 0) {
                val pull = commands.run(listOf("pull", "--platform=linux/amd64", image.pinnedImage))
                check(pull.exitCode == 0) { "Digest pull failed: ${image.product}" }
                inspection = commands.run(listOf("image", "inspect", image.pinnedImage))
            }
            check(inspection.exitCode == 0) { "Image not present after acquisition: ${image.product}" }
            val actual = Json.parseToJsonElement(inspection.output).jsonArray.single().jsonObject
            require(actual.getValue("Id").jsonPrimitive.content.removePrefix("sha256:") == image.imageId &&
                actual.getValue("Digest").jsonPrimitive.content == image.selectedManifestDigest &&
                actual.getValue("Architecture").jsonPrimitive.content == image.architecture &&
                actual.getValue("Os").jsonPrimitive.content == image.os) { "Image content identity mismatch: ${image.product}" }
            image.product
        }
    }
}
