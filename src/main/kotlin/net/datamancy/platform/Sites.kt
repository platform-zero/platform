package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Explicit workloads only. Inventory is not an installation specification. */
@Serializable
data class Workload(val id: String, val image: String)

@Serializable
data class Site(val id: String, val workloads: List<Workload>)

@Serializable
data class Sites(val schemaVersion: Int, val sites: List<Site>) {
    fun select(id: String): Site {
        require(SLUG.matches(id)) { "Invalid site ID" }
        return sites.singleOrNull { it.id == id } ?: throw IllegalArgumentException("Unknown site: $id")
    }

    fun validate() {
        require(schemaVersion == 1) { "Unsupported sites schema: $schemaVersion" }
        require(sites.isNotEmpty() && sites.size <= 32) { "Expected 1..32 sites" }
        require(sites.map { it.id }.distinct().size == sites.size) { "Duplicate site ID" }
        val inventory = ServiceCatalog.bundled().serviceIds.toSet()
        sites.forEach { site ->
            require(SLUG.matches(site.id)) { "Invalid site ID" }
            require(site.workloads.isNotEmpty() && site.workloads.size <= 64) { "Expected 1..64 explicit workloads" }
            require(site.workloads.map { it.id }.distinct().size == site.workloads.size) { "Duplicate workload ID" }
            site.workloads.forEach { workload ->
                require(SLUG.matches(workload.id)) { "Invalid workload ID" }
                require(workload.id !in inventory) { "Inventory ID is not an installable workload: ${workload.id}" }
                require(IMAGE.matches(workload.image)) { "Image must be a digest-pinned repository reference" }
            }
        }
    }

    companion object {
        private val SLUG = Regex("[a-z][a-z0-9-]{0,29}")
        // No tags, shell metacharacters, control characters, or mutable image references.
        private val IMAGE = Regex("[a-z0-9]+(?:[.-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+@sha256:[a-f0-9]{64}")
        private val json = Json { ignoreUnknownKeys = false }

        fun from(path: Path): Sites {
            require(Files.isRegularFile(path)) { "Not a sites file" }
            require(Files.size(path) <= 131072) { "Sites file too large" }
            return json.decodeFromString<Sites>(Files.readString(path)).also(Sites::validate)
        }
    }
}

@Serializable
data class RenderedFile(val name: String, val content: String)

@Serializable
data class RenderPlan(val siteId: String, val files: List<RenderedFile>) {
    companion object {
        fun forSite(site: Site): RenderPlan = RenderPlan(site.id, site.workloads.sortedBy { it.id }.map { workload ->
            val name = "p0v3-${site.id}-${workload.id}"
            RenderedFile("$name.container", """[Unit]
Description=Isolated v3 workload $name

[Container]
Image=${workload.image}
ContainerName=$name
Network=none
ReadOnly=true

[Install]
WantedBy=default.target
""")
        })
    }
}
