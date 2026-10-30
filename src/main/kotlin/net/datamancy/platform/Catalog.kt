package net.datamancy.platform

import java.io.InputStream
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class ServiceModule(val id: String, val services: List<String>)

@Serializable
data class ServiceCatalog(val schemaVersion: Int, val modules: List<ServiceModule>) {
    val serviceIds: List<String> get() = modules.flatMap(ServiceModule::services)

    fun validate() {
        require(schemaVersion == 1) { "Unsupported catalog schema: $schemaVersion" }
        require(modules.isNotEmpty()) { "Catalog has no modules" }
        val idPattern = Regex("[a-z0-9]+(?:-[a-z0-9]+)*")
        require(modules.all { idPattern.matches(it.id) && it.services.isNotEmpty() }) {
            "Each module needs a valid ID and at least one service"
        }
        require(modules.map(ServiceModule::id).distinct().size == modules.size) {
            "Duplicate module ID"
        }
        require(serviceIds.all(idPattern::matches)) { "Invalid service ID" }
        require(serviceIds.distinct().size == serviceIds.size) { "Duplicate service ID" }
        require(serviceIds.size == 89) {
            "The agreed inventory has 89 service IDs; found ${serviceIds.size}"
        }
    }

    companion object {
        fun from(input: InputStream): ServiceCatalog = input.use { stream ->
            Json { ignoreUnknownKeys = false }.decodeFromString<ServiceCatalog>(
                stream.bufferedReader().readText()
            ).also(ServiceCatalog::validate)
        }

        fun bundled(): ServiceCatalog = from(
            checkNotNull(ServiceCatalog::class.java.getResourceAsStream("/services.json")) {
                "Missing bundled services.json"
            }
        )
    }
}
