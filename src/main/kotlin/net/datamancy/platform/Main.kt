package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    try {
        val catalog = ServiceCatalog.bundled()
        when (args.toList()) {
            listOf("catalog", "validate") ->
                println("Inventory valid: ${catalog.serviceIds.size} IDs in ${catalog.modules.size} known modules; no installation or acceptance claimed")
            listOf("catalog", "list") ->
                catalog.modules.forEach { module ->
                    module.services.forEach { service -> println("${module.id}\t$service\tinventory-only") }
                }
            else -> when {
                args.size == 4 && args[0] == "site" && args[1] == "validate" -> {
                    val sites = Sites.from(Path.of(args[2]))
                    sites.select(args[3])
                    println("Explicit site ${args[3]} valid; no installation or acceptance claimed")
                }
                args.size == 4 && args[0] == "plan" && args[1] == "render" -> {
                    val site = Sites.from(Path.of(args[2])).select(args[3])
                    println(Json.encodeToString(RenderPlan.forSite(site)))
                }
                args.size == 5 && args[0] == "stage" && args[1] == "offline" -> {
                    IsolatedStage.stage(Sites.from(Path.of(args[2])), args[3], Path.of(args[4]))
                    println("Offline staged ${args[3]}; Podman/systemd not invoked")
                }
                args.size == 4 && args[0] == "stage" && args[1] == "restore" -> {
                    IsolatedStage.restore(Path.of(args[2]), args[3])
                    println("Offline workspace restored; no live services changed")
                }
                else -> {
                    System.err.println("Usage: platform catalog validate|list | site validate <sites.json> <site> | plan render <sites.json> <site> | stage offline <sites.json> <site> <temp-workspace> | stage restore <temp-workspace> <site>")
                    exitProcess(2)
                }
            }
        }
    } catch (e: Exception) {
        System.err.println("Rejected: ${e.message}")
        exitProcess(1)
    }
}
