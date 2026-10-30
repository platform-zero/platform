package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.system.exitProcess

fun main(args: Array<String>) {
    val status = runCommand(args, ::println, System.err::println)
    if (status != 0) exitProcess(status)
}

/** Testable CLI boundary: only main can terminate the process. */
internal fun runCommand(args: Array<String>, out: (String) -> Unit, err: (String) -> Unit): Int {
    return try {
    when (args.toList()) {
        listOf("catalog", "validate") -> {
            val catalog = ServiceCatalog.bundled()
            out("Inventory valid: ${catalog.serviceIds.size} IDs in ${catalog.modules.size} known modules; no installation or acceptance claimed")
        }
        listOf("catalog", "list") ->
            ServiceCatalog.bundled().modules.forEach { module ->
                module.services.forEach { service -> out("${module.id}\t$service\tinventory-only") }
            }
        else -> when {
            args.size == 4 && args[0] == "site" && args[1] == "validate" -> {
                val sites = Sites.from(Path.of(args[2]))
                sites.select(args[3])
                out("Explicit site ${args[3]} valid; no installation or acceptance claimed")
            }
            args.size == 4 && args[0] == "plan" && args[1] == "render" -> {
                val site = Sites.from(Path.of(args[2])).select(args[3])
                out(Json.encodeToString(RenderPlan.forSite(site)))
            }
            args.size == 5 && args[0] == "lane" && args[1] == "plan" -> {
                val request = LaneAccountRequest.from(Path.of(args[2]))
                val occupied = LaneAccounts.occupiedFrom(Path.of(args[4]))
                out(Json.encodeToString(LaneAccounts.plan(request, args[3], occupied)))
            }
            args.size == 5 && args[0] == "stage" && args[1] == "offline" -> {
                IsolatedStage.stage(Sites.from(Path.of(args[2])), args[3], Path.of(args[4]))
                out("Offline staged ${args[3]}; Podman/systemd not invoked")
            }
            args.size == 4 && args[0] == "stage" && args[1] == "restore" -> {
                IsolatedStage.restore(Path.of(args[2]), args[3])
                out("Offline workspace restored; no live services changed")
            }
            else -> {
                err("Usage: platform catalog validate|list | site validate <sites.json> <site> | plan render <sites.json> <site> | lane plan <request.json> <trusted-issuer> <occupied-usernames.json> | stage offline <sites.json> <site> <temp-workspace> | stage restore <temp-workspace> <site>")
                return 2
            }
        }
    }
    0
} catch (e: Exception) {
    err("Rejected: ${e.message}")
    1
    }
}
