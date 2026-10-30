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
            args.size == 3 && args[0] == "module" && args[1] == "sandbox-backup" &&
                args[2] in setOf("due", "two") -> {
                val count = if (args[2] == "due") {
                    if (SandboxBackupSchedule.real().runDue()) 1 else 0
                } else SandboxBackupSchedule.real(periodSeconds = 3).runBounded(maxRuns = 2)
                out("Bounded two-module sandbox backup completed $count slot(s); no full-stack acceptance")
            }
            args.size in 3..4 && args[0] == "module" && args[1] == "postgres" -> {
                val sandbox = PostgresSandbox.real()
                when (args[2]) {
                    "prepare" -> { require(args.size == 3); sandbox.prepare() }
                    "install" -> { require(args.size == 3); sandbox.install() }
                    "stop" -> { require(args.size == 3); sandbox.stop() }
                    "remove" -> { require(args.size == 3); sandbox.remove() }
                    "write" -> { require(args.size == 3); sandbox.writeFixture() }
                    "query" -> { require(args.size == 3); out(sandbox.query()) }
                    "backup" -> { require(args.size == 4); sandbox.backup(args[3]) }
                    "restore" -> { require(args.size == 4); sandbox.restore(args[3]) }
                    "restored-write" -> { require(args.size == 4); sandbox.writeRestored(args[3]) }
                    "restored-query" -> { require(args.size == 4); out(sandbox.query(args[3])) }
                    "restore-remove" -> { require(args.size == 4); sandbox.removeRestore(args[3]) }
                    else -> throw IllegalArgumentException("Unknown postgres sandbox action")
                }
                out("Isolated postgres sandbox ${args[2]} completed; no other inventory module accepted")
            }
            args.size in 3..4 && args[0] == "module" && args[1] == "ntfy" -> {
                val sandbox = NtfySandbox.real()
                when (args[2]) {
                    "prepare" -> { require(args.size == 3); sandbox.prepare() }
                    "install" -> { require(args.size == 3); sandbox.install() }
                    "stop" -> { require(args.size == 3); sandbox.stop() }
                    "remove" -> { require(args.size == 3); sandbox.remove() }
                    "snapshot" -> { require(args.size == 4); sandbox.snapshot(args[3]) }
                    "restore" -> { require(args.size == 4); sandbox.restore(args[3]) }
                    "restore-remove" -> { require(args.size == 4); sandbox.removeRestore(args[3]) }
                    else -> throw IllegalArgumentException("Unknown ntfy sandbox action")
                }
                out("Isolated ntfy sandbox ${args[2]} completed; no other inventory module accepted")
            }
            args.size in 4..5 && args[0] == "probe" && args[1] in setOf("prepare", "install", "stop", "remove", "snapshot", "restore") -> {
                val selection = ProbeSelection(args[2], args[3])
                val lifecycle = ProbeLifecycle.real()
                when (args[1]) {
                    "prepare" -> { require(args.size == 4); lifecycle.prepare(selection) }
                    "install" -> { require(args.size == 4); lifecycle.install(selection) }
                    "stop" -> { require(args.size == 4); lifecycle.stop(selection) }
                    "remove" -> { require(args.size == 4); lifecycle.remove(selection) }
                    "snapshot" -> { require(args.size == 5); lifecycle.snapshot(selection, args[4]) }
                    "restore" -> { require(args.size == 5); lifecycle.restoreIsolated(selection, args[4]) }
                }
                out("Restricted probe ${args[1]} completed; no catalog module or production service accepted")
            }
            args.size == 6 && args[0] == "contract" && args[1] == "plan" -> {
                val site = DeploymentSite.hostLocal(Path.of(args[2]))
                val boundary = DeploymentBoundary(Path.of(args[4]), Path.of(args[5]), DeploymentSite.approvedHosts(Path.of(args[3])))
                out(Json.encodeToString(DeploymentContracts.plan(site, boundary)))
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
                err("Usage: platform module sandbox-backup due|two | module postgres prepare|install|stop|remove|write|query|backup|restore|restored-write|restored-query|restore-remove [backup-id] | module ntfy prepare|install|stop|remove|snapshot|restore|restore-remove [snapshot-id] | probe prepare|install|stop|remove <site> <local-sha256-image-id> | probe snapshot|restore <site> <local-sha256-image-id> <snapshot-id> | catalog validate|list | site validate <sites.json> <site> | plan render <sites.json> <site> | contract plan <site.json> <approved-hosts.json> <data-root> <backup-root> | lane plan <request.json> <trusted-issuer> <occupied-usernames.json> | stage offline <sites.json> <site> <temp-workspace> | stage restore <temp-workspace> <site>")
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
