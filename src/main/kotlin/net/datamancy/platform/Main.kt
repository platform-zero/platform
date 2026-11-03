package net.datamancy.platform

import java.nio.file.Path
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.system.exitProcess

private val releaseOutputJson = Json { encodeDefaults = true }

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
            out("Historical evidence valid: ${catalog.serviceIds.size} IDs in ${catalog.modules.size} old modules; NOT an install schema")
        }
        listOf("catalog", "products") -> ProductSelection.bundled().products.sorted().forEach {
            out("$it\tprovisional-logical-product")
        }
        listOf("catalog", "list") ->
            ServiceCatalog.bundled().modules.forEach { module ->
                module.services.forEach { service -> out("${module.id}\t$service\tinventory-only") }
            }
        else -> when {
            args.size == 3 && args[0] == "release" && args[1] in setOf("install", "update", "backup", "restore-test", "rollback", "reconcile", "qualify", "activate") -> {
                val request = ReleaseDispatch.read(Path.of(args[2]))
                require(ReleaseDispatch.operation(request) == args[1]) { "Typed release request operation differs from CLI" }
                val runtime = GenerationRuntime.real()
                val dispatcher = ReleaseDispatch.real(runtime) { inventory, generation, capture, target ->
                    runtime.restoreKopiaWholeRelease(inventory, generation.id, generation.bundleSha256, capture, target,
                        targetStore = RuntimeStore.CANONICAL_V2)
                }
                out(dispatcher.execute(request))
            }
            args.size == 3 && args[0] == "runtime" && args[1] == "ingress-lifecycle" -> {
                val request = CaddyLifecycle.readHttps(Path.of(args[2]))
                out(releaseOutputJson.encodeToString(CaddyLifecycle.real().execute(request)))
            }
            args.size == 3 && args[0] == "runtime" && args[1] == "private-pki-lifecycle" -> {
                val request = CaddyLifecycle.readPrivatePki(Path.of(args[2]))
                out(releaseOutputJson.encodeToString(CaddyLifecycle.privatePki(request)))
            }
            args.contentEquals(arrayOf("release", "runtime-store-v2-policy")) -> {
                val store = RuntimeStore.CANONICAL_V2
                out(Json.encodeToString(mapOf("graph" to store.graph, "run" to store.run, "network" to store.network,
                    "module" to store.module.toString(), "configuration" to store.configuration,
                    "objectLimit" to RuntimeLockBudget.ISOLATED_OBJECT_LIMIT.toString())))
                0
            }
            args.size == 6 && args[0] == "release" && args[1] in setOf("site-ownership-check", "generation-prepare-owned") -> {
                try {
                    val plan = GenerationAssembly().plan(GenerationAssembly.readRequest(Path.of(args[3])),
                        GenerationAssembly.readInventory(Path.of(args[2])))
                    val contract = SiteOwnerships.decode(ReleaseLocks.privateBytes(Path.of(args[4])))
                    val hosts = ReleaseLocks.approvedHosts(Path.of(args[5]))
                    if (args[1] == "site-ownership-check") {
                        out(releaseOutputJson.encodeToString(SiteOwnerships.check(plan, contract, hosts)))
                        out("Structural ownership only; no credentials generated, central wiring verified or routes activated")
                    } else {
                        val digest = GenerationRuntime.real().prepareOwnedAssembly(plan, contract, hosts)
                        out("${plan.generation.id} $digest")
                        out("Prepared ownership-bound private inputs; no services started or public authority inherited")
                    }
                } catch (failure: Exception) {
                    err("Site ownership operation rejected (${failure.javaClass.simpleName}); retain any preparation intents and partial inputs, never regenerate credentials")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] in setOf("generation-assembly-plan", "generation-canonical-plan", "generation-prepare", "site-ownership-inventory") -> {
                try {
                    val plan = GenerationAssembly().plan(GenerationAssembly.readRequest(Path.of(args[3])),
                        GenerationAssembly.readInventory(Path.of(args[2])))
                    if (args[1] == "generation-canonical-plan") out(releaseOutputJson.encodeToString(CanonicalTopology.compile(plan, false).topology))
                    else if (args[1] == "generation-assembly-plan") out(releaseOutputJson.encodeToString(plan.summary))
                    else if (args[1] == "site-ownership-inventory") out(releaseOutputJson.encodeToString(SiteOwnerships.inspect(plan)))
                    else {
                        val digest = GenerationRuntime.real().prepareAssembly(plan)
                        out("${plan.generation.id} $digest")
                        out("Prepared typed private assembly; no services started, unseal, publication or full-stack qualification")
                    }
                } catch (failure: Exception) {
                    err("Typed assembly rejected (${failure.javaClass.simpleName}); retain partial inputs, do not regenerate credentials")
                    return 1
                }
            }
            args.size == 3 && args[0] == "release" && args[1] == "generation-seal" -> {
                try {
                    val request = GenerationRuntime.request(Path.of(args[2]))
                    val digest = GenerationRuntime.real().seal(request)
                    out("${request.id} $digest")
                    out("Sealed private generation inputs; no services started, no release qualification")
                } catch (failure: Exception) {
                    err("Generation seal rejected (${failure.javaClass.simpleName}); private inputs retained")
                    return 1
                }
            }
            args.firstOrNull() == "release" && ((args.size == 5 && args[1] == "weekly-restore-enroll") ||
                (args.size == 4 && args[1] in setOf("weekly-restore-units", "weekly-restore-tick", "weekly-restore-suspend", "weekly-restore-alert"))) -> {
                try {
                    val scheduler = WeeklyRestoreSchedule.real()
                    when (args[1]) {
                        "weekly-restore-enroll" -> out(releaseOutputJson.encodeToString(scheduler.enroll(
                            GenerationRuntime.privateInput(Path.of(args[2])),
                            Json.decodeFromString<WeeklyRestoreBinding>(GenerationRuntime.privateInput(Path.of(args[3])).decodeToString()),
                            GenerationRuntime.privateInput(Path.of(args[4])))))
                        "weekly-restore-units" -> out(releaseOutputJson.encodeToString(scheduler.units(args[2], args[3])))
                        "weekly-restore-tick" -> out(releaseOutputJson.encodeToString(scheduler.tick(args[2], args[3])))
                        "weekly-restore-suspend" -> { scheduler.suspend(args[2], args[3]); out("Weekly restore suspended; evidence retained") }
                        "weekly-restore-alert" -> { scheduler.signalFailure(args[2], args[3]); err("Weekly restore failure retained; no retry or resume") }
                    }
                } catch (failure: InterruptedException) {
                    Thread.currentThread().interrupt(); err("Weekly restore interrupted; no automatic retry or resume"); return 1
                } catch (failure: Exception) {
                    err("Weekly restore rejected (${failure.javaClass.simpleName}); retain all source/target fences and intents"); return 1
                }
            }
            args.size == 6 && args[0] == "release" && args[1] == "generation-kopia-retain" -> {
                try {
                    val inventory = Json.decodeFromString<AcquiredInventory>(GenerationRuntime.privateInput(Path.of(args[2])).decodeToString())
                    out(releaseOutputJson.encodeToString(GenerationRuntime.real().retainKopia(inventory, args[3], args[4], args[5])))
                } catch (failure: InterruptedException) {
                    Thread.currentThread().interrupt(); err("Retention interrupted; unknown deletion retained"); return 1
                } catch (failure: Exception) {
                    err("Retention rejected (${failure.javaClass.simpleName}); references and pending outcomes retained"); return 1
                }
            }
            args.firstOrNull() == "release" && ((args.size == 7 && args[1] == "backup-schedule-enroll") ||
                (args.size == 4 && args[1] in setOf("backup-schedule-units", "backup-schedule-tick", "backup-schedule-suspend", "backup-schedule-alert"))) -> {
                try {
                    val scheduler = GenerationBackupSchedule.real()
                    when (args[1]) {
                        "backup-schedule-enroll" -> out(releaseOutputJson.encodeToString(scheduler.enroll(
                            GenerationAssembly.readInventory(Path.of(args[2])), args[3], args[4], args[5], args[6].toInt())))
                        "backup-schedule-units" -> out(releaseOutputJson.encodeToString(scheduler.units(args[2], args[3])))
                        "backup-schedule-tick" -> out(releaseOutputJson.encodeToString(scheduler.tick(args[2], args[3])))
                        "backup-schedule-suspend" -> { scheduler.suspend(args[2], args[3]); out("Schedule suspended; evidence and source state retained") }
                        "backup-schedule-alert" -> { scheduler.signalFailure(args[2], args[3]); err("Scheduled backup blocked or failed; retained state requires reconciliation") }
                    }
                } catch (failure: InterruptedException) {
                    Thread.currentThread().interrupt(); err("Scheduled backup interrupted; no automatic replay authorized"); return 1
                } catch (failure: Exception) {
                    err("Schedule operation rejected (${failure.javaClass.simpleName}); retain all bindings and intents; no automatic retry authorized")
                    return 1
                }
            }
            args.size == 7 && args[0] == "release" && args[1] == "generation-backup-reconcile" -> {
                try {
                    val result = GenerationRuntime.real().reconcileBackup(args[2], args[3], args[4], args[5], args[6])
                    out(releaseOutputJson.encodeToString(result))
                    if (!result.passed) return 1
                    out("Stop-only backup reconciliation; original leases, intents, snapshots and outcomes retained")
                } catch (failure: Exception) {
                    err("Backup reconciliation rejected (${failure.javaClass.simpleName}); no resume or snapshot replay authorized")
                    return 1
                }
            }
            args.size == 6 && args[0] == "release" && args[1] in setOf("generation-kopia-capture", "generation-kopia-backup") -> {
                try {
                    val inventory = Json.decodeFromString<AcquiredInventory>(GenerationAssembly.readInventory(Path.of(args[2])).decodeToString())
                    if (args[1] == "generation-kopia-backup") {
                        val result = GenerationRuntime.real().backupKopia(inventory, args[3], args[4], args[5])
                        out(releaseOutputJson.encodeToString(result))
                        if (!result.passed) return 1
                        out("Routine canonical backup resumed its own source; functional restore and full-stack qualification still required")
                    } else {
                        out(releaseOutputJson.encodeToString(GenerationRuntime.real().captureKopia(inventory, args[3], args[4], args[5])))
                        out("Native encrypted Kopia snapshot only; source remains stopped and fenced, functional restoration still required")
                    }
                } catch (failure: Exception) {
                    err("Kopia capture rejected (${failure.javaClass.simpleName}); retain repository, custody and pending intents; never resubmit uncertain snapshots")
                    return 1
                }
            }
            args.size == 7 && args[0] == "release" && args[1] in setOf("generation-restore-foundation", "generation-restore-applications", "generation-restore-canonical-core", "generation-kopia-restore-canonical-core", "generation-kopia-restore-canonical-core-v2") -> {
                try {
                    val inventory = Json.decodeFromString<AcquiredInventory>(GenerationAssembly.readInventory(Path.of(args[2])).decodeToString())
                    val runtime = GenerationRuntime.real()
                    val result = when (args[1]) {
                        "generation-restore-applications" -> runtime.restoreApplications(inventory, args[3], args[4], args[5], args[6])
                        "generation-restore-canonical-core" -> runtime.restoreCanonicalCore(inventory, args[3], args[4], args[5], args[6])
                        "generation-kopia-restore-canonical-core-v2" -> runtime.restoreKopiaCanonicalCore(inventory, args[3], args[4], args[5], args[6], targetStore = RuntimeStore.CANONICAL_V2)
                        "generation-kopia-restore-canonical-core" -> runtime.restoreKopiaCanonicalCore(inventory, args[3], args[4], args[5], args[6])
                        else -> runtime.restoreFoundation(inventory, args[3], args[4], args[5], args[6])
                    }
                    out(releaseOutputJson.encodeToString(result))
                    if (!result.passed) {
                        out("Import failed; inspect retained isolation outcome, never start or replay the failed target")
                        return 1
                    }
                    out("Fresh targets remain stopped and fenced; native functional readback is still required")
                } catch (failure: Exception) {
                    err("Compiled cohort restoration rejected (${failure.javaClass.simpleName}); retain all intents, imports and fences")
                    return 1
                }
            }
            args.size == 8 && args[0] == "release" && args[1] == "generation-recovery-check" -> {
                try {
                    val verified = RecoveryCapsule.verify(Path.of(args[2]), Path.of(args[3]), args[4], args[5], args[6])
                    out(releaseOutputJson.encodeToString(GenerationRecovery.validate(Path.of(args[7]), verified).check))
                } catch (failure: Exception) {
                    err("Recovery binding rejected (${failure.javaClass.simpleName}); no runtime import authorized")
                    return 1
                }
            }
            args.size == 8 && args[0] == "release" && args[1] == "capsule-extract" -> {
                try {
                    out(releaseOutputJson.encodeToString(RecoveryCapsule.extract(Path.of(args[2]), Path.of(args[3]), args[4], args[5], args[6], Path.of(args[7]))))
                } catch (failure: Exception) {
                    err("Capsule extraction rejected (${failure.javaClass.simpleName}); retain partial private destination; no runtime import")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] == "volume-tar-inspect" -> {
                try {
                    out(releaseOutputJson.encodeToString(VolumeTar.inspect(Path.of(args[2]), args[3].toInt())))
                } catch (failure: Exception) {
                    err("Volume archive rejected (${failure.javaClass.simpleName}); no extraction or runtime effects")
                    return 1
                }
            }
            args.size == 7 && args[0] == "release" && args[1] == "capsule-verify" -> {
                try {
                    out(releaseOutputJson.encodeToString(RecoveryCapsule.verify(Path.of(args[2]), Path.of(args[3]), args[4], args[5], args[6])))
                } catch (failure: Exception) {
                    err("Capsule verification rejected (${failure.javaClass.simpleName}); no extraction or runtime effects")
                    return 1
                }
            }
            args.size == 5 && args[0] == "release" && args[1] in setOf("generation-capture", "generation-verify-capture") -> {
                try {
                    val runtime = GenerationRuntime.real()
                    if (args[1] == "generation-capture") out(releaseOutputJson.encodeToString(runtime.capture(args[2], args[3], args[4])))
                    else out(releaseOutputJson.encodeToString(runtime.verifyCapture(args[2], args[3], args[4])))
                    out("Authenticated local cold capture only; functional restoration and full-stack qualification remain unproven")
                } catch (failure: Exception) {
                    err("Generation capture rejected (${failure.javaClass.simpleName}); retain capture and custody evidence")
                    return 1
                }
            }
            args.size == 6 && args[0] == "release" && args[1] == "generation-reconcile-isolation" -> {
                try {
                    val result = GenerationRuntime.real().reconcileIsolation(args[2], args[3], args[4], args[5])
                    out(releaseOutputJson.encodeToString(result))
                    if (!result.passed) return 1
                    out("Private isolation reconciliation only; no initialization, writes, restart or publication")
                } catch (failure: Exception) {
                    err("Isolation reconciliation rejected (${failure.javaClass.simpleName}); original evidence retained")
                    return 1
                }
            }
            args.size == 4 && args[0] == "release" && args[1] in setOf("generation-audit", "generation-stage", "generation-isolate") -> {
                try {
                    val runtime = GenerationRuntime.real()
                    if (args[1] == "generation-audit") out(releaseOutputJson.encodeToString(runtime.inspect(args[2], args[3])))
                    else {
                        val result = if (args[1] == "generation-stage") runtime.stage(args[2], args[3]) else runtime.isolate(args[2], args[3])
                        out(releaseOutputJson.encodeToString(result))
                        if (!result.passed) return 1
                    }
                    out("Private generation only: no public activation or full-stack qualification")
                } catch (failure: Exception) {
                    err("Generation operation rejected (${failure.javaClass.simpleName}); retain intents and reconcile, do not replay")
                    return 1
                }
            }
            args.size == 5 && args[0] == "runtime" && args[1] == "boot-unit" -> {
                val bytes = ReleaseLocks.privateBytes(RuntimeBootUnits.manifest(args[2]))
                val hash = RuntimeBootUnits.hash(bytes)
                val spec = RuntimeBootUnits.boundSpec(args[2], hash)
                out(RuntimeBootUnits.render(spec, hash, args[3], args[4].toInt()))
            }
            args.size == 4 && args[0] == "runtime" && args[1] in setOf("boot-apply", "boot-stop") -> {
                val spec = RuntimeBootUnits.boundSpec(args[2], args[3])
                val runtime = PrivateDeployment.real()
                val result = if (args[1] == "boot-apply") runtime.apply(spec) else runtime.stop(spec)
                out(releaseOutputJson.encodeToString(result))
            }
            args.size in 3..4 && args[0] == "runtime" && args[1] in setOf("prepare-foundation", "prepare-identity", "prepare-observability", "prepare-forgejo", "prepare-planka", "prepare-sql-cache", "prepare-jellyfin", "prepare-donetick", "prepare-homeassistant", "prepare-notebook", "prepare-qbittorrent", "prepare-synapse", "prepare-matrix", "prepare-opensearch", "prepare-firefly", "prepare-bookstack", "prepare-knowledge-identity", "prepare-livekit", "prepare-openbao", "prepare-mastodon", "prepare-matrix-identity", "prepare-matrix-rtc", "prepare-searxng", "prepare-erpnext", "prepare-crowdsec", "prepare-seafile", "prepare-office", "prepare-keykeeper", "prepare-node-metrics", "prepare-backup", "prepare-huly", "prepare-jupyterhub", "prepare-sogo", "prepare-mail", "prepare-sogo-mail") -> {
                val inventory = ImageStaging.inventory(Path.of(args[2]))
                val path = when (args[1]) {
                    "prepare-foundation" -> FoundationRuntime.prepare(inventory, name = args.getOrNull(3) ?: "foundation")
                    "prepare-identity" -> IdentityRuntime.prepare(inventory, name = args.getOrNull(3) ?: "identity")
                    "prepare-observability" -> ObservabilityRuntime.prepare(inventory, name = args.getOrNull(3) ?: "observability")
                    "prepare-forgejo" -> ForgejoRuntime.prepare(inventory, name = args.getOrNull(3) ?: "forgejo")
                    "prepare-planka" -> PlankaRuntime.prepare(inventory, name = args.getOrNull(3) ?: "planka")
                    "prepare-sql-cache" -> SqlCacheRuntime.prepare(inventory, name = args.getOrNull(3) ?: "sql-cache")
                    "prepare-jellyfin" -> JellyfinRuntime.prepare(inventory, name = args.getOrNull(3) ?: "jellyfin")
                    "prepare-erpnext" -> ErpNextRuntime.prepare(inventory, name = args.getOrNull(3) ?: "erpnext")
                    "prepare-crowdsec" -> CrowdsecRuntime.prepare(inventory, name = args.getOrNull(3) ?: "crowdsec")
                    "prepare-seafile" -> SeafileRuntime.prepare(inventory, name = args.getOrNull(3) ?: "seafile")
                    "prepare-office" -> OfficeRuntime.prepare(inventory, name = args.getOrNull(3) ?: "files-office")
                    "prepare-keykeeper" -> KeykeeperRuntime.prepare(inventory, name = args.getOrNull(3) ?: "keykeeper-identity")
                    "prepare-node-metrics" -> NodeMetricsRuntime.prepare(inventory, name = args.getOrNull(3) ?: "node-metrics")
                    "prepare-backup" -> KopiaRuntime.prepare(inventory, name = args.getOrNull(3) ?: "backup")
                    "prepare-huly" -> HulyRuntime.prepare(inventory, name = args.getOrNull(3) ?: "huly")
                    "prepare-jupyterhub" -> JupyterHubRuntime.prepare(inventory, name = args.getOrNull(3) ?: "jupyterhub")
                    "prepare-sogo" -> SogoRuntime.prepare(inventory, name = args.getOrNull(3) ?: "sogo")
                    "prepare-sogo-mail" -> SogoMailRuntime.prepare(inventory, name = args.getOrNull(3) ?: "sogo-mail")
                    "prepare-mail" -> MailRuntime.prepare(name = args.getOrNull(3) ?: "mail")
                    "prepare-searxng" -> SearxngRuntime.prepare(inventory, name = args.getOrNull(3) ?: "searxng")
                    "prepare-donetick" -> DonetickRuntime.prepare(inventory, name = args.getOrNull(3) ?: "donetick")
                    "prepare-homeassistant" -> HomeAssistantRuntime.prepare(inventory, name = args.getOrNull(3) ?: "homeassistant")
                    "prepare-notebook" -> NotebookRuntime.prepare(inventory, name = args.getOrNull(3) ?: "notebook")
                    "prepare-qbittorrent" -> QbittorrentRuntime.prepare(inventory, name = args.getOrNull(3) ?: "qbittorrent")
                    "prepare-synapse" -> SynapseRuntime.prepare(inventory, name = args.getOrNull(3) ?: "synapse")
                    "prepare-matrix" -> MatrixRuntime.prepare(inventory, name = args.getOrNull(3) ?: "matrix")
                    "prepare-opensearch" -> OpenSearchRuntime.prepare(inventory, name = args.getOrNull(3) ?: "opensearch")
                    "prepare-firefly" -> FireflyRuntime.prepare(inventory, name = args.getOrNull(3) ?: "firefly")
                    "prepare-bookstack" -> BookStackRuntime.prepare(inventory, name = args.getOrNull(3) ?: "bookstack")
                    "prepare-knowledge-identity" -> KnowledgeIdentityRuntime.prepare(inventory, name = args.getOrNull(3) ?: "knowledge-identity")
                    "prepare-matrix-rtc" -> MatrixRtcRuntime.prepare(inventory, name = args.getOrNull(3) ?: "matrix-rtc")
                    "prepare-livekit" -> LiveKitRuntime.prepare(inventory, name = args.getOrNull(3) ?: "livekit")
                    "prepare-openbao" -> OpenBaoRuntime.prepare(inventory, name = args.getOrNull(3) ?: "openbao")
                    "prepare-mastodon" -> MastodonRuntime.prepare(inventory, name = args.getOrNull(3) ?: "mastodon")
                    else -> MatrixIdentityRuntime.prepare(inventory, name = args.getOrNull(3) ?: "matrix-identity")
                }
                out("Prepared persistent private runtime at $path; credentials retained privately, no services started")
            }
            args.size == 5 && args[0] == "runtime" && args[1] in setOf("prepare-forgejo-restore", "prepare-single-user-restore", "prepare-firefly-restore", "prepare-livekit-restore", "prepare-mastodon-restore", "prepare-searxng-restore", "prepare-seafile-restore", "prepare-node-metrics-restore", "prepare-sogo-mail-restore", "prepare-erpnext-restore") -> {
                val inventory = ImageStaging.inventory(Path.of(args[2]))
                val path = when (args[1]) {
                    "prepare-forgejo-restore" -> ForgejoRuntime.prepareRestore(inventory, Path.of(args[3]), name = args[4])
                    "prepare-searxng-restore" -> SearxngRecovery.prepare(inventory, Path.of(args[3]), name = args[4])
                    "prepare-seafile-restore" -> SeafileRecovery.prepare(inventory, Path.of(args[3]), name = args[4])
                    "prepare-node-metrics-restore" -> NodeMetricsRecovery.prepare(inventory, Path.of(args[3]), name = args[4])
                    "prepare-erpnext-restore" -> ErpNextRecovery.prepare(inventory, Path.of(args[3]), name = args[4])
                    "prepare-sogo-mail-restore" -> SogoMailRecovery.prepare(inventory, Path.of(args[3]), name = args[4])
                    "prepare-livekit-restore" -> LiveKitRuntime.prepareRestore(inventory, Path.of(args[3]), name = args[4])
                    "prepare-firefly-restore" -> FireflyRecovery.prepare(inventory, Path.of(args[3]), name = args[4])
                    "prepare-mastodon-restore" -> MastodonRecovery.prepare(inventory, Path.of(args[3]), name = args[4])
                    else -> SingleUserRestore.prepare(inventory, Path.of(args[3]), name = args[4])
                }
                out("Prepared isolated restore manifest at $path; recovered data must be verified before apply")
            }
            args.size in 4..5 && args[0] == "runtime" && args[1] == "maintenance-enter" -> {
                val spec = PrivateDeployment.read(Path.of(args[2]))
                out(releaseOutputJson.encodeToString(PrivateDeployment.real().enterMaintenance(spec, args[3], args.getOrNull(4))))
            }
            args.size == 3 && args[0] == "runtime" && args[1] == "maintenance-status" -> {
                out(releaseOutputJson.encodeToString(PrivateDeployment.real().maintenanceStatus(PrivateDeployment.read(Path.of(args[2])))))
            }
            args.size == 4 && args[0] == "runtime" && args[1] == "maintenance-leave" -> {
                PrivateDeployment.real().leaveMaintenance(PrivateDeployment.read(Path.of(args[2])), args[3])
                out("Maintenance released; applications remain stopped")
            }
            args.size == 4 && args[0] == "runtime" && args[1] == "stage-private" -> {
                val spec = PrivateDeployment.read(Path.of(args[2]))
                out(releaseOutputJson.encodeToString(PrivateDeployment.real().stage(spec, args[3])))
                out("Dependency-only staging; a maintenance-enter fence is required to block ordinary startup; not full-stack activation")
            }
            args.size == 3 && args[0] == "runtime" && args[1] in setOf("provision-private", "apply-private", "stop-private", "status-private") -> {
                val spec = PrivateDeployment.read(Path.of(args[2]))
                val runtime = PrivateDeployment.real()
                val result = when (args[1]) {
                    "provision-private" -> runtime.provision(spec)
                    "apply-private" -> runtime.apply(spec)
                    "stop-private" -> runtime.stop(spec)
                    else -> runtime.status(spec)
                }
                out(releaseOutputJson.encodeToString(result))
                out("Private runtime only: no published ports, no full-stack or public release acceptance")
            }
            RssScheduleCommands.run(args, out) -> Unit
            args.size == 3 && args[0] == "rss" && args[1] == "initialize" -> {
                val root = Path.of(args[2])
                require(root.isAbsolute) { "Absolute RSS state path required" }
                if (!java.nio.file.Files.exists(root, java.nio.file.LinkOption.NOFOLLOW_LINKS))
                    java.nio.file.Files.createDirectory(root, java.nio.file.attribute.PosixFilePermissions.asFileAttribute(
                        java.nio.file.attribute.PosixFilePermissions.fromString("rwx------")))
                RssStateStore(root).initializeFresh()
                out("Initialized fresh RSS state; existing state is never reset on reinstall")
            }
            args.size == 4 && args[0] == "rss" && args[1] == "verify-accounts" -> {
                val sender = MastodonRssSender(java.net.URI(args[2]), { account ->
                    MastodonRssSender.privateToken(Path.of(args[3]).resolve("$account.token"))
                }, JdkRssHttp())
                val accounts = RssPacks.load().map { sender.verifyAccount(it.feed.account) }
                require(accounts.distinct().size == accounts.size) { "RSS account identities are not distinct" }
                out("Verified ${accounts.size} distinct RSS bot accounts; read-only, no publication enabled")
            }
            args.size in setOf(4, 6) && args[0] == "rss" && args[1] == "poll" -> {
                val gate = PollGate.valueOf(args[2].uppercase())
                require((gate == PollGate.ACTIVE && args.size == 6) || (gate != PollGate.ACTIVE && args.size == 4))
                require(gate != PollGate.ACTIVE) { "Active RSS requires an enrolled release-bound schedule; use rss schedule-tick" }
                val http = JdkRssHttp()
                val result = RssWorker(RssStateStore(Path.of(args[3])), RssFetcher(http)::fetch,
                    { error("Outbound publishing disabled; use an enrolled release-bound schedule") }).poll(gate)
                out("RSS ${gate.name.lowercase()}: ${result.feeds} feeds, ${result.observed} observed, ${result.confirmed} confirmed, ${result.failedFeeds.size} failed")
                require(result.failedFeeds.isEmpty()) { "RSS feeds failed without checkpoint advancement: ${result.failureTypes.entries.joinToString(",") { "${it.key}:${it.value}" }}" }
            }
            args.size == 3 && args[0] == "images" && args[1] == "stage" -> {
                val staged = ImageStaging.real().stage(ImageStaging.inventory(Path.of(args[2])))
                out("Verified ${staged.size} content-addressed images in the private v3 store; no services started or compatibility accepted")
            }
            args.size == 7 && args[0] == "release" && args[1] in setOf("validate", "plan") -> {
                val (lock, hash) = ReleaseLocks.validate(Path.of(args[2]), Path.of(args[3]), Path.of(args[4]),
                    Path.of(args[5]), Path.of(args[6]))
                if (args[1] == "plan") out(releaseOutputJson.encodeToString(ReleasePlanning.offline(lock, hash)))
                else out("Validated ${lock.products.size} logical products; lock sha256:$hash; offline only, no images or releases verified upstream")
            }
            args.size == 8 && args[0] == "release" && args[1] == "generator-dryrun" -> {
                val (lock, hash) = ReleaseLocks.validate(Path.of(args[2]), Path.of(args[3]), Path.of(args[4]),
                    Path.of(args[5]), Path.of(args[6]))
                val approved = ReleaseLocks.approvedHosts(Path.of(args[6]))
                val bundle = PrivateQuadlets.render(lock, approved, Path.of(args[7]))
                val count = QuadletDryRun.verify(bundle)
                out("$count temporary Quadlet files passed generator private-store audit for sha256:$hash; no install or Podman execution")
            }
            args.size == 3 && args[0] == "release" && args[1] == "status" -> {
                val records = TransactionJournal.verify(Path.of(args[2]))
                val last = records.last()
                out(Json.encodeToString(last))
            }
            args.firstOrNull() == "release" && args.getOrNull(1) in setOf("install", "update", "status", "backup", "restore-test", "rollback") -> {
                throw IllegalStateException("Release executor not implemented; no v3 production resources changed")
            }
            args.size == 4 && args[0] == "site" && args[1] == "validate" -> {
                val sites = Sites.from(Path.of(args[2]))
                sites.select(args[3])
                out("Explicit site ${args[3]} valid; no installation or acceptance claimed")
            }
            args.size == 4 && args[0] == "plan" && args[1] == "render" -> {
                val site = Sites.from(Path.of(args[2])).select(args[3])
                out(Json.encodeToString(RenderPlan.forSite(site)))
            }
            args.size in 3..4 && args[0] == "module" && args[1] == "identity" -> {
                val sandbox = IdentitySandbox.real()
                when (args[2]) {
                    "prepare" -> { require(args.size == 3); sandbox.prepare() }
                    "install" -> { require(args.size == 3); sandbox.install() }
                    "stop" -> { require(args.size == 3); sandbox.stop() }
                    "remove" -> { require(args.size == 3); sandbox.remove() }
                    "backup" -> { require(args.size == 4); sandbox.backup(args[3]) }
                    "restore" -> { require(args.size == 4); sandbox.restore(args[3]) }
                    "restore-remove" -> { require(args.size == 4); sandbox.removeRestore(args[3]) }
                    else -> throw IllegalArgumentException("Unknown identity sandbox action")
                }
                out("Fake identity sandbox ${args[2]} completed; no production SSO acceptance")
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
                err("Usage: platform release install|update|backup|restore-test|rollback|reconcile|qualify|activate <private-request.json> | runtime ingress-lifecycle|private-pki-lifecycle <private-request.json> | release site-ownership-inventory <inventory.json> <private-assembly-request.json> | release site-ownership-check|generation-prepare-owned <inventory.json> <private-assembly-request.json> <private-ownership.json> <private-approved-hosts.json> | release capsule-extract <archive> <key-file> <cap-id> <q-id> <bundle-sha256> <fresh-private-directory> | release volume-tar-inspect <private-tar> <expected-uid-and-gid> | release capsule-verify <archive> <key-file> <cap-id> <q-id> <bundle-sha256> | release generation-capture|generation-verify-capture <q-generation-id> <bundle-sha256> <cap-capture-id> | release generation-assembly-plan|generation-canonical-plan|generation-prepare <inventory.json> <private-assembly-request.json> | release generation-seal <private-generation-request.json> | release generation-audit|generation-stage|generation-isolate <q-generation-id> <bundle-sha256> | release generation-reconcile-isolation <q-generation-id> <bundle-sha256> <r-reconciliation-id> <original-isolation-intent-sha256> | runtime maintenance-enter <manifest> backup|restore|update [stage-target] | runtime maintenance-status <manifest> | runtime maintenance-leave <manifest> <fence-id> | runtime stage-private <private-runtime-manifest.json> <process-id> | runtime boot-unit <deployment-name> <controller-tree-sha256> <non-root-uid> | runtime boot-apply|boot-stop <deployment-name> <manifest-sha256> | runtime prepare-foundation|prepare-identity|prepare-observability|prepare-forgejo|prepare-planka|prepare-sql-cache|prepare-jellyfin|prepare-donetick|prepare-homeassistant|prepare-notebook|prepare-qbittorrent|prepare-synapse|prepare-matrix|prepare-opensearch|prepare-firefly|prepare-bookstack|prepare-knowledge-identity|prepare-livekit|prepare-openbao|prepare-mastodon|prepare-matrix-identity|prepare-matrix-rtc|prepare-searxng|prepare-erpnext|prepare-crowdsec|prepare-seafile|prepare-office|prepare-keykeeper|prepare-node-metrics|prepare-backup|prepare-huly|prepare-jupyterhub|prepare-sogo|prepare-mail|prepare-sogo-mail <candidate-inventory.json> [deployment-name] | runtime prepare-forgejo-restore|prepare-single-user-restore|prepare-firefly-restore|prepare-livekit-restore|prepare-mastodon-restore|prepare-searxng-restore|prepare-seafile-restore|prepare-node-metrics-restore|prepare-sogo-mail-restore|prepare-erpnext-restore <inventory.json> <recovered-private-input-directory> <new-name> | runtime provision-private|apply-private|stop-private|status-private <private-runtime-manifest.json> | rss verify-accounts <https-origin> <private-token-directory> | rss initialize <private-state-dir> | rss poll staging|restoring <private-state-dir> | rss schedule-enroll <private-schedule-root> <private-binding.json> | rss schedule-units|schedule-tick|schedule-pause <private-schedule-root> <binding-sha256> | rss reconcile <private-schedule-root> <binding-sha256> <state-sha256> <account> <item-key> <status-id> | images stage <downloaded-candidate-inventory.json> | release validate|plan <private-lock.json> <private-sha256-file> <private-signature-base64> <trusted-ed25519-public-key-base64> <private-approved-hosts.json> | release generator-dryrun <same-five-lock-inputs> <explicit-v3-owned-root> | release status <private-journal-file> (verification only; no live resource inventory) (typed operations remain subject to complete lineage, coverage and activation admission) | module identity prepare|install|stop|remove|backup|restore|restore-remove [backup-id] | module sandbox-backup due|two | module postgres prepare|install|stop|remove|write|query|backup|restore|restored-write|restored-query|restore-remove [backup-id] | module ntfy prepare|install|stop|remove|snapshot|restore|restore-remove [snapshot-id] | probe prepare|install|stop|remove <site> <local-sha256-image-id> | probe snapshot|restore <site> <local-sha256-image-id> <snapshot-id> | catalog validate|list|products | site validate <sites.json> <site> | plan render <sites.json> <site> | contract plan <site.json> <approved-hosts.json> <data-root> <backup-root> | lane plan <request.json> <trusted-issuer> <occupied-usernames.json> | stage offline <sites.json> <site> <temp-workspace> | stage restore <temp-workspace> <site>")
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
