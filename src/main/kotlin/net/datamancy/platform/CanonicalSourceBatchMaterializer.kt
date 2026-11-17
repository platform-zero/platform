package net.datamancy.platform

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE_NEW
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/** Offline SOURCE conversion for reviewed OLD-derived native adapters. No recipe/index is
 * activated, no image is pulled, no credential or original user/source state is generated.
 * A historic local build receipt identifies a *source artifact*, not native-store custody.
 * Invoked as a standalone development utility, never from serving/qualification paths.
 */
internal object CanonicalSourceBatchMaterializer {
    @JvmStatic fun main(args: Array<String>) {
        require(args.contentEquals(arrayOf("--offline-source-only")))
        val broad = Json.decodeFromString<AcquiredInventory>(Files.readString(
            Path.of("release/downloaded-candidate-inventory.json")))
        val dev = Json.decodeFromString<AcquiredInventory>(Files.readString(
            Path.of("release/forgejo-pg-v2-development-inventory.json")))
        fun local(product: String, receipt: String, pin: String, id: String): AcquiredImage {
            val source = Path.of("/mnt/media/p0-v3/image-acquisition-receipts/$receipt/receipt.json")
            val record = Json.parseToJsonElement(Files.readString(source)) as JsonObject
            val pinned = record["image"] ?: record["reference"] ?: record["pinnedImage"]
            val digest = record["imageDigest"] ?: record["digest"]
            require(record["passed"].toString() == "true" &&
                record["imageId"].toString().trim('"') == id &&
                (pinned?.toString()?.trim('"') == pin || digest?.toString()?.trim('"') == pin.substringAfter('@'))) {
                "Historical local build receipt differs from reviewed adapter for $product"
            }
            return AcquiredImage(product, "source-only-historical-build-receipt", pin.substringBefore('@') + ":source-only",
                pin, id, emptyList(), pin.substringAfter('@'), "amd64", "linux")
        }
        val inventory = broad.copy(status = "SOURCE_ONLY_NOT_ACQUIRED", images = broad.images +
            dev.images.single { it.product == "postgres-timescale" } +
            local("huly-caddy-adapted", "p0v3-huly-caddy-build-1a587d36647d",
                HulyRuntime.CADDY_IMAGE, HulyRuntime.CADDY_ID))
        val base = CanonicalSharedYamlGraph.spec(inventory, "source-only-full-private")
        val externals = mapOf("postgres" to "postgres", "valkey" to "valkey", "mariadb" to "mariadb", "caddy" to "caddy",
            "keycloak" to "keycloak", "memcached" to "memcached", "mail" to "mailserver",
            "mas" to "matrix-authentication-service", "synapse" to "synapse")
        fun emit(fresh: CanonicalProviderFragment, cold: CanonicalProviderFragment,
            extraInputOwners: Map<String, String> = emptyMap(), attachIngress: String? = null) {
            val owned = fresh.spec.processes.associate { it.id to fresh.product }
            val owners = externals + owned
            val inputFiles = PrivateDeployment.inputNames(fresh.spec).toSet()
            val inputs = inputFiles.associateWith { extraInputOwners[it] ?: fresh.product }
            val translated = CanonicalFullFragmentTranslator.translate(fresh, cold, inventory, owners, inputs,
                "private-${fresh.product}")
            val roles = translated.providers.associateWith { provider ->
                externals.filterValues { it == provider }.keys.filter { external ->
                    fresh.spec.processes.any { external in it.dependencies } ||
                        cold.spec.processes.any { external in it.dependencies }
                }
            }.filterValues { it.isNotEmpty() }
            val attached = translated.copy(providerProcesses = roles)
            val declaration = if (attachIngress == null) attached else attached.copy(
                providers = (attached.providers + "caddy").distinct(),
                providerProcesses = attached.providerProcesses + ("caddy" to listOf("caddy")),
                networks = (attached.networks + "ingress-control").distinct(),
                providerNetworks = attached.providerNetworks + ("caddy" to listOf("ingress-control")),
                processes = attached.processes.map { if (it.id == attachIngress)
                    it.copy(networks = (it.networks + "ingress-control").distinct()) else it },
                install = attached.install.copy(dependencies = attached.install.dependencies.mapValues { (id, deps) ->
                    if (id == attachIngress) (deps + "caddy").distinct() else deps }),
                restore = attached.restore.copy(dependencies = attached.restore.dependencies.mapValues { (id, deps) ->
                    if (id == attachIngress) (deps + "caddy").distinct() else deps }))
            val caddyTrust = mapOf("jupyterhub" to "jupyterhub-ca.pem",
                "mastodon" to "mastodon-ca.pem", "erpnext" to "erp-ca.pem")
            val bound = caddyTrust[fresh.product]?.let { ca -> declaration.copy(
                exportedInputs = listOf(ca)) } ?: declaration
            val bytes = Json.encodeToString(GraphFragment.serializer(), bound.validate()).toByteArray()
            require(GraphFragment.lint(bytes) == bound)
            val target = Path.of("src/main/resources/fragments/v3/${fresh.product}/r1/fragment.yaml")
            Files.createDirectories(target.parent)
            if (Files.exists(target)) require(Files.readAllBytes(target).contentEquals(bytes)) {
                "Existing source differs; review instead of overwriting ${fresh.product}"
            } else Files.write(target, bytes, CREATE_NEW)
        }
        val hub = JupyterHubRuntime.canonicalFragment(inventory, base.name)
        emit(hub, JupyterHubRuntime.coldRestoreFragment(hub), attachIngress = "hub")
        val social = MastodonRuntime.canonicalFragment(inventory, base)
        emit(social, MastodonRuntime.canonicalColdFragment(inventory, base, social),
            extraInputOwners = mapOf("postgres-ca.pem" to "postgres"), attachIngress = "social")
        // The pinned release provider already carries original Firefly native
        // migration/user/bootstrap SQL and exact cold-retirement semantics. Extract
        // its bounded product processes; do not fabricate original subjects/inputs.
        val release = CanonicalCoreRuntime.releaseProvidersSpec(inventory, base.name)
            .copy(store = RuntimeStore.CANONICAL_V2)
        val recovered = CanonicalCoreRuntime.releaseColdRestoreProvidersSpec(release)
        val fireflyIds = release.processes.map { it.id }.filter { it.startsWith("firefly-") || it == "firefly" }.toSet()
        val financeVolumes = release.volumes.filter { it.id.startsWith("firefly-") }
        val financeNetworks = (release.processes.filter { it.id in fireflyIds }.flatMap { it.networks } +
            "firefly-web").distinct()
        fun finance(source: PrivateDeploymentSpec) = CanonicalProviderFragment("firefly-iii",
            PrivateDeploymentSpec(name = base.name, store = RuntimeStore.CANONICAL_V2,
                processes = source.processes.filter { it.id in fireflyIds }, volumes = financeVolumes,
                networks = financeNetworks, databaseAccess = source.databaseAccess.filter { it.consumer in fireflyIds },
                unmountedRecoveryVolumes = if (source === recovered) financeVolumes.map { it.id }.toSet() -
                    source.processes.filter { it.id in fireflyIds }.flatMap { it.volumes }.map { it.volume }.toSet()
                    else emptySet()), webNetworks = setOf("firefly-web"),
            providerNetworks = mapOf("postgres" to setOf("firefly-data")))
        emit(finance(release), finance(recovered), extraInputOwners = mapOf("postgres-ca.pem" to "postgres"),
            attachIngress = "firefly")
        // Frappe's native site and the single authenticated Valkey bridge replace
        // its OLD duplicate MariaDB and two Redis instances. The cold graph retires
        // the site installer and separately journalled Maria cutover, not the bridge.
        val legacyErp = ErpNextRuntime.spec(inventory, base.name)
        val erpVolumes = legacyErp.volumes.filter { it.id in setOf("sites", "logs", "config") }
            .map { it.copy(id = "erp-${it.id}") }
        fun erpProcess(p: RuntimeProcess): RuntimeProcess = p.copy(
            volumes = p.volumes.map { m -> m.copy(volume = "erp-${m.volume}") },
            files = p.files.map { file -> when (file.file) {
                "process-init.py", "nginx.conf", "ca.pem", "web.pem", "web-key.pem" ->
                    file.copy(file = "erp-${file.file}")
                else -> file
            } })
        val nativeSite = erpProcess(ErpNextRuntime.releaseNativeSiteInstall(inventory, base.name))
            .copy(dependencies = listOf("mariadb", "erp-redis-bridge"),
                networks = listOf("maria-data", "erp-data", "erp-cache"))
        val bridge = ErpNextRuntime.releaseRedisBridge(inventory, base.name)
        val cutover = ErpNextRuntime.releaseMariaCutover(inventory, base.name)
        val legacyApps = legacyErp.processes.filter { it.id in setOf("backend", "websocket", "worker", "scheduler", "erp") }
        val erpApps = legacyApps.map { original -> erpProcess(original).copy(
            dependencies = if (original.id == "erp") listOf("backend", "websocket", "worker", "scheduler")
                else listOf("erp-maria-cutover", "erp-redis-bridge"),
            networks = if (original.id == "erp") listOf("erp-data", "erp-web")
                else listOf("maria-data", "erp-data", "erp-cache")) }
        val erpProcesses = listOf(nativeSite, bridge, cutover) + erpApps
        val erpNetworks = listOf("maria-data", "maria-admin", "cache-data", "erp-data", "erp-cache", "erp-web")
        fun erpPart(processes: List<RuntimeProcess>) = CanonicalProviderFragment("erpnext",
            PrivateDeploymentSpec(name = base.name, store = RuntimeStore.CANONICAL_V2, processes = processes,
                volumes = erpVolumes, networks = erpNetworks), webNetworks = setOf("erp-web"),
            providerNetworks = mapOf("mariadb" to setOf("maria-data", "maria-admin"), "valkey" to setOf("cache-data")))
        val restoredErp = listOf(bridge) + erpApps.map { process ->
            if (process.id == "erp") process else process.copy(
                dependencies = listOf("mariadb", "erp-redis-bridge"), entrypoint = "/bin/sh",
                command = listOf("-ec", "test -f /home/frappe/frappe-bench/sites/.erp-maria-cutover-result.json; " +
                    "test ! -L /home/frappe/frappe-bench/sites/.erp-maria-cutover-result.json; exec \"\u0024@\"",
                    "restored-erp", requireNotNull(process.entrypoint)) + process.command)
        }
        emit(erpPart(erpProcesses), erpPart(restoredErp),
            extraInputOwners = mapOf("mariadb-ca.pem" to "mariadb"), attachIngress = "erp")
    }
}
