package net.datamancy.platform

import kotlinx.serialization.json.*

internal enum class QualificationExecutionMode { HOST_NATIVE, HOST_NATIVE_WITH_DENIAL_PROBE, QCLIENT_RUNNER }

/** The C2 source consumer never reinterprets legacy independently assembled members. */
internal object QualificationCanonicalTopology {
    fun require(bundle: GenerationBundle, restoredTarget: Boolean = false,
        allowOwnedUpdateSource: Boolean = false): GenerationPin {
        val name = "${bundle.request.id}-v2"
        require(bundle.request.store == RuntimeStore.CANONICAL_V2 &&
            bundle.request.members.size == 1 && bundle.request.members.single().name == name &&
            bundle.members.size == 1 && bundle.members.single().member.name == name &&
            bundle.members.single().spec.name == name &&
            bundle.members.single().spec.store == RuntimeStore.CANONICAL_V2 &&
            bundle.members.single().runtimeFingerprint.matches(Regex("[a-f0-9]{64}"))) {
            "C2 requires the sealed canonical-release-v2 member, not legacy recipe topology"
        }
        if (allowOwnedUpdateSource) OwnedReleaseUpdates.validate(bundle)
        val pin = bundle.members.single()
        val spec = pin.spec
        require(setOf("caddy", "livekit").all { service ->
            spec.processes.count { it.id == service && !it.oneShot &&
                "qualification-web" in it.networks } == 1
        } && "qualification-web" in spec.networks &&
            (if (restoredTarget) spec.ingress == null && spec.nativeIngress == null
             else if (allowOwnedUpdateSource) bundle.ownedUpdate != null &&
                 spec.ingress == null && spec.nativeIngress == null && bundle.ownership != null
             else spec.ingress?.approvedHosts?.isNotEmpty() == true) &&
            PrivateDeployment.expectedFingerprint(spec, pin.inputHashes) == pin.runtimeFingerprint) {
            "C2 client lacks real sealed Caddy/LiveKit on its one bounded private network"
        }
        return pin
    }
}

/** A case is admitted only when BOTH the pinned manifest and this fixed source table agree.
 * It never chooses a mode from caller-controlled context. */
internal object QualificationExecutionPolicy {
    private val native = setOf("alertmanager", "alloy", "backup-restore", "caddy", "crowdsec", "erpnext",
        "grafana", "human-agent-authorization", "identity-onboarding", "keykeeper", "kopia", "loki",
        "mailserver", "mariadb", "mastodon", "mastodon-rss-publisher", "memcached", "node-exporter",
        "onlyoffice", "openbao", "opensearch", "pi", "postgres", "prometheus", "qbittorrent",
        "rss-jobs", "rss-pack-analysis", "rss-pack-aus", "rss-pack-aus-state", "rss-pack-china",
        "rss-pack-china-state", "rss-pack-tas", "rss-pack-us", "rss-pack-us-state", "rss-pack-world",
        "seafile", "searxng", "sogo", "tuios", "valkey", "worklane", "homeassistant", "jellyfin",
        "bookstack", "donetick", "element", "firefly-iii", "forgejo", "huly", "jupyter-notebook",
        "jupyterhub", "keycloak", "livekit", "matrix-authentication-service", "ntfy", "planka", "synapse")
    private val publicOfficial = setOf("grafana", "prometheus", "alertmanager", "mastodon",
        "sogo", "seafile", "homeassistant", "jellyfin", "qbittorrent", "searxng")
    private val denialProbe = setOf("alloy", "loki")
    private val web = setOf("alertmanager", "bookstack", "donetick", "element", "erpnext",
        "firefly-iii", "forgejo", "grafana", "homeassistant", "huly", "identity-onboarding",
        "jellyfin", "jupyter-notebook", "jupyterhub", "keycloak", "keykeeper", "kopia",
        "livekit", "mastodon", "matrix-authentication-service", "ntfy", "onlyoffice",
        "planka", "prometheus", "qbittorrent", "seafile", "searxng", "sogo")
    private val android = setOf("donetick", "element", "homeassistant", "jellyfin", "livekit",
        "mastodon", "matrix-authentication-service", "ntfy", "onlyoffice", "seafile", "synapse")
    internal data class Predecessor(val service: String, val surface: String, val variant: String,
        val fields: Set<String>, val restoreOriginalFields: Set<String> = emptySet())
    private val nativeFiles = setOf("sourceNativeOracleFile", "sourceNativeOracleSha256",
        "sourceNativeObservationFile", "sourceNativeObservationSha256")
    private val browserFiles = setOf("browserSourceOracleFile", "browserSourceOracleSha256",
        "browserSourceObservationFile", "browserSourceObservationSha256")
    private val hubBrowserFiles = setOf("hubBrowserSourceOracleFile", "hubBrowserSourceOracleSha256",
        "hubBrowserSourceObservationFile", "hubBrowserSourceObservationSha256")
    fun predecessor(service: String, surface: String, variant: String): Predecessor? = when {
        surface == "WEB" && variant == "BROWSER" && service in setOf(
            "alertmanager", "prometheus", "qbittorrent") ->
            Predecessor(service,"HEADLESS","NATIVE",nativeFiles,nativeFiles)
        surface == "WEB" && variant == "BROWSER" && service in setOf("grafana", "firefly-iii") ->
            Predecessor(service, "HEADLESS", "NATIVE",
                if (service == "grafana") nativeFiles else setOf("sourceNativeOracleFile"))
        surface in setOf("WEB", "ANDROID") && (surface != "ANDROID" || variant in setOf("API34", "API36")) &&
            service in setOf("seafile", "homeassistant", "jellyfin", "mastodon") ->
            Predecessor(service, "HEADLESS", "NATIVE",
                nativeFiles + (if (service == "mastodon") setOf("originalSocialOracleFile") else emptySet()),
                if (service in setOf("homeassistant", "jellyfin")) nativeFiles else
                    if (service == "mastodon") setOf("originalSocialOracleFile") else emptySet())
        surface == "ANDROID" && variant in setOf("API34", "API36") &&
            service in setOf("element", "synapse", "matrix-authentication-service", "livekit") ->
            Predecessor("element", "HEADLESS", "NATIVE", nativeFiles, nativeFiles)
        service == "jupyter-notebook" && surface == "WEB" && variant == "BROWSER" ->
            Predecessor("jupyterhub", "WEB", "BROWSER", hubBrowserFiles, hubBrowserFiles)
        service == "identity-onboarding" && surface == "WEB" && variant == "BROWSER" ->
            Predecessor("keycloak", "WEB", "BROWSER", browserFiles, browserFiles)
        service == "ntfy" && surface == "WEB" && variant == "BROWSER" ->
            // Only completed original owner custody precedes ntfy; its GROUP
            // session is a result of this case, never an input to CASE_PREPARE.
            Predecessor("keycloak", "WEB", "BROWSER", emptySet())
        service == "onlyoffice" && (surface == "HEADLESS" && variant == "NATIVE" ||
            surface == "ANDROID" && variant in setOf("API34", "API36")) ->
            Predecessor("onlyoffice", "WEB", "BROWSER", browserFiles)
        surface != "HEADLESS" || variant != "NATIVE" -> null
        service == "loki" -> Predecessor("alloy", "HEADLESS", "NATIVE", setOf(
            "alloySourceOracleFile", "alloySourceOracleSha256", "alloySourceObservationFile", "alloySourceObservationSha256"))
        service == "huly" -> Predecessor("huly", "WEB", "BROWSER", setOf("hulyBrowserSourceOracleFile"))
        service in setOf("jupyterhub", "jupyter-notebook") ->
            Predecessor("jupyterhub", "WEB", "BROWSER", hubBrowserFiles, hubBrowserFiles)
        service in setOf("keycloak", "identity-onboarding") ->
            Predecessor(service, "WEB", "BROWSER", browserFiles, browserFiles)
        service == "human-agent-authorization" -> Predecessor("identity-onboarding", "HEADLESS", "NATIVE", emptySet())
        else -> null
    }
    fun select(manifestBytes: ByteArray, service: String, surface: String, variant: String,
        journey: String): QualificationExecutionMode {
        require(manifestBytes.size in 1..4194304 && service in native && journey.matches(Regex("[a-z][a-z0-9-]{0,95}")))
        val manifest = Json { ignoreUnknownKeys = false }.parseToJsonElement(
            manifestBytes.decodeToString(throwOnInvalidSequence = true)).jsonObject
        require(manifest.getValue("schemaVersion").jsonPrimitive.int == 2)
        val matches = manifest.getValue("cases").jsonArray.map { it.jsonObject }.filter {
            it.getValue("serviceId").jsonPrimitive.content == service &&
                it.getValue("surface").jsonPrimitive.content == surface &&
                it.getValue("variant").jsonPrimitive.content == variant &&
                it.getValue("journey").jsonPrimitive.content == journey
        }
        require(matches.size == 1 && matches.single().getValue("runner").jsonPrimitive.content ==
            "scripts/qualified-runner.py" && matches.single().getValue("adapter") is JsonPrimitive &&
            matches.single().getValue("adapter").jsonPrimitive.isString &&
            matches.single().getValue("adapter").jsonPrimitive.content.startsWith("runners/")) {
            "Exactly one pinned executable original journey required"
        }
        require(surface == "HEADLESS" && variant == "NATIVE" ||
            surface == "WEB" && variant == "BROWSER" && service in web ||
            surface == "ANDROID" && variant in setOf("API34", "API36") && service in android) {
            "Service/surface/variant is not in the source-declared table"
        }
        return when {
            surface == "HEADLESS" && variant == "NATIVE" && service in denialProbe ->
                QualificationExecutionMode.HOST_NATIVE_WITH_DENIAL_PROBE
            surface == "HEADLESS" && variant == "NATIVE" && service in publicOfficial ->
                QualificationExecutionMode.QCLIENT_RUNNER
            surface == "HEADLESS" && variant == "NATIVE" -> QualificationExecutionMode.HOST_NATIVE
            surface == "WEB" && variant == "BROWSER" -> QualificationExecutionMode.QCLIENT_RUNNER
            surface == "ANDROID" && variant in setOf("API34", "API36") -> QualificationExecutionMode.QCLIENT_RUNNER
            else -> throw IllegalArgumentException("Unknown qualified service/surface/variant")
        }
    }
}
