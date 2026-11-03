package net.datamancy.platform

/** Logical responsibility from the compiled recipe implementations, not OCI image provenance.
 * Database volumes belong to their database product; application migrations retain application responsibility.
 * Private proxies and helper workers belong to the application they serve, not the image they reuse.
 * This describes existing private composites; it does not consolidate their duplicate databases/identity providers.
 */
internal object CompiledProcessOwners {
    private fun owned(product: String, ids: String): Map<String, String> = ids.split(' ').associateWith { product }
    private val pg = owned("postgres", "postgres-init postgres")
    private val maria = owned("mariadb", "mariadb-init mariadb")
    private val identity = pg + owned("postgres", "identity-db-init") + owned("keycloak", "keycloak")
    private val synapse = pg + owned("postgres", "synapse-db-init") + owned("synapse", "signing-key-init synapse")
    private val bookstack = maria + owned("bookstack", "bookstack-files-init bookstack-migrate php bookstack")
    private val seafile = maria + owned("valkey", "cache") + owned("seafile", "schema-init server users-init backend files")
    private val sogo = owned("postgres", "database-init database accounts-init") + owned("memcached", "cache") + owned("sogo", "sogod groupware")
    private val mail = owned("mailserver", "mail-init mail")
    // Responsible consumer of shared physical inputs, reviewed against the composing input generators.
    // These are not claims about a central secret issuer or grants of new access to those files.
    val sharedInputs: Map<String, Map<String, String>> = mapOf(
        "canonical-core" to mapOf("postgres-ca.pem" to "postgres"),
        "canonical-providers" to mapOf("postgres-ca.pem" to "postgres"),
        "matrix-rtc" to mapOf("rtc-registration.yaml" to "synapse"),
        "keykeeper" to mapOf("ca.pem" to "openbao"),
        "node-metrics" to mapOf("ca.pem" to "node-exporter"),
        "office" to mapOf("ca.pem" to "seafile", "process-init.py" to "seafile"),
        "sogo" to mapOf("db-ca.pem" to "postgres"),
        "sogo-mail" to mapOf("db-ca.pem" to "postgres", "mail-ca.pem" to "mailserver"))
    fun inputOwner(recipe: String, file: String, consumerProducts: Set<String?>): String? {
        if (consumerProducts.isEmpty() || null in consumerProducts) return null
        if (consumerProducts.size == 1) return consumerProducts.single()
        return sharedInputs[recipe]?.get(file)?.also { require(it in consumerProducts) { "Shared input policy no longer matches its consumers" } }
    }
    val recipes: Map<String, Map<String, String>> = mapOf(
        "foundation" to (pg + owned("valkey", "valkey") + owned("ntfy", "ntfy")),
        "canonical-core" to (pg + owned("valkey", "valkey") + owned("ntfy", "ntfy") +
            owned("postgres", "planka-db-init postgres-finalize") + owned("planka", "planka-init planka")),
        "canonical-providers" to (pg + maria + owned("valkey", "valkey") + owned("ntfy", "ntfy-auth-init ntfy") +
            owned("memcached", "memcached") + owned("postgres", "planka-db-init postgres-finalize") +
            owned("planka", "planka-init planka") + owned("keycloak", "identity-db-init identity-realm-init identity-db-finalize keycloak") +
            owned("postgres", "firefly-db-init firefly-db-finalize") +
            owned("firefly-iii", "firefly-files-init firefly-migrate firefly-runtime-config firefly-php firefly") + owned("caddy", "caddy")),
        "sql-cache" to (maria + owned("memcached", "memcached")),
        "identity" to identity,
        "caddy" to owned("caddy", "caddy"),
        "observability" to listOf("alertmanager", "loki", "prometheus", "alloy", "grafana").associateWith { it },
        "forgejo" to owned("forgejo", "forgejo-init forgejo"),
        "planka" to (pg + owned("postgres", "planka-db-init") + owned("planka", "planka-init planka")),
        "jellyfin" to owned("jellyfin", "media-init jellyfin"),
        "donetick" to owned("donetick", "donetick"),
        "homeassistant" to owned("homeassistant", "config-init homeassistant"),
        "notebook" to owned("jupyter-notebook", "notebook-init notebook"),
        "qbittorrent" to owned("qbittorrent", "config-init qbittorrent"),
        "synapse" to synapse,
        "matrix" to (synapse + owned("element", "element-web caddy")),
        "matrix-identity" to (identity + synapse + owned("keycloak", "identity") + owned("postgres", "mas-db-init") +
            owned("matrix-authentication-service", "mas-migrate mas-config-init auth") + owned("element", "element")),
        "matrix-rtc" to (identity + synapse + owned("keycloak", "identity") + owned("postgres", "mas-db-init") +
            owned("matrix-authentication-service", "mas-migrate mas-config-init auth") + owned("element", "element") +
            owned("livekit", "livekit rtc rtc-authorizer")),
        "opensearch" to owned("opensearch", "search-config-init opensearch search-security-init"),
        "firefly" to (pg + owned("postgres", "firefly-db-init") + owned("firefly-iii", "firefly-files-init firefly-migrate php firefly")),
        "bookstack" to bookstack,
        "knowledge-identity" to (identity + (bookstack - "bookstack") + owned("bookstack", "knowledge")),
        "livekit" to owned("livekit", "livekit rtc"),
        "openbao" to owned("openbao", "bao"),
        "mastodon" to (pg + owned("postgres", "mastodon-db-init") + owned("valkey", "valkey") +
            owned("mastodon", "mastodon-migrate mastodon-accounts mastodon-rss-accounts mastodon sidekiq streaming social")),
        "searxng" to owned("searxng", "corpus-init searxng search"),
        "erpnext" to (maria + owned("mariadb", "installer-retire") + owned("valkey", "cache queue") +
            owned("erpnext", "site-config-init site-init backend websocket worker scheduler erp")),
        "crowdsec" to owned("crowdsec", "guard-init guard"),
        "seafile" to seafile,
        "office" to (seafile + owned("onlyoffice", "office-state-init docservice office")),
        "keykeeper" to ((identity - "keycloak") + owned("keycloak", "identity") + owned("openbao", "bao") + owned("keykeeper", "trust-init keeper")),
        "node-metrics" to (owned("node-exporter", "metrics-init node") + owned("prometheus", "prometheus")),
        "backup" to owned("kopia", "repository-init backup"),
        "huly" to owned("huly", "cockroach database-init elastic-config-init elastic elastic-users objects redpanda stats account-bootstrap account workspace transactor collaborator rekoni fulltext front kvs huly"),
        "jupyterhub" to owned("jupyterhub", "alice bob hub controller"),
        "sogo" to sogo,
        "mail" to mail,
        "sogo-mail" to (sogo + mail)
    )
}
