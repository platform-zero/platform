package net.datamancy.platform

import java.util.Base64
import java.util.HexFormat

/** Exact one-provider Maria/Seafile/ONLYOFFICE/BookStack/ERP credential projection.
 * Credentials are generated ONCE after complete pure graph admission. Nothing here
 * installs state, replays bootstrap, fabricates an original identity or grants a
 * second SQL/cache provider. The caller must bind the returned bytes before sealing.
 */
internal data class CanonicalMariaOfficeBundle(val inputs: Map<String, String>,
    val erp: CanonicalMariaCredentialPair, val erpCutoverPassword: String,
    val seafileCachePassword: String)

internal object CanonicalMariaOfficeSource {
    fun inputs(rootPassword: String, originalOwnerUuid: String, oidcClientSecret: String,
        password: () -> String = RuntimePreparation::password,
        mariaPki: () -> Map<String, String> = { PrivateWebPki.generate("mariadb") },
        freshApi: FreshNativeIngressGrants? = null, generation: String? = null,
        outsiderUuid: String? = null): CanonicalMariaOfficeBundle {
        require(rootPassword.matches(Regex("[a-f0-9]{64}")) &&
            oidcClientSecret.matches(Regex("[a-f0-9]{64}")) && rootPassword != oidcClientSecret &&
            runCatching { java.util.UUID.fromString(originalOwnerUuid).toString() == originalOwnerUuid }.getOrDefault(false))
        val used = mutableSetOf(rootPassword, oidcClientSecret)
        fun fresh(): String = password().also { require(it.matches(Regex("[a-f0-9]{64}")) && used.add(it)) }
        val health = fresh()
        val seafile = CanonicalMariaCredentialPair(fresh(), fresh())
        val bookstack = CanonicalMariaCredentialPair(fresh(), fresh())
        val erp = CanonicalMariaCredentialPair(fresh(), fresh())
        val cutover = fresh()
        val cacheSeafile = fresh()
        val bookstackApp = "base64:" + Base64.getEncoder().encodeToString(HexFormat.of().parseHex(fresh()))
        val admin = fresh()
        val tls = mariaPki()
        require(tls.keys == setOf("ca.pem", "web.pem", "web-key.pem") && tls.values.all { it.startsWith("-----BEGIN ") })
        val office = OfficeRuntime.canonicalInputs(seafile.migrationPassword, seafile.runtimePassword,
            cacheSeafile, tls.getValue("ca.pem"))
        // The one source CA is exported by Maria and referenced by Seafile/BookStack/ERP.
        // Never regenerate a second file with the same name in another family.
        val storage = office.seafile.filterKeys { it != "seafile-mariadb-ca.pem" }
        require(office.seafile.getValue("seafile-mariadb-ca.pem") == tls.getValue("ca.pem"))
        val editor = office.onlyoffice.filterKeys { it != "onlyoffice-ca.pem" } +
            mapOf("seafile-ca.pem" to storage.getValue("seafile-ca.pem"))
        require(office.onlyoffice.getValue("onlyoffice-ca.pem") == storage.getValue("seafile-ca.pem"))
        val outsiderGrant = if (freshApi?.outsiderBookstackApiId != null) {
            require(outsiderUuid != null && outsiderUuid != originalOwnerUuid &&
                runCatching { java.util.UUID.fromString(outsiderUuid).toString() == outsiderUuid }.getOrDefault(false))
            FreshBookstackOutsiderGrant(outsiderUuid, freshApi.outsiderBookstackApiId,
                requireNotNull(freshApi.outsiderBookstackApiSecret))
        } else {
            require(outsiderUuid == null)
            null
        }
        val books = BookStackRuntime.releaseInputs(bookstack, bookstackApp, originalOwnerUuid,
            oidcClientSecret, admin, freshApi, generation, outsiderGrant = outsiderGrant)
        val output = mapOf(
            "mariadb-bootstrap.env" to "MARIADB_ROOT_PASSWORD=$rootPassword\nMARIADB_HEALTH_PASSWORD=$health\n",
            "mariadb-health.env" to "MARIADB_HEALTH_PASSWORD=$health\n",
            "mariadb-seafile-grants.env" to "SEAFILE_MIGRATION_PASSWORD=${seafile.migrationPassword}\n" +
                "SEAFILE_RUNTIME_PASSWORD=${seafile.runtimePassword}\n",
            "mariadb-bookstack-grants.env" to "BOOKSTACK_MIGRATION_PASSWORD=${bookstack.migrationPassword}\n" +
                "BOOKSTACK_RUNTIME_PASSWORD=${bookstack.runtimePassword}\n",
            "mariadb-erp-grants.env" to "ERP_MIGRATION_PASSWORD=${erp.migrationPassword}\n" +
                "ERP_RUNTIME_PASSWORD=${erp.runtimePassword}\nERP_CUTOVER_PASSWORD=$cutover\n",
            "mariadb-ca.pem" to tls.getValue("ca.pem"),
            "mariadb.pem" to tls.getValue("web.pem"),
            "mariadb-key.pem" to tls.getValue("web-key.pem")
        ) + storage + editor + books
        require(output.size == 8 + storage.size + editor.size + books.size - 1 &&
            output.keys.all { it.matches(Regex("[a-z][a-z0-9.-]{0,79}")) }) {
            "Maria/office families attempted to overwrite a provider or peer input"
        }
        return CanonicalMariaOfficeBundle(output, erp, cutover, cacheSeafile)
    }
}
