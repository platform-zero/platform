package net.datamancy.platform

import java.util.Base64
import java.util.HexFormat

/** Fresh-only pinned importer 2.3.5 manual-file mode. It has its own key,
 * subject-owned job metadata and volume; never receives a global Firefly API
 * bearer or auto-import secret. Passport client is minted in the Firefly native
 * user intent and is read back before that intent's successful receipt.
 */
internal object FreshFinanceImporterSource {
    fun inputs(publicClientId: String, keyHex: String, generation: String): String {
        require(publicClientId.matches(Regex("[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")) &&
            keyHex.matches(Regex("[a-f0-9]{64}")) && generation.matches(Regex("q-[a-f0-9]{12}")))
        val appKey = Base64.getEncoder().encodeToString(HexFormat.of().parseHex(keyHex))
        return """
            APP_ENV=production
            APP_DEBUG=false
            APP_KEY=base64:$appKey
            APP_URL=https://firefly-importer.datamancy.net
            FIREFLY_III_PATH=/var/www/html
            FIREFLY_III_URL=https://firefly.datamancy.net
            VANITY_URL=https://firefly.datamancy.net
            FIREFLY_III_CLIENT_ID=$publicClientId
            FIREFLY_OIDC_ISSUER=https://auth.datamancy.net/realms/p0v3
            P0V3_GENERATION=$generation
            FIREFLY_III_ACCESS_TOKEN=
            CAN_POST_AUTOIMPORT=false
            CAN_POST_FILES=false
            AUTO_IMPORT_SECRET=
            EXPECT_SECURE_URL=true
            VERIFY_TLS_SECURITY=true
            CURL_CA_BUNDLE=/run/secrets/finance-ingress-ca.pem
            SSL_CERT_FILE=/run/secrets/finance-ingress-ca.pem
            FAKE_DATA=false
            STORE_FAKE_DATA=false
            ENABLE_MAIL_REPORT=false
            ENABLE_BANKING_IMPORT_IP=127.0.0.1
            LOG_LEVEL=warning
            LOG_OUTPUT_LEVEL=warn
            LOG_CHANNEL=stderr
            AUTORUN_ENABLED=false
            IS_DOCKER=true
            SESSION_DRIVER=file
            SESSION_LIFETIME=15
            SESSION_COOKIE=__Host-firefly_importer_app
            SESSION_SECURE_COOKIE=true
            TRUSTED_PROXIES=**
            TZ=UTC
        """.trimIndent() + "\n"
    }
}
