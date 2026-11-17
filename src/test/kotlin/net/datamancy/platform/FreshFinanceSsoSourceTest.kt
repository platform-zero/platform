package net.datamancy.platform

import kotlin.test.*

class FreshFinanceSsoSourceTest {
    @Test fun `fresh finance browser identity requires exact subject and separate PKCE clients`() {
        val secret = "a".repeat(64)
        val cookie = "b".repeat(64)
        val client = FreshFinanceSsoSource.client("firefly-sso", "https://firefly.datamancy.net", secret)
        assertContains(client.toString(), "firefly.datamancy.net/oauth2/callback")
        assertContains(client.toString(), "pkce.code.challenge.method")
        val env = FreshFinanceSsoSource.inputs("firefly-sso", "https://firefly.datamancy.net", secret,
            cookie, "http://firefly:8080/")
        assertContains(env, "OAUTH2_PROXY_USER_ID_CLAIM=sub\n")
        assertContains(env, "OAUTH2_PROXY_ALLOWED_GROUPS=admins,operators,users\n")
        assertContains(env, "OAUTH2_PROXY_COOKIE_NAME=__Host-firefly_sso\n")
        assertContains(env, "OAUTH2_PROXY_PROVIDER_CA_FILE=/run/secrets/identity-ca.pem\n")
        assertFails { FreshFinanceSsoSource.inputs("firefly-sso", "https://firefly.datamancy.net", secret,
            secret, "http://firefly:8080/") }
        assertFails { FreshFinanceSsoSource.client("firefly-sso", "https://attacker.invalid", secret) }
        assertFails { FreshFinanceSsoSource.inputs("firefly-sso", "https://firefly.datamancy.net", secret,
            cookie, "http://firefly-importer:8080/") }
    }
}
