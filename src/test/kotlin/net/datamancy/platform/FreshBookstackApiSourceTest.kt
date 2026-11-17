package net.datamancy.platform

import kotlin.test.*

class FreshBookstackApiSourceTest {
    private val grants = FreshNativeIngressGrants("e".repeat(64),
        "\$2a\$12\$0un/uJ8ntkji/FFOdcPUgeK4Zo/x0qsj.n6yfmRLORMk8mTKBCPu2",
        bookstackApiId = "p0v3-" + "b".repeat(32), bookstackApiSecret = "c".repeat(64))

    @Test fun `fresh outsider is separate read-capable API subject with no owner page grant`() {
        val outsider = FreshBookstackOutsiderGrant("00000000-0000-4000-8000-000000000002",
            "p0v3-" + "d".repeat(32), "a".repeat(64))
        val inputs = BookStackRuntime.releaseInputs(CanonicalMariaCredentialPair("a".repeat(64), "d".repeat(64)),
            "base64:" + "A".repeat(43) + "=", "00000000-0000-4000-8000-000000000001",
            "f".repeat(64), "1".repeat(64), grants, "q-000000000099", outsider)
        val env = inputs.getValue("bookstack-migration.env")
        assertContains(env, "P0V3_BOOKSTACK_OUTSIDER_SUB=${outsider.subjectUuid}\n")
        assertContains(env, "P0V3_BOOKSTACK_OUTSIDER_API_ID=${outsider.tokenId}\n")
        val source = inputs.getValue("bookstack-api.php")
        for (required in listOf("attachment-create-all", "book-view-own", "page-view-own",
            "p0v3-outsider", "outsiderEntry->user->external_auth_id", "api_tokens')->count() !== 2"))
            assertContains(source, required)
        assertFalse(source.contains(outsider.tokenSecret) || source.contains(outsider.tokenId))
        assertFalse(source.contains("\${d}"))
        assertFails { BookStackRuntime.releaseInputs(CanonicalMariaCredentialPair("a".repeat(64), "d".repeat(64)),
            "base64:" + "A".repeat(43) + "=", outsider.subjectUuid, "f".repeat(64),
            "1".repeat(64), grants, "q-000000000099", outsider) }
    }

    @Test fun `fresh API grant is bound to one journaled native one-shot and never included in script`() {
        val inputs = BookStackRuntime.releaseInputs(CanonicalMariaCredentialPair("a".repeat(64), "d".repeat(64)),
            "base64:" + "A".repeat(43) + "=", "00000000-0000-4000-8000-000000000001",
            "f".repeat(64), "1".repeat(64), grants, "q-000000000099")
        assertContains(inputs.getValue("bookstack-migration.env"), "P0V3_BOOKSTACK_API_SECRET=${"c".repeat(64)}\n")
        val source = inputs.getValue("bookstack-api.php")
        assertFalse("c".repeat(64) in source || "e".repeat(64) in source)
        for (guard in listOf("fopen(\$intent, 'x')", "fsync(\$directory)", "api_tokens",
            "role_permissions", "Hash::check", "fopen(\$receipt, 'x')")) assertContains(source, guard)
        assertFalse("echo \$secret" in source)
        assertFailsWith<IllegalArgumentException> {
            BookStackRuntime.releaseInputs(CanonicalMariaCredentialPair("a".repeat(64), "d".repeat(64)),
                "base64:" + "A".repeat(43) + "=", "00000000-0000-4000-8000-000000000001",
                "f".repeat(64), "1".repeat(64), grants, "q-bad")
        }
        val fragment = PackagedGraphFragment.loadPendingV3("private-bookstack", 4, 9).definition
        assertEquals("bookstack", fragment.product)
        assertTrue(fragment.processes.any { it.id == "bookstack-migrate" && it.oneShot &&
            it.environmentFile == "bookstack-migration.env" &&
            it.command.last().contains("php /run/secrets/bookstack-api.php") &&
            it.files.any { file -> file.file == "bookstack-api.php" } })
        assertTrue(fragment.install.dependencies.getValue("bookstack-php").contains("bookstack-migrate"))
        assertTrue(fragment.install.dependencies.getValue("bookstack-migrate").contains("keycloak"))
        assertTrue(fragment.processes.single { it.id == "bookstack-php" }.files.any {
            it.file == "identity-ca.pem" && it.target == "/run/secrets/identity-ca.pem" })
        assertContains(inputs.getValue("bookstack-fpm.conf"), "curl.cainfo] = /run/secrets/identity-ca.pem")
        assertFalse(fragment.restore.processes.contains("bookstack-migrate"))
    }
}
