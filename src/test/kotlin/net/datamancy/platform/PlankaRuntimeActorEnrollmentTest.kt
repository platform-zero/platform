package net.datamancy.platform

import java.net.URI
import java.net.http.HttpClient
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PlankaRuntimeActorEnrollmentTest {
    private val grant = FreshPlankaActorGrant("q-abcdef012345", "a".repeat(64), "b".repeat(64))

    @Test fun firstUseEnrollmentHasRealTaggedApiAndFencedEffectOrdering() {
        val inputs = PlankaRuntime.freshActorEnrollmentInputs(grant, "c".repeat(64))
        assertEquals(setOf("planka-enrollment.env", "planka-enroll.js"), inputs.keys)
        assertTrue(inputs.getValue("planka-enrollment.env").contains("PLANKA_OWNER_PASSWORD=${"a".repeat(64)}\n"))
        assertTrue(inputs.getValue("planka-enrollment.env").contains("PLANKA_OUTSIDER_PASSWORD=${"b".repeat(64)}\n"))
        assertFalse(inputs.getValue("planka-enrollment.env").contains("DEFAULT_ADMIN_PASSWORD="))
        val js = inputs.getValue("planka-enroll.js")
        assertTrue(js.indexOf("record('attempted.json'") < js.indexOf("const admin = await login("))
        assertTrue(js.indexOf("record('owner-created.json'") < js.indexOf("const outsiderCreated ="))
        assertTrue(js.indexOf("record('outsider-created.json'") < js.indexOf("const ownerToken ="))
        assertTrue(js.indexOf("record(role + '-terms.intent.json'") < js.indexOf("'/api/access-tokens/accept-terms', null,"))
        assertTrue(js.contains("fs.mkdirSync(directory, { mode: 0o700 })"))
        assertTrue(js.contains("fs.fsyncSync(fd)"))
        assertTrue(js.contains("role: 'boardUser'"))
        assertTrue(js.contains("request('GET', '/api/users', outsiderToken, null)).status !== 403"))
        assertTrue(js.contains("'User-Agent': 'p0v3-original-planka-enrollment'"))
        assertFalse(js.contains("console.log("))
    }

    @Test fun r2InstallOnlyEnrollsAfterBootstrapAndServingAndRestoreNeverDoes() {
        val file = requireNotNull(javaClass.getResourceAsStream("/fragments/v3/planka/r2/fragment.yaml"))
            .use { it.readBytes().decodeToString() }
        assertTrue(file.startsWith("schemaVersion: 2\nid: planka-postgres\nrevision: 2\n"))
        assertTrue(file.contains("planka-enroll: [planka]"))
        assertTrue(file.contains("networks: [planka-enrollment]"))
        assertTrue(file.contains("networks: [planka-data, planka-web, planka-enrollment]"))
        assertTrue(file.contains("webNetworks: [planka-web]"))
        assertTrue(file.substringAfter("install:").substringBefore("restore:")
            .contains("processes: [planka-db-init, planka-init, planka-db-finalize, planka, planka-enroll]"))
        assertFalse(file.substringAfter("restore:").contains("planka-enroll"))
        assertFalse(file.substringAfter("restore:").contains("planka-enrollment.env"))
    }

    @Test fun invalidCredentialsAndForeignRouteAreRejectedBeforeAnyEffect() {
        assertFailsWith<IllegalArgumentException> { FreshPlankaActorGrant("q-abcdef012345", "a".repeat(64), "a".repeat(64)) }
        assertFailsWith<IllegalArgumentException> { PlankaRuntime.freshActorEnrollmentInputs(grant, "a".repeat(64)) }
        val owner = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
        val outsider = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
        assertFailsWith<IllegalArgumentException> {
            PlankaRuntime.nativeActorReadback(owner, outsider, URI.create("https://planka.private.invalid"),
                "a".repeat(64), "b".repeat(64), "123", "124")
        }
        assertFailsWith<IllegalArgumentException> {
            PlankaRuntime.nativeActorReadback(owner, outsider, URI.create("https://planka.datamancy.net:8443"),
                "a".repeat(64), "b".repeat(64), "123", "124")
        }
        assertFailsWith<IllegalArgumentException> {
            PlankaRuntime.nativeActorReadback(owner, outsider, URI.create("https://planka.datamancy.net"),
                "a".repeat(64), "a".repeat(64), "123", "124")
        }
        assertFailsWith<IllegalArgumentException> {
            PlankaRuntime.nativeActorReadback(owner, outsider, URI.create("https://boards.datamancy.net"),
                "a".repeat(64), "b".repeat(64), "123", "124")
        }
    }
}
