package net.datamancy.platform

import java.net.URI
import kotlin.test.*

class DonetickRuntimeActorOriginTest {
    @Test fun `r3 one use enrollment fences all three distinct native roles`() {
        val selected = PackagedGraphFragment.pendingV3R9().first.fragments
            .single { it.id == "private-donetick" }
        assertEquals(3, selected.revision)
        val fragment = PackagedGraphFragment.loadPendingV3(selected.id, selected.revision, candidate = 9).definition
        val init = fragment.processes.single { it.id == "donetick-actors-init" }
        val nonmemberFile = "donetick-app-nonmember-signup.json"
        assertTrue(fragment.inputs.any { it.name == nonmemberFile && "donetick-actors-init" in it.consumers })
        assertTrue(init.files.any { it.file == nonmemberFile && it.target == "/run/secrets/$nonmemberFile" })
        assertFalse("donetick-actors-init" in fragment.restore.processes)
        val grant = FreshDonetickActorGrant("q-abcdef012345", "a".repeat(64),
            "b".repeat(64), "c".repeat(64))
        val inputs = DonetickRuntime.freshActorEnrollmentInputs(grant,
            DonetickRuntime.canonicalInputs { "d".repeat(64) }.getValue("selfhosted.yaml"))
        assertEquals(mapOf("OWNER" to "owner", "APP_NON_MEMBER" to "app-nonmember",
            "GATEWAY_OUTSIDER" to "outsider"), DonetickRuntime.actorUsernames)
        assertContains(inputs.getValue(nonmemberFile), "\"username\":\"app-nonmember\"")
        assertContains(inputs.getValue("donetick-outsider-signup.json"), "\"username\":\"outsider\"")
        assertContains(inputs.getValue("donetick-actor-enroll.sh"),
            "busybox sha256sum /run/secrets/donetick-owner-signup.json /run/secrets/donetick-outsider-signup.json /run/secrets/$nonmemberFile")
        assertEquals(2, inputs.getValue("donetick-actor-enroll.sh").split(
            "--post-file=/run/secrets/$nonmemberFile").size)
        assertFailsWith<IllegalArgumentException> {
            FreshDonetickActorGrant("q-abcdef012345", "a".repeat(64), "b".repeat(64), "b".repeat(64))
        }
    }

    @Test fun `gateway outsider cannot substitute APP nonmember in native readback`() {
        val client = java.net.http.HttpClient.newBuilder()
            .followRedirects(java.net.http.HttpClient.Redirect.NEVER).build()
        assertFailsWith<IllegalArgumentException> {
            DonetickRuntime.nativeIssuanceReadback(client, client,
                URI.create("https://donetick.datamancy.net"), "owner", "a".repeat(64),
                "outsider", "b".repeat(64), 1, "original")
        }
        val otherClient = java.net.http.HttpClient.newBuilder()
            .followRedirects(java.net.http.HttpClient.Redirect.NEVER).build()
        assertFailsWith<IllegalArgumentException> {
            DonetickRuntime.nativeIssuanceReadback(client, otherClient,
                URI.create("https://donetick.datamancy.net"), "owner", "a".repeat(64),
                "outsider", "b".repeat(64), 1, "original")
        }
    }
    @Test fun `readback and generated serving policy use only selected Donetick GROUP origin`() {
        val routes = PackagedGraphFragment.pendingV3R9().first.integratedReference!!.modules
            .single { it.id == "donetick" }.privateRoutes
        val route = routes.single { it.policy == "GROUP" }
        assertEquals("donetick.datamancy.net", route.host)
        assertTrue(routes.any { it.policy == "NATIVE" && it.host != route.host })
        val selected = URI.create("https://${route.host}")
        assertEquals("https://donetick.datamancy.net", DonetickRuntime.requireActorOrigin(selected))
        val config = DonetickRuntime.canonicalInputs { "a".repeat(64) }.getValue("selfhosted.yaml")
        assertContains(config, "public_host: https://donetick.datamancy.net\n")
        assertContains(config, "cors_allow_origins: ['https://donetick.datamancy.net']")
        assertContains(config, "allowed_origins: ['https://donetick.datamancy.net']")
        assertFalse("chores.datamancy.net" in config)
        listOf("https://chores.datamancy.net", "https://donetick-native.datamancy.net",
            "http://donetick.datamancy.net", "https://donetick.datamancy.net:443",
            "https://donetick.datamancy.net/", "https://donetick.datamancy.net@evil.invalid",
            "https://donetick.datamancy.net?q=1", "https://donetick.datamancy.net#fragment")
            .forEach { foreign ->
                assertFailsWith<IllegalArgumentException>(foreign) {
                    DonetickRuntime.requireActorOrigin(URI.create(foreign))
                }
            }
    }
}
