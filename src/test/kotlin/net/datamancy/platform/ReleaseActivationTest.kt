package net.datamancy.platform

import kotlinx.serialization.json.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** Pure route-shape regressions; no registry bootstrap, native CLI or external key is manufactured. */
internal class ReleaseActivationTest {
    private val generation = "q-012345abcdef"
    private val host = "app.datamancy.net"
    private val sha = "a".repeat(64)
    private val spec = PrivateDeploymentSpec(name = "$generation-v2", volumes = emptyList(), processes = emptyList())
    private val pin = GenerationPin(GenerationMember(spec.name), sha, emptyMap(), sha, spec)
    private val owner = BoundSiteOwnership(
        AssemblySummary(AssemblyRequest(id = generation, candidateSha256 = sha, inventorySha256 = sha,
            selections = emptyList(), diskReservationMiB = 10240), emptyList(), emptySet()),
        SiteOwnership(site = "datamancy", assemblySha256 = sha, processes = emptyList(), state = emptyList(),
            inputs = emptyList(), routes = listOf(SiteRouteOwner(host, "app", "$generation-v2/backend", 8080))),
        setOf(host))
    private fun slot(dial: String): JsonObject = buildJsonObject {
        put("handle", buildJsonArray { add(buildJsonObject {
            put("handler", "subroute")
            put("routes", buildJsonArray { add(buildJsonObject {
                put("match", buildJsonArray { add(buildJsonObject {
                    put("host", buildJsonArray { add(host) })
                }) })
                put("handle", buildJsonArray { add(buildJsonObject {
                    put("handler", "reverse_proxy")
                    put("upstreams", buildJsonArray { add(buildJsonObject { put("dial", dial) }) })
                }) })
            }) })
        }) })
    }
    @Test fun `current successor route is the actual recorded source process not predecessor`() {
        val dial = "p0v3-live-$generation-v2-backend:8080"
        assertEquals(listOf(CaddyUpstream(host, dial)),
            originalSuccessorUpstreams(slot(dial), ReleaseGeneration(generation, sha), owner, pin))
        assertFailsWith<IllegalArgumentException> {
            originalSuccessorUpstreams(slot("p0v3-live-q-abcdef012345-v2-backend:8080"),
                ReleaseGeneration(generation, sha), owner, pin)
        }
        assertFailsWith<IllegalArgumentException> {
            originalSuccessorUpstreams(slot("p0v3-live-$generation-v2-backend:9000"),
                ReleaseGeneration(generation, sha), owner, pin)
        }
    }
    @Test fun `read only authority refuses invented bootstrap paths before touching files`() {
        val forged = RestoredOriginalRouteAuthority(ReleaseGeneration(generation, sha), "datamancy",
            setOf(host), sha, ActivationInput("/tmp/invented-head.json", sha),
            ActivationInput("/tmp/invented-route.json", sha), null,
            listOf(CaddyUpstream(host, "p0v3-live-$generation-v2-backend:8080")), sha, sha)
        assertFailsWith<IllegalArgumentException> { forged.recheck() }
    }
    @Test fun `read only entry refuses foreign source before any registry access`() {
        assertFailsWith<IllegalArgumentException> {
            ActiveSiteRegistry.readOriginalRoutes(ReleaseGeneration("foreign", sha), "datamancy",
                setOf(host), sha)
        }
    }
}
