package net.datamancy.platform

import kotlinx.serialization.json.*
import kotlin.test.*

/** Pure JSON source assertions; no Caddy admin API or public listener touched. */
class CanonicalProtectedCaddyRouteTest {
    @Test fun `protected routes require a fresh trusted auth response with group and subject before upstream`() {
        val host = "portal.datamancy.net"
        val upstream = buildJsonObject { put("handler", "reverse_proxy") }
        val route = CanonicalProtectedCaddyRoute.guarded(host, "q-123456789abc", upstream)
        val steps = route.getValue("routes").jsonArray
        assertEquals(4, steps.size)
        val clean = steps[0].jsonObject.getValue("handle").jsonArray
        val removed = clean[0].jsonObject.getValue("request").jsonObject.getValue("delete").jsonArray.map { it.jsonPrimitive.content }
        assertContains(removed, "Remote-Groups")
        assertContains(removed, "Remote_Groups")
        assertContains(removed, "X-Webservices-SSO-Subject")
        val auth = steps[1].jsonObject.getValue("handle").jsonArray.single().jsonObject
        assertEquals("/oauth2/auth", auth.getValue("rewrite").jsonObject.getValue("uri").jsonPrimitive.content)
        assertContains(auth.toString(), "p0v3-live-q-123456789abc-auth-gateway:4180")
        assertContains(auth.toString(), "X-Auth-Request-Groups")
        val allowed = steps[2].jsonObject
        assertContains(allowed.getValue("match").toString(), "admins|operators|users")
        assertContains(allowed.getValue("match").toString(), "X-Webservices-SSO-Subject")
        assertEquals(upstream, allowed.getValue("handle").jsonArray.single().jsonObject)
        assertEquals(403, steps[3].jsonObject.getValue("handle").jsonArray.single().jsonObject.getValue("status_code").jsonPrimitive.int)
        val native = CanonicalProtectedCaddyRoute.guarded("seafile.datamancy.net", "q-123456789abc", upstream)
            .getValue("routes").jsonArray
        assertEquals(5, native.size)
        assertContains(native[1].jsonObject.getValue("match").toString(), "/seafhttp/*")
        assertEquals(upstream, native[1].jsonObject.getValue("handle").jsonArray.single().jsonObject)
        val control = CanonicalProtectedCaddyRoute.guarded("control.datamancy.net", "q-123456789abc", upstream)
            .getValue("routes").jsonArray
        assertEquals(5, control.size)
        assertContains(control[2].jsonObject.getValue("match").toString(), "admins|operators")
        assertContains(control[2].jsonObject.getValue("match").toString(), "/ops/*")
        assertContains(control[3].jsonObject.getValue("match").toString(), "not")
        assertEquals(null, CanonicalProtectedCaddyRoute.groupPolicy("mastodon.datamancy.net"))
        assertEquals(null, CanonicalProtectedCaddyRoute.groupPolicy("portal.datamancy.net.evil"))
        assertFails { CanonicalProtectedCaddyRoute.guarded("portal.datamancy.net.evil", "q-123456789abc", upstream) }
    }
}
