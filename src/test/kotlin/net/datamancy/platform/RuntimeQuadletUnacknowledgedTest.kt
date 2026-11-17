package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails

class RuntimeQuadletUnacknowledgedTest {
    private val member = "q-123456abcdef-canonical-shared-core-v3"
    private val fingerprint = "f".repeat(64)
    private val image = "a".repeat(64)
    private val cid = "b".repeat(64)
    private fun spec(oneShot: Boolean = true): PrivateDeploymentSpec {
        val p = RuntimeProcess("identity-realm-init", "keycloak@test", image,
            userId = 1000, oneShot = oneShot)
        return PrivateDeploymentSpec(name = member, volumes = emptyList(), processes = listOf(p),
            store = RuntimeStore.CANONICAL_V2, executionBackend = RuntimeExecutionBackend.QUADLET_V2)
    }
    private fun inspect(status: String = "exited", running: Boolean = false, exit: Int = 1,
        owner: String = member, fp: String = fingerprint, id: String = cid,
        img: String = image, name: String = "p0v3-live-$member-identity-realm-init",
        pid: Int = 0, startedAt: String = "0001-01-01T00:00:00Z"): String =
        """[{"Id":"$id","Name":"$name","Image":"sha256:$img","Config":{"Labels":{
            "io.p0v3.private-deployment":"$owner","io.p0v3.runtime-fingerprint":"$fp"}},
            "State":{"Status":"$status","Running":$running,"ExitCode":$exit,
                "Pid":$pid,"StartedAt":"$startedAt"}}]"""

    @Test fun `failed first boot only admits exact stopped one-shot native identity without an original ACK`() {
        val spec = spec()
        assertEquals(QuadletUnacknowledgedCid(cid, image, 1, "native-read-only"),
            parseUnacknowledgedNative(spec, spec.processes.single(), fingerprint, inspect()))
        // -1 is observable native state, never itself a terminal-capacity authorization.
        assertEquals(-1, parseUnacknowledgedNative(spec, spec.processes.single(), fingerprint,
            inspect(exit = -1)).exitCode)
        assertEquals(2, parseUnacknowledgedNative(spec, spec.processes.single(), fingerprint,
            inspect(exit = 2)).exitCode) // failed original import is NOT a clean initializer ACK
        for (bad in listOf(inspect(status = "running", running = true), inspect(exit = 256),
            inspect(owner = "foreign"), inspect(fp = "c".repeat(64)), inspect(id = "z".repeat(64)),
            inspect(img = "e".repeat(64)), inspect(name = "other"), "[]")) {
            assertFails { parseUnacknowledgedNative(spec, spec.processes.single(), fingerprint, bad) }
        }
        val daemon = spec(oneShot = false)
        assertFails { parseUnacknowledgedNative(daemon, daemon.processes.single(), fingerprint, inspect()) }
        assertEquals(0, parseUnacknowledgedNative(daemon, daemon.processes.single(), fingerprint,
            inspect(exit = 0)).exitCode)
        assertEquals("native-created-never-started-read-only", parseUnacknowledgedNative(daemon,
            daemon.processes.single(), fingerprint, inspect(status = "created", exit = 0)).reason)
        for (bad in listOf(inspect(status = "created", exit = 1),
            inspect(status = "created", exit = 0, pid = 1234),
            inspect(status = "created", exit = 0, startedAt = "2026-11-11T06:45:54Z"),
            inspect(status = "created", exit = 0, running = true))) {
            assertFails { parseUnacknowledgedNative(daemon, daemon.processes.single(), fingerprint, bad) }
        }
    }
}
