package net.datamancy.platform

import org.junit.jupiter.api.Test
import kotlin.test.*
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.nio.file.Path

/** No host/issuer state is written by these prospective source policy tests. */
class GenerationWorkingEnvelopeIssuerTest {
    private fun p(id: String, cap: Int, oneShot: Boolean = false) = RuntimeProcess(id,
        "example.test/source@sha256:" + "a".repeat(64), "b".repeat(64), 1000,
        memoryMiB = cap, oneShot = oneShot, readiness = if (oneShot) emptyList() else listOf("true"))

    @Test fun `selected tuning forecasts are not resident RSS and fallback retains every unchanged cap`() {
        val spec = PrivateDeploymentSpec(name = "source", volumes = emptyList(), processes = listOf(
            p("huly-cockroach", 2048), p("huly-elastic", 1536), p("huly-redpanda", 1024),
            p("alice", 2048), p("bob", 2048), p("unbounded-app", 1024), p("init", 512, true)))
        val rows = GenerationWorkingEnvelopeIssuer.forecastRows(spec).associateBy { it.process.substringAfter('/') }
        assertEquals(768L, rows.getValue("huly-cockroach").prospectiveMiB)
        assertEquals(1024L, rows.getValue("huly-elastic").prospectiveMiB)
        assertEquals(1024L, rows.getValue("huly-redpanda").prospectiveMiB)
        assertEquals(2048L, rows.getValue("alice").prospectiveMiB)
        assertEquals(2048L, rows.getValue("bob").prospectiveMiB)
        assertEquals(1024L, rows.getValue("unbounded-app").prospectiveMiB)
        assertEquals(512L, rows.getValue("init").prospectiveMiB)
        assertTrue(rows.getValue("unbounded-app").basis.contains("not RSS"))
        assertTrue(rows.values.all { it.prospectiveMiB <= it.hardCeilingMiB && it.prospectiveMiB >= 64 })
        val plan = GenerationCapacityPlanner.plan(listOf(spec), 1024,
            GenerationWorkingBudget(ActivationInput("/tmp/source-only", "a".repeat(64)),
                rows.mapValues { it.value.prospectiveMiB }.mapKeys { "source/${it.key}" },
                "r9-full-private-incremental-first-start"))
        assertEquals(2560L, plan.install.memoryMiB)
        assertTrue(plan.steady.memoryMiB > plan.install.memoryMiB)
        assertFails { GenerationCapacityPlanner.phase(plan, GenerationPhase.BACKUP) }
    }

    @Test fun `successor r10 forecasts all selected processes including install only Planka enrollment`() {
        if (System.getenv("P0V3_VERIFY_R10_GRAPH_ONLY") != "1") return
        val inventory = Json.decodeFromString<AcquiredInventory>(ReleasePrivateFiles.read(Path.of(
            "/mnt/media/p0-v3/release-bootstrap-anchors/assembly/q-5712d9335843/inventory.json"),2097152)
            .decodeToString(throwOnInvalidSequence=true))
        val spec = CanonicalSharedYamlGraph.pendingR10Spec(inventory, "q-5712d9335843-v2",
            controllerSha256="c".repeat(64), controllerUid=1000, controllerGid=1000)
        val rows = GenerationWorkingEnvelopeIssuer.forecastRows(spec)
        assertEquals(134, rows.size)
        assertEquals(79, rows.count { !it.oneShot })
        assertEquals(1, rows.count { it.process.endsWith("/planka-enroll") && it.oneShot })
        assertTrue(rows.all { it.prospectiveMiB in 64L..it.hardCeilingMiB })
    }
}
