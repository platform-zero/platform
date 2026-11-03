package net.datamancy.platform

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class ReleasePlanTest {
    private val digest = "a".repeat(64)
    private val image = "example.org/app@sha256:${"b".repeat(64)}"
    private fun product(id: String, dependencies: List<String>) = ProductContract(id, "1.0",
        listOf(LockedProcess(id, ProcessRole.DAEMON, image, dependencies, "ready", emptyList(), 65532, listOf(NetworkRole.APP), emptyList())),
        emptyList(), emptyList(), listOf(Journey("healthy", "works")))

    @Test fun `offline dependency plan is sorted and explicitly non executable`() {
        val p = ReleasePlanning.offline(ReleaseLock(1, listOf(product("a", listOf("z")), product("z", emptyList()))), digest)
        assertEquals(listOf("z", "a"), p.processOrder)
        assertFalse(p.executable)
        assertEquals(emptyList(), p.outwardHosts)
    }
    @Test fun `missing dependency and cycles cannot produce plan`() {
        assertFailsWith<NoSuchElementException> { ReleasePlanning.offline(ReleaseLock(1, listOf(product("a", listOf("missing")))), digest) }
        assertFailsWith<IllegalArgumentException> { ReleasePlanning.offline(ReleaseLock(1,
            listOf(product("a", listOf("z")), product("z", listOf("a")))), digest) }
    }
}
