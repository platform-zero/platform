package net.datamancy.platform

import kotlin.test.*

class FreshSeafileSplitBudgetTest {
    @Test fun `r9 splits old two GiB Seafile into two app caps and one bounded proxy`() {
        val r9 = PackagedGraphFragment.pendingV3R9().first
        assertEquals(2, r9.fragments.single { it.id == "private-seafile" }.revision)
        val graph = PackagedGraphFragment.loadPendingV3("private-seafile",2,9).definition
        val steady = graph.processes.filter { it.id in graph.install.processes && !it.oneShot }.associateBy { it.id }
        assertEquals(setOf("seafile-server", "seafile-backend", "seafile-files"), steady.keys)
        assertEquals(1024, steady.getValue("seafile-server").memoryMiB)
        assertEquals(1024, steady.getValue("seafile-backend").memoryMiB)
        assertEquals(256, steady.getValue("seafile-files").memoryMiB)
        assertEquals(2304, steady.values.sumOf { it.memoryMiB })
        val config = SeafileRuntime.inputs(pki = { emptyMap() }).getValue("nginx.conf")
        assertContains(config,"worker_processes 1;")
        assertContains(config,"worker_connections 512;")
        assertContains(config,"client_body_temp_path /tmp/body;")
        assertContains(config,"client_max_body_size 10m;")
    }
}
