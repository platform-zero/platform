package net.datamancy.platform

import kotlin.test.*

class RuntimeCapacityCensusTest {
    @Test fun `retired Quadlet capacity also binds every original CID and denies foreign extra identities`() {
        val spec = FragmentAssemblyFixture.plan().specs.single()
        val owner = spec.name; val fp = "a".repeat(64)
        val cids = mapOf("postgres" to "b".repeat(64), "forgejo" to "c".repeat(64))
        fun row(id: String, cid: String, name: String = "p0v3-live-$owner-$id", label: String = owner) =
            RuntimeCapacityCensus.Container(cid, name, "exited", label, fp)
        val valid = cids.map { (id, cid) -> row(id, cid) }
        assertTrue(RuntimeQuadletCapacityTerminal.matchesOriginalCids(owner, cids, valid))
        assertFalse(RuntimeQuadletCapacityTerminal.matchesOriginalCids(owner, cids, valid.drop(1)))
        assertFalse(RuntimeQuadletCapacityTerminal.matchesOriginalCids(owner, cids,
            listOf(row("postgres", "d".repeat(64)), valid[1])))
        assertFalse(RuntimeQuadletCapacityTerminal.matchesOriginalCids(owner, cids,
            valid + row("unexpected", "e".repeat(64))))
        assertFalse(RuntimeQuadletCapacityTerminal.matchesOriginalCids(owner, cids,
            valid + row("postgres", "f".repeat(64))))
        assertFalse(RuntimeQuadletCapacityTerminal.matchesOriginalCids(owner, cids,
            listOf(row("postgres", cids.getValue("postgres"), label = "foreign"), valid[1]) +
                row("extra", "e".repeat(64), label = owner)))
        assertTrue(RuntimeQuadletCapacityTerminal.matchesOriginalCids(owner, emptyMap(), emptyList()))
    }

    @Test fun `current census binds exact process name owner fingerprint and quiescent state in both directions`() {
        val spec = FragmentAssemblyFixture.plan().specs.single()
        val fingerprint = "a".repeat(64)
        val cid = "b".repeat(64)
        val name = "p0v3-live-${spec.name}-${spec.processes.first().id}"
        var response = "$cid\t$name\texited\t${spec.name}\t$fingerprint\n"
        val census = RuntimeCapacityCensus { RuntimeCommands { RuntimeCommandResult(0, response) } }
        val owners = listOf(RuntimeCapacityCensus.Member(spec, fingerprint))
        fun observed() = census.snapshot(RuntimeStore.LEGACY)
        assertTrue(census.quiescent(owners, observed()))
        // Missing/foreign labels cannot hide an exact owned native process name.
        for (foreign in listOf("<no value>", "other-member")) {
            response = "$cid\t$name\texited\t$foreign\t$fingerprint\n"
            assertFalse(census.quiescent(owners, observed()))
        }
        // Correct label on a renamed or unrecognized process is also foreign.
        response = "$cid\tp0v3-live-${spec.name}-unknown\texited\t${spec.name}\t$fingerprint\n"
        assertFalse(census.quiescent(owners, observed()))
        response = "$cid\tforeign-name\texited\t${spec.name}\t$fingerprint\n"
        assertFalse(census.quiescent(owners, observed()))
        // Namespace prefix catches a missing/foreign label on an unknown process too.
        response = "$cid\tp0v3-live-${spec.name}-unknown\texited\t<no value>\t<no value>\n"
        assertFalse(census.quiescent(owners, observed()))
        response = "$cid\t$name\trunning\t${spec.name}\t$fingerprint\n"
        assertFalse(census.quiescent(owners, observed()))
        response = "$cid\t$name\tpaused\t${spec.name}\t$fingerprint\n"
        assertFalse(census.quiescent(owners, observed()))
        response = "$cid\t$name\tunknown\t${spec.name}\t$fingerprint\n"
        assertFalse(census.quiescent(owners, observed()))
        response = "$cid\t$name\texited\t${spec.name}\t${"c".repeat(64)}\n"
        assertFalse(census.quiescent(owners, observed()))
        // Different CIDs claiming the same exact identity are not one process.
        response = "$cid\t$name\texited\t${spec.name}\t$fingerprint\n" +
            "${"c".repeat(64)}\t$name\texited\t${spec.name}\t$fingerprint\n"
        assertFalse(census.quiescent(owners, observed()))
        // Global native CID duplication cannot bypass by changing the name.
        response = "$cid\t$name\texited\t${spec.name}\t$fingerprint\n" +
            "$cid\tforeign-name\texited\t<no value>\t<no value>\n"
        assertFails { observed() }
        response = "short\t$name\texited\t${spec.name}\t$fingerprint\n"
        assertFails { observed() }
    }
}
