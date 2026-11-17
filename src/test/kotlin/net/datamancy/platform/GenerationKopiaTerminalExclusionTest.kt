package net.datamancy.platform

import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

internal class GenerationKopiaTerminalExclusionTest {
    @Test fun `only exact original stopped worker and no concurrent generation writer can enter callback`() {
        val generation = "q-000000000099"
        val id = "cap-000000000099"
        val name = "p0v3-kopia-$generation-$id-snapshot"
        val original = KopiaOriginalWorkerCreate("a".repeat(64), name, "b".repeat(64))
        val pin = ActivationInput("/protected/original-snapshot.intent.json", "b".repeat(64))
        fun worker(cid: String = original.containerId, name: String = original.container,
            state: String = "exited") = RuntimeCapacityCensus.Container(cid, name, state, "", "")
        fun check(record: KopiaOriginalWorkerCreate = original,
            observed: List<RuntimeCapacityCensus.Container> = listOf(worker())) =
            GenerationKopiaTerminalExclusion.requireOriginalWorkerQuiescent(generation, id, "snapshot",
                record, pin, observed)
        check()
        assertThrows(IllegalArgumentException::class.java) { check(observed = emptyList()) }
        assertThrows(IllegalArgumentException::class.java) { check(observed = listOf(worker(state = "running"))) }
        assertThrows(IllegalArgumentException::class.java) { check(observed = listOf(worker(cid = "c".repeat(64)))) }
        assertThrows(IllegalArgumentException::class.java) { check(observed = listOf(worker(),
            worker(name = "p0v3-kopia-$generation-$id-verify", state = "running"))) }
        assertThrows(IllegalArgumentException::class.java) { check(record = original.copy(unit = "systemd:unknown")) }
        assertThrows(IllegalArgumentException::class.java) { check(record = original.copy(intentSha256 = "0".repeat(64))) }
    }
}
