package net.datamancy.platform

import kotlin.test.*

class RuntimeQuadletSystemdTest {
    @Test fun `supervising MainPID is confined to the exact delegated subgroup`() {
        val unit = "p0v3-q-aabbccddeeff-canonical-shared-core-v3-forgejo.service"
        val root = "/system.slice/$unit"
        assertTrue(RuntimeQuadletSystemd.delegatedMainPid(unit, root,
            "0::$root/p0v3-supervisor\n"))
        assertTrue(RuntimeQuadletSystemd.delegatedMainPid(unit, root,
            "0::$root/p0v3-supervisor/runtime\n"))
        for (foreign in listOf("0::$root\n", "0::$root/other\n",
            "0::$root/p0v3-supervisor-other\n", "0::/user.slice/$unit/p0v3-supervisor\n")) {
            assertFalse(RuntimeQuadletSystemd.delegatedMainPid(unit, root, foreign))
        }
        assertFalse(RuntimeQuadletSystemd.delegatedMainPid(unit, "/system.slice/other.service",
            "0::$root/p0v3-supervisor\n"))
    }
    @Test fun `notified conmon MainPID must bind original CID and canonical bundle path`() {
        val cid = "a".repeat(64)
        val store = RuntimeStore.CANONICAL_V2
        val argv = listOf("/usr/bin/conmon", "--api-version", "1", "-c", cid,
            "-b", "${store.graph}/overlay-containers/$cid/userdata", "-r", "/usr/bin/crun")
        assertTrue(RuntimeQuadletSystemd.conmonBound(argv, cid, store))
        assertFalse(RuntimeQuadletSystemd.conmonBound(argv, "b".repeat(64), store))
        assertFalse(RuntimeQuadletSystemd.conmonBound(argv, cid, RuntimeStore.LEGACY))
        assertFalse(RuntimeQuadletSystemd.conmonBound(argv + listOf("-c", cid), cid, store))
        assertFalse(RuntimeQuadletSystemd.conmonBound(argv + listOf("-b", "other"), cid, store))
        assertFalse(RuntimeQuadletSystemd.conmonBound(argv.drop(1), cid, store))
        assertFalse(RuntimeQuadletSystemd.conmonBound(argv.map {
            if (it == "${store.graph}/overlay-containers/$cid/userdata") "$cid/userdata" else it
        }, cid, store))
    }
}
